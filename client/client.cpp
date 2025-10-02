// client.cpp
// Enhanced client with:
//  - parallel piece downloads (thread pool + scheduler)
//  - seeder selection heuristics (back-off, prefer responsive seeders)
//  - auto upload_file after successful verified download
//  - automatic set_addr registration after login (tracker supports set_addr)
//  - progress indicators
//
// Build: g++ client.cpp -pthread -o client -lreadline -lcrypto
// Run: ./client <TRACKER_IP> <TRACKER_PORT> [listen_port]
// Example: ./client 127.0.0.1 6000 10000

#include <string>
#include <iostream>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <fstream>
#include <vector>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <sstream>
#include <sys/stat.h>
#include <cstring>
#include <fcntl.h>
#include <chrono>
#include <atomic>
#include <algorithm>
#include <condition_variable>
#include <cmath>
#include <random> // For std::shuffle
#include <openssl/sha.h> // For SHA1 functions

using namespace std;
using u32 = uint32_t;
using u64 = uint64_t;

static const size_t PIECE_SIZE = 512 * 1024; // 512KB
static const size_t MAX_FRAME = 10 * 1024 * 1024;

// --------------------------- Download Tracking for show_downloads ---------------------------
struct DownloadState {
    string group_id;
    string file_name;
    atomic<int> completed_pieces;
    int total_pieces;
    atomic<bool> is_complete;

    // Constructor to initialize atomics
    DownloadState(string gid, string fname, int t_pieces)
        : group_id(gid), file_name(fname), completed_pieces(0), total_pieces(t_pieces), is_complete(false) {}

    // Since atomics are not copyable, we need to define copy constructor and assignment
    DownloadState(const DownloadState& other)
        : group_id(other.group_id), file_name(other.file_name), completed_pieces(other.completed_pieces.load()), total_pieces(other.total_pieces), is_complete(other.is_complete.load()) {}

    DownloadState& operator=(const DownloadState& other) {
        if (this != &other) {
            group_id = other.group_id;
            file_name = other.file_name;
            completed_pieces.store(other.completed_pieces.load());
            total_pieces = other.total_pieces;
            is_complete.store(other.is_complete.load());
        }
        return *this;
    }
};
static mutex downloads_mtx;
static unordered_map<string, DownloadState> ongoing_downloads; // Key: group/filename

// --------------------------- network helpers ---------------------------
u64 hton64(u64 v){
#if __BYTE_ORDER==__LITTLE_ENDIAN
    return (((u64)htonl((uint32_t)(v & 0xffffffffULL))) << 32) | htonl((uint32_t)((v >> 32) & 0xffffffffULL));
#else
    return v;
#endif
}
u64 ntoh64(u64 v){
#if __BYTE_ORDER==__LITTLE_ENDIAN
    return (((u64)ntohl((uint32_t)(v & 0xffffffffULL))) << 32) | ntohl((uint32_t)((v >> 32) & 0xffffffffULL));
#else
    return v;
#endif
}
ssize_t readn(int fd, void* buf, size_t n){
    size_t left = n; char* ptr = (char*)buf;
    while(left){
        ssize_t r = ::recv(fd, ptr, left, 0);
        if(r < 0){ if(errno == EINTR) continue; return -1; }
        if(r == 0) return 0; // Connection closed
        left -= r; ptr += r;
    }
    return (ssize_t)n;
}
ssize_t writen(int fd, const void* buf, size_t n){
    size_t left = n; const char* ptr = (const char*)buf;
    while(left){
        ssize_t w = ::send(fd, ptr, left, 0);
        if(w <= 0){ if(errno == EINTR) continue; return -1; }
        left -= w; ptr += w;
    }
    return (ssize_t)n;
}
static int connect_to(const string &ip, int port){
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0) return -1;
    sockaddr_in s{}; s.sin_family = AF_INET; s.sin_port = htons(port);
    if(inet_pton(AF_INET, ip.c_str(), &s.sin_addr) <= 0){ close(fd); return -1; }
    if(::connect(fd, (sockaddr*)&s, sizeof(s)) < 0){ close(fd); return -1; }
    struct timeval tv; tv.tv_sec = 10; tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}
// best-effort local IP for destination (no traffic sent)
static bool get_local_ip_for_destination(const string &dest_ip, int dest_port, string &local_ip){
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if(s < 0) return false;
    sockaddr_in srv{}; srv.sin_family = AF_INET; srv.sin_port = htons(dest_port);
    if(inet_pton(AF_INET, dest_ip.c_str(), &srv.sin_addr) <= 0){ close(s); return false; }
    if(connect(s, (sockaddr*)&srv, sizeof(srv)) < 0){ close(s); return false; }
    sockaddr_in local{}; socklen_t len = sizeof(local);
    if(getsockname(s, (sockaddr*)&local, &len) < 0){ close(s); return false; }
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &local.sin_addr, buf, sizeof(buf));
    local_ip = string(buf);
    close(s);
    return true;
}

// --------------------------- SHA1 (using OpenSSL) ---------------------------
static string bytes_to_hex(const unsigned char *d, size_t n){
    static const char hex[]="0123456789abcdef"; string s; s.reserve(n*2);
    for(size_t i=0;i<n;i++){ s.push_back(hex[(d[i]>>4)&0xF]); s.push_back(hex[d[i]&0xF]); }
    return s;
}
static string sha1_hex_of_buffer(const void *data, size_t len){
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char*)data, len, digest);
    return bytes_to_hex(digest, SHA_DIGEST_LENGTH);
}
static bool compute_file_piece_hashes(const string &path, uint64_t &file_size, string &whole_sha, vector<string> &piece_sha){
    int fd = open(path.c_str(), O_RDONLY);
    if(fd < 0) return false;
    struct stat st; if(fstat(fd,&st) < 0){ close(fd); return false; }
    file_size = (uint64_t)st.st_size;
    
    SHA_CTX whole_ctx;
    SHA1_Init(&whole_ctx);
    
    piece_sha.clear();
    vector<char> buf(64*1024);
    uint64_t total_bytes_read = 0;

    while(total_bytes_read < file_size){
        SHA_CTX piece_ctx;
        SHA1_Init(&piece_ctx);
        
        uint64_t piece_bytes_to_read = min((uint64_t)PIECE_SIZE, file_size - total_bytes_read);
        uint64_t current_piece_bytes_read = 0;

        lseek(fd, total_bytes_read, SEEK_SET); // Position fd for the piece read

        while(current_piece_bytes_read < piece_bytes_to_read){
            ssize_t r = read(fd, buf.data(), min(buf.size(), (size_t)(piece_bytes_to_read - current_piece_bytes_read)));
            if(r <= 0){ close(fd); return false; }
            SHA1_Update(&piece_ctx, (const unsigned char*)buf.data(), (size_t)r);
            SHA1_Update(&whole_ctx, (const unsigned char*)buf.data(), (size_t)r);
            current_piece_bytes_read += r;
        }

        unsigned char pd[SHA_DIGEST_LENGTH];
        SHA1_Final(pd, &piece_ctx);
        piece_sha.push_back(bytes_to_hex(pd, SHA_DIGEST_LENGTH));
        
        total_bytes_read += piece_bytes_to_read;
    }
    
    unsigned char wd[SHA_DIGEST_LENGTH];
    SHA1_Final(wd, &whole_ctx);
    whole_sha = bytes_to_hex(wd, SHA_DIGEST_LENGTH);
    
    close(fd);
    return true;
}


// --------------------------- tracker comm helper ---------------------------
static pair<string,u64> send_request_to_tracker(const string &tracker_ip, int tracker_port, u64 session, const string &payload){
    int fd = connect_to(tracker_ip, tracker_port);
    if(fd < 0) return {"ERR connect", 0};
    u64 netsess = hton64(session);
    u32 payload_len = (u32)payload.size();
    u32 frame_len = (u32)(sizeof(netsess) + payload_len);
    u32 netlen = htonl(frame_len);
    if(writen(fd, &netlen, sizeof(netlen))<0){ close(fd); return {"ERR send header",0}; }
    if(writen(fd, &netsess, sizeof(netsess))<0){ close(fd); return {"ERR send sess",0}; }
    if(payload_len){
        if(writen(fd, payload.data(), payload_len) < 0){ close(fd); return {"ERR send payload",0}; }
    }
    u32 resp_netlen;
    if(readn(fd, &resp_netlen, sizeof(resp_netlen)) <= 0){ close(fd); return {"ERR no resp",0}; }
    u32 resp_len = ntohl(resp_netlen);
    if(resp_len < sizeof(u64) || resp_len > MAX_FRAME){ close(fd); return {"ERR bad resp len",0}; }
    u64 resp_netsess;
    if(readn(fd, &resp_netsess, sizeof(resp_netsess)) <= 0){ close(fd); return {"ERR no resp sess",0}; }
    u64 resp_sess = ntoh64(resp_netsess);
    size_t resp_payload = resp_len - sizeof(u64);
    string resp;
    if(resp_payload){
        vector<char> buf(resp_payload);
        if(readn(fd, buf.data(), resp_payload) <= 0){ close(fd); return {"ERR resp read fail",0}; }
        resp.assign(buf.data(), resp_payload);
    }
    close(fd);
    return {resp, resp_sess};
}

// --------------------------- local seeding store & peer listener ---------------------------
struct LocalFile {
    string group;
    string file_name;
    string path;
    uint64_t file_size;
    string whole_sha1;
    vector<string> piece_sha;
};
static unordered_map<string, LocalFile> local_files;
static mutex local_files_mtx;
static inline string make_key(const string &g, const string &f){ return g + "/" + f; }

static atomic<bool> stop_peer_listener(false);
static int peer_listen_fd = -1;
static int agreed_listen_port = 0;

static void handle_peer_connection(int cfd){
    u32 netlen;
    if(readn(cfd, &netlen, sizeof(netlen)) <= 0){ close(cfd); return; }
    u32 len = ntohl(netlen);
    if(len == 0 || len > 1024*1024){ close(cfd); return; }
    vector<char> buf(len);
    if(readn(cfd, buf.data(), len) <= 0){ close(cfd); return; }
    string req(buf.data(), len);
    stringstream ss(req);
    string cmd; ss >> cmd;
    if(cmd != "GET_PIECE"){ close(cfd); return; }
    string group, fname; int idx; ss >> group >> fname >> idx;
    if(group.empty() || fname.empty() || idx < 0){ close(cfd); return; }
    string key = make_key(group, fname);
    LocalFile lf;
    {
        lock_guard<mutex> lk(local_files_mtx);
        if(!local_files.count(key)){ close(cfd); return; }
        lf = local_files[key];
    }
    uint64_t piece_offset = (uint64_t)idx * PIECE_SIZE;
    if(piece_offset >= lf.file_size){ close(cfd); return; }
    size_t piece_len = (size_t)min<uint64_t>(PIECE_SIZE, lf.file_size - piece_offset);
    int fd = open(lf.path.c_str(), O_RDONLY);
    if(fd < 0){ close(cfd); return; }
    vector<char> out(piece_len);
    ssize_t r = pread(fd, out.data(), piece_len, piece_offset);
    close(fd);
    if(r != (ssize_t)piece_len){ close(cfd); return; } 
    u32 outlen = htonl((u32)piece_len);
    if(writen(cfd, &outlen, sizeof(outlen)) < 0){ close(cfd); return; }
    if(writen(cfd, out.data(), piece_len) < 0){ close(cfd); return; }
    close(cfd);
}

static void peer_listener_thread(int listen_port){
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0){ perror("peer socket"); return; }
    int opt = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(listen_port); addr.sin_addr.s_addr = INADDR_ANY;
    if(::bind(fd, (sockaddr*)&addr, sizeof(addr)) < 0){ perror("peer bind"); close(fd); return; }
    sockaddr_in got{}; socklen_t gl = sizeof(got);
    if(getsockname(fd, (sockaddr*)&got, &gl) == 0) agreed_listen_port = ntohs(got.sin_port);
    if(listen(fd, 50) < 0){ perror("peer listen"); close(fd); return; }
    peer_listen_fd = fd;
    cerr << "[peer] listening on port " << agreed_listen_port << "\n";
    while(!stop_peer_listener.load()){
        sockaddr_in cli; socklen_t clen = sizeof(cli);
        int c = accept(fd, (sockaddr*)&cli, &clen);
        if(c < 0){
            if(errno==EINTR || errno == EBADF) continue;
            break;
        }
        thread t(handle_peer_connection, c);
        t.detach();
    }
    if (fd >= 0) close(fd);
}

// --------------------------- upload command ---------------------------
static void do_upload_file(const string &tracker_ip, int tracker_port, u64 &session_id, const string &group, const string &file_path){
    struct stat st; if(stat(file_path.c_str(), &st) < 0){ cerr << "file not found\n"; return; }
    uint64_t file_size; string whole_sha; vector<string> piece_hashes;
    cerr << "[upload] computing hashes (this may take a bit)...\n";
    if(!compute_file_piece_hashes(file_path, file_size, whole_sha, piece_hashes)){ cerr << "hash computation failed\n"; return; }
    string fname; size_t pos = file_path.find_last_of("/\\"); fname = (pos==string::npos)?file_path:file_path.substr(pos+1);
    stringstream ss; ss << "upload_file " << group << " " << fname << " " << to_string(file_size) << " " << whole_sha << " " << (int)piece_hashes.size();
    for(auto &p: piece_hashes) ss << " " << p;
    auto [resp, new_sess] = send_request_to_tracker(tracker_ip, tracker_port, session_id, ss.str());
    if(new_sess != 0) session_id = new_sess;
    if(resp.rfind("OK",0)==0){
        LocalFile lf; lf.group=group; lf.file_name=fname; lf.path=file_path; lf.file_size=file_size; lf.whole_sha1=whole_sha; lf.piece_sha=::move(piece_hashes);
        lock_guard<mutex> lk(local_files_mtx);
        local_files[make_key(group,fname)] = ::move(lf);
        cerr << "[upload] tracker accepted metadata\n";
    } else {
        cerr << "[upload] failed: " << resp << "\n";
    }
}

// --------------------------- peer download helper ---------------------------
static bool download_piece_from_seeder(const string &seeder, const string &group, const string &fname, int idx, vector<char> &outbuf){
    size_t p = seeder.find(':'); if(p==string::npos) return false;
    string ip = seeder.substr(0,p);
    int port = stoi(seeder.substr(p+1));
    int fd = connect_to(ip, port);
    if(fd < 0) return false;
    string req = string("GET_PIECE ") + group + " " + fname + " " + to_string(idx);
    u32 nlen = htonl((u32)req.size());
    if(writen(fd, &nlen, sizeof(nlen))<0){ close(fd); return false; }
    if(writen(fd, req.data(), req.size())<0){ close(fd); return false; }
    u32 piece_netlen;
    if(readn(fd, &piece_netlen, sizeof(piece_netlen)) <= 0){ close(fd); return false; }
    u32 piece_len = ntohl(piece_netlen);
    if(piece_len == 0 || piece_len > PIECE_SIZE + 10){ close(fd); return false; }
    outbuf.resize(piece_len);
    if(readn(fd, outbuf.data(), piece_len) <= 0){ close(fd); return false; }
    close(fd);
    return true;
}

// --------------------------- parallel downloader ---------------------------
struct SeederStat { int fail_count = 0; int succ_count = 0; chrono::steady_clock::time_point next_allowed = chrono::steady_clock::now(); };
void do_download_file_parallel(const string &tracker_ip, int tracker_port, u64 &session_id, const string &group, const string &file_name, const string &dest_path){
    auto [resp, new_sess] = send_request_to_tracker(tracker_ip, tracker_port, session_id, string("get_file ") + group + " " + file_name);
    if(new_sess != 0) session_id = new_sess;
    if(resp.rfind("ERR",0) == 0){ cerr << "[get_file] " << resp << "\n"; return; }
    stringstream ss(resp);
    string tag; ss >> tag;
    if(tag != "FILEINFO"){ cerr << "[get_file] unexpected reply: " << resp << "\n"; return; }
    uint64_t file_size; string whole_sha; int num_pieces;
    ss >> file_size >> whole_sha >> num_pieces;
    if(!ss || num_pieces <= 0){ cerr << "[get_file] bad metadata\n"; return; }
    vector<string> piece_hashes(num_pieces);
    for(int i=0;i<num_pieces;i++){ string ph; ss >> ph; if(ph.empty()){ cerr << "[get_file] missing piece hash\n"; return; } piece_hashes[i]=ph; }
    string seeders_token; ss >> seeders_token;
    string seeders_raw;
    if(seeders_token == "SEEDERS"){ string rest; getline(ss, rest); if(!rest.empty() && rest[0]==' ') rest.erase(0,1); seeders_raw = rest; }
    vector<string> seeders;
    if(!seeders_raw.empty()){
        string cur; for(char c: seeders_raw){ if(c==','){ if(!cur.empty()) seeders.push_back(cur); cur.clear(); } else cur.push_back(c); } if(!cur.empty()) seeders.push_back(cur);
    }
    if(seeders.empty()){ cerr << "[download] no seeders available\n"; return; }

    cerr << "[download] file size=" << file_size << " pieces=" << num_pieces << " seeders=" << seeders.size() << "\n";

    string dl_key = make_key(group, file_name);
    {
        lock_guard<mutex> lk(downloads_mtx);
        ongoing_downloads.emplace(piecewise_construct, make_tuple(dl_key), make_tuple(group, file_name, num_pieces));
    }

    thread([=, &session_id](){
        string tmp_path = dest_path + ".part";
        int outfd = open(tmp_path.c_str(), O_CREAT|O_RDWR, 0666);
        if(outfd < 0){ perror("open out"); return; }
        if(ftruncate(outfd, (off_t)file_size) < 0){ /*not fatal*/ }

        vector<atomic<int>> state(num_pieces);
        for(int i=0; i<num_pieces; ++i) state[i] = 0;
        
        unordered_map<string, SeederStat> seeder_stats;
        for(auto &s: seeders) seeder_stats[s] = SeederStat();

        mutex m; 
        condition_variable cv;
        atomic<int> completed_pieces(0);
        
        auto pick_piece = [&](int &out_idx)->bool{
            int expected = 0;
            for(int i=0; i<num_pieces; ++i){
                 if(state[i].compare_exchange_strong(expected, 1)){
                     out_idx = i;
                     return true;
                 }
                 expected = 0;
            }
            return false;
        };

        auto worker = [&](int id){
            while(completed_pieces.load() < num_pieces){
                int idx;
                if(!pick_piece(idx)){
                    unique_lock<mutex> lk(m);
                    if(completed_pieces.load() == num_pieces) break;
                    cv.wait_for(lk, chrono::milliseconds(200));
                    continue;
                }

                bool piece_ok = false;
                vector<string> current_seeders = seeders;
                
                std::random_device rd;
                std::mt19937 g(rd());
                std::shuffle(current_seeders.begin(), current_seeders.end(), g);

                for(const auto& seeder : current_seeders){
                    vector<char> piece_data;
                    bool ok = download_piece_from_seeder(seeder, group, file_name, idx, piece_data);
                    
                    if(!ok || sha1_hex_of_buffer(piece_data.data(), piece_data.size()) != piece_hashes[idx]){
                        continue; // Try next seeder
                    }
                    
                    off_t offset = (off_t)idx * (off_t)PIECE_SIZE;
                    ssize_t w = pwrite(outfd, piece_data.data(), piece_data.size(), offset);
                    if(w != (ssize_t)piece_data.size()){
                        continue; // Try next seeder
                    }
                    
                    completed_pieces.fetch_add(1);
                    state[idx] = 2; // Mark as done
                    
                    {
                        lock_guard<mutex> lk(downloads_mtx);
                        ongoing_downloads.at(dl_key).completed_pieces.fetch_add(1);
                    }

                    unique_lock<mutex> lk(m);
                    cv.notify_all();
                    lk.unlock();

                    piece_ok = true;
                    break;
                }

                if(!piece_ok){
                    int expected = 1;
                    state[idx].compare_exchange_strong(expected, 0); // Mark as pending again
                }
            }
        };

        unsigned hw = thread::hardware_concurrency();
        int pool_size = (int)max(4u, min((unsigned)16, (hw>0?hw:4u)*2u));
        pool_size = min(pool_size, num_pieces);
        vector<thread> workers;
        for(int i=0;i<pool_size;i++) workers.emplace_back(worker, i);
        for(auto &t: workers) if(t.joinable()) t.join();

        if(completed_pieces.load() != num_pieces){
            cerr << "\n[download] failed to get all pieces\n";
            close(outfd);
            unlink(tmp_path.c_str());
            return;
        }

        fsync(outfd);
        
        SHA_CTX ctx; SHA1_Init(&ctx);
        const size_t BUFSZ = 64*1024; vector<char> buf(BUFSZ);
        lseek(outfd, 0, SEEK_SET);
        ssize_t r;
        while((r = read(outfd, buf.data(), buf.size())) > 0) SHA1_Update(&ctx,(const unsigned char*)buf.data(),(size_t)r);
        unsigned char digest[SHA_DIGEST_LENGTH]; SHA1_Final(digest,&ctx);
        string final_hash = bytes_to_hex(digest,20);
        close(outfd);
        
        if(final_hash != whole_sha){
            cerr << "\n[download] whole-file hash mismatch! expected " << whole_sha << " got " << final_hash << "\n";
            unlink(tmp_path.c_str());
            return;
        }

        if(rename(tmp_path.c_str(), dest_path.c_str()) < 0){
            perror("rename"); unlink(tmp_path.c_str()); return;
        }

        cerr << "\n[download] complete and verified: " << dest_path << "\n";
        
        {
            lock_guard<mutex> lk(downloads_mtx);
            ongoing_downloads.at(dl_key).is_complete = true;
        }
        
        stringstream upl;
        upl << "upload_file " << group << " " << file_name << " " << to_string(file_size) << " " << whole_sha << " " << num_pieces;
        for(auto &p: piece_hashes) upl << " " << p;
        auto [rx, nsess2] = send_request_to_tracker(tracker_ip, tracker_port, session_id, upl.str());
        if(nsess2 != 0) session_id = nsess2;
        if(rx.rfind("OK",0) == 0){
            LocalFile lf; lf.group = group; lf.file_name = file_name; lf.path = dest_path; lf.file_size = file_size; lf.whole_sha1 = whole_sha; lf.piece_sha = ::move(piece_hashes);
            {
                lock_guard<mutex> lk(local_files_mtx);
                local_files[make_key(group,file_name)] = ::move(lf);
            }
            cerr << "[auto-upload] registered as seeder with tracker\n";
        } else {
            cerr << "[auto-upload] failed: " << rx << "\n";
        }
    }).detach();
}

// --------------------------- show downloads command ---------------------------
static void do_show_downloads(){
    lock_guard<mutex> lk(downloads_mtx);
    if(ongoing_downloads.empty()){
        cout << "No active or completed downloads.\n";
        return;
    }
    for(const auto& pair : ongoing_downloads){
        const auto& state = pair.second;
        if(state.is_complete){
            cout << "[C] [" << state.group_id << "] " << state.file_name << "\n";
        } else {
            cout << "[D] [" << state.group_id << "] " << state.file_name << " (" 
                 << state.completed_pieces << "/" << state.total_pieces << " pieces)\n";
        }
    }
}

// --------------------------- convenience: set_addr registration ---------------------------
static bool send_set_addr_if_logged_in(const string &tracker_ip, int tracker_port, u64 &session_id){
    if(session_id == 0 || agreed_listen_port == 0) return false;
    string local_ip;
    if(!get_local_ip_for_destination(tracker_ip, tracker_port, local_ip)) local_ip = "127.0.0.1";
    string cmd = string("set_addr ") + local_ip + " " + to_string(agreed_listen_port);
    auto [resp, new_sess] = send_request_to_tracker(tracker_ip, tracker_port, session_id, cmd);
    if(new_sess != 0) session_id = new_sess;
    return (resp.rfind("OK",0) == 0);
}

// --------------------------- main REPL ---------------------------
int main(int argc, char **argv){
    if(argc < 3){
        cerr << "Usage: " << argv[0] << " <TRACKER_IP> <TRACKER_PORT> [listen_port]\n";
        return 1;
    }
    string tracker_ip = argv[1];
    int tracker_port = stoi(argv[2]);
    int requested_listen = 0;
    if(argc >= 4) requested_listen = stoi(argv[3]);

    thread listener([requested_listen](){ peer_listener_thread(requested_listen); });
    
    this_thread::sleep_for(chrono::milliseconds(200));
    if(agreed_listen_port == 0) this_thread::sleep_for(chrono::milliseconds(300));

    if(agreed_listen_port != 0) cerr << "[main] peer listener port: " << agreed_listen_port << "\n";
    else cerr << "[main] peer listener not available\n";

    u64 session_id = 0;

    while(true){
        char* input = readline("> ");
        if(!input){ cout << "\nExiting...\n"; break; }
        string line(input);
        free(input);
        if(line.empty()) continue;
        if(line == "quit") break;
        add_history(line.c_str());

        string cmdword;
        { stringstream ss(line); ss >> cmdword; }

        if(cmdword == "upload_file"){
            string group, path; stringstream ss(line); ss >> cmdword >> group >> path;
            if(group.empty() || path.empty()){ cerr << "Usage: upload_file <group> <file_path>\n"; continue; }
            if(session_id == 0){ cerr << "Login required before upload\n"; continue; }
            do_upload_file(tracker_ip, tracker_port, session_id, group, path);
            continue;
        }
        if(cmdword == "download_file"){
            string group, fname, dest; stringstream ss(line); ss >> cmdword >> group >> fname >> dest;
            if(group.empty() || fname.empty() || dest.empty()){ cerr << "Usage: download_file <group> <file_name> <destination_path>\n"; continue; }
            if(session_id == 0) { cerr << "Login required to download files.\n"; continue; }
            do_download_file_parallel(tracker_ip, tracker_port, session_id, group, fname, dest);
            continue;
        }
        if(cmdword == "show_downloads"){
            do_show_downloads();
            continue;
        }

        // Generic tracker command
        auto [resp, new_sess] = send_request_to_tracker(tracker_ip, tracker_port, session_id, line);
        if(new_sess != 0) session_id = new_sess;
        cout << "< " << resp << "\n";

        if(cmdword == "login" && resp.rfind("OK",0) == 0){
            bool reg = send_set_addr_if_logged_in(tracker_ip, tracker_port, session_id);
            if(reg) cerr << "[main] registered listening address with tracker\n";
            else cerr << "[main] failed to register listening address\n";
        }
    }

    stop_peer_listener.store(true);
    if(peer_listen_fd > 0) {
        shutdown(peer_listen_fd, SHUT_RDWR);
        close(peer_listen_fd);
    }
    if(listener.joinable()) listener.join();
    cout << "Client exiting\n";
    return 0;
}

