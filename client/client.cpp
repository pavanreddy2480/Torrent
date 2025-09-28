// client.cpp
// Enhanced client with:
//  - parallel piece downloads (thread pool + scheduler)
//  - seeder selection heuristics (back-off, prefer responsive seeders)
//  - auto upload_file after successful verified download
//  - automatic set_addr registration after login (tracker supports set_addr)
//  - progress indicators
//
// Build: g++ client.cpp -pthread -o client
// Run: ./client <TRACKER_IP> <TRACKER_PORT> [listen_port]
// Example: ./client 127.0.0.1 9000 10000
//
// Notes:
//  - This client expects the tracker protocol you provided:
//      framed (u32 length) (u64 session) (payload string)
//    and tracker commands like `get_file`, `upload_file`, `set_addr`, etc.
//  - Peer-to-peer uses simple framing for requests and returns piece bytes
//    (request: u32 len + payload "GET_PIECE <group> <file> <idx>")
//    (response: u32 piece_len + raw bytes)
//  - The client spawns a peer listener that serves pieces to other peers.

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

using namespace std;
using u32 = uint32_t;
using u64 = uint64_t;

static const size_t PIECE_SIZE = 512 * 1024; // 512KB
static const size_t MAX_FRAME = 10 * 1024 * 1024;

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
        if(r == 0) return 0;
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

// --------------------------- SHA1 (compact) ---------------------------
struct SHA1_CTX { uint32_t state[5]; uint64_t count; unsigned char buffer[64]; };
static inline uint32_t rol(uint32_t v, unsigned int b){ return (v<<b)|(v>>(32-b)); }
static void SHA1Transform(uint32_t state[5], const unsigned char buffer[64]){
    uint32_t w[80];
    for(int i=0;i<16;i++){
        w[i] = ((uint32_t)buffer[i*4] << 24) | ((uint32_t)buffer[i*4+1] << 16) |
               ((uint32_t)buffer[i*4+2] << 8) | ((uint32_t)buffer[i*4+3]);
    }
    for(int t=16;t<80;t++) w[t] = rol(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16], 1);
    uint32_t a=state[0], b=state[1], c=state[2], d=state[3], e=state[4];
    for(int t=0;t<80;t++){
        uint32_t f,k;
        if(t<20){ f=(b&c)|((~b)&d); k=0x5A827999; }
        else if(t<40){ f=b^c^d; k=0x6ED9EBA1; }
        else if(t<60){ f=(b&c)|(b&d)|(c&d); k=0x8F1BBCDC; }
        else { f=b^c^d; k=0xCA62C1D6; }
        uint32_t temp = rol(a,5) + f + e + k + w[t];
        e=d; d=c; c=rol(b,30); b=a; a=temp;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d; state[4]+=e;
}
static void SHA1Init(SHA1_CTX *c){ c->state[0]=0x67452301; c->state[1]=0xEFCDAB89; c->state[2]=0x98BADCFE; c->state[3]=0x10325476; c->state[4]=0xC3D2E1F0; c->count=0; }
static void SHA1Update(SHA1_CTX *c, const unsigned char *data, size_t len){
    size_t i=0, idx=(size_t)((c->count>>3)&63); c->count += (uint64_t)len<<3;
    if(idx){
        size_t fill = 64-idx;
        if(len >= fill){ memcpy(c->buffer + idx, data, fill); SHA1Transform(c->state, c->buffer); i += fill; idx = 0; }
        else { memcpy(c->buffer + idx, data, len); return; }
    }
    for(; i+64 <= len; i+=64) SHA1Transform(c->state, data + i);
    if(i < len) memcpy(c->buffer, data + i, len - i);
}
static void SHA1Final(unsigned char digest[20], SHA1_CTX *c){
    unsigned char finalcount[8]; for(int i=0;i<8;i++) finalcount[i] = (unsigned char)((c->count >> ((7-i)*8)) & 255);
    size_t idx = (size_t)((c->count>>3)&63);
    unsigned char one = 0x80; SHA1Update(c, &one, 1);
    unsigned char zeros[64] = {0}; size_t padlen = (idx < 56) ? (56-idx) : (120-idx);
    if(padlen) SHA1Update(c, zeros, padlen);
    SHA1Update(c, finalcount, 8);
    for(int i=0;i<20;i++) digest[i] = (unsigned char)((c->state[i>>2] >> ((3-(i&3))*8)) & 0xff);
}
static string bytes_to_hex(const unsigned char *d, size_t n){
    static const char hex[]="0123456789abcdef"; string s; s.reserve(n*2);
    for(size_t i=0;i<n;i++){ s.push_back(hex[(d[i]>>4)&0xF]); s.push_back(hex[d[i]&0xF]); }
    return s;
}
static string sha1_hex_of_buffer(const void *data, size_t len){
    SHA1_CTX ctx; unsigned char digest[20]; SHA1Init(&ctx); SHA1Update(&ctx,(const unsigned char*)data,len); SHA1Final(digest,&ctx); return bytes_to_hex(digest,20);
}
// static string sha1_hex_of_file_range(int fd, off_t offset, size_t len){
//     SHA1_CTX ctx; unsigned char digest[20]; SHA1Init(&ctx);
//     const size_t BUFSZ = 64*1024;
//     vector<char> buf(BUFSZ);
//     size_t left = len; off_t pos = offset;
//     while(left){
//         size_t toread = (left>BUFSZ)?BUFSZ:left;
//         ssize_t r = pread(fd, buf.data(), toread, pos);
//         if(r <= 0) return string();
//         SHA1Update(&ctx, (const unsigned char*)buf.data(), (size_t)r);
//         left -= r; pos += r;
//     }
//     SHA1Final(digest,&ctx); return bytes_to_hex(digest,20);
// }
static bool compute_file_piece_hashes(const string &path, uint64_t &file_size, string &whole_sha, vector<string> &piece_sha){
    int fd = open(path.c_str(), O_RDONLY);
    if(fd < 0) return false;
    struct stat st; if(fstat(fd,&st) < 0){ close(fd); return false; }
    file_size = (uint64_t)st.st_size;
    SHA1_CTX whole; SHA1Init(&whole);
    piece_sha.clear();
    vector<char> buf(64*1024);
    uint64_t left = file_size;
    while(left){
        size_t piece_to_read = (left > PIECE_SIZE) ? PIECE_SIZE : (size_t)left;
        size_t read_left = piece_to_read;
        SHA1_CTX piecectx; SHA1Init(&piecectx);
        while(read_left){
            size_t rsz = (read_left > buf.size())?buf.size():read_left;
            ssize_t r = read(fd, buf.data(), rsz);
            if(r <= 0){ close(fd); return false; }
            SHA1Update(&piecectx,(const unsigned char*)buf.data(),(size_t)r);
            SHA1Update(&whole,(const unsigned char*)buf.data(),(size_t)r);
            read_left -= r;
        }
        unsigned char pd[20]; SHA1Final(pd,&piecectx); piece_sha.push_back(bytes_to_hex(pd,20));
        left -= piece_to_read;
    }
    unsigned char wd[20]; SHA1Final(wd,&whole); whole_sha = bytes_to_hex(wd,20);
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
    // request framing: u32 len + payload (text)
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
    if(r <= 0){ close(cfd); return; }
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
    // determine port assigned
    sockaddr_in got{}; socklen_t gl = sizeof(got);
    if(getsockname(fd, (sockaddr*)&got, &gl) == 0) agreed_listen_port = ntohs(got.sin_port);
    if(listen(fd, 50) < 0){ perror("peer listen"); close(fd); return; }
    peer_listen_fd = fd;
    cerr << "[peer] listening on port " << agreed_listen_port << "\n";
    while(!stop_peer_listener.load()){
        sockaddr_in cli; socklen_t clen = sizeof(cli);
        int c = accept(fd, (sockaddr*)&cli, &clen);
        if(c < 0){
            if(errno==EINTR) continue;
            perror("accept");
            break;
        }
        thread t(handle_peer_connection, c);
        t.detach();
    }
    close(fd);
}

// --------------------------- upload command ---------------------------
static bool do_upload_file(const string &tracker_ip, int tracker_port, u64 &session_id, const string &group, const string &file_path){
    struct stat st; if(stat(file_path.c_str(), &st) < 0){ cerr << "file not found\n"; return false; }
    uint64_t file_size; string whole_sha; vector<string> piece_hashes;
    cerr << "[upload] computing hashes (this may take a bit)...\n";
    if(!compute_file_piece_hashes(file_path, file_size, whole_sha, piece_hashes)){ cerr << "hash computation failed\n"; return false; }
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
        return true;
    } else {
        cerr << "[upload] failed: " << resp << "\n";
        return false;
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
static bool do_download_file_parallel(const string &tracker_ip, int tracker_port, u64 &session_id, const string &group, const string &file_name, const string &dest_path){
    // request metadata
    auto [resp, new_sess] = send_request_to_tracker(tracker_ip, tracker_port, session_id, string("get_file ") + group + " " + file_name);
    if(new_sess != 0) session_id = new_sess;
    if(resp.rfind("ERR",0) == 0){ cerr << "[get_file] " << resp << "\n"; return false; }
    stringstream ss(resp);
    string tag; ss >> tag;
    if(tag != "FILEINFO"){ cerr << "[get_file] unexpected reply: " << resp << "\n"; return false; }
    uint64_t file_size; string whole_sha; int num_pieces;
    ss >> file_size >> whole_sha >> num_pieces;
    if(!ss || file_size == 0 || num_pieces <= 0){ cerr << "[get_file] bad metadata\n"; return false; }
    vector<string> piece_hashes(num_pieces);
    for(int i=0;i<num_pieces;i++){ string ph; ss >> ph; if(ph.empty()){ cerr << "[get_file] missing piece hash\n"; return false; } piece_hashes[i]=ph; }
    string seeders_token; ss >> seeders_token;
    string seeders_raw;
    if(seeders_token == "SEEDERS"){ string rest; getline(ss, rest); if(!rest.empty() && rest[0]==' ') rest.erase(0,1); seeders_raw = rest; }
    vector<string> seeders;
    if(!seeders_raw.empty()){
        string cur; for(char c: seeders_raw){ if(c==','){ if(!cur.empty()) seeders.push_back(cur); cur.clear(); } else cur.push_back(c); } if(!cur.empty()) seeders.push_back(cur);
    }
    if(seeders.empty()){ cerr << "[download] no seeders available\n"; return false; }

    cerr << "[download] file size=" << file_size << " pieces=" << num_pieces << " seeders=" << seeders.size() << "\n";

    // create temp file and preallocate
    string tmp_path = dest_path + ".part";
    int outfd = open(tmp_path.c_str(), O_CREAT|O_RDWR, 0666);
    if(outfd < 0){ perror("open out"); return false; }
    if(ftruncate(outfd, (off_t)file_size) < 0){ /*not fatal*/ }

    // state arrays
    vector<int> state(num_pieces, 0); // 0=pending,1=inprogress,2=done
    vector<unordered_set<string>> piece_succeeded_by(num_pieces); // which seeders served piece
    vector<int> piece_attempts(num_pieces, 0);

    unordered_map<string, SeederStat> seeder_stats;
    for(auto &s: seeders) seeder_stats[s] = SeederStat();

    mutex m; condition_variable cv;
    atomic<int> completed_pieces(0);
    atomic<bool> abort_flag(false);

    // scheduler chooses next piece to download (rarest-first based on observed availability)
    auto pick_piece = [&](int &out_idx)->bool{
        lock_guard<mutex> lk(m);
        // compute availability counts (lower is rarer)
        int best = -1; int best_count = INT_MAX;
        for(int i=0;i<num_pieces;i++){
            if(state[i] != 0) continue;
            int avail = (int)piece_succeeded_by[i].size();
            if(avail < best_count){ best_count = avail; best = i; }
        }
        if(best == -1) return false;
        state[best] = 1; out_idx = best; return true;
    };

    // worker function
    auto worker = [&](int id){
        while(!abort_flag.load()){
            int idx;
            if(!pick_piece(idx)){ // no pending piece for now
                // either all done or wait briefly
                unique_lock<mutex> lk(m);
                if(completed_pieces.load() == num_pieces) break;
                cv.wait_for(lk, chrono::milliseconds(200));
                continue;
            }

            // try seeders for this piece based on seeder_stats ordering
            bool piece_ok = false;
            vector<pair<string, pair<int,int>>> order; // seeder -> (fail_count, -succ_count)
            {
                lock_guard<mutex> lk(m);
                for(auto &kv: seeder_stats){
                    order.push_back({kv.first, {kv.second.fail_count, -kv.second.succ_count}});
                }
            }
            sort(order.begin(), order.end(), [&](auto &a, auto &b){
                if(a.second.first != b.second.first) return a.second.first < b.second.first;
                return a.second.second < b.second.second;
            });

            for(auto &entry : order){
                string seeder = entry.first;
                // check backoff
                {
                    lock_guard<mutex> lk(m);
                    if(seeder_stats[seeder].next_allowed > chrono::steady_clock::now()) continue;
                }
                vector<char> piece_data;
                bool ok = download_piece_from_seeder(seeder, group, file_name, idx, piece_data);
                if(!ok){
                    // failure: increment fail_count + set backoff
                    lock_guard<mutex> lk(m);
                    seeder_stats[seeder].fail_count++;
                    // exponential backoff up to 60s
                    int back = (1 << min(seeder_stats[seeder].fail_count, 10)); // big cap
                    if(back > 60) back = 60;
                    seeder_stats[seeder].next_allowed = chrono::steady_clock::now() + chrono::seconds(back);
                    continue;
                }
                // verify piece hash
                string got = sha1_hex_of_buffer(piece_data.data(), piece_data.size());
                if(got != piece_hashes[idx]){
                    // bad piece: treat as failure
                    lock_guard<mutex> lk(m);
                    seeder_stats[seeder].fail_count++;
                    int back = (1 << min(seeder_stats[seeder].fail_count, 10));
                    if(back > 60) back = 60;
                    seeder_stats[seeder].next_allowed = chrono::steady_clock::now() + chrono::seconds(back);
                    continue;
                }
                // write piece to file using pwrite
                off_t offset = (off_t)idx * (off_t)PIECE_SIZE;
                ssize_t w = pwrite(outfd, piece_data.data(), piece_data.size(), offset);
                if(w != (ssize_t)piece_data.size()){
                    lock_guard<mutex> lk(m);
                    seeder_stats[seeder].fail_count++;
                    int back = (1 << min(seeder_stats[seeder].fail_count, 10));
                    if(back > 60) back = 60;
                    seeder_stats[seeder].next_allowed = chrono::steady_clock::now() + chrono::seconds(back);
                    continue;
                }
                // success
                {
                    lock_guard<mutex> lk(m);
                    piece_succeeded_by[idx].insert(seeder);
                    seeder_stats[seeder].succ_count++;
                    state[idx] = 2;
                    completed_pieces.fetch_add(1);
                    cv.notify_all();
                }
                piece_ok = true;
                break;
            }

            if(!piece_ok){
                // Mark piece back to pending so it can be retried later
                lock_guard<mutex> lk(m);
                state[idx] = 0;
                piece_attempts[idx]++;
                // small sleep before other workers reattempt to avoid busy loop
                this_thread::sleep_for(chrono::milliseconds(100));
            }
        }
    };

    // start worker threads
    unsigned hw = thread::hardware_concurrency();
    int pool_size = (int)max(2u, min((unsigned)8, (hw>0?hw:2u)*2u));
    pool_size = min(pool_size, num_pieces);
    vector<thread> workers;
    for(int i=0;i<pool_size;i++) workers.emplace_back(worker, i);

    // progress thread
    atomic<bool> stop_progress(false);
    thread progress([&](){
        while(!stop_progress.load()){
            int done = completed_pieces.load();
            double pct = (double)done * 100.0 / (double)num_pieces;
            cerr << "\r[progress] pieces: " << done << "/" << num_pieces << " (" << (int)pct << "%) " << flush;
            if(done == num_pieces) break;
            this_thread::sleep_for(chrono::milliseconds(600));
        }
        cerr << "\n";
    });

    // wait for workers
    for(auto &t: workers) if(t.joinable()) t.join();
    // signal progress thread
    stop_progress.store(true);
    if(progress.joinable()) progress.join();

    if(completed_pieces.load() != num_pieces){
        cerr << "[download] failed to get all pieces\n";
        close(outfd);
        unlink(tmp_path.c_str());
        return false;
    }

    // verify whole file
    fsync(outfd);
    close(outfd);
    // compute whole sha of tmp_path
    int fd2 = open(tmp_path.c_str(), O_RDONLY);
    if(fd2 < 0){ perror("open tmp"); unlink(tmp_path.c_str()); return false; }
    SHA1_CTX ctx; SHA1Init(&ctx);
    const size_t BUFSZ = 64*1024; vector<char> buf(BUFSZ);
    ssize_t r;
    while((r = read(fd2, buf.data(), buf.size())) > 0) SHA1Update(&ctx,(const unsigned char*)buf.data(),(size_t)r);
    unsigned char digest[20]; SHA1Final(digest,&ctx);
    string final_hash = bytes_to_hex(digest,20);
    close(fd2);
    if(final_hash != whole_sha){
        cerr << "[download] whole-file hash mismatch! expected " << whole_sha << " got " << final_hash << "\n";
        unlink(tmp_path.c_str());
        return false;
    }

    // ::move tmp to dest_path
    if(rename(tmp_path.c_str(), dest_path.c_str()) < 0){
        perror("rename"); unlink(tmp_path.c_str()); return false;
    }

    cerr << "[download] complete and verified: " << dest_path << "\n";

    // auto-upload/register as seeder: call upload_file using metadata from tracker (we have piece_hashes already)
    // Build upload command and send. We don't recompute piece hashes (they match the tracker).
    stringstream upl;
    upl << "upload_file " << group << " " << file_name << " " << to_string(file_size) << " " << whole_sha << " " << num_pieces;
    for(auto &p: piece_hashes) upl << " " << p;
    auto [rx, nsess2] = send_request_to_tracker(tracker_ip, tracker_port, session_id, upl.str());
    if(nsess2 != 0) session_id = nsess2;
    if(rx.rfind("OK",0) == 0){
        // register local file to serve
        LocalFile lf; lf.group = group; lf.file_name = file_name; lf.path = dest_path; lf.file_size = file_size; lf.whole_sha1 = whole_sha; lf.piece_sha = ::move(piece_hashes);
        {
            lock_guard<mutex> lk(local_files_mtx);
            local_files[make_key(group,file_name)] = ::move(lf);
        }
        cerr << "[auto-upload] registered as seeder with tracker\n";
    } else {
        cerr << "[auto-upload] failed: " << rx << "\n";
    }

    return true;
}

// --------------------------- convenience: set_addr registration ---------------------------
static bool send_set_addr_if_logged_in(const string &tracker_ip, int tracker_port, u64 &session_id){
    if(session_id == 0) return false;
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

    // start peer listener thread
    thread listener([requested_listen](){ peer_listener_thread(requested_listen); });
    listener.detach();

    // small wait for listener to bind
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
            // ensure user logged in (needed for auto-upload)
            if(session_id == 0) cerr << "Warning: not logged in. You can still download, but auto-seed registration needs login.\n";
            bool res = do_download_file_parallel(tracker_ip, tracker_port, session_id, group, fname, dest);
            (void)res;
            continue;
        }

        // Generic tracker command
        auto [resp, new_sess] = send_request_to_tracker(tracker_ip, tracker_port, session_id, line);
        if(new_sess != 0) session_id = new_sess;
        cout << "< " << resp << "\n";

        // If login succeeded, register our peer listening address with tracker (set_addr)
        if(cmdword == "login" && resp.rfind("OK",0) == 0){
            bool reg = send_set_addr_if_logged_in(tracker_ip, tracker_port, session_id);
            if(reg) cerr << "[main] registered listening address with tracker\n";
            else cerr << "[main] failed to register listening address\n";
        }
    }

    stop_peer_listener.store(true);
    if(peer_listen_fd > 0) close(peer_listen_fd);
    cout << "Client exiting\n";
    return 0;
}