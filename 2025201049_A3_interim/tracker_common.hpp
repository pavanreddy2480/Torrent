#pragma once
#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>

using namespace std;
using u32 = uint32_t; using u64 = uint64_t;
static const size_t MAX_FRAME = 10 * 1024 * 1024;

inline u64 hton64(u64 v){
#if __BYTE_ORDER==__LITTLE_ENDIAN
    return (((u64)htonl((uint32_t)(v&0xffffffffULL)))<<32) | htonl((uint32_t)((v>>32)&0xffffffffULL));
#else
    return v;
#endif
}
inline u64 ntoh64(u64 v){
#if __BYTE_ORDER==__LITTLE_ENDIAN
    return (((u64)ntohl((uint32_t)(v&0xffffffffULL)))<<32) | ntohl((uint32_t)((v>>32)&0xffffffffULL));
#else
    return v;
#endif
}
inline ssize_t readn(int fd, void* buf, size_t n){
    size_t left = n; char* p = (char*)buf;
    while(left){
        ssize_t r = recv(fd, p, left, 0);
        if(r < 0){ if(errno==EINTR) continue; return -1; }
        if(r == 0) return 0;
        left -= r; p += r;
    }
    return n;
}
inline ssize_t writen(int fd, const void* buf, size_t n){
    size_t left = n; const char* p = (const char*)buf;
    while(left){
        ssize_t w = send(fd, p, left, 0);
        if(w <= 0){ if(errno==EINTR) continue; return -1; }
        left -= w; p += w;
    }
    return n;
}

struct GroupInfo{
    string owner;
    unordered_set<string> members;
    unordered_set<string> pending;
};

// File metadata stored by tracker
struct FileInfo{
    string group;
    string owner;              // uploader (first uploader)
    string file_name;
    string whole_sha1;         // hex string (40 chars)
    vector<string> piece_sha1; // each hex string
    size_t file_size = 0;
    unordered_set<u64> seeder_sessions; // sessions that are seeding
    unordered_set<string> seeder_addrs; // ip:port strings
};

class Tracker{
    mutex m;
    unordered_map<string,string> users;          // username -> password
    unordered_map<u64,string> sessions;          // sess -> username
    unordered_map<u64,string> session_addrs;    // sess -> "ip:port"
    unordered_map<u64,unordered_set<string>> session_files; // sess -> set of file keys it seeds
    unordered_map<string,GroupInfo> groups;
    unordered_map<string,FileInfo> files;        // key = group + '/' + filename
    static u64 nextId(){ static atomic<u64> c(1); return c++; }

    static string make_key(const string&g,const string&f){ return g+"/"+f; }

public:
    // peer_ip and peer_port are optional; when provided, they are used to record seeder info
    pair<string,u64> handle(u64 sess,const string& cmdline,const string& peer_ip="",int peer_port=0){
        stringstream ss(cmdline);
        string cmd; ss >> cmd;
        if(cmd.empty()) return {"ERR empty", sess};

        lock_guard<mutex> lk(m);
        string user = (sess && sessions.count(sess)) ? sessions[sess] : "";

        // update session address mapping if provided (from connection metadata or explicit set_addr)
        if(sess && !peer_ip.empty() && peer_port>0){
            session_addrs[sess] = peer_ip + ":" + to_string(peer_port);
        }

        if(cmd=="create_user"){
            string u,p; ss>>u>>p;
            if(u.empty()||p.empty()) return {"ERR usage", sess};
            if(users.count(u)) return {"ERR exists", sess};
            users[u]=p; return {"OK user created", sess};
        }

        if(cmd=="login"){
            string u,p; ss>>u>>p;
            if(!users.count(u)) return {"ERR no such user", sess};
            if(users[u]!=p) return {"ERR bad password", sess};
            if(sess==0) sess = nextId();
            sessions[sess] = u;
            // ensure session_addrs keeps current addr if provided
            if(!peer_ip.empty() && peer_port>0) session_addrs[sess] = peer_ip+":"+to_string(peer_port);
            return {"OK logged in", sess};
        }

        if(cmd=="logout"){
            if(!sessions.count(sess) || sessions[sess].empty()) return {"ERR not logged in", sess};
            // remove any seeds associated with this session
            string addr = session_addrs.count(sess)?session_addrs[sess]:"";
            for(auto it = files.begin(); it!=files.end(); ++it){
                auto &fi = it->second;
                if(fi.seeder_sessions.count(sess)){
                    fi.seeder_sessions.erase(sess);
                }
                if(!addr.empty()) fi.seeder_addrs.erase(addr);
            }
            session_files.erase(sess);
            sessions[sess].clear();
            session_addrs.erase(sess);
            return {"OK logged out", sess};
        }

        // explicit command for clients to set their reachable address (ip port)
        if(cmd=="set_addr"){
            string ip; int port; ss >> ip >> port;
            if(sess==0 || sessions.find(sess)==sessions.end() || sessions[sess].empty()) return {"ERR login required", sess};
            if(ip.empty()||port<=0) return {"ERR usage", sess};
            session_addrs[sess] = ip + ":" + to_string(port);
            // also update any files this session is seeding
            for(auto &k : session_files[sess]){
                if(files.count(k)){
                    files[k].seeder_addrs.insert(session_addrs[sess]);
                }
            }
            return {"OK set_addr", sess};
        }

        if(cmd=="create_group"){
            string g; ss>>g;
            if(g.empty()||user.empty()) return {"ERR usage/login", sess};
            if(groups.count(g)) return {"ERR group exists", sess};
            GroupInfo gi; gi.owner = user; gi.members.insert(user);
            groups[g]=std::move(gi);
            return {"OK group created", sess};
        }

        if(cmd=="join_group"){
            string g; ss>>g;
            if(g.empty()||user.empty()) return {"ERR usage/login", sess};
            if(!groups.count(g)) return {"ERR no such group", sess};
            auto &gi = groups[g];
            if(gi.members.count(user)) return {"ERR already member", sess};
            gi.pending.insert(user);
            return {"OK join requested", sess};
        }

        if(cmd=="accept_request"){
            string g,u; ss>>g>>u;
            if(!groups.count(g)) return {"ERR no group", sess};
            auto &gi = groups[g];
            if(gi.owner != user) return {"ERR not owner", sess};
            if(!gi.pending.count(u)) return {"ERR no such req", sess};
            gi.pending.erase(u); gi.members.insert(u);
            return {"OK accepted", sess};
        }

        if(cmd=="list_groups"){
            string out = "Groups:";
            for(auto &kv: groups) out += " " + kv.first;
            return {out, sess};
        }

        // ----- File related commands -----
        if(cmd=="upload_file"){
            // Format:
            // upload_file <group> <file_name> <file_size> <whole_sha1> <num_pieces> <piece_sha1_1> <piece_sha1_2> ...
            string g, fname, fsize_s, whole;
            int num_pieces = 0;
            ss >> g >> fname >> fsize_s >> whole >> num_pieces;
            if(g.empty() || fname.empty() || fsize_s.empty() || whole.empty() || num_pieces<=0) return {"ERR usage", sess};
            if(user.empty()) return {"ERR login required", sess};
            if(!groups.count(g)) return {"ERR no such group", sess};
            if(!groups[g].members.count(user)) return {"ERR not a member", sess};
            size_t fsize = 0;
            try{ fsize = stoull(fsize_s); } catch(...) { return {"ERR bad size", sess}; }
            vector<string> pieces;
            pieces.reserve(num_pieces);
            for(int i=0;i<num_pieces;i++){
                string p; ss >> p;
                if(p.empty()) return {"ERR missing piece hashes", sess};
                pieces.push_back(p);
            }
            string key = make_key(g,fname);
            FileInfo fi;
            fi.group = g; fi.owner = user; fi.file_name = fname; fi.whole_sha1 = whole; fi.piece_sha1 = std::move(pieces); fi.file_size = fsize;

            // add or update existing entry
            if(files.count(key)==0){
                files[key] = fi;
            } else {
                // keep existing owner/metadata but ensure piece list matches
                auto &ex = files[key];
                if(ex.whole_sha1 != fi.whole_sha1 || ex.piece_sha1.size() != fi.piece_sha1.size()){
                    // replace metadata
                    ex.whole_sha1 = fi.whole_sha1;
                    ex.piece_sha1 = fi.piece_sha1;
                    ex.file_size = fi.file_size;
                }
            }
            // record seeder info
            string addr = "";
            if(!peer_ip.empty() && peer_port>0) addr = peer_ip + ":" + to_string(peer_port);
            if(sess) files[key].seeder_sessions.insert(sess);
            if(!addr.empty()) files[key].seeder_addrs.insert(addr);
            if(sess) session_files[sess].insert(key);
            return {"OK uploaded", sess};
        }

        if(cmd=="list_files"){
            string g; ss>>g;
            if(g.empty()) return {"ERR usage", sess};
            string out = "Files:";
            for(auto &kv: files){
                if(kv.second.group==g) out += " " + kv.second.file_name;
            }
            return {out, sess};
        }

        if(cmd=="get_file"){
            string g,fname; ss>>g>>fname;
            if(g.empty()||fname.empty()) return {"ERR usage", sess};
            string key = make_key(g,fname);
            if(!files.count(key)) return {"ERR no such file", sess};
            auto &fi = files[key];
            // build reply: FILEINFO <file_size> <whole_sha1> <num_pieces> <piecehashes...> SEEDERS <ip:port,...>
            string out = "FILEINFO ";
            out += to_string(fi.file_size) + " ";
            out += fi.whole_sha1 + " ";
            out += to_string(fi.piece_sha1.size());
            for(auto &p: fi.piece_sha1) out += " " + p;
            out += " SEEDERS";
            bool first = true;
            for(auto &a: fi.seeder_addrs){
                out += (first?" ":",") + a; first=false;
            }
            return {out, sess};
        }

        if(cmd=="stop_share"){
            string g,fname; ss>>g>>fname;
            if(g.empty()||fname.empty()) return {"ERR usage", sess};
            string key = make_key(g,fname);
            if(!files.count(key)) return {"ERR no such file", sess};
            auto &fi = files[key];
            if(sess && fi.seeder_sessions.count(sess)) fi.seeder_sessions.erase(sess);
            string addr = session_addrs.count(sess)?session_addrs[sess]:"";
            if(!addr.empty()) fi.seeder_addrs.erase(addr);
            if(sess) session_files[sess].erase(key);
            return {"OK stopped", sess};
        }

        return {"ERR unknown", sess};
    }
};

struct SyncItem{ u64 sess; string cmd; string origin_ip; int origin_port; };

class SyncQueue{
    string peer_ip; int peer_port;
    deque<SyncItem> q;
    mutex m; condition_variable cv;
    bool stop=false;
public:
    SyncQueue(const string& ip="", int port=0):peer_ip(ip),peer_port(port){}
    void enqueue(u64 s, const string &c, const string &origin_ip="", int origin_port=0){
        lock_guard<mutex> lk(m);
        q.push_back({s,c,origin_ip,origin_port});
        cv.notify_one();
    }
    void run(){
        while(true){
            unique_lock<mutex> lk(m);
            cv.wait(lk,[&]{ return stop || !q.empty(); });
            if(stop) break;
            SyncItem it = q.front(); q.pop_front();
            lk.unlock();

            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if(fd < 0){ this_thread::sleep_for(chrono::seconds(1)); continue; }
            sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(peer_port);
            inet_pton(AF_INET, peer_ip.c_str(), &addr.sin_addr);
            if(connect(fd, (sockaddr*)&addr, sizeof(addr)) < 0){ close(fd); this_thread::sleep_for(chrono::seconds(1)); continue; }

            // payload: "SYNC <origin_ip> <origin_port> <original_cmd>"
            string oip = it.origin_ip.empty()? string("0.0.0.0"): it.origin_ip;
            int oport = it.origin_port;
            string payload = string("SYNC ") + oip + " " + to_string(oport) + " " + it.cmd;
            u32 len = htonl(sizeof(u64) + payload.size());
            u64 sess = hton64(it.sess);
            if(writen(fd, &len, sizeof(len))<0){ close(fd); continue; }
            if(writen(fd, &sess, sizeof(sess))<0){ close(fd); continue; }
            if(!payload.empty()) if(writen(fd, payload.data(), payload.size())<0){ close(fd); continue; }
            close(fd);
        }
    }
};

inline void sessionWorker(int fd, Tracker &tracker, SyncQueue *sync, bool doForward){
    while(true){
        u32 netlen;
        ssize_t r = readn(fd, &netlen, sizeof(netlen));
        if(r <= 0) break;
        u32 len = ntohl(netlen);
        if(len < sizeof(u64) || len > MAX_FRAME) break;
        u64 nets; if(readn(fd, &nets, sizeof(nets)) <= 0) break;
        u64 sess = ntoh64(nets);
        size_t pay = len - sizeof(u64);
        string cmd;
        if(pay){
            vector<char> buf(pay);
            if(readn(fd, buf.data(), pay) <= 0) break;
            cmd.assign(buf.data(), pay);
        }

        bool isSync = false;
        string origin_ip = ""; int origin_port = 0;

        // If payload is a sync from peer tracker it starts with "SYNC "
        if(cmd.rfind("SYNC ", 0) == 0){
            isSync = true;
            string rest = cmd.substr(5);
            stringstream sss(rest);
            sss >> origin_ip >> origin_port;
            string remaining; getline(sss, remaining);
            if(!remaining.empty() && remaining[0]==' ') remaining.erase(0,1);
            cmd = remaining;
        } else {
            // normal client connection: obtain peer ip/port
            sockaddr_in peer{}; socklen_t plen = sizeof(peer);
            if(getpeername(fd, (sockaddr*)&peer, &plen) == 0){
                char buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &peer.sin_addr, buf, sizeof(buf));
                origin_ip = string(buf);
                origin_port = ntohs(peer.sin_port);
            }
        }

        auto [reply, newSess] = tracker.handle(sess, cmd, origin_ip, origin_port);

        u32 respLen = htonl(sizeof(u64) + reply.size());
        u64 respSess = hton64(newSess);
        if(writen(fd, &respLen, sizeof(respLen)) < 0) break;
        if(writen(fd, &respSess, sizeof(respSess)) < 0) break;
        if(!reply.empty()) if(writen(fd, reply.data(), reply.size()) < 0) break;

        // forward to other tracker if applicable (include origin ip/port)
        if(doForward && !isSync && sync){
            sync->enqueue(newSess, cmd, origin_ip, origin_port);
        }
    }
    close(fd);
}

inline int prepare_listener(const string &ip, int port){
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0){ perror("socket"); exit(1); }
    int opt = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
    if(::bind(fd, (sockaddr*)&addr, sizeof(addr)) < 0){ perror("bind"); exit(1); }
    if(listen(fd, 50) < 0){ perror("listen"); exit(1); }
    return fd;
}