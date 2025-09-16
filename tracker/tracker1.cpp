// tracker_fixed.cpp
// Tracker server: framed protocol, session-per-thread, safe frame validation

#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <thread>
#include <mutex>
#include <atomic>
using namespace std;
using u32 = uint32_t;
using u64 = uint64_t;

static const size_t MAX_FRAME = 10 * 1024 * 1024; // 10 MB

u64 hton64(u64 v){
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return (((u64)htonl((uint32_t)(v & 0xffffffffULL)))<<32) | htonl((uint32_t)((v>>32) & 0xffffffffULL));
#else
    return v;
#endif
}
u64 ntoh64(u64 v){
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return (((u64)ntohl((uint32_t)(v & 0xffffffffULL)))<<32) | ntohl((uint32_t)((v>>32) & 0xffffffffULL));
#else
    return v;
#endif
}

// read exactly n bytes or return -1 on error, 0 on EOF
ssize_t readn(int fd, void* buf, size_t n){
    size_t left=n;
    char* ptr=(char*)buf;
    while(left){
        ssize_t r = ::recv(fd,ptr,left,0);
        if(r<0){
            if(errno==EINTR) continue;
            return -1;
        }
        if(r==0) return 0;
        left -= r;
        ptr += r;
    }
    return (ssize_t)n;
}
ssize_t writen(int fd,const void* buf,size_t n){
    size_t left=n;
    const char* ptr=(const char*)buf;
    while(left){
        ssize_t w = ::send(fd,ptr,left,0);
        if(w<=0){
            if(errno==EINTR) continue;
            return -1;
        }
        left -= w;
        ptr += w;
    }
    return (ssize_t)n;
}

// session id generator
u64 make_session_id(){
    static atomic<u64> ctr(1);
    return ctr.fetch_add(1);
}

// Tracker data
struct GroupInfo{
    string owner;
    unordered_set<string> members;
    unordered_set<string> pending;
};

class Tracker{
    mutex mtx;
    unordered_map<string,string> users;   // uid->pwd
    unordered_map<u64,string> sessions;   // session->uid (empty if logged out)
    unordered_map<string,GroupInfo> groups;
public:
    // returns pair(response_text, session_id_to_return)
    pair<string,u64> handleCommand(u64 session,const string &cmdline){
        stringstream ss(cmdline);
        string cmd; ss>>cmd;
        if(cmd.empty()) return {"ERR empty",session};

        lock_guard<mutex> lk(mtx);
        string curUser="";
        if(session!=0 && sessions.count(session)) curUser = sessions[session];

        if(cmd=="create_user"){
            string u,p; ss>>u>>p;
            if(u.empty()||p.empty()) return {"ERR usage: create_user <user> <pass>",session};
            if(users.count(u)) return {"ERR user exists",session};
            users[u]=p;
            return {"OK user created",session};
        }
        if(cmd=="login"){
            string u,p; ss>>u>>p;
            if(u.empty()||p.empty()) return {"ERR usage: login <user> <pass>",session};
            if(!users.count(u)) return {"ERR no such user",session};
            if(users[u]!=p) return {"ERR wrong password",session};
            if(session==0) session = make_session_id();
            sessions[session]=u;
            return {"OK logged in",session};
        }
        if(cmd=="logout"){
            if(session==0 || !sessions.count(session) || sessions[session].empty())
                return {"ERR not logged in",session};
            sessions[session].clear();
            return {"OK logged out",session};
        }
        if(cmd=="create_group"){
            string gid; ss>>gid;
            if(gid.empty()) return {"ERR usage: create_group <group>",session};
            if(curUser.empty()) return {"ERR must be logged in",session};
            if(groups.count(gid)) return {"ERR group exists",session};
            GroupInfo gi;
            gi.owner = curUser;
            gi.members.insert(curUser);
            groups[gid]=std::move(gi);
            return {"OK group created",session};
        }
        if(cmd=="join_group"){
            string gid; ss>>gid;
            if(gid.empty()) return {"ERR usage: join_group <group>",session};
            if(curUser.empty()) return {"ERR must be logged in",session};
            if(!groups.count(gid)) return {"ERR no such group",session};
            auto &gi = groups[gid];
            if(gi.members.count(curUser)) return {"ERR already member",session};
            if(gi.pending.count(curUser)) return {"ERR already requested",session};
            gi.pending.insert(curUser);
            return {"OK join request sent",session};
        }
        if(cmd=="leave_group"){
            string gid; ss>>gid;
            if(gid.empty()) return {"ERR usage: leave_group <group>",session};
            if(curUser.empty()) return {"ERR must be logged in",session};
            if(!groups.count(gid)) return {"ERR no such group",session};
            auto &gi = groups[gid];
            if(!gi.members.count(curUser)) return {"ERR not a member",session};
            if(gi.owner==curUser) return {"ERR owner cannot leave",session};
            gi.members.erase(curUser);
            return {"OK left group",session};
        }
        if(cmd=="list_groups"){
            string out="Groups:";
            for(auto &kv:groups) out += " " + kv.first;
            return {out,session};
        }
        if(cmd=="list_requests"){
            string gid; ss>>gid;
            if(gid.empty()) return {"ERR usage: list_requests <group>",session};
            if(!groups.count(gid)) return {"ERR no such group",session};
            auto &gi = groups[gid];
            if(gi.owner != curUser) return {"ERR only owner",session};
            string out="Requests:";
            for(auto &u:gi.pending) out += " " + u;
            return {out,session};
        }
        if(cmd=="accept_request"){
            string gid,uid; ss>>gid>>uid;
            if(gid.empty()||uid.empty()) return {"ERR usage: accept_request <group> <user>",session};
            if(!groups.count(gid)) return {"ERR no such group",session};
            auto &gi = groups[gid];
            if(gi.owner != curUser) return {"ERR only owner",session};
            if(!gi.pending.count(uid)) return {"ERR no such request",session};
            gi.pending.erase(uid);
            gi.members.insert(uid);
            return {"OK request accepted",session};
        }
        return {"ERR unknown",session};
    }
};

void sessionWorker(int fd, Tracker &tracker){
    // frame: [u32 len][u64 session][payload]
    while(true){
        u32 netlen;
        ssize_t r = readn(fd,&netlen,sizeof(netlen));
        if(r==0||r<0) break;
        u32 len = ntohl(netlen);
        if(len < sizeof(u64) || len > MAX_FRAME){ // invalid frame
            break;
        }
        u64 netsess;
        r = readn(fd,&netsess,sizeof(netsess));
        if(r==0||r<0) break;
        u64 sess = ntoh64(netsess);
        size_t payload_len = (size_t)len - sizeof(u64);
        string cmd;
        if(payload_len){
            vector<char> buf(payload_len);
            r = readn(fd,buf.data(),payload_len);
            if(r==0||r<0) break;
            cmd.assign(buf.data(),payload_len);
        }
        auto pr = tracker.handleCommand(sess,cmd);
        string resp = pr.first;
        u64 new_sess = pr.second;
        u32 resp_payload = (u32)resp.size();
        u32 resp_len = sizeof(u64) + resp_payload;
        u32 resp_netlen = htonl(resp_len);
        u64 resp_netsess = hton64(new_sess);
        if(writen(fd,&resp_netlen,sizeof(resp_netlen))<0) break;
        if(writen(fd,&resp_netsess,sizeof(resp_netsess))<0) break;
        if(resp_payload){
            if(writen(fd,resp.data(),resp_payload)<0) break;
        }
        // continue
    }
    close(fd);
}

int main(){
    string bind_ip,other_ip;
    int port,other_port;
    cerr<<"Start tracker: enter bind_ip port other_ip other_port\n";
    if(!(cin>>bind_ip>>port>>other_ip>>other_port)){
        cerr<<"usage\n"; return 1;
    }

    int listenFd = socket(AF_INET,SOCK_STREAM,0);
    if(listenFd<0){ perror("socket"); return 1; }
    int opt=1; setsockopt(listenFd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family=AF_INET;
    addr.sin_port=htons(port);
    inet_pton(AF_INET,bind_ip.c_str(),&addr.sin_addr);
    if(::bind(listenFd,(sockaddr*)&addr,sizeof(addr))<0){ perror("bind"); return 1; }
    if(listen(listenFd,50)<0){ perror("listen"); return 1; }

    cerr<<"Tracker listening on "<<bind_ip<<":"<<port<<endl;
    Tracker tracker;

    while(true){
        sockaddr_in cli; socklen_t clen=sizeof(cli);
        int cfd = accept(listenFd,(sockaddr*)&cli,&clen);
        if(cfd<0){
            if(errno==EINTR) continue;
            perror("accept"); break;
        }
        char cli_ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET,&cli.sin_addr,cli_ip,sizeof(cli_ip));
        cerr<<"accepted from "<<cli_ip<<":"<<ntohs(cli.sin_port)<<", spawning handler\n";
        thread t(sessionWorker,cfd,ref(tracker));
        t.detach();
    }

    close(listenFd);
    return 0;
}