#pragma once
#include<bits/stdc++.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<unistd.h>
#include<thread>
#include<mutex>
#include<atomic>
using namespace std;
using u32=uint32_t;using u64=uint64_t;
static const size_t MAX_FRAME=10*1024*1024;
inline u64 hton64(u64 v){
#if __BYTE_ORDER==__LITTLE_ENDIAN
    return(((u64)htonl((uint32_t)(v&0xffffffffULL)))<<32)|htonl((uint32_t)((v>>32)&0xffffffffULL));
#else
    return v;
#endif
}
inline u64 ntoh64(u64 v){
#if __BYTE_ORDER==__LITTLE_ENDIAN
    return(((u64)ntohl((uint32_t)(v&0xffffffffULL)))<<32)|ntohl((uint32_t)((v>>32)&0xffffffffULL));
#else
    return v;
#endif
}
inline ssize_t readn(int fd,void*buf,size_t n){
    size_t left=n;char*p=(char*)buf;
    while(left){
        ssize_t r=recv(fd,p,left,0);
        if(r<0){if(errno==EINTR)continue;return-1;}
        if(r==0)return 0;
        left-=r;p+=r;
    }
    return n;
}
inline ssize_t writen(int fd,const void*buf,size_t n){
    size_t left=n;const char*p=(const char*)buf;
    while(left){
        ssize_t w=send(fd,p,left,0);
        if(w<=0){if(errno==EINTR)continue;return-1;}
        left-=w;p+=w;
    }
    return n;
}
struct GroupInfo{
    string owner;
    unordered_set<string>members;
    unordered_set<string>pending;
};
class Tracker{
    mutex m;
    unordered_map<string,string>users;
    unordered_map<u64,string>sessions;
    unordered_map<string,GroupInfo>groups;
    static u64 nextId(){static atomic<u64>c(1);return c++;}
public:
    pair<string,u64> handle(u64 sess,const string&cmdline){
        stringstream ss(cmdline);
        string cmd;ss>>cmd;
        if(cmd.empty())return{"ERR empty",sess};
        lock_guard<mutex>lk(m);
        string user=(sess&&sessions.count(sess))?sessions[sess]:"";
        if(cmd=="create_user"){
            string u,p;ss>>u>>p;
            if(u.empty()||p.empty())return{"ERR usage",sess};
            if(users.count(u))return{"ERR exists",sess};
            users[u]=p;return{"OK user created",sess};
        }
        if(cmd=="login"){
            string u,p;ss>>u>>p;
            if(!users.count(u))return{"ERR no such user",sess};
            if(users[u]!=p)return{"ERR bad password",sess};
            if(sess==0)sess=nextId();
            sessions[sess]=u;
            return{"OK logged in",sess};
        }
        if(cmd=="logout"){
            if(!sessions.count(sess)||sessions[sess].empty())return{"ERR not logged in",sess};
            sessions[sess].clear();
            return{"OK logged out",sess};
        }
        if(cmd=="create_group"){
            string g;ss>>g;
            if(g.empty()||user.empty())return{"ERR usage/login",sess};
            if(groups.count(g))return{"ERR group exists",sess};
            GroupInfo gi;gi.owner=user;gi.members.insert(user);
            groups[g]=::move(gi);
            return{"OK group created",sess};
        }
        if(cmd=="join_group"){
            string g;ss>>g;
            if(g.empty()||user.empty())return{"ERR usage/login",sess};
            if(!groups.count(g))return{"ERR no such group",sess};
            auto&gi=groups[g];
            if(gi.members.count(user))return{"ERR already member",sess};
            gi.pending.insert(user);
            return{"OK join requested",sess};
        }
        if(cmd=="accept_request"){
            string g,u;ss>>g>>u;
            if(!groups.count(g))return{"ERR no group",sess};
            auto&gi=groups[g];
            if(gi.owner!=user)return{"ERR not owner",sess};
            if(!gi.pending.count(u))return{"ERR no such req",sess};
            gi.pending.erase(u);gi.members.insert(u);
            return{"OK accepted",sess};
        }
        if(cmd=="list_groups"){
            string out="Groups:";
            for(auto&kv:groups)out+=" "+kv.first;
            return{out,sess};
        }
        return{"ERR unknown",sess};
    }
};
struct SyncItem{u64 sess;string cmd;};
class SyncQueue{
    string peer_ip;int peer_port;
    deque<SyncItem>q;
    mutex m;condition_variable cv;
    bool stop=false;
public:
    SyncQueue(const string&ip="",int port=0):peer_ip(ip),peer_port(port){}
    void enqueue(u64 s,const string&c){
        lock_guard<mutex>lk(m);q.push_back({s,c});cv.notify_one();
    }
    void run(){
        while(true){
            unique_lock<mutex>lk(m);
            cv.wait(lk,[&]{return stop||!q.empty();});
            if(stop)break;
            SyncItem it=q.front();q.pop_front();
            lk.unlock();
            int fd=socket(AF_INET,SOCK_STREAM,0);
            if(fd<0){this_thread::sleep_for(1s);continue;}
            sockaddr_in addr{};addr.sin_family=AF_INET;
            addr.sin_port=htons(peer_port);
            inet_pton(AF_INET,peer_ip.c_str(),&addr.sin_addr);
            if(connect(fd,(sockaddr*)&addr,sizeof(addr))<0){close(fd);this_thread::sleep_for(1s);continue;}
            string payload="SYNC:"+it.cmd;
            u32 len=htonl(sizeof(u64)+payload.size());
            u64 sess=hton64(it.sess);
            writen(fd,&len,sizeof(len));
            writen(fd,&sess,sizeof(sess));
            writen(fd,payload.data(),payload.size());
            close(fd);
        }
    }
};
inline void sessionWorker(int fd,Tracker&tracker,SyncQueue*sync,bool doForward){
    while(true){
        u32 netlen;
        ssize_t r=readn(fd,&netlen,sizeof(netlen));
        if(r<=0)break;
        u32 len=ntohl(netlen);
        if(len<sizeof(u64)||len>MAX_FRAME)break;
        u64 nets;if(readn(fd,&nets,sizeof(nets))<=0)break;
        u64 sess=ntoh64(nets);
        size_t pay=len-sizeof(u64);
        string cmd;
        if(pay){
            vector<char>buf(pay);
            if(readn(fd,buf.data(),pay)<=0)break;
            cmd.assign(buf.data(),pay);
        }
        bool isSync=false;
        if(cmd.rfind("SYNC:",0)==0){isSync=true;cmd=cmd.substr(5);}
        auto[reply,newSess]=tracker.handle(sess,cmd);
        u32 respLen=htonl(sizeof(u64)+reply.size());
        u64 respSess=hton64(newSess);
        if(writen(fd,&respLen,sizeof(respLen))<0)break;
        if(writen(fd,&respSess,sizeof(respSess))<0)break;
        if(!reply.empty())if(writen(fd,reply.data(),reply.size())<0)break;
        if(doForward&&!isSync&&sync)sync->enqueue(newSess,cmd);
    }
    close(fd);
}
inline int prepare_listener(const string&ip,int port){
    int fd=socket(AF_INET,SOCK_STREAM,0);
    if(fd<0){perror("socket");exit(1);}
    int opt=1;setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
    sockaddr_in addr{};addr.sin_family=AF_INET;
    addr.sin_port=htons(port);
    inet_pton(AF_INET,ip.c_str(),&addr.sin_addr);
    if(::bind(fd,(sockaddr*)&addr,sizeof(addr))<0){perror("bind");exit(1);}
    if(listen(fd,50)<0){perror("listen");exit(1);}
    return fd;
}