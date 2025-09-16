// client_fixed.cpp
// Interactive client speaking the tracker framed protocol

// #include <bits/stdc++.h>
#include<string>
#include<iostream>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <readline/readline.h>
#include <readline/history.h>
using namespace std;
using u32 = uint32_t;
using u64 = uint64_t;

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

ssize_t readn(int fd, void* buf, size_t n){
    size_t left=n; char* ptr=(char*)buf;
    while(left){
        ssize_t r = ::recv(fd,ptr,left,0);
        if(r<0){
            if(errno==EINTR) continue;
            return -1;
        }
        if(r==0) return 0;
        left -= r; ptr += r;
    }
    return (ssize_t)n;
}
ssize_t writen(int fd,const void* buf,size_t n){
    size_t left=n; const char* ptr=(const char*)buf;
    while(left){
        ssize_t w = ::send(fd,ptr,left,0);
        if(w<=0){
            if(errno==EINTR) continue;
            return -1;
        }
        left -= w; ptr += w;
    }
    return (ssize_t)n;
}

int connect_to(const string &ip,int port){
    int fd = socket(AF_INET,SOCK_STREAM,0);
    if(fd<0) return -1;
    sockaddr_in s{}; s.sin_family=AF_INET; s.sin_port=htons(port);
    if(inet_pton(AF_INET,ip.c_str(),&s.sin_addr)<=0){ close(fd); return -1; }
    if(::connect(fd,(sockaddr*)&s,sizeof(s))<0){ close(fd); return -1; }
    // set recv timeout so client doesn't block forever
    struct timeval tv; tv.tv_sec=5; tv.tv_usec=0;
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
    return fd;
}

int main(){
    string ip; int port;
    if(!(cin>>ip>>port)) { cerr<<"usage\n"; return 1; }
    cin.ignore(numeric_limits<streamsize>::max(),'\n');
    cout<<"Client ready to connect to "<<ip<<":"<<port<<"\n";

    u64 session_id = 0;

    while(true){
        char* input = readline("> ");
        if(!input){ cout<<"\nExiting...\n"; break; }
        string line(input);
        free(input);
        if(line.empty()) continue;
        if(line=="quit") break;
        add_history(line.c_str());

        int fd = connect_to(ip,port);
        if(fd<0){ perror("connect"); continue; }

        // build frame
        u64 netsess = hton64(session_id);
        u32 payload_len = (u32)line.size();
        u32 frame_len = (u32)(sizeof(netsess) + payload_len);
        u32 netlen = htonl(frame_len);

        if(writen(fd,&netlen,sizeof(netlen))<0){ perror("send"); close(fd); continue; }
        if(writen(fd,&netsess,sizeof(netsess))<0){ perror("send"); close(fd); continue; }
        if(payload_len){
            if(writen(fd,line.data(),payload_len)<0){ perror("send"); close(fd); continue; }
        }

        // read response frame header
        u32 resp_netlen;
        if(readn(fd,&resp_netlen,sizeof(resp_netlen))<=0){ cerr<<"no response or timeout\n"; close(fd); continue; }
        u32 resp_len = ntohl(resp_netlen);
        if(resp_len < sizeof(u64) || resp_len > 10*1024*1024){ cerr<<"bad resp len\n"; close(fd); continue; }
        u64 resp_netsess;
        if(readn(fd,&resp_netsess,sizeof(resp_netsess))<=0){ cerr<<"no response2\n"; close(fd); continue; }
        u64 resp_sess = ntoh64(resp_netsess);
        size_t resp_payload = resp_len - sizeof(u64);
        string resp;
        if(resp_payload){
            vector<char> buf(resp_payload);
            if(readn(fd,buf.data(),resp_payload)<=0){ cerr<<"resp read fail\n"; close(fd); continue; }
            resp.assign(buf.data(),resp_payload);
        }
        if(resp_sess!=0) session_id = resp_sess;
        cout<<"< "<<resp<<"\n";
        close(fd);
    }
    cout<<"Client exiting\n";
    return 0;
}