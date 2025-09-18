#include "tracker_common.hpp"
int main(){
    string bind_ip,peer_ip;
    int bind_port,peer_port;
    if(!(cin>>peer_ip>>peer_port>>bind_ip>>bind_port)){
        cerr<<"Invalid input format\n";
        return 1;
    }
    Tracker tracker;
    SyncQueue dummy(peer_ip,peer_port); // created but not used for forwarding
    int listenFd=prepare_listener(bind_ip,bind_port);
    cerr<<"Tracker2 listening on "<<bind_ip<<":"<<bind_port
        <<" peer="<<peer_ip<<":"<<peer_port<<"\n";
    while(true){
        sockaddr_in cli; socklen_t clen=sizeof(cli);
        int cfd=accept(listenFd,(sockaddr*)&cli,&clen);
        if(cfd<0){if(errno==EINTR)continue;perror("accept");break;}
        thread t(sessionWorker,cfd,ref(tracker),&dummy,false);
        t.detach();
    }
    close(listenFd);
}