// tracker2.cpp  -- Secondary tracker that stays in sync but never forwards

#include "tracker_common.hpp"   // see below

int main(int argc,char**argv){
    if(argc!=5){
        cerr<<"Usage: "<<argv[0]
            <<" <bind_ip> <bind_port> <peer_ip> <peer_port>\n";
        return 1;
    }
    string bind_ip  = argv[1];
    int    bind_port= stoi(argv[2]);
    string peer_ip  = argv[3];    // still passed for symmetry
    int    peer_port= stoi(argv[4]);

    Tracker tracker;
    SyncQueue dummy(peer_ip,peer_port);    // created but never used
    int listenFd = prepare_listener(bind_ip,bind_port);
    cerr<<"Tracker2 listening on "<<bind_ip<<":"<<bind_port
        <<"  peer="<<peer_ip<<":"<<peer_port<<"\n";

    while(true){
        sockaddr_in cli; socklen_t clen=sizeof(cli);
        int cfd = accept(listenFd,(sockaddr*)&cli,&clen);
        if(cfd<0){ if(errno==EINTR) continue; perror("accept"); break; }
        // forward flag = false so we do NOT push to peer
        thread t(sessionWorker,cfd,ref(tracker),&dummy,false);
        t.detach();
    }
    close(listenFd);
}