// tracker1.cpp  -- Primary tracker that also forwards updates to Tracker2

#include "tracker_common.hpp"   // see below

int main(int argc,char**argv){
    if(argc!=5){
        cerr<<"Usage: "<<argv[0]
            <<" <bind_ip> <bind_port> <peer_ip> <peer_port>\n";
        return 1;
    }
    string bind_ip  = argv[1];
    int    bind_port= stoi(argv[2]);
    string peer_ip  = argv[3];
    int    peer_port= stoi(argv[4]);

    Tracker tracker;
    SyncQueue sync(peer_ip,peer_port);     // <== Forwarder is active in tracker1
    thread retrier(&SyncQueue::run,&sync); retrier.detach();

    int listenFd = prepare_listener(bind_ip,bind_port);
    cerr<<"Tracker1 listening on "<<bind_ip<<":"<<bind_port
        <<"  forwarding to "<<peer_ip<<":"<<peer_port<<"\n";

    while(true){
        sockaddr_in cli; socklen_t clen=sizeof(cli);
        int cfd = accept(listenFd,(sockaddr*)&cli,&clen);
        if(cfd<0){ if(errno==EINTR) continue; perror("accept"); break; }
        thread t(sessionWorker,cfd,ref(tracker),&sync,true); // forward=true
        t.detach();
    }
    close(listenFd);
}