#include "tracker_common.hpp"
#include <iostream>

int main(int argc, char* argv[]){
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0] << " <bind_ip> <bind_port> <peer_ip> <peer_port>\n";
        return 1;
    }

    std::string bind_ip = argv[1];
    int bind_port = std::stoi(argv[2]);
    std::string peer_ip = argv[3];
    int peer_port = std::stoi(argv[4]);

    Tracker tracker;
    SyncQueue sync(peer_ip, peer_port);
    std::thread retrier(&SyncQueue::run, &sync);
    retrier.detach();

    int listenFd = prepare_listener(bind_ip, bind_port);
    std::cerr << "Tracker listening on " << bind_ip << ":" << bind_port << " forwarding to " << peer_ip << ":" << peer_port << " \n";

    while(true){
        sockaddr_in cli;
        socklen_t clen = sizeof(cli);
        int cfd = accept(listenFd, (sockaddr*)&cli, &clen);
        if(cfd < 0) {
            if(errno == EINTR) continue;
            perror("accept");
            break;
        }
        std::thread t(sessionWorker, cfd, std::ref(tracker), &sync, true);
        t.detach();
    }
    close(listenFd);
    return 0;
}

