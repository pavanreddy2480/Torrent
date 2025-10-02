#include "tracker_common.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <atomic>
#include <sys/select.h>
#include <readline/readline.h>

// Global flag to signal shutdown
atomic<bool> should_exit(false);

void console_listener() {
    auto input=readline(">");
    string line(input);
    free(input);
    if (line == "exit" || line == "quit") {
            should_exit = true;
        }
    
}

int main(int argc, char* argv[]){
    if (argc != 3) {
        cerr << "Usage: " << argv[0] << " <tracker_info_file> <tracker_no>\n";
        return 1;
    }

    string tracker_file_path = argv[1];
    int tracker_no = 0;
    try {
        tracker_no = stoi(argv[2]);
    } catch (...) {
        cerr << "Error: <tracker_no> must be a number (1 or 2).\n";
        return 1;
    }

    ifstream infile(tracker_file_path);
    if (!infile.is_open()) {
        cerr << "Error: Could not open tracker info file: " << tracker_file_path << "\n";
        return 1;
    }

    vector<pair<string, int>> trackers;
    string line;
    while (getline(infile, line)) {
        size_t p = line.find(':');
        if (p != string::npos) {
            try {
                trackers.push_back({line.substr(0, p), stoi(line.substr(p + 1))});
            } catch (...) {
                cerr << "Error: Invalid line in tracker info file: " << line << "\n";
                return 1;
            }
        }
    }

    if (trackers.size() != 2) {
        cerr << "Error: tracker_info.txt must contain exactly two tracker addresses.\n";
        return 1;
    }
    if (tracker_no != 1 && tracker_no != 2) {
        cerr << "Error: <tracker_no> must be 1 or 2.\n";
        return 1;
    }

    string bind_ip = trackers[tracker_no - 1].first;
    int bind_port = trackers[tracker_no - 1].second;
    string peer_ip = trackers[tracker_no == 1 ? 1 : 0].first;
    int peer_port = trackers[tracker_no == 1 ? 1 : 0].second;

    Tracker tracker_state;
    SyncQueue sync_queue(peer_ip, peer_port);
    thread sync_thread(&SyncQueue::run, &sync_queue);
    sync_thread.detach();

    int listenFd = prepare_listener(bind_ip, bind_port);
    cerr << "Tracker " << tracker_no << " listening on " << bind_ip << ":" << bind_port 
         << " (peer: " << peer_ip << ":" << peer_port << ")\n";
    cerr << "Type 'exit' or 'quit' to shut down.\n";

    // Start a thread to listen for console commands
    thread console_thread(console_listener);

    while(!should_exit.load()){
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(listenFd, &read_fds);
        
        struct timeval tv;
        tv.tv_sec = 1; // Check for exit command every second
        tv.tv_usec = 0;

        int activity = select(listenFd + 1, &read_fds, nullptr, nullptr, &tv);

        if ((activity < 0) && (errno!=EINTR)) {
            perror("select error");
        }

        if (FD_ISSET(listenFd, &read_fds)) {
            int cfd = accept(listenFd, nullptr, nullptr);
            if(cfd < 0) {
                if(errno == EINTR) continue;
                perror("accept");
                break;
            }
            thread(sessionWorker, cfd, ref(tracker_state)).detach();
        }
    }

    cout << "\nShutting down tracker...\n";
    close(listenFd);
    if(console_thread.joinable()){
        // To unblock the getline in the console thread
        // This is a bit of a hack for stdin, but works for shutdown
        pthread_cancel(console_thread.native_handle()); 
        console_thread.join();
    }
    return 0;
}

