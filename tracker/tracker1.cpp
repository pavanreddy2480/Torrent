#include<iostream>
#include<sys/socket.h>
#include<netinet/in.h>
#include<unistd.h>
#include<arpa/inet.h>
#include<sstream>
#include<map>
#include<set>
using namespace std;

// ======================= Tracker functionality ==========================
class Tracker{
    map<string,string> users;                 // user -> password
    map<string,set<string>> groups;           // group -> members
public:
    string handleCommand(const string &cmdline){
        stringstream ss(cmdline);
        string cmd; ss>>cmd;
        if(cmd=="create_user"){
            string uid,pwd; ss>>uid>>pwd;
            if(users.count(uid)) return "User already exists";
            users[uid]=pwd;
            return "User created";
        }else if(cmd=="create_group"){
            string gid; ss>>gid;
            if(groups.count(gid)) return "Group already exists";
            groups[gid]; // create empty set
            return "Group created";
        }else if(cmd=="join_group"){
            string gid,uid; ss>>gid>>uid;
            if(!groups.count(gid)) return "No such group";
            groups[gid].insert(uid);
            return "User "+uid+" joined group "+gid;
        }else if(cmd=="list_groups"){
            string res="Groups: ";
            for(auto &g:groups)res+=g.first+" ";
            return res;
        }else if(cmd=="list_users"){
            string res="Users: ";
            for(auto &u:users)res+=u.first+" ";
            return res;
        }else{
            return "Unknown command";
        }
    }
};

// ======================= Tracker Server ================================
int main(){
    string ip1,ip2; int port1,port2;
    cin>>ip1>>port1>>ip2>>port2;

    int sockFd=socket(AF_INET,SOCK_STREAM,0);
    sockaddr_in serverAddr{};
    serverAddr.sin_family=AF_INET;
    serverAddr.sin_port=htons(port1);
    inet_pton(AF_INET,ip1.c_str(),&serverAddr.sin_addr);
    ::bind(sockFd,(struct sockaddr*)&serverAddr,sizeof(serverAddr));
    listen(sockFd,5);

    Tracker tracker;

    cout<<"Tracker1 running on "<<ip1<<":"<<port1<<endl;
    while(true){
        int cSock=accept(sockFd,NULL,NULL);
        char buff[1024]={0};
        int n=recv(cSock,buff,sizeof(buff),0);
        if(n>0){
            string msg(buff,n);
            cout<<"[T1]cmd:"<<msg<<endl;

            string reply=tracker.handleCommand(msg);
            send(cSock,reply.c_str(),reply.size(),0);

            // forward to tracker2
            int t2Sock=socket(AF_INET,SOCK_STREAM,0);
            sockaddr_in t2Addr{};
            t2Addr.sin_family=AF_INET;
            t2Addr.sin_port=htons(port2);
            inet_pton(AF_INET,ip2.c_str(),&t2Addr.sin_addr);
            if(connect(t2Sock,(struct sockaddr*)&t2Addr,sizeof(t2Addr))==0){
                send(t2Sock,msg.c_str(),msg.size(),0);
            }
            close(t2Sock);
        }
        close(cSock);
    }
    close(sockFd);
    return 0;
}