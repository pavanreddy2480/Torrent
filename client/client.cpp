#include<iostream>
#include<sys/socket.h>
#include<netinet/in.h>
#include<unistd.h>
#include<arpa/inet.h>
using namespace std;

int main(){
    string ip;
    int port;
    cin>>ip>>port;

    int cSock=socket(AF_INET,SOCK_STREAM,0);
    sockaddr_in serverAddr{};
    serverAddr.sin_family=AF_INET;
    serverAddr.sin_port=htons(port);
    inet_pton(AF_INET,ip.c_str(),&serverAddr.sin_addr);
    connect(cSock,(struct sockaddr*)&serverAddr,sizeof(serverAddr));

    string msg="hello from client";
    send(cSock,msg.c_str(),msg.size(),0);
    close(cSock);
    return 0;
}