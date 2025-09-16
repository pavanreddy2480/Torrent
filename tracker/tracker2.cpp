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

    int sockFd=socket(AF_INET,SOCK_STREAM,0);
    sockaddr_in serverAddr{};
    serverAddr.sin_family=AF_INET;
    serverAddr.sin_port=htons(port);
    inet_pton(AF_INET,ip.c_str(),&serverAddr.sin_addr);
    ::bind(sockFd,(struct sockaddr*)&serverAddr,sizeof(serverAddr));
    listen(sockFd,5);

    while(true){
        int cSock=accept(sockFd,NULL,NULL);
        char buff[1024]={0};
        int n=recv(cSock,buff,sizeof(buff),0);
        if(n>0)cout<<"[T2]fwd:"<<buff<<endl;
        close(cSock);
    }
    close(sockFd);
    return 0;
}