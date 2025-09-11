#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
using namespace std;

int main(){
    string ip_addr;
    int port;
    cin>>ip_addr>>port;

    int sockFd=socket(AF_INET,SOCK_STREAM,0);

    sockaddr_in serverAddr;
    serverAddr.sin_family=AF_INET;
    serverAddr.sin_port=htons(port);

    inet_pton(AF_INET,ip_addr.c_str(),&serverAddr.sin_addr);
    ::bind(sockFd,(struct sockaddr*)&serverAddr,sizeof(serverAddr));

    listen(sockFd,5);
    int clientSocket=accept(sockFd,NULL,NULL);
    char buff[1024]={0};
    recv(clientSocket,buff,sizeof(buff),0);

    cout<<"msg for client : "<<buff<<endl;
    close(sockFd);
    close(clientSocket);
    return 0;
}