#include<iostream>
#include<sys/socket.h>
#include<netinet/in.h>
#include<unistd.h>
#include<arpa/inet.h>
using namespace std;

int main(){
    string ip1,ip2;
    int port1,port2;
    cin>>ip1>>port1>>ip2>>port2;

    int sockFd=socket(AF_INET,SOCK_STREAM,0);
    sockaddr_in serverAddr{};
    serverAddr.sin_family=AF_INET;
    serverAddr.sin_port=htons(port1);
    inet_pton(AF_INET,ip1.c_str(),&serverAddr.sin_addr);
    ::bind(sockFd,(struct sockaddr*)&serverAddr,sizeof(serverAddr));
    listen(sockFd,5);

    while(true){
        int cSock=accept(sockFd,NULL,NULL);
        char buff[1024]={0};
        int n=recv(cSock,buff,sizeof(buff),0);
        if(n>0){
            cout<<"[T1]msg:"<<buff<<endl<<flush;
            //forward to tracker2
            int t2Sock=socket(AF_INET,SOCK_STREAM,0);
            sockaddr_in t2Addr{};
            t2Addr.sin_family=AF_INET;
            t2Addr.sin_port=htons(port2);
            inet_pton(AF_INET,ip2.c_str(),&t2Addr.sin_addr);
            if(connect(t2Sock,(struct sockaddr*)&t2Addr,sizeof(t2Addr))==0){
                send(t2Sock,buff,n,0);
            }
            close(t2Sock);
        }
        close(cSock);
    }
    close(sockFd);
    return 0;
}