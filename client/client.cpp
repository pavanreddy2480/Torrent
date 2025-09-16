#include<iostream>
#include<sys/socket.h>
#include<netinet/in.h>
#include<unistd.h>
#include<arpa/inet.h>
#include<readline/readline.h>
#include<readline/history.h>   // optional for add_history
#include<cstring>
#include<cstdlib>
using namespace std;

int main(){
    string ip; int port;
    cin>>ip>>port;
    cout<<"Client connected to "<<ip<<":"<<port<<endl;

    while(true){
        int cSock=socket(AF_INET,SOCK_STREAM,0);
        sockaddr_in serverAddr{};
        serverAddr.sin_family=AF_INET;
        serverAddr.sin_port=htons(port);
        inet_pton(AF_INET,ip.c_str(),&serverAddr.sin_addr);
        if(connect(cSock,(struct sockaddr*)&serverAddr,sizeof(serverAddr))<0){
            cerr<<"Cannot connect\n"; return 1;
        }

        char* input=readline("> ");
        if(!input){ // EOF (Ctrl-D) or error
            cout<<"\nExiting...\n";
            close(cSock);
            break;
        }

        string line(input);
        free(input); // free buffer allocated by readline

        if(line=="quit"){
            close(cSock);
            break;
        }

        if(!line.empty()) add_history(line.c_str());

        send(cSock,line.c_str(),line.size(),0);

        char buff[1024]={0};
        int n=recv(cSock,buff,sizeof(buff),0);
        if(n>0) cout<<"[Tracker] "<<string(buff,n)<<endl;
        close(cSock);
    }
    return 0;
}