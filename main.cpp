#include <sys/socket.h>
#include <sys/select.h>
#include <iostream>
#include <errno.h>
#include <signal.h>
#include <memory.h>
#include <linux/if_ether.h> // 为了socket第三个参数的ETH_P_ALL
#include <sys/types.h>

#include "network_packet.hpp"

#define MAX_PACKET 65536

typedef struct rc_option{
    unsigned int s_ip;  //目的ip
    unsigned short port;  //端口号
}rc_option;

// 显示可用参数
void show_option(){
    std::cout << "USAGE : sniffer -p(port_number) [-i(ip_address)]" << std::endl;
}

// 解析参数
void resolve_option(int num, char *option[], rc_option &opt){
    for(int i = 0; i < num; ++i){
        switch(option[i][1]){
            case 'i':
                ++i;
                opt.s_ip = static_cast<unsigned int>(inet_addr(option[i]));
                break;
            case 'p':
                ++i;
                opt.port = static_cast<unsigned short>(atoi(option[i]));
                break;
        }
    }
}

bool throw_away_the_packet(sockaddr &from, rc_option &opt){

}

void process_packet(unsigned char *buffer, int size){

}

int main(int argc, char *argv[]){

    if (argc < 2 || (argc&0x1) == 0){
        show_option();
        perror("argument too less: ");
        exit(1);
    }

    rc_option opt;
    memset(opt, 0, sizeof(rc_option));
    resolve_option(argc-1, &option[1], opt);

    int socketfd;

    // 接收发往本机mac的所有类型ip arp rarp的数据帧，接收从本机发出的所有类型的数据帧。
    socketfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(socketfd < 0){
        perror("socket failed: ");
        exit(1);
    }

    fd_set fd_read, fd_write;
    std::shared_ptr<unsigned char> buffer(new unsigned char[MAX_PACKET]);
    if(buffer == NULL){
        perror("std::shared_ptr error: ");
        exit(1);
    }

    sockaddr from;
    int recv_size;
    FD_ZERO(&fd_read);
    FD_ZERO(&fd_write);
    while(1){
        FD_SET(0, &fd_read);
        FD_SET(socketfd, &fd_read);
        FD_SET(socketfd, &fd_write);

        res = select(socketfd+1, &fd_read, &fd_write, NULL, NULL);
        if(res < 0){
            close(socketfd);
            if(errno != EINTR)
                perror("select() ");
            exit(1);
        }else{
            if(FD_ISSET(0, &fd_read)){
                // 标准输入可读，调用command_interpreter处理程序。暂时只支持'quit'命令
                if(command_interpreter(socketfd) == 1)
                break;
            }else if(FD_ISSET(socketfd, &fd_read)){
                recv_size = recvfrom(socketfd, buffer.get(), MAX_PACKET, 0, &from, &sizeof(sockaddr));

                if(recv_size <= 0){
                    close(socketfd);
                    perror("recvfrom(): ");
                    exit(1);
                }

                if(throw_away_the_packet(from, opt))
                    continue;

                // 处理数据包
                process_packet(buffer.get(), recv_size);
            }
        }
    }

    close(socketfd);
    return 0;
}
