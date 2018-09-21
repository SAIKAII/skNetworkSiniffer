#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <iostream>
#include <errno.h>
#include <signal.h>
#include <memory>
#include <linux/if_ether.h> // 为了socket第三个参数的ETH_P_ALL
#include <sys/types.h>
#include <map>
#include <string.h>
#include <unistd.h>
#include <cstdlib>

#include "network_packet.hpp"
#include "util.hpp"

#define MAX_PACKET 65536

#define RECVPACKET true
#define SNDPACKET false

static std::map<unsigned short, std::string> kProtocol;

void init(){
    kProtocol[6] = "TCP";
    kProtocol[17] = "UDP";
}

// 显示可用参数
void show_option(){
    std::cout << "USAGE : sniffer -p(port_number) [-i(ip_address)]" << std::endl;
}

// 解析参数
void resolve_option(int num, auto option /*char *option[] */, rc_option &opt){
    for(int i = 0; i < num; ++i){
        switch(option[i][1]){
            case 'i':
                ++i;
                inet_aton(option[i], &opt.ip);
                break;
            case 'p':
                unsigned short port;
                ++i;
                port = static_cast<unsigned short>(atoi(option[i]));
                opt.port = htons(port);
                break;
        }
    }
}

bool exec_cmd(char *buffer, int len){
    if(strncmp(buffer, "quit", 4) == 0)
        return true;
    return false;
}

bool command_interpreter(const int &socketfd){
    int len;
    char buf[512];

    len = read(0, buf, 512);
    if(len > 0){
        if(exec_cmd(buf, len))
            return true;
    }
    return false;
}

void recv_packet(const int &socketfd, auto &buffer){
    int recv_size;
    recv_size = recv(socketfd, buffer.get(), MAX_PACKET, 0);

    if(recv_size <= 0){
        close(socketfd);
        perror("recvfrom(): ");
        exit(1);
    }
}

void process_packet(unsigned char *buffer, int size){
    EthernetFrameHeader *efh = reinterpret_cast<EthernetFrameHeader *>(buffer);
    std::cout << "----------EthernetFrame : " << std::endl;
    std::cout << "D_MAC : " << mac_to_little_endian(efh->destination_mac) << " S_MAC : " << mac_to_little_endian(efh->source_mac) << std::endl;

    IPHeader *iph = reinterpret_cast<IPHeader *>(buffer + 6 + 6 + 2);
    std::cout << "----------IP : " << std::endl;
    std::cout << "TTL : " << static_cast<unsigned short>(iph->ttl);
    unsigned short prot = static_cast<unsigned short>(iph->protocol);
    std::cout << "\tprotocol : " << kProtocol[prot] << std::endl;
    in_addr iph_ip;
    iph_ip.s_addr = iph->source_ip;
    std::cout << "source ip : " << inet_ntoa(iph_ip) << std::endl;
    iph_ip.s_addr = iph->destination_ip;
    std::cout << "destination ip : " << inet_ntoa(iph_ip) << std::endl;
    std::cout << std::endl;

    // ...
}

int main(int argc, char *argv[]){

    if (argc < 2 || (argc&0x1) == 0){
        show_option();
        perror("argument too less: ");
        exit(1);
    }

    init();

    rc_option opt;
    memset((void *)&opt, 0, sizeof(rc_option));
    resolve_option(argc-1, &argv[1], opt);

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

    FD_ZERO(&fd_read);
    // FD_ZERO(&fd_write);
    int res;
    while(1){
        res = -1;
        FD_SET(0, &fd_read);
        FD_SET(socketfd, &fd_read);
        // FD_SET(socketfd, &fd_write);

        // res = select(socketfd+1, &fd_read, &fd_write, NULL, NULL);
        res = select(socketfd+1, &fd_read, NULL, NULL, NULL);
        if(res < 0){
            close(socketfd);
            if(errno != EINTR)
                perror("select() ");
            exit(1);
        }else{
            if(FD_ISSET(0, &fd_read)){
                // 标准输入可读，调用command_interpreter处理程序。暂时只支持'quit'命令
                if(command_interpreter(socketfd))
                    break;
            }else if(FD_ISSET(socketfd, &fd_read)){
                recv_packet(socketfd, buffer);

                if(throw_away_the_packet(buffer.get(), opt, RECVPACKET))
                    continue;

                // 处理数据包
                process_packet(buffer.get(), res);
            }
            // if(FD_ISSET(socketfd, &fd_write)){
            //     recv_packet(socketfd, buffer, from);
            //
            //     if(throw_away_the_packet(from, opt))
            //         continue;
            //
            //
            // }
        }
    }

    close(socketfd);
    return 0;
}
