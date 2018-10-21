#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <iostream>
#include <errno.h>
#include <signal.h>
#include <memory>
#include <linux/if_ether.h> // 为了socket第三个参数的ETH_P_ALL
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <cstdlib>
#include <fstream>
#include <netdb.h>

#include "tool/util.hpp"
#include "layer/sniffer_ip.hpp"
#include "layer/sniffer_tcp.hpp"
#include "layer/sniffer_eth.hpp"
#include "layer/sniffer_udp.hpp"
#include "layer/sniffer_icmp.hpp"

#define MAX_PACKET 65535

static bool open_log = false;

// 显示可用参数
void show_option(){
    std::cout << "USAGE : sniffer -p(port_number) [-i(ip_address) -l(any char) -h(url)]" << std::endl;
}

// 名字、地址转换
void hostname_to_addr(char *name, rc_option &opt){
    hostent *hptr = gethostbyname(name);
    if(nullptr == hptr){
        perror("gethostname(): ");
        exit(1);
    }
    opt.ip = *((in_addr*)(*(hptr->h_addr_list)));
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
            case 'l':
                open_log = true;
                break;
            case 'h':
                ++i;
                hostname_to_addr(option[i], opt);
                break;
        }
    }
}

bool exec_cmd(char *buffer, int len){
    if(strncmp(buffer, "quit", 4) == 0){
        return true;
    }
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

void recv_packet(const int &socketfd, auto &buffer, size_t &size){
    int recv_size;
    recv_size = recvfrom(socketfd, buffer.get(), MAX_PACKET, 0, 0, 0);

    if(recv_size <= 0){
        close(socketfd);
        perror("recvfrom(): ");
        exit(1);
    }
    size = recv_size;
}

void process_packet(unsigned char *buffer, int size){
    SnifferEth *prot_ptr = judge_protocol_and_return_obj(buffer);

    if(nullptr == prot_ptr){
        std::cout << "wrong datagram!" << std::endl;
        return;
    }

    prot_ptr->display_header(std::cout);
    std::cout << std::endl;
    // 写到log文件
    if(open_log){
        std::ofstream os("./log_file.dat", std::ofstream::out | std::ofstream::app | std::ofstream::ate);
        prot_ptr->display_header(os);
        os << std::endl;
        os.close();
    }

    delete prot_ptr;
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
    int socketfd;
    // 接收发往本机mac的所有类型ip arp rarp的数据帧，接收从本机发出的所有类型的数据帧。
    socketfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(socketfd < 0){
        perror("socket failed: ");
        exit(1);
    }
    memset((void *)&opt, 0, sizeof(rc_option));
    resolve_option(argc-1, &argv[1], opt);

    fd_set fd_read;
    std::shared_ptr<unsigned char> buffer(new unsigned char[MAX_PACKET]);
    if(NULL == buffer){
        perror("std::shared_ptr error: ");
        exit(1);
    }

    FD_ZERO(&fd_read);
    int res;
    size_t size;
    while(1){
        res = -1;
        FD_SET(0, &fd_read);
        FD_SET(socketfd, &fd_read);

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
            }
            if(FD_ISSET(socketfd, &fd_read)){
                recv_packet(socketfd, buffer, size);

                if(throw_away_the_packet(buffer.get(), opt))
                    continue;

                // 处理数据包
                process_packet(buffer.get(), size);
            }
        }
    }

    close(socketfd);
    return 0;
}
