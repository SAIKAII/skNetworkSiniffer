#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <iostream>
#include <errno.h>
#include <signal.h>
#include <linux/if_ether.h> // 为了socket第三个参数的ETH_P_ALL
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <cstdlib>
#include <netdb.h>

#include "tool/util.hpp"
#include "layer/sniffer_ip.hpp"
#include "layer/sniffer_tcp.hpp"
#include "layer/sniffer_eth.hpp"
#include "layer/sniffer_udp.hpp"
#include "layer/sniffer_icmp.hpp"

sem_t buffer_empty_sem;
sem_t buffer_full_sem;
bool run = true;

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
        run = false;
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

void recv_packet(const int &socketfd, std::shared_ptr<rc_buffer> pack_buffer, size_t &size, int &tail_index){
    int recv_size;
    recv_size = recvfrom(socketfd, (pack_buffer.get() + tail_index)->buffer, MAX_PACKET, 0, 0, 0);

    if(recv_size <= 0){
        close(socketfd);
        perror("recvfrom(): ");
        exit(1);
    }
    size = recv_size;
    ++tail_index;
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

    std::shared_ptr<rc_buffer> pack_buffer(new(std::nothrow) rc_buffer[MAX_BUFFER]); // 用了nothrow才是失败返回nullptr
    if(nullptr == pack_buffer){
        perror("buffer new error: ");
        exit(1);
    }


    sem_init(&buffer_empty_sem, 0, 10);
    sem_init(&buffer_full_sem, 0, 0);

    int head_index = 0;
    int tail_index = 0;
    size_t size;

    std::thread t([pack_buffer, &head_index, &size](){
        while(run){
            sem_wait(&buffer_full_sem);
            process_packet(pack_buffer, size, head_index);
            if(head_index >= MAX_BUFFER)
                head_index = 0;
            sem_post(&buffer_empty_sem);
        }
    });

    fd_set fd_read;

    FD_ZERO(&fd_read);
    int res;
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
                sem_wait(&buffer_empty_sem);
                recv_packet(socketfd, pack_buffer, size, tail_index);

                if(throw_away_the_packet(pack_buffer, opt, tail_index - 1)){
                    sem_post(&buffer_empty_sem);
                    --tail_index;
                    continue;
                }

                if(tail_index >= MAX_BUFFER)
                    tail_index = 0;
                sem_post(&buffer_full_sem);
            }
        }
    }

    t.join();
    close(socketfd);
    return 0;
}
