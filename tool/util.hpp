#ifndef SKNETWORKSNIFFER_UTIL_HPP_
#define SKNETWORKSNIFFER_UTIL_HPP_

#include <string>
#include <arpa/inet.h>
#include <cstddef>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <map>
#include <unordered_map>
#include <thread>
#include <chrono>
#include <vector>
#include <semaphore.h>
#include <memory>
#include <fstream>

#include "../layer/sniffer_eth.hpp"
#include "../layer/sniffer_ip.hpp"
#include "../layer/sniffer_tcp.hpp"
#include "../layer/sniffer_udp.hpp"
#include "../layer/sniffer_icmp.hpp"

#define ICMP 1
#define IGMP 2
#define IP 4
#define TCP 6
#define UDP 17

#define MAX_PACKET 65535
#define MAX_BUFFER 10

typedef struct rc_option{
    in_addr ip;  //inet_aton之后的ip
    unsigned short port;  //htons之后的端口号
}rc_option;

typedef struct rc_buffer{
    unsigned char buffer[MAX_PACKET];
}rc_buffer;

const std::string kHex[16] = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"};
extern std::map<unsigned short, std::string> kProtocol;
extern bool open_log;

extern void init();
extern std::string mac_to_little_endian(const unsigned char (&v)[6]);
extern bool throw_away_the_packet(const std::shared_ptr<rc_buffer> buffer, rc_option &opt, int tail_index);
extern std::string switch_to_hex(const char c);
extern SnifferEth *judge_protocol_and_return_obj(unsigned char *buffer);
extern void process_packet(std::shared_ptr<rc_buffer> buffer, int size, int &head_index);

#endif
