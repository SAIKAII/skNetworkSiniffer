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

#include "../layer/sniffer_eth.hpp"
#include "../layer/sniffer_ip.hpp"
#include "../layer/sniffer_tcp.hpp"
#include "../layer/sniffer_udp.hpp"

#define ICMP 1
#define IGMP 2
#define IP 4
#define TCP 6
#define UDP 17

typedef struct rc_option{
    in_addr ip;  //inet_aton之后的ip
    unsigned short port;  //htons之后的端口号
}rc_option;

typedef struct repeated_filter{
    unsigned char mf;
    unsigned short frag_off;

    bool operator==(const repeated_filter &rhs){
        return frag_off == rhs.frag_off;
    }
}repeated_filter;

const std::string kHex[16] = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"};
extern bool thread_loop;
extern std::map<unsigned short, std::string> kProtocol;
extern std::unordered_map<unsigned short, repeated_filter> identification;

extern void init();
extern std::string mac_to_little_endian(const unsigned char (&v)[6]);
extern bool throw_away_the_packet(const unsigned char *buffer, rc_option &opt, bool recv);
extern std::string switch_to_hex(const char c);
extern SnifferEth *judge_protocol_and_return_obj(unsigned char *buffer);

#endif
