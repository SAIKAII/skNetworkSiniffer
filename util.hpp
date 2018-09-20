#ifndef SKNETWORKSNIFFER_UTIL_HPP_
#define SKNETWORKSNIFFER_UTIL_HPP_

#include <string>
#include <arpa/inet.h>
#include <cstddef>

typedef struct rc_option{
    in_addr ip;  //inet_aton之后的ip
    unsigned short port;  //htons之后的端口号
}rc_option;

const std::string kHex[16] = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"};

extern std::string mac_to_little_endian(const unsigned char (&v)[6]);
extern bool throw_away_the_packet(const unsigned char *buffer, rc_option &opt, bool recv);
extern std::string switch_to_hex(const char c);

#endif
