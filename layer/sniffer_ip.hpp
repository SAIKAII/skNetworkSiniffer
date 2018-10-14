#ifndef SKNETWORKSNIFFER_LAYER_SNIFFER_IP_HPP_
#define SKNETWORKSNIFFER_LAYER_SNIFFER_IP_HPP_

#include <netinet/ip.h>
#include <string>
#include <map>
#include <netinet/if_ether.h>
#include <cstring>
#include <arpa/inet.h>

#include "sniffer_eth.hpp"

extern std::map<unsigned short, std::string> kProtocol;
const static std::string kFlags[5] = {" ", " ", "DF", " ", "MF"};

class SnifferIP : public SnifferEth{
public:
    SnifferIP(unsigned char *buffer) : SnifferEth(buffer){
        iph = reinterpret_cast<iphdr *>(buffer + sizeof(ethhdr));
    }
    virtual void display_header(std::ostream &out);
    virtual unsigned short get_header_length(){
        return static_cast<unsigned short>(iph->ihl * 4);
    }
    virtual unsigned short get_upper_level_protocol(){
        return static_cast<unsigned short>(iph->protocol);
    }
    virtual ~SnifferIP() = default;

private:
    iphdr *iph;
};

#endif
