#ifndef SKNETWORKSNIFFER_LAYER_SNIFFER_ICMP_HPP_
#define SKNETWORKSNIFFER_LAYER_SNIFFER_ICMP_HPP_

#include <netinet/ip_icmp.h>
#include "sniffer_ip.hpp"

class SnifferICMP : public SnifferIP{
public:
    SnifferICMP(unsigned char *buffer) : SnifferIP(buffer){
        icmp = reinterpret_cast<icmphdr *>(buffer + sizeof(ethhdr) + SnifferIP::get_header_length());
    }
    virtual void display_header(std::ostream &out);
    virtual unsigned short get_header_length(){};
    virtual ~SnifferICMP() = default;

private:
    icmphdr *icmp;
};

#endif
