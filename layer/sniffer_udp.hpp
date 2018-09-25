#ifndef SKNETWORKSNIFFER_LAYER_SNIFFER_UDP_HPP_
#define SKNETWORKSNIFFER_LAYER_SNIFFER_UDP_HPP_

#include <netinet/udp.h>

#include "sniffer_ip.hpp"

class SnifferUDP : public SnifferIP{
public:
    SnifferUDP(unsigned char *buffer) : SnifferIP(buffer){
        udph = reinterpret_cast<udphdr *>(buffer + sizeof(ethhdr) + SnifferIP::get_header_length());
    }
    virtual void display_header();
    virtual unsigned short get_header_length(){
        return sizeof(udphdr);
    }

private:
    udphdr *udph;
};

#endif
