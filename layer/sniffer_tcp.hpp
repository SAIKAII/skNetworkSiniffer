#ifndef SKNETWORKSNIFFER_LAYER_SNIFFER_TCP_HPP_
#define SKNETWORKSNIFFER_LAYER_SNIFFER_TCP_HPP_

#include <netinet/tcp.h>
#include <netinet/if_ether.h>

#include "sniffer_ip.hpp"

class SnifferTCP : public SnifferIP{
public:
    SnifferTCP(unsigned char *buffer) : SnifferIP(buffer){
        tcph = reinterpret_cast<tcphdr*>(buffer + sizeof(ethhdr) + SnifferIP::get_header_length());
    }
    virtual void display_header();
    virtual unsigned short get_header_length(){
        return static_cast<unsigned short>(tcph->doff * 4);
    }
    virtual ~SnifferTCP(){}

private:
    tcphdr *tcph;
};

#endif
