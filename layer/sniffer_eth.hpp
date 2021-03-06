#ifndef SKNETWORKSNIFFER_LAYER_SNIFFER_ETH_HPP_
#define SKNETWORKSNIFFER_LAYER_SNIFFER_ETH_HPP_

#include <netinet/if_ether.h>
#include <iostream>
#include <string>

extern std::string mac_to_little_endian(const unsigned char (&v)[6]);

class SnifferEth{
public:
    SnifferEth(unsigned char *buffer){
        eth = reinterpret_cast<ethhdr *>(buffer);
    }
    virtual void display_header(std::ostream &out){
        out << "----------EthernetFrame : " << std::endl;
        std::string dest_buffer(mac_to_little_endian(eth->h_dest));
        std::string source_buffer(mac_to_little_endian(eth->h_source));
        out << "D_MAC : " << dest_buffer << " S_MAC : " << source_buffer << std::endl;
    }
    virtual unsigned short get_upper_level_protocol(){
        return ntohs(eth->h_proto);
    }
    virtual unsigned short get_header_length(){};
    virtual ~SnifferEth() = default;

private:
    ethhdr *eth;
};

#endif
