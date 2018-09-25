#ifndef SKNETWORKSNIFFER_LAYER_SNIFFER_ETH_HPP_
#define SKNETWORKSNIFFER_LAYER_SNIFFER_ETH_HPP_

#include <netinet/if_ether.h>
#include <iostream>

extern std::string mac_to_little_endian(const unsigned char (&v)[6]);

class SnifferEth{
public:
    SnifferEth(unsigned char *buffer){
        eth = reinterpret_cast<ethhdr *>(buffer);
    }
    virtual void display_header(){
        std::cout << "----------EthernetFrame : " << std::endl;
        std::cout << "D_MAC : " << mac_to_little_endian(eth->h_dest) << " S_MAC : " << mac_to_little_endian(eth->h_source) << std::endl;
    }
    virtual unsigned short get_upper_level_protocol(){
        return ntohs(eth->h_proto);
    }

private:
    ethhdr *eth;
};

#endif
