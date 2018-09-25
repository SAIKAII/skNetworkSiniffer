#include "sniffer_udp.hpp"

void SnifferUDP::display_header(){
    SnifferIP::display_header();
    std::cout << "----------UDP : " << std::endl;
    std::cout << "source port : " << ntohs(udph->source);
    std::cout << "\tdestination port : " << ntohs(udph->dest);
    std::cout << "\tsize of datagram : " << ntohs(udph->len) << std::endl;
}
