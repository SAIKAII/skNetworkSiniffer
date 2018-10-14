#include "sniffer_udp.hpp"

void SnifferUDP::display_header(std::ostream &out){
    SnifferIP::display_header(out);
    out << "----------UDP : " << std::endl;
    out << "source port : " << ntohs(udph->source);
    out << "\tdestination port : " << ntohs(udph->dest);
    out << "\tsize of datagram : " << ntohs(udph->len) << std::endl;
}
