#include "sniffer_ip.hpp"

void SnifferIP::display_header(std::ostream &out){
    SnifferEth::display_header(out);
    out << "----------IP : " << std::endl;
    out << "header length : " << (iph->ihl)*4;
    out << "\ttotol length : " << (iph->tot_len)*4;
    out << "\tflags : [" << kFlags[ntohs(iph->frag_off)&0x7] << "]";
    out << "\tTTL : " << static_cast<unsigned short>(iph->ttl);
    unsigned short prot = static_cast<unsigned short>(iph->protocol);
    out << "\tprotocol : " << kProtocol[prot] << std::endl;
    sockaddr_in source;
    sockaddr_in destination;
    memset((void *)&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    memset((void *)&destination, 0, sizeof(destination));
    destination.sin_addr.s_addr = iph->daddr;
    out << "source ip : " << inet_ntoa(source.sin_addr);
    out << "\tdestination ip : " << inet_ntoa(destination.sin_addr) << std::endl;
}
