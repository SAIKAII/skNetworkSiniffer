#include "sniffer_ip.hpp"

void SnifferIP::display_header(){
    SnifferEth::display_header();
    std::cout << "----------IP : " << std::endl;
    std::cout << "header length : " << (iph->ihl)*4;
    std::cout << "\ttotol length : " << (iph->tot_len)*4;
    std::cout << "\tflags : [" << kFlags[ntohs(iph->frag_off)&0x7] << "]";
    std::cout << "\tTTL : " << static_cast<unsigned short>(iph->ttl);
    unsigned short prot = static_cast<unsigned short>(iph->protocol);
    std::cout << "\tprotocol : " << kProtocol[prot] << std::endl;
    sockaddr_in source;
    sockaddr_in destination;
    memset((void *)&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    memset((void *)&destination, 0, sizeof(destination));
    destination.sin_addr.s_addr = iph->daddr;
    std::cout << "source ip : " << inet_ntoa(source.sin_addr);
    std::cout << "\tdestination ip : " << inet_ntoa(destination.sin_addr) << std::endl;
}
