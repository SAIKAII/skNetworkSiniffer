#include "sniffer_tcp.hpp"

void SnifferTCP::display_header(){
    SnifferIP::display_header();
    std::cout << "----------TCP : " << std::endl;
    std::cout << "source port : " << ntohs(tcph->source);
    std::cout << "\tdestination port : " << ntohs(tcph->dest);
    std::cout << "\tseq : " << ntohl(tcph->seq);
    std::cout << "\tack : " << ntohl(tcph->ack_seq) << std::endl;
    std::cout << "header length : " << (tcph->doff) * 4;
    std::cout << "\tURG : " << static_cast<unsigned short>(tcph->urg);
    std::cout << "\tACK : " << static_cast<unsigned short>(tcph->ack);
    std::cout << "\tPSH : " << static_cast<unsigned short>(tcph->psh);
    std::cout << "\tRST : " << static_cast<unsigned short>(tcph->rst);
    std::cout << "\tSYN : " << static_cast<unsigned short>(tcph->syn);
    std::cout << "\tFIN : " << static_cast<unsigned short>(tcph->fin);
    std::cout << "\twindow size : " << ntohs(tcph->window);
    std::cout << "\turgent pointer : " << tcph->urg_ptr << std::endl;
}
