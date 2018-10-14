#include "sniffer_tcp.hpp"

void SnifferTCP::display_header(std::ostream &out){
    SnifferIP::display_header(out);
    out << "----------TCP : " << std::endl;
    out << "source port : " << ntohs(tcph->source);
    out << "\tdestination port : " << ntohs(tcph->dest);
    out << "\tseq : " << ntohl(tcph->seq);
    out << "\tack : " << ntohl(tcph->ack_seq) << std::endl;
    out << "header length : " << (tcph->doff) * 4;
    out << "\tURG : " << static_cast<unsigned short>(tcph->urg);
    out << "\tACK : " << static_cast<unsigned short>(tcph->ack);
    out << "\tPSH : " << static_cast<unsigned short>(tcph->psh);
    out << "\tRST : " << static_cast<unsigned short>(tcph->rst);
    out << "\tSYN : " << static_cast<unsigned short>(tcph->syn);
    out << "\tFIN : " << static_cast<unsigned short>(tcph->fin);
    out << "\twindow size : " << ntohs(tcph->window);
    out << "\turgent pointer : " << tcph->urg_ptr << std::endl;
}
