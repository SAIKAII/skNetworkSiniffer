#include "sniffer_icmp.hpp"

void SnifferICMP::display_header(std::ostream &out){
    SnifferIP::display_header(out);
    out << "----------ICMP : " << std::endl;
    out << "type : " << static_cast<unsigned short>(icmp->type);
    out << "\tcode : " << static_cast<unsigned short>(icmp->code) << std::endl;
    // ...
}
