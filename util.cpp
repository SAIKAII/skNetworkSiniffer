#include "util.hpp"
#include "network_packet.hpp"

std::string mac_to_little_endian(const unsigned char (&v)[6]){
    std::string str_rtn;
    const unsigned char *mac = &v[5];

    for(int i = 0; i < 6; ++i){
        str_rtn += switch_to_hex(*mac);
        --mac;
        if(i != 5)
            str_rtn += ':';
    }

    return str_rtn;
}

std::string switch_to_hex(const char c){
    size_t front = (size_t)(c >> 4);
    size_t behind = (size_t)(c & 0x0f);
    return std::string(kHex[front]) + std::string(kHex[behind]);
}

bool throw_away_the_packet(const auto buffer, rc_option &opt, bool recv){
    bool throw_ip, throw_port;
    throw_ip = throw_port = true;
    const IPHeader *buffer_ip = buffer + 6 + 6 + 2;
    const TCPHeader *buffer_tcp = buffer + 6 + 6 + 2
                + (static_cast<unsigned short>(IP_HEADER_LEN(buffer_ip->ver_and_header_len))<<2);
    unsigned int ip = true == recv ? buffer_ip->source_ip : buffer_ip->destination_ip;
    unsigned short port = true == recv ? buffer_tcp->destination_port : buffer_tcp->source_port;

    if(opt.ip.s_addr == 0 || (opt.ip.s_addr != 0 && opt.ip.s_addr == ip)){
        throw_ip = false;
    }
    if(opt.port == 0 || (opt.port != 0 && opt.port == port)){
        throw_port = false;
    }
    return (throw_ip || throw_port);
}
