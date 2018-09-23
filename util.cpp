#include "util.hpp"
#include "network_packet.hpp"

std::string mac_to_little_endian(const unsigned char (&v)[6]){
    std::string str_rtn;
    const unsigned char *mac = &v[0];

    for(int i = 0; i < 6; ++i){
        str_rtn += switch_to_hex(*mac);
        ++mac;
        if(i != 5)
            str_rtn += ':';
    }

    return str_rtn;
}

std::string switch_to_hex(const char c){
    size_t front = (size_t)((c >> 4) & 0x0f);
    size_t behind = (size_t)(c & 0x0f);
    return std::string(kHex[front]) + std::string(kHex[behind]);
}

bool throw_away_the_packet(const unsigned char *buffer, rc_option &opt, bool recv){
    bool throw_ip, throw_port;
    throw_ip = throw_port = true;
    const iphdr *buffer_ip = reinterpret_cast<const iphdr *>(buffer + 6 + 6 + 2);
    const tcphdr *buffer_tcp = reinterpret_cast<const tcphdr *>(buffer + 6 + 6 + 2
                + (static_cast<unsigned short>(buffer_ip->ihl * 4)));
    unsigned int ip = true == recv ? buffer_ip->saddr : buffer_ip->daddr;
    unsigned short port = true == recv ? buffer_tcp->dest : buffer_tcp->source;

    if(opt.ip.s_addr == 0 || (opt.ip.s_addr != 0 && opt.ip.s_addr == ip)){
        throw_ip = false;
    }
    if(opt.port == 0 || (opt.port != 0 && opt.port == port)){
        throw_port = false;
    }
    return (throw_ip || throw_port);
}
