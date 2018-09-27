#include "util.hpp"

std::map<unsigned short, std::string> kProtocol;

void init(){
    kProtocol[1] = "ICMP";
    kProtocol[2] = "IGMP";
    kProtocol[4] = "IP";
    kProtocol[6] = "TCP";
    kProtocol[17] = "UDP";
}

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
    static std::unordered_map<unsigned short, repeated_filter> identification;
    bool throw_ip, throw_port;
    throw_ip = throw_port = true;
    const iphdr *buffer_ip = reinterpret_cast<const iphdr *>(buffer + 6 + 6 + 2);
    const tcphdr *buffer_tcp = reinterpret_cast<const tcphdr *>(buffer + 6 + 6 + 2
                + (static_cast<unsigned short>(buffer_ip->ihl * 4)));
    unsigned int ip = true == recv ? buffer_ip->saddr : buffer_ip->daddr;
    unsigned short port = true == recv ? buffer_tcp->dest : buffer_tcp->source;
    auto id_iter = identification.find(buffer_ip->id);
    repeated_filter rf;
    rf.mf = ntohs(buffer_ip->frag_off)&0x4;
    rf.frag_off = buffer_ip->frag_off;  // 这里没有使用ntohs，以后要注意

    // 判断是否已经读取过这个数据包
    // ***尚未完善，一段时间后要自动删除元素，不然后续循环使用曾被用过的标识时会出错
    if(id_iter != identification.end() && rf == id_iter->second){
        return true;
    }

    identification[buffer_ip->id] = rf;
    if(opt.ip.s_addr == 0 || (opt.ip.s_addr != 0 && opt.ip.s_addr == ip)){
        throw_ip = false;
    }
    if(opt.port == 0 || (opt.port != 0 && opt.port == port)){
        throw_port = false;
    }
    return (throw_ip || throw_port);
}

SnifferEth *judge_protocol_and_return_obj(unsigned char *buffer){
    // 获取网络层使用的协议
    unsigned short prot = SnifferEth(buffer).get_upper_level_protocol();
    SnifferEth *polymorphism = nullptr;

    switch (prot) {
        case ETH_P_IP:  // 这个定义在linux/if_ether.h文件中
            prot = SnifferIP(buffer).get_upper_level_protocol();
            break;
        default:
            prot = -1;
    }
    if(-1 == prot)
        return nullptr;

    switch (prot) {
        case TCP:
            polymorphism = new SnifferTCP(buffer);
            break;
        case UDP:
            polymorphism = new SnifferUDP(buffer);
            break;
        default:
            polymorphism = new SnifferIP(buffer);
    }

    return polymorphism;
}
