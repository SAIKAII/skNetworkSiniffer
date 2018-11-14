#include "util.hpp"

std::map<unsigned short, std::string> kProtocol;
bool open_log = false;

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

bool throw_away_the_packet(const std::shared_ptr<rc_buffer> buffer, rc_option &opt, int tail_index){
    bool throw_ip, throw_port;
    throw_ip = throw_port = true;
    unsigned char *pack_buffer = (buffer.get() + tail_index)->buffer;
    const iphdr *buffer_ip = reinterpret_cast<const iphdr *>(pack_buffer + 6 + 6 + 2);
    const tcphdr *buffer_tcp = reinterpret_cast<const tcphdr *>(pack_buffer + 6 + 6 + 2
                + (static_cast<unsigned short>(buffer_ip->ihl * 4)));

    if(opt.ip.s_addr == 0 || (opt.ip.s_addr != 0 && (opt.ip.s_addr == buffer_ip->saddr || opt.ip.s_addr == buffer_ip->daddr))){
        throw_ip = false;
    }
    if(opt.port == 0 || (opt.port != 0 && (opt.port == buffer_tcp->source || opt.port == buffer_tcp->dest))){
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
        case ICMP:
            polymorphism = new SnifferICMP(buffer);
            break;
        default:
            polymorphism = new SnifferIP(buffer);
    }

    return polymorphism;
}

void process_packet(std::shared_ptr<rc_buffer> buffer, int size, int &head_index){
    SnifferEth *prot_ptr = judge_protocol_and_return_obj((buffer.get() + head_index)->buffer);

    if(nullptr == prot_ptr){
        std::cout << "wrong datagram!" << std::endl;
        return;
    }

    prot_ptr->display_header(std::cout);
    std::cout << std::endl;
    // 写到log文件
    if(open_log){
        std::ofstream os("./log_file.dat", std::ofstream::out | std::ofstream::app | std::ofstream::ate);
        prot_ptr->display_header(os);
        os << std::endl;
        os.close();
    }

    delete prot_ptr;
    ++head_index;
    // ...
}
