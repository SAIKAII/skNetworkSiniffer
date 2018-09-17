#ifndef SKNETWORKSNIFFER_NETWORK_PACKET_HPP_
#define SKNETWORKSNIFFER_NETWORK_PACKET_HPP_


typedef struct TCPHeader{
    unsigned short source_port;
    unsigned short destination_port;
    unsigned int seq;
    unsigned int ack;
    unsigned char header_len;
    unsigned char control_bits;
    unsigned short win_size;
    unsigned short checksum;
    unsigned short urgent_ptr;
}TCPHeader;
#define ACK 0x10
#define SYN 0x02
#define FIN 0x01

typedef struct UDPHeader{
    unsigned short source_port;
    unsigned short destination_port;
    unsigned short total_len;
    unsigned short checksum;
}UDPHeader;

typedef struct IPHeader{
    unsigned char ver_and_header_len;
    unsigned char service_type;
    unsigned short total_len;
    unsigned short identification;
    unsigned short flags_and_offset;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short header_checksum;
    unsigned int source_ip;
    unsigned int destination_ip;
}IPHeader;
#define IP_VER(ver) ver&0x0f
#define IP_HEADER_LEN(len) len>>4

typedef struct EthernetFrameHeader{
    unsigned char destination_mac[6];
    unsigned char source_mac[6];
    unsigned short ethernet_len;
}EthernetFrameHeader;

#endif
