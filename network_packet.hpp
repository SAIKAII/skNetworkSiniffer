#ifndef SKNETWORKSNIFFER_NETWORK_PACKET_HPP_
#define SKNETWORKSNIFFER_NETWORK_PACKET_HPP_

typedef struct EthernetFrameHeader{
    unsigned char destination_mac[6];
    unsigned char source_mac[6];
    unsigned short ethernet_len;
}EthernetFrameHeader;

#endif
