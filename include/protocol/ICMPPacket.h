//
// Created by asujy on 2026/1/19.
//

#ifndef ICMPPACKET_H
#define ICMPPACKET_H

#include <string>

struct icmp_header_t{
    uint8_t  type;           // 类型
    uint8_t  code;           // 代码
    uint16_t checksum;       // 校验和
    uint16_t identifier;     // 标识符
    uint16_t sequence_num;   // 序列号
} __attribute__((packed));

class ICMPPacket {
public:
    ICMPPacket() = default;
    ICMPPacket(const ICMPPacket&) = default;
    ICMPPacket& operator=(const ICMPPacket&) = default;
    ICMPPacket(ICMPPacket&&) = default;
    ICMPPacket& operator=(ICMPPacket&&) = default;
    ~ICMPPacket() = default;

    bool ParseProtocolHeader(const unsigned char* packet);
private:
    void PrintICMPHeader();
private:
    icmp_header_t m_header;
};

#endif //ICMPPACKET_H
