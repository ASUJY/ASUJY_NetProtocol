//
// Created by asujy on 2026/1/17.
//

#ifndef IPPACKET_H
#define IPPACKET_H

#include <string>

struct ip_header_t {
    uint8_t  version_ihl;     // 版本和头部长度
    uint8_t  tos;             // 服务类型
    uint16_t total_length;    // 总长度
    uint16_t identification;  // 标识符
    uint16_t flags_fragment;  // 标志和片偏移
    uint8_t  ttl;             // 生存时间
    uint8_t  protocol;        // 协议
    uint16_t checksum;        // 校验和
    uint32_t src_ip;          // 源IP地址
    uint32_t dst_ip;          // 目的IP地址
} __attribute__((packed));

class IPPacket {
public:
    IPPacket() = default;
    IPPacket(const IPPacket&) = default;
    IPPacket& operator=(const IPPacket&) = default;
    IPPacket(IPPacket&&) = default;
    IPPacket& operator=(IPPacket&&) = default;
    ~IPPacket() = default;

    bool ParseProtocolHeader(const unsigned char* packet);

private:
    void PrintIPHeader();
private:
    ip_header_t m_header;
};

#endif //IPPACKET_H
