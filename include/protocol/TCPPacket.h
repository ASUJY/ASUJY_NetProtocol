//
// Created by asujy on 2026/1/19.
//

#ifndef TCPPACKET_H
#define TCPPACKET_H

#include "protocol/Protocol.h"
#include "protocol/EthernetPacket.h"
#include "log/Logger.h"

#define IP_PROTOCOL_TCP     6
#define TCP_SYN     0x02

// 伪包头（tcp、udp用）
struct pseudo_header_t{
    uint32_t src_addr;      // 源IP地址
    uint32_t dest_addr;     // 目的IP地址
    uint8_t  reserved;      // 保留字节，置0
    uint8_t  protocol;      // 协议号，常为6表示TCP协议
    uint16_t length;        // TCP头部长度
} __attribute__((packed));

struct tcp_header_t {
    std::uint16_t source_port{0};     // 源端口
    std::uint16_t dest_port{0};       // 目的端口
    std::uint32_t sequence_num{0};    // 序列号
    std::uint32_t ack_num{0};         // 确认号
    std::uint8_t data_offset{0};      // 数据偏移，指示TCP头部的长度
    std::uint8_t flags{0};            // 标识TCP头部的不同标志 0 0 URG ACK PSH RST SYN FIN
    std::uint16_t window_size{0};     // 窗口大小
    std::uint16_t checksum{0};        // 校验和
    std::uint16_t urgent_pointer{0};  // 紧急指针
} __attribute__((packed));

class TCPPacket {
public:
    TCPPacket() = default;
    TCPPacket(const TCPPacket&) = default;
    TCPPacket& operator=(const TCPPacket&) = default;
    TCPPacket(TCPPacket&&) = default;
    TCPPacket& operator=(TCPPacket&&) = default;
    ~TCPPacket() = default;

    bool SendProtocolPacket(
        const Machine_t &localMachine, const Machine_t &targetMachine);
    bool CreateProtocolHeader(
        const Machine_t &localMachine, const Machine_t &targetMachine,
        u_char* options, size_t optionsLen, char* str, size_t strLen);

    void SetFlag(uint8_t flag) {
        m_header.flags = flag;
    }
    void SetSeqNum(uint32_t num) {
        m_header.sequence_num = num;
    }
    void SetAckNum(uint32_t num) {
        m_header.ack_num = num;
    }
private:
    tcp_header_t m_header;
    pseudo_header_t m_pheader;
};

#endif //TCPPACKET_H
