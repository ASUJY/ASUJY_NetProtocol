//
// Created by asujy on 2026/1/17.
//

#include "protocol/IPPacket.h"
#include "Utils.h"
#include "log/Logger.h"
#include <arpa/inet.h>

bool IPPacket::ParseProtocolHeader(const unsigned char *packet) {
    const ip_header_t* ip =
        reinterpret_cast<const ip_header_t*>(packet + sizeof(struct ip_header_t));
    m_header.version_ihl = ip->version_ihl;
    m_header.tos = ip->tos;
    m_header.total_length = ip->total_length;
    m_header.identification = ip->identification;
    m_header.flags_fragment = ip->flags_fragment;
    m_header.ttl = ip->ttl;
    m_header.protocol = ip->protocol;
    m_header.checksum = ip->checksum;
    m_header.src_ip = ip->src_ip;
    m_header.dst_ip = ip->dst_ip;
    PrintIPHeader();
    return true;
}

void IPPacket::PrintIPHeader() {
    Print2Hex("版本和头部长度: 0x", m_header.version_ihl);
    LOG_INFO << "服务类型: " << m_header.tos;
    LOG_INFO << "总长度: " << htons(m_header.total_length);
    Print4Hex("标识符: 0x", htons(m_header.identification));
    Print4Hex("标志和片偏移: 0x", htons(m_header.flags_fragment));
    LOG_INFO << "生存时间: " << m_header.ttl;
    Print2Hex("协议: 0x", m_header.protocol);
    Print4Hex("checksum: 0x", htons(m_header.checksum));
    PrintIP("src_ip: ", m_header.src_ip);
    PrintIP("dst_ip: ", m_header.dst_ip);
}

