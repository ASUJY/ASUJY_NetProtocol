//
// Created by asujy on 2026/1/17.
//

#include "protocol/IPPacket.h"
#include "Utils.h"
#include "log/Logger.h"
#include "protocol/EthernetPacket.h"
#include "protocol/ICMPPacket.h"

bool IPPacket::ParseProtocolHeader(const unsigned char *packet) {
    const ip_header_t* ip =
        reinterpret_cast<const ip_header_t*>(packet + sizeof(struct ether_header_t));
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

bool IPPacket::CreateProtocolHeader(
    const Machine_t &localMachine, const Machine_t &targetMachine) {
    m_header.version_ihl = 0x45;
    m_header.tos = 0;
    m_header.total_length = htons(sizeof(ip_header_t) +
        sizeof(icmp_header_t));
    m_header.identification = htons(1);
    m_header.flags_fragment = htons(0x4000);
    m_header.ttl = 64;
    m_header.protocol = 1;
    m_header.checksum = 0;
    m_header.src_ip = localMachine.m_ip;
    m_header.dst_ip = targetMachine.m_ip;
    m_header.checksum = IPChecksum(reinterpret_cast<uint16_t *>(&m_header),
        sizeof(ip_header_t));
    return true;
}

