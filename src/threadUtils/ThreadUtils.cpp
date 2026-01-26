//
// Created by asujy on 2026/1/17.
//

#include "threadUtils/ThreadUtils.h"
#include "protocol/Protocol.h"
#include "protocol/TCPPacket.h"
#include "protocol/ARPPacket.h"
#include "protocol/ICMPPacket.h"
#include "Utils/Utils.h"

#include <thread>

void Worker(Machine_t &localMachine, Machine_t &targetMachine, std::string protocolType) {
    if (protocolType == "arp") {
        Protocol<ARPPacket, arp_header_t> arpProt;
        arpProt.SendProtocolPacket(localMachine, targetMachine);
    } else if (protocolType == "icmp") {
        std::string targetIP(IPv4ToStr(targetMachine.m_ip));
        auto iter = ARPPacket::m_resultSet.find(IPv4ToStr(targetMachine.m_ip));
        while (iter == ARPPacket::m_resultSet.end() ||
            (iter->second[1].compare("00:00:00:00:00:00") == 0)) {
            Protocol<ARPPacket, arp_header_t> arpProt;
            arpProt.SendProtocolPacket(localMachine, targetMachine);
            std::this_thread::sleep_for(std::chrono::seconds(5));
            iter = ARPPacket::m_resultSet.find(IPv4ToStr(targetMachine.m_ip));
        }
        targetMachine.m_mac = StrToMac(iter->second[1]);

        Protocol<ICMPPacket, icmp_header_t> icmpProt;
        icmpProt.SendProtocolPacket(localMachine, targetMachine);
    } else if (protocolType == "tcp") {
        std::string targetIP(IPv4ToStr(targetMachine.m_ip));
        auto iter = ARPPacket::m_resultSet.find(IPv4ToStr(targetMachine.m_ip));
        while (iter == ARPPacket::m_resultSet.end() ||
            (iter->second[1].compare("00:00:00:00:00:00") == 0)) {
            Protocol<ARPPacket, arp_header_t> arpProt;
            arpProt.SendProtocolPacket(localMachine, targetMachine);
            std::this_thread::sleep_for(std::chrono::seconds(5));
            iter = ARPPacket::m_resultSet.find(IPv4ToStr(targetMachine.m_ip));
        }
        targetMachine.m_mac = StrToMac(iter->second[1]);

        Protocol<TCPPacket, tcp_header_t> tcpProt;
        tcpProt.SetFlag(TCP_SYN);
        tcpProt.SetSeqNum(rand());
        tcpProt.SetAckNum(0);
        tcpProt.SendProtocolPacket(localMachine, targetMachine);
    }
}