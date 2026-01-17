//
// Created by asujy on 2026/1/17.
//

#include "threadUtils/ThreadUtils.h"
#include "protocol/Protocol.h"
#include "protocol/ARPPacket.h"

void Worker(uint32_t ip) {
    Protocol<ARPPacket, arp_header_t> arpProt;
    arpProt.SetTargetIP(ip);
    arpProt.SendProtocolPacket();
}