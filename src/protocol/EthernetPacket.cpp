//
// Created by asujy on 2026/1/15.
//

#include "protocol/EthernetPacket.h"
#include "log/Logger.h"
#include "Utils/Utils.h"

#include <iomanip>
#include <arpa/inet.h>

bool EthernetPacket::ParseProtocolHeader(const unsigned char* packet) {
    const ether_header_t* eHeader =
        reinterpret_cast<const ether_header_t*>(packet);
    if (eHeader == nullptr) {
        LOG_ERROR << "Error: ether_header pointer is null!";
        return false;
    }

    std::copy(eHeader->etherDHost,eHeader->etherDHost + ETH_ALEN,
        m_header.etherDHost);
    std::copy(eHeader->etherSHost,eHeader->etherSHost + ETH_ALEN,
        m_header.etherSHost);
    m_header.etherType = eHeader->etherType;
    // PrintMac("Destination MAC: ", m_header.etherDHost);
    // PrintMac("SOURCE MAC: ", m_header.etherSHost);
    // Print4Hex("protocol: 0x", m_header.etherType);
    return true;
}