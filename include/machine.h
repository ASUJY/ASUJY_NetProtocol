//
// Created by asujy on 2026/1/15.
//

#ifndef MACHINE_H
#define MACHINE_H

#include <pcap.h>
#include <memory>

struct Machine_t {
    std::string m_device;
    std::uint32_t m_ip;
    std::unique_ptr<unsigned char[]> m_mac;
    unsigned short int m_port;
    pcap_t* m_handler;
};

#endif //MACHINE_H
