//
// Created by asujy on 2026/1/15.
//

#ifndef MACHINE_H
#define MACHINE_H

#include <pcap.h>
#include <memory>
#include <cstring>

struct Machine_t {
    std::string m_device;
    std::uint32_t m_ip;
    std::unique_ptr<unsigned char[]> m_mac;
    unsigned short int m_port;
    pcap_t* m_handler;

    Machine_t() : m_ip(0), m_port(0), m_handler(nullptr) {}
    // 深拷贝
    Machine_t(const Machine_t& machine) : m_device(machine.m_device),
    m_ip(machine.m_ip), m_port(machine.m_port), m_handler(machine.m_handler) {
        if (machine.m_mac != nullptr) {
            m_mac = std::unique_ptr<unsigned char[]>(new unsigned char[6]);
            std::memcpy(m_mac.get(), machine.m_mac.get(), 6);
        }
    }
    Machine_t& operator=(Machine_t other) {
        swap(*this, other);
        return *this;
    }
    friend void swap(Machine_t& lhs, Machine_t& rhs) noexcept {
        using std::swap;
        swap(lhs.m_device, rhs.m_device);
        swap(lhs.m_ip, rhs.m_ip);
        swap(lhs.m_mac, rhs.m_mac);
        swap(lhs.m_port, rhs.m_port);
        swap(lhs.m_handler, rhs.m_handler);
    }
    ~Machine_t() = default;
};

#endif //MACHINE_H
