//
// Created by asujy on 2026/1/15.
//

#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <memory>

#define ETHER_ADDR_LEN 6

std::string GetNetDev(int index);
std::uint32_t GetLocalIP(const char* name);
std::unique_ptr<unsigned char[]> GetLocalMac(const char* name);

#endif //UTILS_H
