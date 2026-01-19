//
// Created by asujy on 2026/1/15.
//

#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <memory>
#include <netinet/ether.h>

std::string GetNetDev(int index);
std::uint32_t GetLocalIP(const char* name);
std::unique_ptr<unsigned char[]> GetLocalMac(const char* name);

void PrintMac(const char* msg, const unsigned char* mac);
void PrintIP(const char* msg, const struct in_addr ip);
void PrintIP(const char* msg, const std::uint32_t ip);
void PrintIP(const char* msg, const std::uint8_t ip[]);

void Print2Hex(const std::string msg, std::uint16_t hex);
void Print4Hex(const std::string msg, std::uint16_t hex);

std::string IPv4ToStr(const std::uint8_t ip[4]);
std::string IPv4ToStr(const uint32_t ip);
std::string MacToStr(const std::uint8_t mac[ETH_ALEN], const std::string& sep = ":");
std::unique_ptr<unsigned char[]> StrToMac(std::string mac, const char sep = ':');
std::string GetBasename(const std::string& path);

uint16_t IPChecksum(uint16_t *data, int length);

#endif //UTILS_H
