//
// Created by asujy on 2026/1/26.
//

#include "Utils/CmdUtils.h"
#include "log/Logger.h"
#include <iostream>
#include <algorithm>

static void Usage(char* filename) {
    std::cout << "Usage: " << filename << " [--exec]=(monitor/sendpacket)"
        << "\n" << "--exec " << "\n\t" << "monitor: for network monitoring"
        << "\n\t" << "sendpacket: for send packet" << std::endl;
    std::cout << "--protocol: What type of network packet do you want to send, "
                 "an ARP packet, an ICMP packet, or a TCP packet?"
        << "\n\t arp: arp packet" << "\n\t icmp: icmp packet"
        << "\n\t tcp: tcp packet" << std::endl;
    std::cout << "--ip: target IP Address" << std::endl;
    std::cout << "--tp: target port" << std::endl;
    std::cout << "--lp: local port" << std::endl;
    std::cout << "--help: show the usage" << std::endl;
}

static struct option longOptions[] = {
    {"protocol", required_argument, nullptr, 'p'},
    {"ip", required_argument, nullptr, 'i'},
    {"tp", required_argument, nullptr, 'T'},
    {"lp", required_argument, nullptr, 'L'},
    {"exec", required_argument, nullptr, 'e'},
    {"help", no_argument, nullptr, 'h'},
    {0,0,0,0}
};

void CmdHandler(int argc, char* argv[], Option &option) {
    int c = -1;
    int optIndex = -1;
    while (1) {
        c = getopt_long(argc, argv, "e:p:i:T:L:", longOptions, &optIndex);
        if (c == -1) {
            break;
        }
        switch (c) {
        case 'e': {
            if (!optarg) {
                exit(EXIT_FAILURE);
            }
            std::string tmp(optarg);
            std::transform(tmp.begin(), tmp.end(), tmp.begin(), ::tolower);
            if (tmp.compare("monitor") == 0) {
                option.exec = 0;
            } else if (tmp.compare("sendpacket") == 0) {
                option.exec = 1;
            }
            break;
        }
        case 'p': {
            if (!optarg) {
                exit(EXIT_FAILURE);
            }
            std::string protocolType(optarg);
            std::transform(protocolType.begin(), protocolType.end(), protocolType.begin(), ::tolower);
            option.protocol = protocolType;
            break;
        }
        case 'i':
            if (!optarg) {
                exit(EXIT_FAILURE);
            }
            option.targetIp = optarg;
            break;
        case 'T':
            if (!optarg) {
                exit(EXIT_FAILURE);
            }
            option.targetPort = optarg;
            break;
        case 'L':
            if (!optarg) {
                exit(EXIT_FAILURE);
            }
            option.localPort = optarg;
            break;
        case 'h':
            Usage(argv[0]);
            break;
        case '?':
        default:
            LOG_WARN << "Unknown parameter !";
            break;
        }
    }
}