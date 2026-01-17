//
// Created by asujy on 2026/1/15.
//

#include <string>
#include <netinet/ip.h>
#include <iostream>
#include <thread>

#include "machine.h"
#include "Utils.h"
#include "log/Logger.h"
#include "handler/PacketHandler.h"
#include "threadUtils/ThreadUtils.h"

Machine_t g_localMachine;

static void PcapDeleter(pcap_t* ptr) {
    if (ptr != nullptr) {
        pcap_close(ptr);
    }
}

int main(int argc, char* argv[])
{
    if (argc <= 1) {
        std::string filename = "programe";
        if (argc > 0 && argv[0]) {
            filename = argv[0];
            filename = GetBasename(filename);
        }
        std::cout << "Usage: " << filename << " IP Address!" << std::endl;
        std::exit(EXIT_FAILURE);
    }

    Logger::Config("NetProtocol.log");
    Machine_t targetMachine;
    targetMachine.m_ip = inet_addr(argv[1]);
    PrintIP("Target IP: ", targetMachine.m_ip);

    g_localMachine.m_device = GetNetDev(0);
    g_localMachine.m_ip = GetLocalIP(g_localMachine.m_device.c_str());
    g_localMachine.m_mac = GetLocalMac(g_localMachine.m_device.c_str());
    LOG_INFO << "NetWork Card Name: " << g_localMachine.m_device;
    PrintIP("LOCAL IP: ", g_localMachine.m_ip);
    PrintMac("LOCAL MAC: ", g_localMachine.m_mac.get());

    // 打开网络设备
    char errBuf[PCAP_ERRBUF_SIZE] = {0};
    g_localMachine.m_handler =
        pcap_open_live(g_localMachine.m_device.c_str(), BUFSIZ, 1, 1000, errBuf);
    if (g_localMachine.m_handler == nullptr) {
        LOG_ERROR << "Couldn't open device '" << g_localMachine.m_device
                  << "' - " << errBuf;
        return EXIT_FAILURE;
    }

    std::thread sendPacketThread(Worker, targetMachine.m_ip);
    sendPacketThread.detach();

    // 抓包处理
    std::unique_ptr<pcap_t, decltype(PcapDeleter)*>
        handler(g_localMachine.m_handler, PcapDeleter);
    int ret = pcap_loop(handler.get(), 0, PacketHandler, nullptr);
    if (ret == -1) {
        LOG_ERROR << "pcap_loop failed - " << pcap_geterr(handler.get());
        return EXIT_FAILURE;
    } else if (ret == -2) {
        LOG_ERROR << "pcap_loop was interrupted (normal exit).";
        return EXIT_FAILURE;
    }

    return 0;
}