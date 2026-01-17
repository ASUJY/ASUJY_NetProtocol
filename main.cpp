//
// Created by asujy on 2026/1/15.
//

#include <string>
#include <netinet/ip.h>

#include "machine.h"
#include "Utils.h"
#include "log/Logger.h"
#include "handler/PacketHandler.h"
#include "db/MySQLManager.h"

static void PcapDeleter(pcap_t* ptr) {
    if (ptr != nullptr) {
        pcap_close(ptr);
    }
}

int main()
{
    Logger::Config("NetProtocol.log");
    Machine_t localMachine;
    localMachine.m_device = GetNetDev(0);
    localMachine.m_ip = GetLocalIP(localMachine.m_device.c_str());
    localMachine.m_mac = GetLocalMac(localMachine.m_device.c_str());
    LOG_INFO << "NetWork Card Name: " << localMachine.m_device;
    PrintIP("LOCAL IP: ", localMachine.m_ip);
    PrintMac("LOCAL MAC: ", localMachine.m_mac.get());

    // 打开网络设备
    char errBuf[PCAP_ERRBUF_SIZE] = {0};
    auto handlerRaw =
        pcap_open_live(localMachine.m_device.c_str(), BUFSIZ, 1, 1000, errBuf);
    if (handlerRaw == nullptr) {
        LOG_ERROR << "Couldn't open device '" << localMachine.m_device
                  << "' - " << errBuf;
        return EXIT_FAILURE;
    }

    // 抓包处理
    std::unique_ptr<pcap_t, decltype(PcapDeleter)*> handler(handlerRaw, PcapDeleter);
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