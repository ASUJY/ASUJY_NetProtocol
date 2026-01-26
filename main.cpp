//
// Created by asujy on 2026/1/15.
//

#include <string>
#include <netinet/ip.h>
#include <iostream>
#include <thread>

#include "machine.h"
#include "Utils/Utils.h"
#include "log/Logger.h"
#include "handler/PacketHandler.h"
#include "threadUtils/ThreadUtils.h"
#include "Utils/CmdUtils.h"

static void PcapDeleter(pcap_t* ptr) {
    if (ptr != nullptr) {
        pcap_close(ptr);
    }
}

int main(int argc, char* argv[])
{
    Logger::Config("NetProtocol.log");
    Option opt;
    CmdHandler(argc, argv, opt);
    if (opt.exec == 0) {

    } else if (opt.exec == 1) {
        Machine_t targetMachine;
        targetMachine.m_ip = inet_addr(opt.targetIp.c_str());
        PrintIP("Target IP: ", targetMachine.m_ip);
        Machine_t localMachine;
        localMachine.m_device = GetNetDev(0);
        localMachine.m_ip = GetLocalIP(localMachine.m_device.c_str());
        localMachine.m_mac = GetLocalMac(localMachine.m_device.c_str());
        if (opt.protocol == "tcp") {
            targetMachine.m_port = std::stoi(opt.targetPort);
            localMachine.m_port = std::stoi(opt.localPort);
        }
        LOG_INFO << "NetWork Card Name: " << localMachine.m_device;
        PrintIP("LOCAL IP: ", localMachine.m_ip);
        PrintMac("LOCAL MAC: ", localMachine.m_mac.get());

        // 打开网络设备
        char errBuf[PCAP_ERRBUF_SIZE] = {0};
        localMachine.m_handler =
            pcap_open_live(localMachine.m_device.c_str(), BUFSIZ, 1, 1000, errBuf);
        if (localMachine.m_handler == nullptr) {
            LOG_ERROR << "Couldn't open device '" << localMachine.m_device
                      << "' - " << errBuf;
            return EXIT_FAILURE;
        }

        std::thread sendPacketThread(Worker, std::ref(localMachine),
            std::ref(targetMachine), opt.protocol);
        sendPacketThread.detach();
        Machine_t machines[2];
        memcpy(&machines[0], &localMachine, sizeof(localMachine));
        memcpy(&machines[1], &targetMachine, sizeof(targetMachine));
        // 抓包处理
        std::unique_ptr<pcap_t, decltype(PcapDeleter)*>
            handler(localMachine.m_handler, PcapDeleter);
        int ret = pcap_loop(handler.get(), 0, PacketHandler,
            reinterpret_cast<u_char*>(machines));
        if (ret == -1) {
            LOG_ERROR << "pcap_loop failed - " << pcap_geterr(handler.get());
            return EXIT_FAILURE;
        } else if (ret == -2) {
            LOG_ERROR << "pcap_loop was interrupted (normal exit).";
            return EXIT_FAILURE;
        }
    }

    return 0;
}