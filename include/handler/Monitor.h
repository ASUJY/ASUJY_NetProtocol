//
// Created by asujy on 2026/1/26.
//

#ifndef MONITOR_H
#define MONITOR_H

#include <atomic>

class Monitor {
public:
    Monitor() = default;
    ~Monitor() = default;
    void AddTraffic(uint64_t bytes, uint64_t packets);

    // 实时显示线程：每秒刷新一次数据
    static void DispTraffic();
private:
    static std::atomic<uint64_t> m_recvBytes;
    static std::atomic<uint64_t> m_recvPackets;
};

#endif //MONITOR_H
