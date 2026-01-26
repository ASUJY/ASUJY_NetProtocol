//
// Created by asujy on 2026/1/26.
//

#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <thread>
#include <list>
#include "threadUtils/Semaphore.h"

template <typename T>
class ThreadPool {
public:
    ThreadPool(int threadNumber = 8, int maxQueueSize = 10000);

    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    ~ThreadPool();

    bool Append(std::unique_ptr<T> request);
private:
    static void* Worker(ThreadPool *pool);
    void Run();
private:
    int m_threadNumber{0};
    std::vector<std::thread> m_threads;

    std::list<std::unique_ptr<T>> m_pendQueue;  // 待处理队列
    int m_maxQueueSize;         // 最大待处理数量
    std::mutex m_queueLocker;   // 队列锁
    Semaphore m_queueStat;      // 信号量
    std::atomic<bool> m_stop{false};
};

template <typename T>
ThreadPool<T>::ThreadPool(int threadNumber, int maxQueueSize) :
    m_threadNumber(threadNumber), m_maxQueueSize(maxQueueSize), m_queueStat(0) {
    if (m_threadNumber <= 0 || m_maxQueueSize <= 0) {
        LOG_ERROR << "Threadpool constructor: threadNumber and "
                     "maxQueueSize must be positive";
        std::exit(EXIT_FAILURE);
    }

    m_threads.reserve(m_threadNumber);
    for (int i = 0; i < m_threadNumber; ++i) {
        try {
            m_threads.emplace_back(Worker, this);
            m_threads.back().detach();
            LOG_DEBUG << "create the " << i << "th thread";
        } catch (const std::exception& e) {
            throw std::runtime_error(
                std::string("create thread failed: ") + e.what());
        }
    }
}

template <typename T>
ThreadPool<T>::~ThreadPool() {
    m_stop.store(true);
    for (int i = 0; i < m_threadNumber; ++i) {
        m_queueStat.Post();
    }
    std::lock_guard<std::mutex> locker(m_queueLocker);
    if (!m_pendQueue.empty()) {
        LOG_ERROR << "threadpool destroyed with" << m_pendQueue.size()
                    << " unprocessed tasks";
    }
}

template <typename T>
bool ThreadPool<T>::Append(std::unique_ptr<T> request) {
    if (request == nullptr) {
        LOG_ERROR << "ThreadPool::Append(): append null task to threadpool!!!";
        return false;
    }
    std::lock_guard<std::mutex> locker(m_queueLocker);
    if (static_cast<int>(m_pendQueue.size()) >= m_maxQueueSize) {
        LOG_WARN << "ThreadPool::Append(): threadpool task queue "
                    "is full (append failed)!!!";
        return false;
    }
    m_pendQueue.emplace_back(std::move(request));
    m_queueStat.Post();
    return true;
}

template <typename T>
void* ThreadPool<T>::Worker(ThreadPool* pool) {
    if (pool == nullptr) {
        return nullptr;
    }
    pool->Run();
    return pool;
}

template <typename T>
void ThreadPool<T>::Run() {
    while (!m_stop.load() || !m_pendQueue.empty()) {
        m_queueStat.Wait();
        std::unique_lock<std::mutex> locker(m_queueLocker);
        if (m_pendQueue.empty()) {
            continue;
        }

        std::unique_ptr<T> request = std::move(m_pendQueue.front());
        m_pendQueue.pop_front();
        if (request != nullptr) {
            request->Process();
        }
    }
}


#endif //THREADPOOL_H
