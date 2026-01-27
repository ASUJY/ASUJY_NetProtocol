//
// Created by asujy on 2026/1/26.
//

#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <thread>
#include <list>
#include "threadUtils/Semaphore.h"
#include "log/Logger.h"

template  <typename T>
struct HasProcess {
private:
    // 匹配有Process的类类型
    template <typename U>
    static auto check(int)->decltype(std::declval<U>().Process(), std::true_type());
    // 匹配无Process()的类类型
    template <typename U>
    static std::false_type check(...);
public:
    static const bool value = decltype(check<T>(0))::value;
};

template <typename T>
class ThreadPool {
public:
    ThreadPool(int threadNumber = 8, int maxQueueSize = 10000);

    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;
    ThreadPool(ThreadPool&&) = delete;
    ThreadPool& operator=(ThreadPool&&) = delete;

    ~ThreadPool();

    bool Append(std::unique_ptr<T> request);
private:
    void Worker();
    void Run(std::unique_ptr<T> task);
private:
    int m_threadNumber{0};
    std::vector<std::thread> m_threads;

    std::list<std::unique_ptr<T>> m_pendQueue;  // 待处理队列
    int m_maxQueueSize{0};         // 最大待处理数量
    std::atomic<int> m_queueSize{0};
    std::mutex m_queueLocker;   // 队列锁
    Semaphore m_queueStat;      // 信号量
    std::atomic<bool> m_stop{false};
};

template <typename T>
ThreadPool<T>::ThreadPool(int threadNumber, int maxQueueSize) :
    m_threadNumber(threadNumber), m_maxQueueSize(maxQueueSize), m_queueStat(0) {
    static_assert(HasProcess<T>::value, "ThreadPool<T>: T must have "
                                        "a member function 'void Process()'");
    if (m_threadNumber <= 0 || m_maxQueueSize <= 0) {
        LOG_ERROR << "Threadpool constructor: threadNumber and "
                     "maxQueueSize must be positive";
        throw std::invalid_argument("ThreadPool constructor: threadNumber "
                                    "and maxQueueSize must be positive");
    }

    m_threads.reserve(m_threadNumber);
    try {
        for (int i = 0; i < m_threadNumber; ++i) {
            m_threads.emplace_back(&ThreadPool::Worker, this);
            LOG_DEBUG << "create the " << i << "th thread";
        }
    } catch (const std::exception& e) {
        LOG_ERROR << "create thread failed: " << e.what();
        m_stop.store(true);
        for (auto& t : m_threads) {
            if (t.joinable()) {
                t.join();
            }
        }
        throw std::runtime_error(
            std::string("create thread failed: ") + e.what());
    }
}

template <typename T>
ThreadPool<T>::~ThreadPool() {
    m_stop.store(true);
    for (int i = 0; i < m_threadNumber; ++i) {
        m_queueStat.Post();
    }
    for (auto& t : m_threads) {
        if (t.joinable()) {
            t.join();
            LOG_DEBUG << "worker thread joined successfully";
        }
    }

    std::lock_guard<std::mutex> locker(m_queueLocker);
    if (!m_pendQueue.empty()) {
        LOG_ERROR << "threadpool destroyed with" << m_pendQueue.size()
                    << " unprocessed tasks";
        m_pendQueue.clear();
        m_queueSize.store(0);
    }
}

template <typename T>
bool ThreadPool<T>::Append(std::unique_ptr<T> request) {
    if (!request) {
        LOG_ERROR << "ThreadPool::Append(): append null task to threadpool!!!";
        return false;
    }
    if (m_stop.load(std::memory_order_acquire)) {
        LOG_WARN << "ThreadPool::Append(): threadpool is stopped, append failed";
        return false;
    }

    std::lock_guard<std::mutex> locker(m_queueLocker);
    if (m_queueSize.load(std::memory_order_relaxed) >= m_maxQueueSize) {
        LOG_WARN << "ThreadPool::Append(): threadpool task queue "
                    "is full (append failed)!!!";
        return false;
    }
    m_pendQueue.emplace_back(std::move(request));
    m_queueSize.fetch_add(1, std::memory_order_relaxed);
    m_queueStat.Post();  // 唤醒一个工作线程
    return true;
}

template <typename T>
void ThreadPool<T>::Worker() {
    while (!m_stop.load(std::memory_order_acquire)) {
        m_queueStat.Wait(); // 等待任务
        std::unique_ptr<T> task;
        {
            std::lock_guard<std::mutex> locker(m_queueLocker);
            if (m_pendQueue.empty()) {
                if (m_stop.load(std::memory_order_acquire)) {
                    break;
                }
                continue;
            }
            task = std::move(m_pendQueue.front());
            m_pendQueue.pop_front();
            m_queueSize.fetch_sub(1, std::memory_order_relaxed);
        }
        if (task) {
            Run(std::move(task));
        }
    }
    LOG_DEBUG << "worker thread exit";
}

template <typename T>
void ThreadPool<T>::Run(std::unique_ptr<T> task) {
    try {
        task->Process();
    } catch (const std::exception& e) {
        LOG_ERROR << "Task Process() throw exception: " << e.what();
    } catch (...) {
        LOG_ERROR << "Task Process() throw unknown exception";
    }
}


#endif //THREADPOOL_H
