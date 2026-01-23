//
// Created by asujy on 2026/1/23.
//

#include <iostream>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <signal.h>

#define PORT 8080

void PrintClientInfo(struct sockaddr_in* p) {
    int port = htons(p->sin_port);

    char ip[16];
    memset(ip, 0, sizeof(ip));

    inet_ntop(AF_INET, &(p->sin_addr.s_addr), ip, sizeof(ip));

    std::cout << "client connected: " << ip << "(" << port << ")" << std::endl;
}

int main() {
    std::cout << "服务器启动......" << std::endl;
    // 创建socket
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in saddr;
    saddr.sin_port = htons(8080);
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;

    // 端口复用
    int optval = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

    // 绑定
    bind(lfd, (struct sockaddr *)&saddr, sizeof(saddr));
    // 监听
    listen(lfd, 8);

    // 创建一个epoll实例
    int epfd = epoll_create(100);
    // 将监听的文件描述符相关的检测信息添加到epoll实例中
    struct epoll_event epev;
    epev.events = EPOLLIN;
    epev.data.fd = lfd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, lfd, &epev);

    struct epoll_event epevs[1024];

    while(1) {
        int ret = epoll_wait(epfd, epevs, 1024, -1);
        if(ret == -1) {
            perror("epoll_wait");
            exit(-1);
        }

        printf("ret = %d\n", ret);
        for(int i = 0; i < ret; i++) {
            int curfd = epevs[i].data.fd;
            if(curfd == lfd) {
                // 监听的文件描述符有数据达到，有客户端连接
                struct sockaddr_in cliaddr;
                int len = sizeof(cliaddr);
                int cfd =
                    accept(lfd, (struct sockaddr *)&cliaddr, reinterpret_cast<socklen_t*>(&len));
                PrintClientInfo(&cliaddr);
                epev.events = EPOLLIN | EPOLLET;    // 设置边沿触发
                epev.data.fd = cfd;
                epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &epev);
            } else if (epevs[i].events & EPOLLIN) {

                // 有数据到达，需要通信
                char buf[1024] = {0};
                int len = read(curfd, buf, sizeof(buf));
                if(len == -1) {
                    perror("read");
                    exit(-1);
                } else if(len == 0) {
                    std::cout << "client closed..." << std::endl;
                    epoll_ctl(epfd, EPOLL_CTL_DEL, curfd, NULL);
                    close(curfd);
                } else if(len > 0) {
                    std::cout << "read buf = " <<  buf << std::endl;
                    write(curfd, buf, strlen(buf) + 1);
                }
            } else if(epevs[i].events & EPOLLOUT) {
                std::cout << "[Info]发生写事件" << std::endl;
            } else {
                std::cout << "[ERROR]未知事件" << std::endl;
            }
        }
    }

    close(lfd);
    close(epfd);

    return 0;
}