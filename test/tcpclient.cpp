//
// Created by asujy on 2026/1/23.
//

#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string>
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc <= 2) {
        std::cout << "Usage: tcpclient" << " IPAddress "
                    << "Port" << std::endl;
        std::exit(EXIT_FAILURE);
    }
    // 创建socket
    int fd = socket(PF_INET, SOCK_STREAM, 0);
    if(fd == -1) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in seraddr;
    inet_pton(AF_INET, argv[1], &seraddr.sin_addr.s_addr);
    seraddr.sin_family = AF_INET;
    seraddr.sin_port = htons(std::stoi(argv[2]));

    // 连接服务器
    int ret = connect(fd, (struct sockaddr *)&seraddr, sizeof(seraddr));
    if(ret == -1){
        perror("connect");
        return -1;
    }

    int num = 0;
    while(1) {
        std::string data;
        std::cout << "发送的数据: ";
        std::cin >> data;
        auto writesize = write(fd, data.c_str(), data.size());
        std::cout << "writesize: " << writesize << std::endl;
        // 接收服务器数据
        char sendBuf[1024] = {0};
        int len = read(fd, sendBuf, sizeof(sendBuf));
        if(len == -1) {
            perror("read");
            return -1;
        }else if(len > 0) {
            std::cout << "read buf = %s\n" << sendBuf << std::endl;
        } else {
            std::cout << "服务器已经断开连接..." << std::endl;
            break;
        }
        sleep(1);
        usleep(1000);
    }

    close(fd);

    return 0;
}