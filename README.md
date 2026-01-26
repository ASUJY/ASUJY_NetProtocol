# ASUJY_NetProtocol

本项目聚焦于网络通信协议的实现。目前已实现 **`ARP协议`**，**`IP协议`**，**`ICMP协议`** 和 **`TCP协议`**。  
实现技术：c++11，cmake，mysql，libpcap


# 快速开始
```shell
apt install cmake
apt install mysql-server mysql-client libmysqlclient-dev
apt install libpcap-dev

git clone https://github.com/ASUJY/ASUJY_NetProtocol.git
cd ASUJY_NetProtocol
mkdir -p build && cd build
cmake ..
make

# 发送arp包
sudo ./NetProtocol --exec=sendpacket --ip=ip地址 --protocol=arp

# 发送icmp包
sudo ./NetProtocol --exec=sendpacket --ip=ip地址 --protocol=icmp

# 发送tcp包
# 先在另外一台机器中拉取ASUJY_NetProtocol代码并编译，然后其他服务器端代码
cd test && ./tcpserver

# 然后在本台机器中执行客户端代码
cd test && ./tcpclient 目的ip地址 目的端口号
sudo ./NetProtocol --exec=sendpacket --ip=目的ip地址 --protocol=tcp --tp=目的端口号 --lp=客户端端口号

```

# 模块说明
|    模块名称     |                     模块用途                      |
|:-----------:|:---------------------------------------------:|
|  protocol   |                 自定义协议包的封装和解包                  |
|     db      |                     数据库管理                     |
|     log     | 多级别日志（DEBUG/INFO/WARN/ERROR）、控制台 / 文件双输出、日志轮转 |
|   handler   |                  处理接收到的网络数据包                  |
| threadUtils |                    发送网络数据包                    |
|    Utils    |               工具类，字符串处理，字节序转换等                |

目录结构：
```
ASUJY_NetProtocol/
├── include/
│   ├── Utils.h               # 通用工具类接口（字符串、数据转换等）
│   ├── machine.h             # 设备/系统环境相关接口声明
│   ├── db/                   # 数据库模块接口（连接管理、CRUD 操作等）
│   ├── handler/              # 网络数据包解析接口
│   ├── log/                  # 日志模块接口（级别控制、输出策略等）
│   ├── protocol/             # 协议模块接口（协议封装、解析、校验等）
│   └── threadUtils/          # 网络数据包发送接口
├── src/
│   ├── Utils.cpp             # 通用工具类实现
│   ├── db/                   # 数据库模块实现（适配具体数据库驱动）
│   ├── handler/              # 解析网络数据包
│   ├── log/                  # 日志模块实现（日志输出、存储逻辑）
│   ├── protocol/             # 协议模块实现（自定义协议编解码）
│   └── threadUtils/          # 发送网络数据包
├── test/                     # 测试模块目录
│   ├── CMakeLists.txt
│   ├── tcpclient.cpp         # TCP 客户端测试用例（链路连通性、数据收发验证）
│   └── tcpserver.cpp         # TCP 服务端测试用例（连接监听、请求处理验证）
├── main.cpp                  # 程序入口
├── CMakeLists.txt
├── LICENSE 
└── README.md
```