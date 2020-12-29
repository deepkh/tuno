## C/C++ based async/non-block socket library by use libevent and openssl for linux and windows

Due to coding the client/server async/non-block socket program by use C/C++ is difficulty comapre to modern language like golang, python, rust,... But some legacy system or embbeded system or some system need high frequency still need low level C/C++ to build their system. 

This is a good start for who would like to understand how the async/non-block socket programming with SSL working by use C/C++.


## Features

* libtuno is written in C 
* Provide C++ wrapper for http client and http server in the sample code
* Based on [OpenSSL](https://www.openssl.org/) for SSL support  
* Based on [libevent](https://libevent.org/) for async/non-block architecture design 
* Use GNU/GCC (6.3.0 20170516) to build target for linux_x86-64 
* Use GNU/Mingw-W64_x86-64 (6.3.0 20170516) to build target for windows_x86-64

## Samples 

* HTTP Client
* HTTP Server
* TCP Reverse Proxy
* RTSP Reverse Proxy 

## Clone

```bash
git clone https://github.com/deepkh/tuno
git submodule update --init --recursive
```

## Build target platform linux_x86-64 on Debian/Ubuntu server

```bash
PF=linux source source.sh
make
```

## Build target platform x86_64-windows on Debian/Ubuntu server

```bash
PF=mingw.linux source source.sh
make
```

## Runtime structures

* runtime.[linux64,win64]/
  * bin/
    * http_client[.exe]
    * http_server[.exe]
    * rtsp_proxy[.exe]
    * tcp_proxy[.exe]
    * libevent-2-1-6.dll (win64 only)
    * libevent_core-2-1-6.dll (win64 only)
    * libevent_extra-2-1-6.dll (win64 only)
    * libevent_openssl-2-1-6.dll (win64 only)
    * libjsoncpp.dll (win64 only)
    * libtuno.dll (win64 only)
    * libssl-1_1-x64.dll (win64 only)
    * libcrypto-1_1-x64.dll (win64 only)
  * include/
  * lib/
    * libevent-2.1.so.6.0.2 (linux64 only)
    * libevent_core-2.1.so.6.0.2 (linux64 only)
    * libevent_extra-2.1.so.6.0.2 (linux64 only)
    * libevent_openssl-2.1.so.6.0.2 (linux64 only)
    * libevent_pthreads-2.1.so.6.0.2
    * libjsoncpp.so (linux64 only)
    * libtuno.so (linux64 only)
    * libssl.so.1.1 (linux64 only)
    * libcrypto.so.1.1 (linux64 only)
  * objs/
  * share/
