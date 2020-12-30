/*
# Copyright (c) 2018, Gary Huang, deepkh@gmail.com, https://github.com/deepkh
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/


#ifndef _COMMON_H_
#define _COMMON_H_
#include <libtuno/tuno_log.h>

#if defined(__WIN32__) || defined(_WIN32) || defined(_WIN32_WCE)
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <errno.h>

typedef int socklen_t;

#define closeSocket closesocket
#ifdef EWOULDBLOCK
#undef EWOULDBLOCK
#endif
#ifdef EINPROGRESS
#undef EINPROGRESS
#endif
#ifdef EAGAIN
#undef EAGAIN
#endif
#ifdef EINTR
#undef EINTR
#endif

#define EALREADY2 WSAEALREADY
#define EWOULDBLOCK WSAEWOULDBLOCK
#define EINPROGRESS WSAEWOULDBLOCK
#define EAGAIN WSAEWOULDBLOCK
#define EINTR WSAEINTR

typedef uint64_t u_int64_t;
typedef uint32_t u_int32_t;
typedef uint16_t u_int16_t;
typedef uint8_t u_int8_t;

#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <net/if.h> 
#include <unistd.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>

#define closeSocket close
#endif

#include <sys/queue.h>

#include <event2/dns.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/event.h>
#include <event2/listener.h>

#include <openssl/rsa.h>       /* SSLeay stuff */
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifndef EALREADY2
#define EALREADY2 EALREADY
#endif

#ifndef SOCKLEN_T
#define SOCKLEN_T socklen_t
#endif

#ifdef HAVE_SOCKADDR_LEN
#define SET_SOCKADDR_SIN_LEN(var) var.sin_len = sizeof var
#else
#define SET_SOCKADDR_SIN_LEN(var)
#endif

#define MAKE_SOCKADDR_IN(var,adr,prt) /*adr,prt must be in network order*/\
    struct sockaddr_in var;\
    var.sin_family = AF_INET;\
    var.sin_addr.s_addr = (adr);\
    var.sin_port = (prt);\
  SET_SOCKADDR_SIN_LEN(var);

typedef void *hnd_t;

int tuno_sys_socket_init(void);
int tuno_sys_socket_address_set_url(char *address, int port, char *url);
int tuno_sys_socket_get_address_port(int skfd, int is_peer, char *address, int size, int *port);
int tuno_sys_socket_errorno();
int tuno_sys_socket_make_reusable(int skfd);
int tuno_sys_socket_make_closeonexec(int skfd);
int tuno_sys_socket_make_nonblock(int skfd, int nonblock);
int tuno_sys_socket_make_nosigpipe(int skfd);
int tuno_sys_socket_show_ip_list(const char *hostname);
void tuno_sys_socket_close(int skfd);    

#define HOSTNAME_IPV6 1
#define HOSTNAME_IPV4 2
char *tuno_sys_socket_hostname_to_ip(const char *hostname, int flag);
int tuno_sys_socket_connect(int skfd, char *host, int port, int is_ipv6);
int tuno_sys_socket_ssl_connect(SSL *ssl);
int tuno_sys_socket_ssl_accept(SSL *ssl);
int tuno_sys_socket_ssl_add_ca_cert_file(SSL_CTX *ssl_ctx, const char *ssl_ca_cert_file);
int tuno_sys_socket_ssl_cert_verify_results(SSL* ssl_skfd, const char *ssl_verify_hostname);

#endif
