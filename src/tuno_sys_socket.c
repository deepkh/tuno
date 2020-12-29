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
#include <libtuno/tuno_sys_socket.h>

static void tuno_sys_socket_library_ssl_init() {
  SSL_library_init();
  ERR_load_crypto_strings();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
}

#if defined(__WIN32__) || defined(_WIN32)
#ifndef IMN_PIM
#define WS_VERSION_CHOICE1 0x202/*MAKEWORD(2,2)*/
#define WS_VERSION_CHOICE2 0x101/*MAKEWORD(1,1)*/
int tuno_sys_socket_init(void) {
    /* We need to call an initialization routine before
        * we can do anything with winsock.  (How fucking lame!):
        */
    static int _haveInitializedWinsock = 0;
    WSADATA wsadata;

    if (!_haveInitializedWinsock) {
        
        if ((WSAStartup(WS_VERSION_CHOICE1, &wsadata) != 0)
            && ((WSAStartup(WS_VERSION_CHOICE2, &wsadata)) != 0)) {
            tunosetmsg("failed to WSAStartup");
            goto error; /* error in initialization */
        }
        
        if ((wsadata.wVersion != WS_VERSION_CHOICE1)
                && (wsadata.wVersion != WS_VERSION_CHOICE2)) {
            WSACleanup();
            tunosetmsg("failed to WSAStartup: version not equaled");
            goto error; /* desired Winsock version was not available */
        }

        _haveInitializedWinsock = 1;
    }

    tuno_sys_socket_library_ssl_init();
    return 0;
error:
    return -1;
}
#else
int tuno_sys_socket_init(void) { 
    tuno_sys_socket_library_ssl_init();
    return 0; 
}
#endif
#else
int tuno_sys_socket_init(void) {
    tuno_sys_socket_library_ssl_init();
    return 0;
}
#endif

int tuno_sys_socket_address_set_url(char *address, int port, char *url)
{
  if (port == 554 || port == 80 || port == 443) {
    sprintf(url, "%s", address);
  } else {
    sprintf(url, "%s:%d", address, port);
  }
  return 0;
}

int tuno_sys_socket_get_address_port(int skfd, int is_peer, char *address, int size, int *port)
{
  struct sockaddr_storage addr;
  socklen_t len = sizeof(addr);

  if (is_peer == 0) {
    if (getsockname(skfd, (struct sockaddr *) &addr, &len)) {
      tunosetmsg("failed to getsockname");
      return -1;
    }
  } else {
    if (getpeername(skfd, (struct sockaddr *) &addr, &len)) {
      tunosetmsg("failed to getpeearname");
      return -1;
    }
  }

  if (addr.ss_family == AF_INET) {
    struct sockaddr_in *s = (struct sockaddr_in *)&addr;
    inet_ntop(AF_INET, &s->sin_addr, address, size);
    
    if (port) {
      *port = ntohs(s->sin_port);
    }
  } else { // AF_INET6
    struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
    inet_ntop(AF_INET6, &s->sin6_addr, address, size);
    
    if (port) {
      *port = ntohs(s->sin6_port);
    }
    //check if is ipv4 mapped address
    /*if (strncmp(p->ipaddr, "::ffff:", 7) == 0) {
      p->is_ipv4mapped_6 = 1;
      sprintf(tmp, "%s", p->ipaddr+7);
      sprintf(p->ipaddr, "%s", tmp);
      p->addr = ntohl(inet_addr(p->ipaddr));
    }*/
  }

  return 0;
}

int tuno_sys_socket_errorno()
{
#if defined(__WIN32__) || defined(_WIN32) || defined(_WIN32_WCE)
  return WSAGetLastError();
#else
  return errno;
#endif
}

int tuno_sys_socket_make_reusable(int skfd)
{
#ifndef WIN32
  /* REUSEADDR on Unix means, "don't hang on to this address after the
   * listener is closed."  On Windows, though, it means "don't keep other
   * processes from binding to this address while we're using it. */
  int reuseFlag = 1;

  if (setsockopt(skfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuseFlag, sizeof(reuseFlag)) < 0) {
    tunosetmsg("failed to set SO_REUSEADDR %d", tuno_sys_socket_errorno());
    return -1;
  }
#endif

#ifdef SO_REUSEPORT
  reuseFlag = 1;
  if (setsockopt(skfd, SOL_SOCKET, SO_REUSEPORT,(const char*)&reuseFlag, sizeof(reuseFlag)) < 0) {
    tunosetmsg("failed to set SO_REUSEPORT %d", tuno_sys_socket_errorno());
    return -1;
  }
#endif
  return 0;
}

int tuno_sys_socket_make_closeonexec(int skfd)
{
#if !defined(WIN32) /*&& defined(_EVENT_HAVE_SETFD)*/
  int flags;
  if ((flags = fcntl(skfd, F_GETFD, NULL)) < 0) {
    tunosetmsg("fcntl(%d, F_GETFD)", skfd);
    return -1;
  }
  if (fcntl(skfd, F_SETFD, flags | FD_CLOEXEC) == -1) {
    tunosetmsg("fcntl(%d, F_SETFD)", skfd);
    return -1;
  }
#endif
  return 0;
}

int tuno_sys_socket_make_nonblock(int skfd, int nonblock)
{
#if defined(__WIN32__) || defined(_WIN32)
  unsigned long arg = (unsigned long) nonblock;
  return ioctlsocket(skfd, FIONBIO, &arg) == 0;
#elif defined(VXWORKS)
  int arg = nonblock;
  return ioctl(skfd, FIONBIO, (int)&arg) == 0;
#else
  int curFlags = fcntl(skfd, F_GETFL, 0);
  return fcntl(skfd, F_SETFL, nonblock ? curFlags | O_NONBLOCK : curFlags^O_NONBLOCK) >= 0;
#endif
}

int tuno_sys_socket_make_nosigpipe(int skfd)
{
#ifdef __APPLE__
  int set = 1;
  setsockopt(skfd, SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int));
#endif
  return 0;
}

void tuno_sys_socket_close(int skfd) {
  if (skfd >= 0) {
#ifdef _FF_USE_SSL_
    //if (p->flow_tuno_sys_socket_type == FLOW_SOCKET_CLIENT) {
    //  SSL_shutdown (p->ssl_skfd);
    //}
#endif
#if defined(__WIN32__) || defined(_WIN32) || defined(_WIN32_WCE)
    shutdown(skfd, SB_BOTH);
#else
    shutdown(skfd, SHUT_RDWR);
#endif
    closeSocket(skfd);
  }
}



int tuno_sys_socket_connect(int skfd, char *host, int port, int is_ipv6)
{
  struct sockaddr_in6 addr_in;
  struct sockaddr_in *paddr_in = (struct sockaddr_in *) &addr_in;
  char *ip = NULL;
  int err;
  
  memset(&addr_in, 0, sizeof(addr_in));

  if ((ip = tuno_sys_socket_hostname_to_ip(host, is_ipv6 ? HOSTNAME_IPV6 : HOSTNAME_IPV4)) == NULL) {
    tunosetmsg2();
    goto error;
  }

  if (is_ipv6) {
    addr_in.sin6_family = AF_INET6;
    inet_pton(AF_INET6, ip, &addr_in.sin6_addr);
    addr_in.sin6_port = htons(port);
    addr_in.sin6_flowinfo = 0;
  } else {
    paddr_in->sin_family = AF_INET; 
    inet_pton(AF_INET, ip, &paddr_in->sin_addr);
    paddr_in->sin_port = htons(port);   
  }
  
  if (connect(skfd, (struct sockaddr*) &addr_in, is_ipv6 ? sizeof(addr_in) : sizeof(struct sockaddr_in))) {
    err = tuno_sys_socket_errorno();
    if (err == EINPROGRESS || err == EWOULDBLOCK) {
      // The connection is pending; we'll need to handle it later.  
      // Wait for our socket to be 'writable', or have an exception.
      
      //can't tunolog in the connect time, otherwise tunolog_server will dead lock
      tunolog("connect EWOULDBLOCK");
      goto finally;
    }
    fprintf(stderr, "failed to connect. %d\n", err);
    goto error;
  }

finally:
  return 0;
error:
  return -1;
}


int tuno_sys_socket_show_ip_list(const char *hostname)
{
  struct addrinfo hints, *res, *p;
  int status;
  char ipstr[INET6_ADDRSTRLEN];

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6 for IPv4,IPv6 
  hints.ai_socktype = SOCK_STREAM;

  if ((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
    return 2;
  }

  printf("IP addresses for %s:\n\n", hostname);

  for(p = res;p != NULL; p = p->ai_next) {
    void *addr;
    const char *ipver;

    if (p->ai_family == AF_INET) { // IPv4
      struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
      addr = &(ipv4->sin_addr);
      ipver = "IPv4";
    } else {            // IPv6
      struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
      addr = &(ipv6->sin6_addr);
      ipver = "IPv6";
    }

    // convert the IP to a string and print it:
    inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
    printf(" %s: %s\n", ipver, ipstr);
  }

  freeaddrinfo(res);
  return 0;
}

char *tuno_sys_socket_hostname_to_ip(const char *hostname, int flag)
{
  struct addrinfo hints, *res = NULL, *p; 
  int ret = -1;
  char *ip = NULL;
  void *addr = NULL;
  
  if ((ip = (char *) malloc(INET6_ADDRSTRLEN+1)) == NULL) {
    tunosetmsg("failed to calloc %d", INET6_ADDRSTRLEN);
    goto finally;
  }
  
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6 for IPv4,IPv6 
  hints.ai_socktype = SOCK_STREAM;

  if ((ret = getaddrinfo(hostname, NULL, &hints, &res)) != 0) {
    tunosetmsg("failed to getaddrinfo: %s", gai_strerror(ret));
    goto finally;
  }

  ret = -1;
  
  for(p = res;p != NULL; p = p->ai_next) {
    if ((flag & HOSTNAME_IPV4) && p->ai_family == AF_INET) { // IPv4
      struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
      addr = &(ipv4->sin_addr);
    } else if ((flag & HOSTNAME_IPV6) && p->ai_family == AF_INET6) {            // IPv6
      struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
      addr = &(ipv6->sin6_addr);
    }

    if (addr) {
      // convert the IP to a string and print it:
      inet_ntop(p->ai_family, addr, ip, INET6_ADDRSTRLEN);
      ret = 0;      
      break;
    }
  }

finally:
  if (ret && ip) {
    free(ip);
    ip = NULL;
  }
  if (res) {
    freeaddrinfo(res);  
  }
  return ip;
}

static char errmsg[1024];

int tuno_sys_socket_ssl_connect(SSL *ssl)
{
  int ret;
  
  if ((ret = SSL_connect(ssl)) < 0) {
    if ((SSL_get_error(ssl, ret) == SSL_ERROR_WANT_READ 
      || SSL_get_error(ssl, ret) == SSL_ERROR_WANT_WRITE)) {
      //the SSL handshake not done yet
      //tunolog("ssl handshake not done yet");
      goto finally;
    }
    tunosetmsg("failed to SSL_Connect: '%s'", ERR_error_string(ERR_get_error(), errmsg));
    goto error;
  }
  
  return 1;
finally:
  return 0;
error:
  return -1;
}

int tuno_sys_socket_ssl_accept(SSL *ssl)
{
  int ret;
  
  if ((ret = SSL_accept(ssl)) < 0) {
    if ((SSL_get_error(ssl, ret) == SSL_ERROR_WANT_READ 
      || SSL_get_error(ssl, ret) == SSL_ERROR_WANT_WRITE)) {
      //the SSL handshake not done yet
      //tunolog("ssl handshake not done yet");
      goto finally;
    }
    tunosetmsg("failed to SSL_accept: '%s'", ERR_error_string(ERR_get_error(), errmsg));
    goto error;
  }
  
  return 1;
finally:
  return 0;
error:
  return -1;
}

