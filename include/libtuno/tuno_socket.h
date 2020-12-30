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
#ifndef _TUNO_SOCKET_H_
#define _TUNO_SOCKET_H_
#include <libtuno/tuno_sys_socket.h>

/***********************************************************
 * tuno buffer
 ***********************************************************/
typedef struct evbuffer tuno_buf;
#define tuno_buf_new evbuffer_new
#define tuno_buf_enable_locking(buf) evbuffer_enable_locking(buf)
#define tuno_buf_lock(buf) evbuffer_lock(buf)
#define tuno_buf_unlock(buf) evbuffer_unlock(buf)
#define tuno_buf_write(buf, data, size) evbuffer_add(buf, data, size)
#define tuno_buf_write_front(buf, data, size) evbuffer_prepend(buf, data, size)
#define tuno_buf_printf(buf,...) evbuffer_add_printf(buf, ##__VA_ARGS__)
#define tuno_buf_pullup(buf,size) evbuffer_pullup(buf, size)
#define tuno_buf_length(buf) evbuffer_get_length(buf)
#define tuno_buf_remove(buf, size) evbuffer_drain(buf, size)
#define tuno_buf_free(buf) evbuffer_free(buf)

struct tuno_socket;
struct tuno_protocol_func;

/***********************************************************
 * enum
 ***********************************************************/
enum {
  TUNO_STATUS_DONE      = 1,
  TUNO_STATUS_NOT_DONE    = 2,
  TUNO_STATUS_NOT_DONE_WAIT   = 3,
  TUNO_STATUS_ERROR       = -1,
};

enum {
  TUNO_SOCKET_FLAG_CLIENT   = 1,
  TUNO_SOCKET_FLAG_SERVER   = 2,
  TUNO_SOCKET_FLAG_SSL    = 4,
  TUNO_SOCKET_FLAG_IPV6     = 8,
  TUNO_SOCKET_FLAG_SSL_CONNECTED  = 16,
};

enum {
  TUNO_ERROR_NONE       = 0,
  TUNO_ERROR_READING      = 32,
  TUNO_ERROR_WRITING      = 64,
  TUNO_ERROR_ERROR      = 128,
  TUNO_ERROR_TIMEOUT      = 256,
  TUNO_ERROR_SYSTEM       = 512,
};

enum {
  TUNO_SOCKET_ENABLE_READ   = 1,
  TUNO_SOCKET_ENABLE_WRITE  = 2,
};

/***********************************************************
 * protocol
 ***********************************************************/
struct tuno_protocol {
  struct tuno_protocol_func *func;
  void *inst;
  void *lparam;
  void *rparam;
};

struct tuno_protocol_func {
  int (*open)(struct tuno_protocol *fp);
  int (*close)(struct tuno_protocol *fp);

  /* protocol init, read, write, finish */
  int (*init)(struct tuno_socket *sk);
  int (*read)(struct tuno_socket *sk);
  int (*write)(struct tuno_socket *sk);
  int (*finish)(struct tuno_socket *sk, int error);
};

struct tuno_socket_inst {
};


/***********************************************************
 * socket
 ***********************************************************/

typedef void (*tuno_socket_notify_cb)(struct tuno_socket *sk, void *lparam, void *rparam);

struct tuno_socket;

struct tuno_socket_write_notify {
  struct tuno_socket *sk;
  struct event *ev_timeout;
  struct timeval tm;
  
  int type;
  tuno_socket_notify_cb cb;
  void *lparam;
  void *rparam;
  TAILQ_ENTRY(tuno_socket_write_notify) next;
};
TAILQ_HEAD(tuno_socket_write_notify_list, tuno_socket_write_notify);

struct tuno_socket_address {
  char local_address[INET6_ADDRSTRLEN];       //127.0.0.1
  int local_port;                   //554
  char local_url[INET6_ADDRSTRLEN+6];         //127.0.0.1:554
  
  char peer_address[INET6_ADDRSTRLEN];        //127.0.0.1
  int peer_port;                    //554
  char peer_url[INET6_ADDRSTRLEN+6];          //127.0.0.1:554
};

struct tuno_socket {
  struct event *ev_connect;             //for client
  struct bufferevent *bev;
  struct tuno_socket_address addr;
  int flag;

  SSL *ssl;                     //for ssl
  SSL_CTX *ssl_ctx;                 //ssl ctx
  const char *ssl_ca_cert_file;      //for client 
  const char *ssl_verify_hostname;//for client
  
  tuno_buf *rbuf;                   //always for caching read buffer
  tuno_buf *wbuf;                   //always for caching read buffer

  int64_t br;
  int64_t bw;

  struct tuno_socket_write_notify_list notify_list;

  /* protocol */
  struct tuno_protocol *protocol; 

  /* socket's parameters */
  void *inst;
  void *lparam;
  void *rparam;
};

struct tuno_listener {  
  struct tuno_protocol *protocol;
  struct evconnlistener *ev_listener;
  struct evdns_base *ev_dns;
  int flag;
  struct timeval *timeout;
  const char *private_key;
  const char *public_key;
  void *lparam;
  void *rparam;
};

struct tuno_socket *tuno_socket_new(
  struct event_base *ev_base
  , struct evdns_base *ev_dns
  , evutil_socket_t fd
  , int flag);


int tuno_socket_free(struct tuno_socket *sk);
int tuno_socket_delay_free(struct tuno_socket *sk);
int tuno_socket_enable(struct tuno_socket *sk, int mode);
int tuno_socket_enable_writecb(struct tuno_socket *sk);
int tuno_socket_disable_writecb(struct tuno_socket *sk);
int tuno_socket_write(struct tuno_socket *sk, uint8_t *buf, int size);
int tuno_socket_flush(struct tuno_socket *sk);
#define tuno_socket_write_output_printf(sk, ...) evbuffer_add_printf(bufferevent_get_output(sk->bev), ##__VA_ARGS__)
//int tuno_socket_input_length(struct tuno_socket *sk);
int tuno_socket_read_to_buf(struct tuno_socket *sk, tuno_buf *buf);
int tuno_socket_write_from_buf(struct tuno_socket *sk, tuno_buf *buf);
int tuno_socket_buf_to_buf(tuno_buf *src, tuno_buf *dst);
int tuno_socket_is_ssl(struct tuno_socket *sk);
int tuno_socket_is_ssl_connected(struct tuno_socket *sk);
int tuno_socket_is_ipv6(struct tuno_socket *sk);
int tuno_socket_is_client(struct tuno_socket *sk);
int tuno_socket_is_server(struct tuno_socket *sk);
void tuno_socket_print_ev_count(struct event_base *base, char *label);

#define tuno_socket_rbuf_length(sk) tuno_buf_length(sk->rbuf)
#define tuno_socket_rbuf_write(sk, buf, size) tuno_buf_write(sk->rbuf, buf, size)
#define tuno_socket_rbuf_printf(sk, ...) tuno_buf_printf(sk->rbuf, ##__VA_ARGS__)
#define tuno_socket_rbuf_pullup(sk, size) tuno_buf_pullup(sk->rbuf, size)
#define tuno_socket_rbuf_remove(sk, size) tuno_buf_remove(sk->rbuf, size)

#define tuno_socket_wbuf_length(sk) tuno_buf_length(sk->wbuf)
#define tuno_socket_wbuf_write(sk, buf, size) tuno_buf_write(sk->wbuf, buf, size)
#define tuno_socket_wbuf_printf(sk, ...) tuno_buf_printf(sk->wbuf, ##__VA_ARGS__)
#define tuno_socket_wbuf_pullup(sk, size) tuno_buf_pullup(sk->wbuf, size)
#define tuno_socket_wbuf_remove(sk, size) tuno_buf_remove(sk->wbuf, size)

enum {
  TUNO_SOCKET_NOTIFY_WRITE = 0,
  TUNO_SOCKET_NOTIFY_CUSTOM = 1,
  TUNO_SOCKET_NOTIFY_READ = 2,
};

int tuno_socket_add_notify(struct tuno_socket *sk, int ms, int type, tuno_socket_notify_cb cb, void *lparam, void *wparam);
int tuno_socket_add_notify_write(struct tuno_socket *sk, int ms);
int tuno_socket_add_notify_read(struct tuno_socket *sk, int ms);
int tuno_socket_del_notify(struct tuno_socket_write_notify *p);

/* client connect (non-block) */
struct tuno_socket *tuno_socket_connect(
  struct tuno_protocol *protocol
  , struct event_base *ev_base
  , struct evdns_base *ev_dns
  , char *host, int port
  , int flag, struct timeval *timeout
  , void *lparam, void *rparam
  , const char *ssl_ca_cert_file
  , const char *ssl_verify_hostname);



/* server listener & accept (non-block) */
struct tuno_listener *tuno_listener_new(
  struct tuno_protocol *protocol
  , struct event_base *ev_base
  , struct evdns_base *ev_dns
  , const char *host, int port
  , int flag, struct timeval *timeout, const char *private_key, const char *public_key
  , void *lparam, void *rparam);
int tuno_listener_free(struct tuno_listener *listener);


#endif
