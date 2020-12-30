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

extern "C" {
#include <libtuno/tuno_socket.h>
}

struct tcp_proxy_param {
    char *forward_host;
    int forward_port;
    int client_ssl;
    int server_ssl;
};


#if 0
static void dump(uint8_t *buf, int len)
{
  uint8_t *buf2 = malloc(len + 1);
  memcpy(buf2, buf, len);
  buf2[len] = 0;
  printf("%s\n", buf2);
  free(buf2);
}
#endif

/***********************************************************
 * tcp proxy client protocol
 ***********************************************************/

int tuno_protocol_tcp_proxy_client_open(struct tuno_protocol *fp)
{
  return 0;
}

int tuno_protocol_tcp_proxy_client_close(struct tuno_protocol *fp)
{
  return 0;
}

int tuno_protocol_tcp_proxy_client_init(struct tuno_socket *sk)
{
  //for first time writecb
  if (tuno_socket_add_notify_write(sk, 0)) {
    tunosetmsg2();
    goto error;
  }

  return 0;
error:
  return TUNO_STATUS_ERROR;
}

int tuno_protocol_tcp_proxy_client_read(struct tuno_socket *sk)
{
  struct tuno_socket *sk2 = (struct tuno_socket *) sk->inst;
  
  tunolog("%s %d", __func__, tuno_socket_rbuf_length(sk));

  //write client's rbuf to server's wbuf
  if (tuno_socket_buf_to_buf(sk->rbuf, sk2->wbuf)) {
    tunosetmsg2();
    goto error;
  }
  
  //notify server's notify
  if (tuno_socket_add_notify_write(sk2, 0)) {
    tunosetmsg2();
    goto error;
  }

  return 0;
error:
  return TUNO_STATUS_ERROR;
}

int tuno_protocol_tcp_proxy_client_write(struct tuno_socket *sk)
{
  tunolog("%s %d", __func__, tuno_socket_wbuf_length(sk));
  
  //write client's wbuf to client's socket
  if (tuno_socket_write_from_buf(sk, sk->wbuf)) {
    tunosetmsg2();
    goto error;
  }

  return 0;
error:
  return TUNO_STATUS_ERROR;
}

int tuno_protocol_tcp_proxy_client_finish(struct tuno_socket *sk, int error)
{
  struct tuno_socket *sk2 = (struct tuno_socket *) sk->inst;
  tunolog("%s", __func__);
  
  // the two func of ...proxy_client_finish ...proxy_server_finish only execution either
  // by who server close socket first or client close socket first
  if (sk2) {
    sk->inst = NULL;
    if (tuno_buf_length(sk2->wbuf) > 0) {
      sk2->protocol->func->write(sk2);
      tuno_socket_delay_free(sk2);
    } else {
      tuno_socket_free(sk2);
    }
  }
  return 0;
}

struct tuno_protocol_func tcp_proxy_client_func = {
  tuno_protocol_tcp_proxy_client_open, tuno_protocol_tcp_proxy_client_close,
  tuno_protocol_tcp_proxy_client_init, tuno_protocol_tcp_proxy_client_read, tuno_protocol_tcp_proxy_client_write, 
  tuno_protocol_tcp_proxy_client_finish
};


struct timeval timeout;


/***********************************************************
 * tcp proxy server protocol
 ***********************************************************/ 
int tuno_protocol_tcp_proxy_server_open(struct tuno_protocol *fp)
{
  struct tuno_protocol *fp2 = NULL;
  tunolog("%s", __func__);

  if ((fp2 = (tuno_protocol*) calloc(1, sizeof(struct tuno_protocol))) == NULL) {
    tunosetmsg("failed to calloc tuno_protocol");
    return -1;
  }

  timeout.tv_sec = 60;
  timeout.tv_usec = 0;  

  fp2->func = &tcp_proxy_client_func;
  fp2->lparam = fp->lparam;
  fp2->rparam = fp->rparam;

  if (fp2->func->open(fp2)) {
    tunosetmsg2();
    goto error;
  }

  fp->inst = fp2;
  return 0;
error:
  if (fp2) {
    free(fp2);
  }
  return -1;
}

int tuno_protocol_tcp_proxy_server_close(struct tuno_protocol *fp)
{
  struct tuno_protocol *fp2 = (struct tuno_protocol *) fp->inst;
  tunolog("%s", __func__);
  
  if (fp2) {
    fp2->func->close(fp2);
    free(fp2);
  }
  fp->inst = NULL;

  return 0;
}

int tuno_protocol_tcp_proxy_server_init(struct tuno_socket *sk)
{
  return 0;
}

int tuno_protocol_tcp_proxy_server_read(struct tuno_socket *sk)
{
  struct tuno_socket *sk2 = (struct tuno_socket *) sk->inst;
  struct tcp_proxy_param *param = (struct tcp_proxy_param *) sk->lparam;
  int len;

  if ((len = tuno_socket_rbuf_length(sk)) == 0 
    || (tuno_socket_rbuf_pullup(sk, len)) == NULL) {
    return 0;
  }
  
  tunolog("%s %d", __func__, len);

  //new client & start connection
  if (sk2 == NULL) {
    tunolog("client connect %s:%d", param->forward_host, param->forward_port);
    if ((sk2 = tuno_socket_connect(
          (struct tuno_protocol *)sk->protocol->inst
        , (struct event_base *) sk->protocol->lparam
        , (struct evdns_base *) sk->protocol->rparam
        , param->forward_host                 //forward host
        , param->forward_port                 //forward port
        , param->client_ssl ? TUNO_SOCKET_FLAG_SSL : 0, &timeout                      //ssl
        , NULL, NULL
        , NULL, NULL)) == NULL) {
      tunosetmsg2();
      goto error;
    }
    sk2->inst = sk;
  }

  //write from server's rbuf to client's wbuf
  if (tuno_socket_buf_to_buf(sk->rbuf, sk2->wbuf)) {
    tunosetmsg2();
    goto error;
  }
  
  //notify client to process this incoming buf
  if (sk->inst == NULL) {
    sk->inst = sk2;
    tunolog("HERER");
  } else {
    if (tuno_socket_add_notify_write(sk2, 0)) {
      tunosetmsg2();
      goto error;
    }
  }

  return 0;
error:
  if (sk2) {
    tuno_socket_free(sk2);
    sk->inst = NULL;
  }
  return TUNO_STATUS_ERROR;
}

int tuno_protocol_tcp_proxy_server_write(struct tuno_socket *sk)
{
  tunolog("%s %d", __func__, tuno_socket_wbuf_length(sk));

  //write server's wbuf to server's socket
  if (tuno_socket_write_from_buf(sk, sk->wbuf)) {
    tunosetmsg2();
    goto error;
  }

  return 0;
error:
  return TUNO_STATUS_ERROR;


  return 0;
}

int tuno_protocol_tcp_proxy_server_finish(struct tuno_socket *sk, int error)
{
  struct tuno_socket *sk2 = (struct tuno_socket *) sk->inst;
  tunolog("%s", __func__);

  // the two func of ...proxy_client_finish ...proxy_server_finish only execution either
  // by who server close socket first or client close socket first
  if (sk2) {
    tuno_socket_free(sk2);
    sk->inst = NULL;
  }
  return 0;
}

struct tuno_protocol_func tcp_proxy_server_func = {
  tuno_protocol_tcp_proxy_server_open, tuno_protocol_tcp_proxy_server_close,
  tuno_protocol_tcp_proxy_server_init, tuno_protocol_tcp_proxy_server_read, tuno_protocol_tcp_proxy_server_write, 
  tuno_protocol_tcp_proxy_server_finish
};






int main(int argc, char* argv[]) {
  struct timeval timeout; 
  struct tuno_listener *listener = NULL;
  int ret;
  struct tuno_protocol protocol = {
    .func = &tcp_proxy_server_func,
    .inst = NULL,
    .lparam = NULL,
    .rparam = NULL,
  };

  struct tcp_proxy_param param;
  struct event_base *ev_base = NULL;
  struct evdns_base *ev_dns = NULL;

  timeout.tv_sec = 10;
  timeout.tv_usec = 0;
  
  if (tuno_sys_socket_init()) {
    tunolog("failed to socket_library_init()");
    return -1;
  }

  if (argc != 6) {
    tunolog("./test_tcp_proxy 5566 192.168.4.22 80 client ssl");
    tunolog("forward the incoming packet from 127.0.0.1:5566 to 192.168.4.22:80 c 1");
    exit(1);
  }

  if ((ev_base = event_base_new()) == NULL) {
    tunolog("failed to event_base_new()");
    return -1;
  }
  
  if ((ev_dns = evdns_base_new(ev_base, 1)) == NULL) {
    tunolog("failed to event_base_new()");
    return -1;
  }

  protocol.lparam = ev_base;
  protocol.rparam = ev_dns;

  memset(&param, 0, sizeof(param));
  param.forward_host = argv[2];
  param.forward_port = atoi(argv[3]);
  
  if (strcmp(argv[5], "1") == 0) {
    if (strcmp(argv[4], "c") == 0) {
      param.client_ssl = 1;
      param.server_ssl = 0;
    } else {
      param.client_ssl = 0;
      param.server_ssl = 1;
    }
  }

  tunolog("client ssl: %d, server ssl:%d '%s'", param.client_ssl, param.server_ssl, argv[4]);

  if (protocol.func->open(&protocol)) {
    tunosetmsg2();
    tunolog(tunogetmsg());
    goto finish;
  }

  //if ((listener = tuno_listener_new(&protocol, ev_base, ev_dns, "0.0.0.0", 5566, "127.0.0.1", "80")) == NULL) {
  if ((listener = tuno_listener_new(&protocol, ev_base, ev_dns, "0.0.0.0", atoi(argv[1]), param.server_ssl ? TUNO_SOCKET_FLAG_SSL : 0, &timeout, "private_key", "public_key", &param, NULL)) == NULL) {
  //if ((listener = tuno_listener_new(&protocol, ev_base, ev_dns, "0.0.0.0", 5566, "netsync.tv", "443")) == NULL) {
    tunosetmsg2();
    tunolog(tunogetmsg());
    goto finish;
  }

  if ((ret = event_base_dispatch(ev_base))) {
    tunolog("ret NOT zero: %d", ret);
#ifdef __WIN32__
    tunolog("WSAGetLastError %d", WSAGetLastError());
#endif
  }
finish:
  tunolog("EXIT");
  protocol.func->close(&protocol);
  tuno_listener_free(listener);
  return 0;
}
