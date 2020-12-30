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
#include <libtuno/tuno_socket.h>

/***********************************************************
 * helper func
 ***********************************************************/
static int tuno_socket_address_get(struct tuno_socket *sk)
{
  int skfd = bufferevent_getfd(sk->bev);
  
  if (tuno_sys_socket_get_address_port(skfd, 0, sk->addr.local_address, sizeof(sk->addr.local_address), &sk->addr.local_port)) {
    tunosetmsg2();
    return -1;
  }
  tuno_sys_socket_address_set_url(sk->addr.local_address, sk->addr.local_port, sk->addr.local_url);
  tunolog("local: %s, %d, %s", sk->addr.local_address, sk->addr.local_port, sk->addr.local_url);

  if (tuno_sys_socket_get_address_port(skfd, 1, sk->addr.peer_address, sizeof(sk->addr.peer_address), &sk->addr.peer_port)) {
    tunosetmsg2();
    return -1;
  }
  tuno_sys_socket_address_set_url(sk->addr.peer_address, sk->addr.peer_port, sk->addr.peer_url);
  tunolog("peer: %s, %d, %s", sk->addr.peer_address, sk->addr.peer_port, sk->addr.peer_url);

  return 0;
}


/***********************************************************
 * libevent's read, write, event
 ***********************************************************/
static void tuno_ev_read(struct bufferevent *bev, void *ptr)
{
  struct tuno_socket *sk = (struct tuno_socket *) ptr;
  int error = TUNO_ERROR_NONE;
  int ret = 0;
  
  //read from socket's buf to rbuf
  if (tuno_socket_read_to_buf(sk, sk->rbuf) == 0) {
    return ;
  }

  //to process rbuf
  if ((ret = sk->protocol->func->read(sk)) == TUNO_STATUS_ERROR) {
    tunosetmsg2();
    tunolog(tunogetmsg());
    error = TUNO_ERROR_SYSTEM;
    goto done;
  }

  if (sk->flag&TUNO_SOCKET_FLAG_CLIENT) {
    if (ret == TUNO_STATUS_DONE) {
      tunolog("%s client done", __func__);
      goto done;
    }
  }

  return;
done:
  sk->protocol->func->finish(sk, error);
  tuno_socket_free(sk);
}

static void tuno_ev_write(struct bufferevent *bev, void *ptr)
{
  struct tuno_socket *sk = (struct tuno_socket *) ptr;
  int error = TUNO_ERROR_NONE;
  int ret = 0;

  if ((ret = sk->protocol->func->write(sk)) == TUNO_STATUS_ERROR) {
    error = TUNO_ERROR_SYSTEM;
    tunolog(tunogetmsg());
    goto done;
  }

  if (sk->flag&TUNO_SOCKET_FLAG_SERVER) {
    if (ret == TUNO_STATUS_DONE) {
      tunolog("%s server done", __func__);
      goto done;
    }
  }
  
  return;
done:
  sk->protocol->func->finish(sk, error);
  tuno_socket_free(sk);
}

static void tuno_ev_event(struct bufferevent *bev, short events, void *ptr)
{
  struct tuno_socket *sk = (struct tuno_socket *) ptr;
  int error = TUNO_ERROR_NONE;
  int eof = 0;
  
  if (events & BEV_EVENT_CONNECTED) {
    //for client init
    tunolog("%s connected", __func__);
    
    if (tuno_socket_address_get(sk)) {
      tunosetmsg2();
      error |= TUNO_ERROR_ERROR;
      tunolog(tunogetmsg());
      goto done;
    }

    if (sk->protocol->func->init) {
      if ((sk->protocol->func->init(sk)) == TUNO_STATUS_ERROR) {
        error = TUNO_ERROR_SYSTEM;
        tunosetmsg2();
        tunolog(tunogetmsg());
        goto done;
      }
    }
  
    // client is write first, server is read first
    if (tuno_socket_is_client(sk)) {
      tuno_ev_write(NULL, sk);
    }
    return;
  }
  
  if (events & BEV_EVENT_EOF) {
    eof = 1;
    tunolog("%s EOF", __func__);
    goto done;
  }

  if (events & BEV_EVENT_READING) {
    error |= TUNO_ERROR_READING;
    tunolog("%s ERROR_READIING", __func__);
  }

  if (events & BEV_EVENT_WRITING) {
    error |= TUNO_ERROR_WRITING;
    tunolog("%s ERROR_WRITING", __func__);
  }

  if (events & BEV_EVENT_ERROR) {
    error |= TUNO_ERROR_ERROR;
    tunolog("%s ERROR", __func__);
  }

  if (events & BEV_EVENT_TIMEOUT) {
    error |= TUNO_ERROR_TIMEOUT;
    tunolog("%s TIMEOUT", __func__);
  }

done:
  if (error || eof) {
    sk->flag |= TUNO_ERROR_ERROR; 
  tunolog("tuno_ev_event err sk->flag:%d", sk->flag);
    sk->protocol->func->finish(sk, error);
    tuno_socket_free(sk);
  }
}

/***********************************************************
 * socket
 ***********************************************************/
struct tuno_socket *tuno_socket_new(
  struct event_base *ev_base
  , struct evdns_base *ev_dns
  , evutil_socket_t fd
  , int flag)
{
  struct tuno_socket *sk = NULL;
  
  if ((sk = (struct tuno_socket*) calloc(1, sizeof(struct tuno_socket))) == NULL) {
    tunosetmsg("failed to calloc struct tuno_socket");
    goto error;
  }

  if ((sk->rbuf = tuno_buf_new()) == NULL) {
    tunosetmsg("failed to tuno_buf_new()");
    goto error;
  }

  if ((sk->wbuf = tuno_buf_new()) == NULL) {
    tunosetmsg("failed to wbuf of tuno_buf_new()");
    goto error;
  }

  TAILQ_INIT(&sk->notify_list);
  sk->flag = flag;
  return sk;
error:
  tuno_socket_free(sk);
  return NULL;
}

static void tuno_ev_delay_free_write_cb(struct bufferevent *bev, void *ptr)
{
  struct tuno_socket *sk = (struct tuno_socket *) ptr;
  tunolog("%s write buffer is zero %d", __func__, evbuffer_get_length(bufferevent_get_output(sk->bev)));
  tuno_socket_free(sk);
}

//flush the write buffer before close socket
int tuno_socket_delay_free(struct tuno_socket *sk)
{
  tunolog("%s %p", __func__, sk);
  bufferevent_setcb(sk->bev, NULL, tuno_ev_delay_free_write_cb, NULL, sk);
  return 0;
}

int tuno_socket_free(struct tuno_socket *sk)
{
  struct tuno_socket_write_notify *node_first;
  struct tuno_socket_write_notify *node_next;

  if (sk == NULL) {
    return -1;
  }

  if (sk->bev && evbuffer_get_length(bufferevent_get_output(sk->bev)) > 0) {
    if ((sk->flag & TUNO_ERROR_ERROR) == 0) {
      tunolog("%s need delay free %d %d"
        , __func__
        , evbuffer_get_length(bufferevent_get_input(sk->bev))
        , evbuffer_get_length(bufferevent_get_output(sk->bev)));
      //tuno_socket_flush(sk);
      return tuno_socket_delay_free(sk);
    } else {
      tunolog("%s need delay free %d %d %d '%s', but ERR or EOF occured"
        , __func__
        , sk->flag
        , evbuffer_get_length(bufferevent_get_input(sk->bev))
        , evbuffer_get_length(bufferevent_get_output(sk->bev))
        , tuno_buf_pullup(bufferevent_get_output(sk->bev), evbuffer_get_length(bufferevent_get_output(sk->bev)))
        );
      return tuno_socket_delay_free(sk);
    }
  }

  //clean notify list
  for (node_first = TAILQ_FIRST(&sk->notify_list); node_first; node_first = node_next) {
    node_next = TAILQ_NEXT(node_first, next);
    TAILQ_REMOVE(&sk->notify_list, node_first, next);
    tuno_socket_del_notify(node_first);
    tunolog("DEL NOTIFY");
  }

  if (sk->bev) {
    //struct event_base *ev_base = bufferevent_get_base(sk->bev);
    //event_base_loopexit(bufferevent_get_base(sk->bev), NULL);
    bufferevent_free(sk->bev);
    //tuno_socket_print_ev_count(ev_base, "*****");
  }

  if (sk->rbuf) {
    tuno_buf_free(sk->rbuf);
  }

  if (sk->wbuf) {
    tuno_buf_free(sk->wbuf);
  }

  if (sk->ev_connect) {
    event_del(sk->ev_connect);
    event_free(sk->ev_connect);
    sk->ev_connect = NULL;
  }

  /*
  if (sk->ssl) {
    SSL_free (sk->ssl);
  }
  */

  if (sk->ssl_ctx) {
    SSL_CTX_free (sk->ssl_ctx);
  }

  free(sk);
  return 0;
}

int tuno_socket_enable(struct tuno_socket *sk, int mode)
{
  int mode2 = 0;

  if (mode & TUNO_SOCKET_ENABLE_READ) {
    mode2 |= EV_READ;
  }

  if (mode & TUNO_SOCKET_ENABLE_WRITE) {
    mode2 |= EV_WRITE;
  }

  bufferevent_enable(sk->bev, mode2);
  return 0;
}

int tuno_socket_enable_writecb(struct tuno_socket *sk)
{
  bufferevent_setcb(sk->bev, tuno_ev_read, tuno_ev_write, tuno_ev_event, sk);
  return 0;
}

int tuno_socket_disable_writecb(struct tuno_socket *sk)
{
  bufferevent_setcb(sk->bev, tuno_ev_read, NULL, tuno_ev_event, sk);
  return 0;
}

int tuno_socket_write(struct tuno_socket *sk, uint8_t *buf, int size)
{
  sk->bw += size;
  return bufferevent_write(sk->bev, buf, size);
}

int tuno_socket_flush(struct tuno_socket *sk)
{
  //-1 on failure, 0 if no data was produces, 1 if data was produced
  return bufferevent_flush(sk->bev, EV_WRITE, BEV_FLUSH);
}

int tuno_socket_read_to_buf(struct tuno_socket *sk, tuno_buf *dst)
{
  struct evbuffer *src = bufferevent_get_input(sk->bev);
  int len = evbuffer_get_length(src);

  if (len == 0) {
    return 0;
  }

  sk->br += len;
  return evbuffer_remove_buffer(src, dst, len);
}

int tuno_socket_write_from_buf(struct tuno_socket *sk, tuno_buf *fbuf)
{
  int len;
  uint8_t *buf;

  //get rbuf's len
  if ((len = tuno_buf_length(fbuf)) == 0 
    || (buf = tuno_buf_pullup(fbuf, len)) == NULL) {
    return 0;
  }

  //write
  if (tuno_socket_write(sk, buf, len)) {
    tunosetmsg("failed to tuno_socket_write");
    return -1;
  }

  //remove
  if (tuno_buf_remove(fbuf, len)) {
    tunosetmsg("failed to tuno_socket_rbuf_remove");
    return -1;
  }

  return 0;
}

int tuno_socket_buf_to_buf(tuno_buf *src, tuno_buf *dst)
{
  int len;
  uint8_t *buf;

  //get rbuf's len
  if ((len = tuno_buf_length(src)) == 0 
    || (buf = tuno_buf_pullup(src, len)) == NULL) {
    return 0;
  }

  //write
  if (tuno_buf_write(dst, buf, len)) {
    tunosetmsg("failed to tuno_buf_write");
    return -1;
  }

  //remove
  if (tuno_buf_remove(src, len)) {
    tunosetmsg("failed to tuno_buf_remove");
    return -1;
  }

  return 0;
}

int tuno_socket_is_ssl(struct tuno_socket *sk)
{
  return (sk->flag & TUNO_SOCKET_FLAG_SSL) ? 1 : 0;
}

int tuno_socket_is_ssl_connected(struct tuno_socket *sk)
{
  return (sk->flag & TUNO_SOCKET_FLAG_SSL_CONNECTED) ? 1 : 0;
}


int tuno_socket_is_ipv6(struct tuno_socket *sk)
{
  return (sk->flag & TUNO_SOCKET_FLAG_IPV6) ? 1 : 0;
}

int tuno_socket_is_client(struct tuno_socket *sk)
{
  return (sk->flag & TUNO_SOCKET_FLAG_CLIENT) ? 1 : 0;
}

int tuno_socket_is_server(struct tuno_socket *sk)
{
  return (sk->flag & TUNO_SOCKET_FLAG_SERVER) ? 1 : 0;
}

void tuno_socket_print_ev_count(struct event_base *base, char *label)
{
  tunolog("%s ev_count:%d %d %d"
  , label
  , event_base_get_num_events(base, EVENT_BASE_COUNT_ACTIVE)
  , event_base_get_num_events(base, EVENT_BASE_COUNT_VIRTUAL)
  , event_base_get_num_events(base, EVENT_BASE_COUNT_ADDED));
}

/*
int tuno_socket_input_length(struct tuno_socket *sk)
{
  return evbuffer_get_length(bufferevent_get_input(sk->bev));
}
*/


/***********************************************************
 * add a write notify event
 ***********************************************************/


static void do_tuno_socket_notify_cb(evutil_socket_t sock, short which, void *arg)
{
  struct tuno_socket_write_notify *p = (struct tuno_socket_write_notify *) arg;
  if (p->type == TUNO_SOCKET_NOTIFY_WRITE) {
    tuno_ev_write(NULL, p->sk);
  } else if (p->type == TUNO_SOCKET_NOTIFY_CUSTOM) {
    p->cb(p->sk, p->lparam, p->rparam);
  } else if (p->type == TUNO_SOCKET_NOTIFY_READ) {
    tuno_ev_read(NULL, p->sk);
  }
  TAILQ_REMOVE(&p->sk->notify_list, p, next);
  tuno_socket_del_notify(p);
}

int tuno_socket_add_notify(struct tuno_socket *sk, int ms, int type, tuno_socket_notify_cb cb, void *lparam, void *rparam)
{
  struct tuno_socket_write_notify *p = NULL;

  if ((p = (struct tuno_socket_write_notify*) calloc(1, sizeof(struct tuno_socket_write_notify))) == NULL) {
    tunosetmsg("failed to calloc struct tuno_socket_write_notify");
    return -1;
  }

  if ((p->ev_timeout = evtimer_new(bufferevent_get_base(sk->bev), do_tuno_socket_notify_cb, p)) == NULL) {
    tunosetmsg("failed to calloc evtimer_new");
    goto error;
  }

  p->sk = sk;
  p->type = type;
  p->cb = cb;
  p->lparam = lparam;
  p->rparam = rparam;

  p->tm.tv_sec = 0;
  p->tm.tv_usec = ms*1000;  //millis second
  evtimer_add(p->ev_timeout, &p->tm);

  TAILQ_INSERT_TAIL(&sk->notify_list, p, next);
  return 0;
error:
  tuno_socket_del_notify(p);
  return -1;
}

int tuno_socket_add_notify_write(struct tuno_socket *sk, int ms)
{
  return tuno_socket_add_notify(sk, ms, TUNO_SOCKET_NOTIFY_WRITE, NULL, NULL, NULL); 
}

int tuno_socket_add_notify_read(struct tuno_socket *sk, int ms)
{
  return tuno_socket_add_notify(sk, ms, TUNO_SOCKET_NOTIFY_READ, NULL, NULL, NULL); 
}

int tuno_socket_del_notify(struct tuno_socket_write_notify *p)
{
  if (!p) {
    return -1;
  }

  if (p->ev_timeout) {
    event_del(p->ev_timeout);
    event_free(p->ev_timeout);
  }

  free(p);
  return 0;
}




/***********************************************************
 * client connect (non-block)
 ***********************************************************/
static void tuno_ev_check_connect(evutil_socket_t ev_sk, short event, void *arg)
{
  struct tuno_socket *sk = (struct tuno_socket *) arg;
  struct event_base *ev_base = event_get_base(sk->ev_connect);
  int error = -1;
  int ret = -1;

  if (event & EV_TIMEOUT) {
    tunolog("connect timeout");
    goto finally;
  }

  if ((event & EV_WRITE) || (event & EV_READ)) {
    //check if SSL negotiation was done
    if (tuno_socket_is_ssl(sk)) {
      if (tuno_socket_is_client(sk)) {
        ret = tuno_sys_socket_ssl_connect(sk->ssl);
      } else if (tuno_socket_is_server(sk)) {
        ret =  tuno_sys_socket_ssl_accept(sk->ssl);
      }
      if (ret < 0) {
        tunosetmsg2();
        tunolog(tunogetmsg());
        goto finally;
      } else if (ret == 0) {
        //not done yet;
        //tunolog("SSL NOT DONE YET");
        error = 0;
        goto finally;
      }
      tunolog("SSL OK");

      //check cert
      if (tuno_socket_is_client(sk) && sk->ssl_ca_cert_file && sk->ssl_verify_hostname) {
        if (tuno_sys_socket_ssl_cert_verify_results(sk->ssl, sk->ssl_verify_hostname)) {
          tunosetmsg("failed to verify cert");
          error = -1;
          ret = -1;
          goto finally;
        }
      }

      sk->flag |= TUNO_SOCKET_FLAG_SSL_CONNECTED;
    }
  
    //close connect event
    event_del(sk->ev_connect);
    event_free(sk->ev_connect);
    sk->ev_connect = NULL;

    /**
     * let bufferevent to do the following task
     */
    if (tuno_socket_is_ssl(sk)) {
      if ((sk->bev = bufferevent_openssl_socket_new(ev_base, ev_sk, sk->ssl, BUFFEREVENT_SSL_OPEN, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS)) == NULL) {
        tunosetmsg("failed to calloc bufferevent_openssl_tuno_sys_socket_new");
        goto finally;
      }
    } else {
      if ((sk->bev = bufferevent_socket_new(ev_base, ev_sk, BEV_OPT_CLOSE_ON_FREE)) == NULL) {
        tunosetmsg("failed to calloc bufferevent_tuno_sys_socket_new");
        goto finally;
      }
    }

    bufferevent_setcb(sk->bev, tuno_ev_read, NULL/*tuno_ev_write*/, tuno_ev_event, sk);
    bufferevent_enable(sk->bev, EV_READ | EV_WRITE);
    tuno_ev_event(sk->bev, BEV_EVENT_CONNECTED, sk);
    error = 0;
  }

finally:
  if (error ) {
    sk->flag |= TUNO_ERROR_ERROR; 
    sk->protocol->func->finish(sk, error);
    tuno_socket_free(sk);
  }
}

struct tuno_socket *tuno_socket_connect(
  struct tuno_protocol *protocol
  , struct event_base *ev_base
  , struct evdns_base *ev_dns
  , char *host, int port
  , int flag, struct timeval *timeout
  , void *lparam, void *rparam
  , const char *ssl_ca_cert_file
  , const char *ssl_verify_hostname
  )
{
  struct tuno_socket *sk = NULL;
  int skfd = -1;
  int on = 1;
  
  if ((sk = tuno_socket_new(ev_base, ev_dns, -1, TUNO_SOCKET_FLAG_CLIENT)) == NULL) {
    tunosetmsg2();
    goto error;
  }

  sk->flag |= flag;
  sk->protocol = protocol;
  sk->lparam = lparam;
  sk->rparam = rparam;
  sk->ssl_ca_cert_file = ssl_ca_cert_file;
  sk->ssl_verify_hostname = ssl_verify_hostname;

#if 0
  if (bufferevent_tuno_sys_socket_connect_hostname(sk->bev, ev_dns, AF_UNSPEC, host, port) < 0) {
    tunosetmsg("failed to connect host %s", host);
    goto error;
  }
#endif

  if ((skfd = socket(sk->flag & TUNO_SOCKET_FLAG_IPV6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0)) < 0) {
    tunosetmsg("failed to create socket: %d", skfd);
    goto error;
  }

  tuno_sys_socket_make_nosigpipe(skfd);
  
  if (!tuno_sys_socket_make_nonblock(skfd, 1)) {
    tunosetmsg2();
    goto error;
  }

  if (tuno_sys_socket_make_closeonexec(skfd)) {
    tunosetmsg2();
    goto error;
  }

  if (setsockopt(skfd, SOL_SOCKET, SO_KEEPALIVE, (const char*)&on, sizeof(on))) {
    tunosetmsg("failed to set SO_KEEPALIVE %d", tuno_sys_socket_errorno());
    goto error;
  }

  if (tuno_sys_socket_make_reusable(skfd)) {
    tunosetmsg2();
    goto error;
  }

  if (tuno_sys_socket_connect(skfd, host, port, sk->flag & TUNO_SOCKET_FLAG_IPV6 ? 1 : 0)) {
    tunosetmsg2();
    goto error;
  }

  if ((sk->ev_connect = event_new(ev_base, skfd
    , EV_WRITE | EV_TIMEOUT | EV_PERSIST, tuno_ev_check_connect, (void*)sk)) == NULL) {
    tunosetmsg("failed to event_new write");
    goto error;
  }

  event_add(sk->ev_connect, timeout);

  if (!tuno_socket_is_ssl(sk)) {
    goto finally;
  }

  /** init ssl */
  //if ((sk->ssl_ctx = SSL_CTX_new(TLSv1_method())) == NULL) {        //cloudflare
  if ((sk->ssl_ctx = SSL_CTX_new(TLSv1_2_client_method())) == NULL) {     //cloudflare & golang-1.7.x
  //if ((sk->ssl_ctx = SSL_CTX_new(SSLv23_method())) == NULL) {       //golang-1.7.x
    tunosetmsg("failed to SSL_CTX_new");
    ERR_print_errors_fp(stderr);
    goto error;
  }

  if (sk->ssl_ca_cert_file && sk->ssl_verify_hostname) {
    if (tuno_sys_socket_ssl_add_ca_cert_file(sk->ssl_ctx, sk->ssl_ca_cert_file)) {
      tunosetmsg2();
      goto error;
    }
  }

  if ((sk->ssl = SSL_new(sk->ssl_ctx)) == NULL) {
    tunosetmsg("failed to SSL_new");
    ERR_print_errors_fp(stderr);
    goto error;
  }

  SSL_set_fd(sk->ssl, skfd);
  SSL_set_tlsext_host_name(sk->ssl, host);                  //cloudflare need this

#if 0
  //using flow_tuno_sys_socket_add_CA instead
  if (SSL_CTX_load_verify_locations(p->ssl_ctx, "CA.pem", NULL) != 1) {
    tunosetmsg("failed to found CA.pem");
    goto error;
  }
#endif
    
finally:
  return sk;
error:
  tuno_socket_free(sk);
  return NULL;
}




/***********************************************************
 * server listen & accept (non-block)
 ***********************************************************/
static void tuno_ev_accept(struct evconnlistener *listener,
  evutil_socket_t skfd,
  struct sockaddr *address,
  int socklen, void *ctx)
{
  struct tuno_listener *fl = (struct tuno_listener*) ctx;
  struct event_base *ev_base = evconnlistener_get_base(listener);
  struct tuno_socket *sk = NULL;
  
  if ((sk = tuno_socket_new(ev_base, fl->ev_dns, skfd, TUNO_SOCKET_FLAG_SERVER)) == NULL) {
    tunosetmsg2();
    goto error;
  }

  sk->flag |= fl->flag;
  sk->protocol = fl->protocol;
  sk->lparam = fl->lparam;
  sk->rparam = fl->rparam;

  if ((sk->ev_connect = event_new(ev_base, skfd
    , EV_READ | EV_TIMEOUT | EV_PERSIST, tuno_ev_check_connect, (void*)sk)) == NULL) {
    tunosetmsg("failed to event_new write");
    goto error;
  }

  event_add(sk->ev_connect, fl->timeout);

  if (!tuno_socket_is_ssl(sk)) {
    goto finally;
  }

  /** init ssl */
  if ((sk->ssl_ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {      //cloudflare & golang-1.7.x
    tunosetmsg("failed to SSLv23_server_method");
    ERR_print_errors_fp(stderr);
    goto error;
  }

  if (SSL_CTX_use_certificate_chain_file(sk->ssl_ctx, fl->public_key) <= 0) {
    tunosetmsg("ssl err");
    ERR_print_errors_fp(stderr);
    goto error;
  }

  if (SSL_CTX_use_PrivateKey_file(sk->ssl_ctx, fl->private_key, SSL_FILETYPE_PEM) <= 0) {
    tunosetmsg("ssl err");
    ERR_print_errors_fp(stderr);
    goto error;
  }
  
  if (!SSL_CTX_check_private_key(sk->ssl_ctx)) {
    tunosetmsg("ssl err");
    fprintf(stderr,"Private key does not match the certificate public key\n");
    goto error;
  }

  if ((sk->ssl = SSL_new(sk->ssl_ctx)) == NULL) {
    tunosetmsg("failed to SSL_new");
    ERR_print_errors_fp(stderr);
    goto error;
  }

  SSL_set_fd(sk->ssl, skfd);
finally:
  return;
error:
  tuno_socket_free(sk);
}

static void tuno_ev_accept_error(struct evconnlistener *listener, void *ctx)
{
  //struct tuno_listener *fl = (struct tuno_listener*) ctx;
  //struct event_base *base = evconnlistener_get_base(listener);
  int err = EVUTIL_SOCKET_ERROR();
  tunolog("Got an error %d (%s) on the listener. Shutting down.", err, evutil_socket_error_to_string(err));
  {
    FILE *fp = fopen("YES", "wb");
    fwrite("OK", 1, 2, fp);
    fclose(fp);
  }
//  tuno_listener_free(fl);
}

struct tuno_listener *tuno_listener_new(
  struct tuno_protocol *protocol
  , struct event_base *ev_base
  , struct evdns_base *ev_dns
  , const char *host, int port
  , int flag, struct timeval *timeout, const char *private_key, const char *public_key
  , void *lparam, void *rparam)
{
  struct tuno_listener *fl;
  struct sockaddr_in sin;
  int skfd;
  int is_ipv6 = 0;
  int on = 1;

  if ((fl = (struct tuno_listener*) calloc(1, sizeof(struct tuno_listener))) == NULL) {
    tunosetmsg("failed to calloc struct tuno_listener");
    goto error;
  }

  fl->flag = flag;
  fl->timeout = timeout;
  fl->private_key = private_key;
  fl->public_key = public_key;

  if ((skfd = socket(is_ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0)) < 0) {
    tunosetmsg("failed to create socket: %d", skfd);
    goto error;
  }
  
  tuno_sys_socket_make_nosigpipe(skfd);
  
  if (!tuno_sys_socket_make_nonblock(skfd, 1)) {
    tunosetmsg2();
    goto error;
  }
  
  if (tuno_sys_socket_make_closeonexec(skfd)) {
    tunosetmsg2();
    goto error;
  }

  if (setsockopt(skfd, SOL_SOCKET, SO_KEEPALIVE, (const char*)&on, sizeof(on))) {
    tunosetmsg("failed to set SO_KEEPALIVE %d", tuno_sys_socket_errorno());
    goto error;
  }

  if (tuno_sys_socket_make_reusable(skfd)) {
    tunosetmsg2();
    goto error;
  }

  fl->protocol = protocol;
  fl->ev_dns = ev_dns;
  fl->lparam = lparam;
  fl->rparam = rparam;

  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(0);   //0.0.0.0
  sin.sin_port = htons(port);

#if 0
  fl->ev_listener = evconnlistener_new_bind(
    ev_base, tuno_ev_accept, fl,
    LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
    (struct sockaddr*)&sin, sizeof(sin));
#else
  if (bind(skfd, (struct sockaddr*)&sin, sizeof(sin)) != 0) {
    tunosetmsg("failed to bind port4: %d", port);
    goto error;
  }

  fl->ev_listener = evconnlistener_new(
    ev_base, tuno_ev_accept, fl,
    LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1
    , skfd);
#endif

  if (fl->ev_listener == NULL) {
    tunosetmsg("failed to crat ev_listener");
    goto error;
  }

  evconnlistener_set_error_cb(fl->ev_listener, tuno_ev_accept_error);
  return fl;
error:
  tuno_listener_free(fl);
  return NULL;
}

int tuno_listener_free(struct tuno_listener *fl)
{
  if (!fl) {
    return -1;
  }

  if (fl->ev_listener) {
    event_base_loopexit(evconnlistener_get_base(fl->ev_listener), NULL);
    evconnlistener_free(fl->ev_listener);
  }

  free(fl);
  return 0;
}
