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

/***********************************************************
 * helper func
 ***********************************************************/
/* by githhub Youka/string_replace.c */
char* str_replace(char* original, char* find, char* replacement, const char free_original){
  // Initializations
  int found_count = 0;
  const size_t find_len = strlen(find), replacement_len = strlen(replacement);
  char* result, *presult;
  const char* poriginal = original, *found;
  
  // Count founds
  while((found = strstr(poriginal, find))){
    found_count++;
    poriginal = found + find_len;
  }

  // Allocate memory for output
  if((result = (char *) malloc(strlen(original) + found_count * (replacement_len - find_len) + 1))){
    // Build output string
    presult = result, poriginal = original;
    while((found = strstr(poriginal, find))){
      found_count = found - poriginal;
      memcpy(presult, poriginal, found_count);
      memcpy(presult+found_count, replacement, replacement_len);
      presult += found_count + replacement_len;
      poriginal = found + find_len;
        }
    strcpy(presult, poriginal);
  }

  // Free old string
  if(free_original) {
    free(original);
  }

  // Return output
  return result;
}

char *str_to_lower(char *str)
{
  size_t i;

  for (i=0; i<strlen(str); i++) {
    str[i] = tolower(str[i]);
  }

  return str;
}

void dump(uint8_t *buf, int len)
{
#if 0
  uint8_t *buf2 = malloc(len + 1);
  memcpy(buf2, buf, len);
  buf2[len] = 0;
  printf("%s\n", buf2);
  free(buf2);
#else
  int i;

  for (i=0; i<len; i++) {
    printf("0x%02X ", buf[i]);
    if ((i+1)%16 == 0) {
      printf("\n");
    }
  }

  if (len) {
    printf("\n");
    fflush(stdout);
  }
#endif
}

static char *rtps_get_header(tuno_buf *fb)
{
  int len = tuno_buf_length(fb);
  uint8_t *buf = NULL;
  uint8_t *find = NULL;
  char *header = NULL;
  int header_len = 0;

  if (len == 0 || (buf = tuno_buf_pullup(fb, len)) == NULL) {
    return NULL;
  }

  if ((find = (uint8_t*)strstr((char *)buf, "\r\n\r\n")) == NULL) {
    return NULL;
  }

  header_len = find - buf + 4;

  if ((header = (char*) malloc(header_len + 1)) == NULL) {
    return NULL;
  }

  strncpy(header, (char *)buf, header_len);
  header[header_len] = 0;

#if 1
  tunolog("%d/%d\n%s", header_len, len, header);
#endif

  tuno_buf_remove(fb, header_len);
  return header;
}

static char *rtps_get_content(tuno_buf *fb)
{
  int len = tuno_buf_length(fb);
  uint8_t *buf = NULL;
  char *content = NULL;

  if (len == 0 || (buf = tuno_buf_pullup(fb, len)) == NULL) {
    return NULL;
  }

  if ((content = (char*) malloc(len + 1)) == NULL) {
    return NULL;
  }

  strncpy(content, (char *)buf, len);
  content[len] = 0;
#if 1
  tunolog("%d\n%s", len, content);
#endif
  tuno_buf_remove(fb, len);
  return content;
}

char *rtsp_replace_rtsp_addr(char *header, char *tmp
    , struct tuno_socket_address *src, int src_local
    , struct tuno_socket_address *dst, int dst_local)
{
  char *src_tmp1 = tmp;
  char *src_tmp2 = tmp + 256;
  char *dst_tmp = tmp + 512;
  int dst_port = dst_local ? dst->local_port : dst->peer_port;
  int found = 0;

  sprintf(src_tmp1, "://%s:%d"
    , src_local ? src->local_address : src->peer_address
    , src_local ? src->local_port : src->peer_port);

  sprintf(src_tmp2, "://%s"
    , src_local ? src->local_address : src->peer_address);

  if (strstr(header, src_tmp1)) {
    found = 1;
  } else if (strstr(header, src_tmp2)) {
    found = 2;
  }

  if (found == 0) {
    return header;
  }

  if (dst_port != 554) {
    sprintf(dst_tmp, "://%s:%d"
      , dst_local ? dst->local_address : dst->peer_address
      , dst_port);
  } else {
    sprintf(dst_tmp, "://%s"
      , dst_local ? dst->local_address : dst->peer_address);
  }
  return str_replace(header, found == 1 ? src_tmp1 : src_tmp2, dst_tmp, 1);
}

char *rtsp_replace_addr(char *header, char *tmp
    , struct tuno_socket_address *src, int src_local
    , struct tuno_socket_address *dst, int dst_local)
{
  char *src_addr = src_local ? src->local_address : src->peer_address;
  char *dst_addr = dst_local ? dst->local_address : dst->peer_address;

  if (strstr(header, src_addr) == NULL) {
    return header;
  }

  return str_replace(header, src_addr, dst_addr, 1);
}

char *rtsp_replace_rtsp_destination_source(char *header
    , char *tmp, int is_destination
    , struct tuno_socket_address *src, int src_local
    , struct tuno_socket_address *dst, int dst_local)
{
  char *src_addr = src_local ? src->local_address : src->peer_address;
  char *dst_addr = dst_local ? dst->local_address : dst->peer_address;
  char *src_tmp = tmp;
  char *dst_tmp = tmp + 512;

  sprintf(src_tmp, "%s=%s", is_destination ? "destination":"source", src_addr);
  sprintf(dst_tmp, "%s=%s", is_destination ? "destination":"source", dst_addr);

  if (strstr(header, src_tmp) == NULL) {
    return header;
  }

  return str_replace(header, src_tmp, dst_tmp, 1);
}



#define CONTENT_LENGTH_HEADER "content-length: "
static int rtps_get_header_value(const char *header1, const char *header_name, char *value)
{
  char *header = str_to_lower(strdup(header1));
  char *start = NULL;
  char *end = NULL;
  int len = 0;
  int found = 0;

  if ((start = strstr(header, header_name)) == NULL) {
    goto done;
  }
  start += strlen(header_name);
  
  if ((end = strstr(start, "\r\n")) == NULL) {
    goto done;
  }
  
  if ((len = end - start) <= 0) {
    goto done;
  }
  
  strncpy(value, start, len);
  value[len] = 0;
  found = 1;
done:
  if (header) {
    free(header);
  }
  return found;
}

/***********************************************************
 * rtsp proxy client & server sharing data
 ***********************************************************/
struct rtsp_proxy_share {
  struct tuno_socket *csk;
  struct tuno_socket *ssk;
  int is_rtp_start;
  int s_content_length;
  char s_header[1024];
  char tmp[8192];
};

struct rtsp_proxy_share *rtsp_proxy_inst_new(struct tuno_socket *csk, struct tuno_socket *ssk)
{
  struct rtsp_proxy_share *s = NULL;
  
  if ((s = (struct rtsp_proxy_share *) calloc(1, sizeof(struct rtsp_proxy_share))) == NULL) {
    tunosetmsg("failed to calloc struct rtsp_proxy_share");
    return NULL;
  }

  s->csk = csk;
  s->ssk = ssk;
  return s;
}

int rtsp_proxy_inst_free(struct rtsp_proxy_share *s)
{
  if (s) {
    free(s);
  }
  return 0;
}

/***********************************************************
 * rtsp proxy client protocol
 ***********************************************************/
int tuno_protocol_rtsp_proxy_client_open(struct tuno_protocol *fp) {return 0;}
int tuno_protocol_rtsp_proxy_client_close(struct tuno_protocol *fp) {return 0;}
int tuno_protocol_rtsp_proxy_client_init(struct tuno_socket *sk)
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

int tuno_protocol_rtsp_proxy_client_read(struct tuno_socket *sk)
{
  struct rtsp_proxy_share *s = (struct rtsp_proxy_share *) sk->inst;
  
  tunolog("%s %d", __func__, tuno_socket_rbuf_length(sk));

  //write client's rbuf to server's wbuf
  if (tuno_socket_buf_to_buf(sk->rbuf, s->ssk->wbuf)) {
    tunosetmsg2();
    goto error;
  }
  
  //notify server's notify
  if (tuno_socket_add_notify_write(s->ssk, 0)) {
    tunosetmsg2();
    goto error;
  }

  return 0;
error:
  return TUNO_STATUS_ERROR;
}

int tuno_protocol_rtsp_proxy_client_write(struct tuno_socket *sk)
{
  struct rtsp_proxy_share *s = (struct rtsp_proxy_share *) sk->inst;
  uint8_t *buf;
  int len = 0;
  char *header = NULL;

  tunolog("%s %d", __func__, tuno_socket_wbuf_length(sk));

  if ((len = tuno_socket_wbuf_length(sk)) == 0) {
    return 0;
  }

  if (s->is_rtp_start) {
    //write server's wbuf to server's socket
    if (tuno_socket_write_from_buf(sk, sk->wbuf)) {
      tunosetmsg2();
      goto error;
    }
  } else {
    buf = tuno_socket_wbuf_pullup(sk, len);

    //find rtsp header
    if ((header = rtps_get_header(sk->wbuf)) == NULL) {
      tunolog("client: RTSP header or RTP not found, may be SDP content");
      dump(buf, len);
      goto error;
    }

    //replace rtsp://127.0.0.1:554 to rtsp://192.168.4.104:554
    if ((header = rtsp_replace_rtsp_addr(header, s->tmp
      , &s->ssk->addr, 1
      , &s->csk->addr, 0)) == NULL) {
      tunosetmsg("failed to replacertsp_replace_rtsp_addrheader");
      goto error;
    }
    tunolog("new HEADER\n%s", header);
    
    //write header
    if (tuno_socket_write(sk, (uint8_t *)header, strlen(header))) {
      tunosetmsg("failed to tuno_socket_write");
      goto error;
    }

    //write again
    if (tuno_socket_wbuf_length(sk)) {
      return tuno_protocol_rtsp_proxy_client_write(sk);
    }
  }

  return 0;
error:
  if (header) {
    free(header);
  }
  return TUNO_STATUS_ERROR;
}

int tuno_protocol_rtsp_proxy_client_finish(struct tuno_socket *sk, int error)
{
  struct rtsp_proxy_share *s = (struct rtsp_proxy_share *) sk->inst;
  tunolog("%s", __func__);
  
  // the two func of ...proxy_client_finish ...proxy_server_finish only execution either
  // by who server close socket first or client close socket first
  if (s) {
    if (s->ssk) {
      tuno_socket_free(s->ssk);
    }
    free(s);
    sk->inst = NULL;
  }
  return 0;
}

struct tuno_protocol_func rtsp_proxy_client_func = {
  tuno_protocol_rtsp_proxy_client_open, tuno_protocol_rtsp_proxy_client_close,
  tuno_protocol_rtsp_proxy_client_init, tuno_protocol_rtsp_proxy_client_read, tuno_protocol_rtsp_proxy_client_write, 
  tuno_protocol_rtsp_proxy_client_finish
};


struct timeval timeout;
/***********************************************************
 * rtsp proxy server protocol
 ***********************************************************/ 
int tuno_protocol_rtsp_proxy_server_open(struct tuno_protocol *fp)
{
  struct tuno_protocol *fp2 = NULL;
  tunolog("%s", __func__);

  timeout.tv_sec = 60;
  timeout.tv_usec = 0;  

  if ((fp2 = (tuno_protocol*) calloc(1, sizeof(struct tuno_protocol))) == NULL) {
    tunosetmsg("failed to calloc tuno_protocol");
    return -1;
  }

  fp2->func = &rtsp_proxy_client_func;
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

int tuno_protocol_rtsp_proxy_server_close(struct tuno_protocol *fp)
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

int tuno_protocol_rtsp_proxy_server_init(struct tuno_socket *sk)
{
  return 0;
}

int tuno_protocol_rtsp_proxy_server_read(struct tuno_socket *sk)
{
  struct rtsp_proxy_share *s = (struct rtsp_proxy_share *) sk->inst;
//  struct tuno_protocol_rtsp_proxy_param *param = (struct tuno_protocol_rtsp_proxy_param *) sk->lparam;
  int len;

  if ((len = tuno_socket_rbuf_length(sk)) == 0 
    || (tuno_socket_rbuf_pullup(sk, len)) == NULL) {
    return 0;
  }
  
  tunolog("%s %d", __func__, len);

  //new client & start connection
  if (s == NULL) {
    if ((s = rtsp_proxy_inst_new(NULL, sk)) == NULL) {
      tunosetmsg2();
      goto error;
    }

    tunolog("client connect to %s:%d", (char *)sk->lparam, atoi((char*)sk->rparam));
    if ((s->csk = tuno_socket_connect(
          (struct tuno_protocol *)sk->protocol->inst
        , (struct event_base *) sk->protocol->lparam
        , (struct evdns_base *) sk->protocol->rparam
        , (char *)sk->lparam      //forward host
        , atoi((char*)sk->rparam)     //forward port
        , 0, &timeout               //ssl, timeout
        , NULL, NULL
        , NULL, NULL
        )) == NULL) {
      tunosetmsg2();
      goto error;
    }

    s->csk->inst = s;
  }

  //write from server's rbuf to client's wbuf
  if (tuno_socket_buf_to_buf(sk->rbuf, s->csk->wbuf)) {
    tunosetmsg2();
    goto error;
  }
  
  //notify client to process this incoming buf
  if (sk->inst == NULL) {
    sk->inst = s;
    tunolog("HERER");
  } else {
    if (tuno_socket_add_notify_write(s->csk, 0)) {
      tunosetmsg2();
      goto error;
    }
  }

  return 0;
error:
  if (s) {
    if (s->csk) {
      tuno_socket_free(s->csk);
    }
    free(s);
    sk->inst = NULL;
  }
  return TUNO_STATUS_ERROR;
}

int tuno_protocol_rtsp_proxy_server_write(struct tuno_socket *sk)
{
  struct rtsp_proxy_share *s = (struct rtsp_proxy_share *) sk->inst;
  uint8_t *buf;
  int len = 0;
  char *header = NULL;
  char *s_header = NULL;
  int new_content_len = 0;

  tunolog("%s %d", __func__, tuno_socket_wbuf_length(sk));

  if ((len = tuno_socket_wbuf_length(sk)) == 0) {
    return 0;
  }

  if (s->is_rtp_start) {
    //write server's wbuf to server's socket
    if (tuno_socket_write_from_buf(sk, sk->wbuf)) {
      tunosetmsg2();
      goto error;
    }
  } else {
    
    if (len < 2) {
      tunolog("LEN < 2 ***************************************************************");
      return 0;
    }

    //check first 2 byte if is 0x24 [0,1,2,3]
    buf = tuno_socket_wbuf_pullup(sk, len);

    if (buf[0] == 0x24 && (buf[1] >= 0 && buf[1] <= 3)) {
      tunolog("MAGIC is found 0x%02X 0x%02X", buf[0], buf[1]);
      s->is_rtp_start = 1;
      return tuno_protocol_rtsp_proxy_server_write(sk);
    }

    //sdp content section
    if (s->s_content_length != 0) {
      //get content
      if ((header = rtps_get_content(sk->wbuf)) == NULL) {
        tunolog("server: RTSP header or RTP not found1 %d", len);
        dump(buf, len);
        goto error;
      }

      //replace 'IN IP4 192.168.4.100' to 'IN IP4 127.0.0.1'
      if ((header = rtsp_replace_addr(header, s->tmp
        , &s->csk->addr, 0
        , &s->ssk->addr, 1
        )) == NULL) {
        tunosetmsg("failed to replacertsp_replace_rtsp_addrheader");
        goto error;
      }

      new_content_len = strlen(header);
      sprintf(s->tmp, ": %d", s->s_content_length);
      sprintf(s->tmp+256, ": %d", new_content_len);
      s_header = str_replace(s->s_header, s->tmp, s->tmp+256, 0);
      tunolog("new header\n%s", s_header);
      tunolog("new content\n%s", header);
      
      //write new header
      if (tuno_socket_write(sk, (uint8_t *)s_header, strlen(s_header))) {
        tunosetmsg("failed to tuno_socket_write");
        goto error;
      }
      
      s->s_content_length = 0;
    } else {
      //get header
      if ((header = rtps_get_header(sk->wbuf)) == NULL) {
        tunolog("server: RTSP header or RTP not found2 %d", len);
        dump(buf, len);
        goto error;
      }

      //replace rtsp://192.168.4.100:554 to rtsp://127.0.0.1:554
      if ((header = rtsp_replace_rtsp_addr(header, s->tmp
        , &s->csk->addr, 0
        , &s->ssk->addr, 1)) == NULL) {
        tunosetmsg("failed to replacertsp_replace_rtsp_addrheader");
        goto error;
      }

      //replace destionation=192.168.4.2 to destination=127.0.0.1
      if ((header = rtsp_replace_rtsp_destination_source(header, s->tmp, 1
        , &s->csk->addr, 1
        , &s->ssk->addr, 0)) == NULL) {
        tunosetmsg("failed to replacertsp_replace_rtsp_addrheader");
        goto error;
      }

      //replace source=192.168.4.104 to source=127.0.0.1
      if ((header = rtsp_replace_rtsp_destination_source(header, s->tmp, 0
        , &s->csk->addr, 0
        , &s->ssk->addr, 1)) == NULL) {
        tunosetmsg("failed to replacertsp_replace_rtsp_addrheader");
        goto error;
      }

      tunolog("new HEADER\n%s", header);

      //found content-length, this is SDP content section
      if (rtps_get_header_value(header, CONTENT_LENGTH_HEADER, s->tmp)) {
        s->s_content_length = atoi(s->tmp);
        tunolog("found content-length %d", s->s_content_length);
        sprintf(s->s_header, "%s", header);
        free(header);
        return tuno_protocol_rtsp_proxy_server_write(sk);
      }
    }

    //write header
    if (tuno_socket_write(sk, (uint8_t *)header, strlen(header))) {
      tunosetmsg("failed to tuno_socket_write");
      goto error;
    }

    //write again
    if (tuno_socket_wbuf_length(sk)) {
      return tuno_protocol_rtsp_proxy_server_write(sk);
    }
  }

  return 0;
error:
  if(s_header) {
    free(s_header);
  }
  if (header) {
    free(header);
  }
  return TUNO_STATUS_ERROR;
}

int tuno_protocol_rtsp_proxy_server_finish(struct tuno_socket *sk, int error)
{
  struct rtsp_proxy_share *s = (struct rtsp_proxy_share *) sk->inst;
  tunolog("%s", __func__);

  // the two func of ...proxy_client_finish ...proxy_server_finish only execution either
  // by who server close socket first or client close socket first
  if (s) {
    if (s->csk) {
      tuno_socket_free(s->csk);
    }
    free(s);
    sk->inst = NULL;
  }
  return 0;
}

struct tuno_protocol_func rtsp_proxy_server_func = {
  tuno_protocol_rtsp_proxy_server_open, tuno_protocol_rtsp_proxy_server_close,
  tuno_protocol_rtsp_proxy_server_init, tuno_protocol_rtsp_proxy_server_read, tuno_protocol_rtsp_proxy_server_write, 
  tuno_protocol_rtsp_proxy_server_finish
};



int main(int argc, char* argv[]) {
  struct timeval timeout;
  struct tuno_listener *listener = NULL;
  int ret;
  struct tuno_protocol protocol = {
    .func = &rtsp_proxy_server_func,
    .inst = NULL,
    .lparam = NULL,
    .rparam = NULL,
  };

  struct event_base *ev_base = NULL;
  struct evdns_base *ev_dns = NULL;

  timeout.tv_sec = 10;
  timeout.tv_usec = 0;

  if (tuno_sys_socket_init()) {
    tunolog("failed to socket_library_init()");
    return -1;
  }

  if (argc != 4) {
    tunolog("./test_rtsp_proxy 554 192.168.4.22 554 [encrypt,decrypt]");
    tunolog("forward the incoming packet from 0.0.0.0:554 to 192.168.4.22:554 encrypt or decrypt");
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

  if (protocol.func->open(&protocol)) {
    tunosetmsg2();
    tunolog(tunogetmsg());
    goto finish;
  }

  if ((listener = tuno_listener_new(
      &protocol, ev_base, ev_dns
      , "0.0.0.0"
      , atoi(argv[1])
      , 0
      , &timeout
      , "private_key", "public_key"
      , argv[2]
      , argv[3])) == NULL) {
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
