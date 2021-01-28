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
#include <string>
#include <algorithm>
#include "http_client.h"

/************************************************
* HttpClient::URL::Parse
***********************************************/
HttpClient::URL HttpClient::URL::Parse(const std::string &uri, std::string ssl_cert_file_path, bool ssl_cert_verify) {
  HttpClient::URL url;
  url.ssl_cert_file_path_ = ssl_cert_file_path;
  url.ssl_cert_verify_ = ssl_cert_verify;

  std::string protocol = "http";
  std::string port = "";

  typedef std::string::const_iterator iterator_t;

  if (uri.length() == 0) {
      return url;
  }

  iterator_t uriEnd = uri.end();

  // get query start
  iterator_t queryBegin = uri.begin();
    iterator_t queryStart = std::find(queryBegin, uriEnd, '?');

  // protocol
  iterator_t protocolStart = uri.begin();
  iterator_t protocolEnd = std::find(protocolStart, uriEnd, ':');            //"://");

  if (protocolEnd != uriEnd) {
    std::string prot = &*(protocolEnd);
    if ((prot.length() > 3) && (prot.substr(0, 3) == "://")) {
      protocol = std::string(protocolStart, protocolEnd);
      protocolEnd += 3;   //      ://
    } else {
      protocolEnd = uri.begin();  // no protocol
    }
  } else {
    protocolEnd = uri.begin();  // no protocol
  }

  // host
  iterator_t hostStart = protocolEnd;
  iterator_t pathStart = std::find(hostStart, uriEnd, '/');  // get pathStart

  iterator_t hostEnd = std::find(protocolEnd, 
    (pathStart != uriEnd) ? pathStart : queryStart, ':');  // check for port

  url.host_ = std::string(hostStart, hostEnd);

  // port
  if ((hostEnd != uriEnd) && ((&*(hostEnd))[0] == ':')) {
    hostEnd++;
    iterator_t portEnd = (pathStart != uriEnd) ? pathStart : queryStart;
    port = std::string(hostEnd, portEnd);
  }

  // path
  if (pathStart != uriEnd) {
    url.path_ = std::string(pathStart, queryStart);
  }

  // query
  if (queryStart != uriEnd) {
    url.path_ = url.path_ + std::string(queryStart, uri.end());
  }

  if (!port.empty()) {
    url.port_ = atoi(port.c_str());
  }

  if (protocol.compare("http") == 0) {
    if (url.port_ == 0) {
      url.port_  = 80;
    }
  } else if (protocol.compare("https") == 0) {
    if (url.port_ == 0) {
      url.port_  = 443;
    }
    url.ssl_ = true;
  }
  return url;
}

/************************************************
 * HttpClient::Reader
 ***********************************************/
int HttpClient::Reader::ReadHead()
{
  char *buf = nullptr;
  char *tmp;
  int len;

  //make sure buf is not empty
  if ((len = context_->Instream()->BufLen()) == 0 ||
      (buf = context_->Instream()->Buf(len)) == NULL) {
    tunolog("READ ZERO or rbuf NULL");
    return 0;
  }

  //find header
  if (!IsHeadDone()) {
    if ((tmp = strstr((char *)buf, "\r\n\r\n"))) {
      //tunolog("found delemiter %d\n'%s'\n", len, buf);
      int head_size = tmp - buf + 2;
      HeadDone();
      context_->Instream()->GetHeader()->SetHeaderString(buf, head_size);
      tunolog("head_size: %d content_length:%lld \n\"%s\""
          , head_size
          , context_->Instream()->GetHeader()->GetContentLength()
          , context_->Instream()->GetHeader()->GetHeaderString().c_str());

      /** remove header from buf */
      context_->Instream()->BufRemove(head_size + 2);
    }
  }

  //check content-length mode or chunk mode
  if (IsHeadDone()) {
    if (content_length_ == -2) {
      content_length_ = context_->Instream()->GetHeader()->GetContentLength();
      if (content_length_ == -1) {
        if (!context_->Instream()->GetHeader()->IsChunkedEncoding()) {
          tunosetmsg("unsupported transfer encoding");
          return TUNO_STATUS_ERROR;
        }
        chunked_mode_ = true;
      }

      if (chunked_mode_ == false && content_length_ == 0) {
        BodyDone();
      }
    }
    tunolog("content_length_: %lld chunked_mode_:%d bodyDone:%d", content_length_, chunked_mode_, IsBodyDone());
  }

  return 0;
}

int HttpClient::Reader::ReadBody(std::string &buf)
{
  if (context_->Instream()->BufLen() == 0) {
    return 0;
  }

  if (!chunked_mode_) {
    //Content-Length mode
    int len = context_->Instream()->BufLen();

    buf.resize(len);
    memcpy(&buf[0], context_->Instream()->Buf(), len);
    
    context_->Instream()->BufRemove(len);
    read_length_ += len;

    //tunolog("read %lld/%lld", read_length_, content_length_);      
    if ((content_length_ >= 0 && read_length_ >= content_length_)) {
      //tunolog("read done %lld/%lld", read_length_, content_length_);      
      BodyDone();
    }
  } else {
    //Chunked mode
    buf.resize(0);
    int ret = context_->Instream()->ReadChunkString(buf);

    if (ret == TUNO_STATUS_DONE) {
      tunolog("read chunked done");
      BodyDone();
      return 0;
    } else if (ret == TUNO_STATUS_ERROR) {
      return -1;
    }

    read_length_ += buf.size();
  }
  
  return 0;
}


/***************************************************
 * HttpClient::Connection
 **************************************************/
HttpClient::Connection::Connection(struct event_base *ev_base
    , std::shared_ptr<HttpClient::Handler> handler
    , int timeout_sec, int timeout_usec) {
  context_ = std::shared_ptr<HttpClient::Context>(
      new HttpClient::Context(
          std::shared_ptr<Http::Context>(new Http::Context())));
  ev_base_ = ev_base;
  handler_ = handler;

  if (timeout_sec || timeout_usec) {
    timeout_.tv_sec = timeout_sec;
    timeout_.tv_usec = timeout_usec;
  } else {
    timeout_.tv_sec = 10;
    timeout_.tv_usec = 0;
  }
  
  protocol_cb_.open = nullptr;
  protocol_cb_.close = nullptr;
  protocol_cb_.init = nullptr;
  protocol_cb_.read = [](struct tuno_socket *sk) -> int {
    HttpClient::Connection *connection = static_cast<HttpClient::Connection*>(sk->protocol->inst);
    return connection->DoRead();
  };
  protocol_cb_.write = [](struct tuno_socket *sk) -> int {
    HttpClient::Connection *connection = static_cast<HttpClient::Connection*>(sk->protocol->inst);
    return connection->DoWrite();
  };
  protocol_cb_.finish = [](struct tuno_socket *sk, int error) -> int {
    HttpClient::Connection *connection = static_cast<HttpClient::Connection*>(sk->protocol->inst);
    return connection->DoFinish(error);
  };

  protocol_.func = &protocol_cb_;
  protocol_.inst = static_cast<void*>(this);
  protocol_.lparam = nullptr;
  protocol_.rparam = nullptr;
}

std::shared_ptr<HttpClient::Connection> HttpClient::Connection::Connect(
    struct event_base *ev_base, std::shared_ptr<HttpClient::Handler> handler, int timeout_sec, int timeout_usec) {
  std::shared_ptr<HttpClient::Connection> connection(
    new HttpClient::Connection(ev_base, handler, timeout_sec, timeout_usec)
  );

  if ((connection->sk_ = tuno_socket_connect(&connection->protocol_
      , connection->ev_base_, nullptr
      , (char *)connection->handler_->Url().Host().c_str()
      , connection->handler_->Url().Port()
      , connection->handler_->Url().SSL() ? TUNO_SOCKET_FLAG_SSL : 0
      , &connection->timeout_
      , nullptr, nullptr
      , connection->handler_->Url().SSLCertVerify() ? connection->handler_->Url().SSLCertFilePah().c_str() : nullptr
      , connection->handler_->Url().SSLCertVerify() ? connection->handler_->Url().Host().c_str() : nullptr
      )) == NULL) {
    tunosetmsg2();
    return std::shared_ptr<HttpClient::Connection>();
  }

  connection->context_->context()->SetSocket(connection->sk_);
  return connection;
}

int HttpClient::Connection::DoRead() {
  /** read head */
  if (!context_->reader()->IsHeadDone()) {
    if (context_->reader()->ReadHead()) {
      tunosetmsg2();
      return TUNO_STATUS_ERROR;
    }
  }

  if (!context_->reader()->IsHeadDone()) {
    return TUNO_STATUS_NOT_DONE;
  }
  
  if (context_->reader()->IsHeadDone()
      && context_->reader()->IsBodyDone()) {
    tunolog("read done 1");
    return TUNO_STATUS_DONE;
  }

  /** read body */
  std::string response;
  
  if (context_->reader()->ReadBody(response)) {
    tunosetmsg2();
    return TUNO_STATUS_ERROR;
  }

  if (response.size() > 0) {
    if (handler_->Handlercb()(context_, response)) {
      tunosetmsg2();
      return TUNO_STATUS_ERROR;
    }
  }

  if (!context_->reader()->IsBodyDone()) {
    return TUNO_STATUS_NOT_DONE;
  }

  tunolog("read done 2");
  return TUNO_STATUS_DONE;
}

int HttpClient::Connection::DoWrite() {
  // write head
  if (!context_->writer()->IsHeadDone()) {
    context_->writer()->Outstream()->WritePrintf("%s %s HTTP/1.1\r\n"
        , handler_->Method()
        , handler_->Url().Path().c_str());
    context_->writer()->Outstream()->WritePrintf("Host: %s\r\n", handler_->Url().Host().c_str());
  }

  // write head & body throw cb
  std::string response;
  if (handler_->Handlercb()(context_, response)) {
    tunosetmsg2();
    return TUNO_STATUS_ERROR;
  }
  
  if (context_->writer()->IsHeadDone()
      && context_->writer()->IsBodyDone()) {
    tunolog("write done");
    return TUNO_STATUS_DONE;
  }

  context_->writer()->Outstream()->AddWriteNotify();
  return TUNO_STATUS_NOT_DONE;
}

int HttpClient::Connection::DoFinish(int error) {
  return 0;
}
