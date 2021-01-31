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
#include "http_server.h"

/************************************************
 * Http::URL 
 ***********************************************/
std::shared_ptr<HttpServer::URL> HttpServer::URL::Parse(std::shared_ptr<Http::Header> header)
{
  std::string header_str = header->GetHeaderString();
  int method = HttpServer::GET;
  std::string host;
  //int port = 80;
  std::string path;

  while(true) {
    std::string first_line = header_str.substr(0, header_str.find("\r\n")+2);

    if (first_line.size() <= 0) {
      break;
    }

    //tunolog("first_line: \"%s\"", first_line.c_str());

    std::size_t pos;
    if ((pos = first_line.find("HTTP/1.1")) != std::string::npos) {
      if (first_line.find("GET") != std::string::npos) {
        method = HttpServer::GET;
        tunolog("method GET");
      } else if (first_line.find("PUT") != std::string::npos) {
        method = HttpServer::PUT;
        tunolog("method PUT");
      }
      pos = first_line.find(" ") + 1;
      path = first_line.substr(pos, first_line.rfind(" ") - pos);
      tunolog("path: \"%s\"", path.c_str());
    } else if ((pos = first_line.find("Host: ")) != std::string::npos) {
      pos += 6;
      host = header_str.substr(pos, header_str.find("\r\n") - pos);
      if ((pos = host.find(":")) != std::string::npos) {
        host = host.substr(0, pos);
      }
      tunolog("host: \"%s\"", host.c_str());
      //tunolog("port: \"%d\"", port);
    }
    header_str = header_str.substr(first_line.size(), header_str.size() - first_line.size());
  }

  return std::shared_ptr<HttpServer::URL>(new HttpServer::URL(method, host, 0/*port*/, path));
}

/************************************************
 * HttpClient::Reader
 ***********************************************/
int HttpServer::Reader::ReadHead()
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
        /*if (!context_->Instream()->GetHeader()->IsChunkedEncoding()) {
          tunosetmsg("unsupported transfer encoding");
          return TUNO_STATUS_ERROR;
        }
        chunked_mode_ = true;*/
        content_length_ = 0;
      }

#if 0
      if (chunked_mode_ == false && content_length_ == 0) {
        BodyDone();
      }
#endif
      if (content_length_ == 0) {
        BodyDone();
      }
    }
    tunolog("content_length_: %lld chunked_mode_:%d bodyDone:%d", content_length_, chunked_mode_, IsBodyDone());
  }

  return 0;
}

int HttpServer::Reader::ReadBody(std::string &buf)
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
  

/************************************************
* HttpServer::Connection
***********************************************/
HttpServer::Connection::Connection(struct tuno_socket *sk, std::shared_ptr<Router> router) {
  context_ = std::shared_ptr<HttpServer::Context>(
      new HttpServer::Context(
          std::shared_ptr<Http::Context>(new Http::Context(sk))));
  router_ = router;
};

HttpServer::Connection::~Connection() {
  tunolog("~Connection()");
};

int HttpServer::Connection::DoRead() 
{
  /** read head */
  if (!context_->reader()->IsHeadDone()) {
    if (context_->reader()->ReadHead()) {
      tunosetmsg2();
      return TUNO_STATUS_ERROR;
    }

    // parse url
    if (context_->reader()->IsHeadDone()) {
      // parser header to get path, host
      std::shared_ptr<URL> url_ = HttpServer::URL::Parse(context_->reader()->GetHeader());
      context_->SetURL(url_);
      
      // find handlercb first
      if ((handler_cb_ = router_->FindHandlerCb(url_->Path())) == nullptr) {
        // otherwise new handler instance for holding instance member variables
        handler_ = router_->NewHandler(url_->Path());
        if (handler_.get() == nullptr) {
          tunosetmsg2();
          return TUNO_STATUS_ERROR;
        }

        handler_cb_ = handler_->GetHandlerCb();
      }
    }
  }

  if (!context_->reader()->IsHeadDone()) {
    return TUNO_STATUS_NOT_DONE;
  }
  
  if (context_->reader()->IsHeadDone()
      && context_->reader()->IsBodyDone()) {
    tunolog("read done 1");
    context_->writer()->Outstream()->AddWriteNotify();
    return TUNO_STATUS_DONE;
  }

  /** read body */
  std::string response;
  
  if (context_->reader()->ReadBody(response)) {
    tunosetmsg2();
    return TUNO_STATUS_ERROR;
  }

  if (response.size() > 0) {
    if (handler_cb_(context_, response)) {
      tunosetmsg2();
      return TUNO_STATUS_ERROR;
    }
  }

  if (!context_->reader()->IsBodyDone()) {
    return TUNO_STATUS_NOT_DONE;
  }

  tunolog("read done 2");
  context_->writer()->Outstream()->AddWriteNotify();
  return TUNO_STATUS_DONE;
};

int HttpServer::Connection::DoWrite() {
  // write head & body throw cb
  std::string response;

  if (!context_->writer()->IsHeadDone()
      || !context_->writer()->IsBodyDone()) {
    if (handler_cb_(context_, response)) {
      tunosetmsg2();
      return TUNO_STATUS_ERROR;
    }
  }

  if (context_->writer()->IsHeadDone()
      && context_->writer()->IsBodyDone()) {
    tunolog("write done");
    return TUNO_STATUS_DONE;
  }

  context_->writer()->Outstream()->AddWriteNotify();
  return TUNO_STATUS_NOT_DONE;
};

int HttpServer::Connection::Finish(int error) {
  return 0;
};


/************************************************
* HttpServer::Server
***********************************************/
HttpServer::Server::Server(struct event_base *ev_base
      , std::shared_ptr<Router> router
      , std::string ssl_public_key
      , std::string ssl_private_key
      , int timeout_sec
      , int timeout_usec) {

  ev_base_ = ev_base;
  router_ = router;

  if (!ssl_public_key.empty()) {
    cert_crt = ssl_public_key;
    cert_key = ssl_private_key;
  }

  timeout_.tv_sec = 10;
  timeout_.tv_usec = 0;

  if (timeout_sec || timeout_usec) {
    timeout_.tv_sec = timeout_sec;
    timeout_.tv_usec = timeout_usec;
  }

  protocol_cb_.open = nullptr;
  protocol_cb_.close = nullptr;

  protocol_cb_.init = [] (struct tuno_socket *sk) -> int {
    HttpServer::Server *p = static_cast<HttpServer::Server*>(sk->protocol->inst);
    auto connection = p->FindConnection(sk);

    if (connection.get() != nullptr) {
      tunosetmsg("sk %p already exist.", sk);
      return -1;
    }

    p->AddConnection(sk);
    return 0;
  };


  protocol_cb_.read = [](struct tuno_socket *sk) -> int {
    HttpServer::Server *p = static_cast<HttpServer::Server*>(sk->protocol->inst);
    auto connection = p->FindConnection(sk);
    
    if (connection.get() == nullptr) {
      tunosetmsg("sk %p not found.", sk);
      return -1;
    }

    return connection->DoRead();
  };

  protocol_cb_.write = [](struct tuno_socket *sk) -> int {
    HttpServer::Server *p = static_cast<HttpServer::Server*>(sk->protocol->inst);
    auto connection = p->FindConnection(sk);
    
    if (connection.get() == nullptr) {
      tunosetmsg("sk %p not found.", sk);
      return -1;
    }

    return connection->DoWrite();
  };

  protocol_cb_.finish = [](struct tuno_socket *sk, int error) -> int {
    HttpServer::Server *p = static_cast<HttpServer::Server*>(sk->protocol->inst);
    auto connection = p->FindConnection(sk);
    
    if (connection.get() == nullptr) {
      tunosetmsg("sk %p not found.", sk);
      return -1;
    }

    int ret = connection->Finish(error);
    p->connection_map_.erase(p->connection_map_.find(sk));
    tunolog("p->connection_map_.size:%d", p->connection_map_.size());
    return ret;
  };

  protocol_.func = &protocol_cb_;
  protocol_.inst = static_cast<void*>(this);
  protocol_.lparam = nullptr;
  protocol_.rparam = nullptr;
};

HttpServer::Server::~Server() {
  ;
};

std::shared_ptr<HttpServer::Server> HttpServer::Server::Listen(struct event_base *ev_base
      , std::shared_ptr<Router> router
      , int port
      , std::string ssl_public_key
      , std::string ssl_private_key
      , int timeout_sec
      , int timeout_usec)
{
  std::shared_ptr<HttpServer::Server> server = std::shared_ptr<HttpServer::Server>(
      new HttpServer::Server(ev_base, router, ssl_public_key, ssl_private_key, timeout_sec, timeout_usec));
  int flag = 0;

  if (!ssl_public_key.empty()) {
    flag = TUNO_SOCKET_FLAG_SSL;
  }

  if ((server->listener_ = tuno_listener_new(&server->protocol_, server->ev_base_, nullptr
          , "0.0.0.0", port, flag, &server->timeout_, server->cert_key.c_str(), server->cert_crt.c_str(), NULL, NULL)) == NULL) {
    tunosetmsg2();
    server = std::shared_ptr<HttpServer::Server>();
  }

  return server;
}

void HttpServer::Server::AddConnection(struct tuno_socket *sk) {
  connection_map_[sk] = std::shared_ptr<HttpServer::Connection>(new HttpServer::Connection(sk, router_));
};

std::shared_ptr<HttpServer::Connection> HttpServer::Server::FindConnection(struct tuno_socket *sk) {
  auto it = connection_map_.find(sk);
  if (it == connection_map_.end()) {
    return std::shared_ptr<Connection>();
  }
  return it->second;
};

int HttpServer::Server::Size() {
  return connection_map_.size();
};

