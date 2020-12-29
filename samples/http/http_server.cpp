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
 * Http::URL General for Server
 ***********************************************/
HttpServer::URL::URL(bool ssl, int port)
{
  ssl_ = ssl;
  port_ = port;
}

HttpServer::URL::~URL()
{

}

int HttpServer::URL::Parse(std::shared_ptr<Http::Header> header)
{
  std::string header_str = header->GetHeaderString();

  while(true) {
    std::string first_line = header_str.substr(0, header_str.find("\r\n")+2);

    if (first_line.size() <= 0) {
      break;
    }

    //tunolog("first_line: \"%s\"", first_line.c_str());

    std::size_t pos;
    if ((pos = first_line.find("HTTP/1.1")) != std::string::npos) {
      if (first_line.find("GET") != std::string::npos) {
        method_ = 0;
        tunolog("method GET");
      } else if (first_line.find("PUT") != std::string::npos) {
        method_ = 1;
        tunolog("method PUT");
      }
      pos = first_line.find(" ") + 1;
      path_ = first_line.substr(pos, first_line.rfind(" ") - pos);
      tunolog("path_: \"%s\"", path_.c_str());
    } else if ((pos = first_line.find("Host: ")) != std::string::npos) {
      pos += 6;
      host_ = header_str.substr(pos, header_str.find("\r\n") - pos);
      if ((pos = host_.find(":")) != std::string::npos) {
        host_ = host_.substr(0, pos);
      }
      tunolog("host_: \"%s\"", host_.c_str());
      tunolog("port_: \"%d\"", port_);
      tunolog("ssl_: \"%d\"", ssl_);
    }
    header_str = header_str.substr(first_line.size(), header_str.size() - first_line.size());
  }
  return 0;
}

std::string &HttpServer::URL::Host() 
{
  return host_;
}

int HttpServer::URL::Port() 
{
  return port_;
}

bool HttpServer::URL::IsSSL()
{
  return ssl_;
}

std::string &HttpServer::URL::Path()
{
  return path_;
}

int HttpServer::URL::Method()
{
  return method_;
}

/************************************************
* HttpServer::Connection
***********************************************/
HttpServer::Connection::Connection(struct tuno_socket *sk, std::shared_ptr<Http::HandlerFactory> handler_factory) {
  context_ = std::shared_ptr<Http::Context>(new Http::Context());
  context_->SetSocket(sk);
  handler_factory_ = handler_factory;
};

HttpServer::Connection::~Connection() {;};

int HttpServer::Connection::DoRead() 
{
  char *buf = nullptr;
  char *tmp;
  int len;

  //make sure buf is not empty
  if ((len = context_->Instream()->BufLen()) == 0 ||
      (buf = context_->Instream()->Buf(len)) == NULL) {
    tunosetmsg("READ ZERO or rbuf NULL");
    return TUNO_STATUS_ERROR;
  }

  //tunolog("len:%d buf:%p", len, buf);

  //find header
  if ((context_->Instream()->GetStatus()->GetStatus() & Http::Status::STATUS_HEAD_DONE) == 0) {
    if ((tmp = strstr((char *)buf, "\r\n\r\n"))) {
      //tunolog("found delemiter %d\n'%s'\n", len, buf);
      int head_size = tmp - buf + 2;
      context_->Instream()->GetStatus()->AppendStatus(Http::Status::STATUS_HEAD_DONE);
      context_->Instream()->GetHeader()->SetHeaderString(buf, head_size);
      tunolog("head_size: %d content_length:%lld \n\"%s\""
          , head_size
          , context_->Instream()->GetHeader()->GetContentLength()
          , context_->Instream()->GetHeader()->GetHeaderString().c_str());

      /** remove header from buf */
      context_->Instream()->BufRemove(head_size + 2);
      len = context_->Instream()->BufLen();
      buf = context_->Instream()->Buf();

      // parser header to get path, host
      std::shared_ptr<HttpServer::URL> url(new HttpServer::URL(context_->IsSSL(), context_->LocalPort()));
      if (url->Parse(context_->Instream()->GetHeader())) {
        tunosetmsg2();
        return TUNO_STATUS_ERROR;
      }

      //set URL
      context_->SetURL(url);
    }
  }

  //find handler
  if ((context_->Instream()->GetStatus()->GetStatus() & Http::Status::STATUS_HEAD_DONE)
      && handler_.get() == nullptr) {
    handler_ = handler_factory_->FindHandler(context_->GetURL());
    if (handler_.get() == nullptr) {
      tunosetmsg2();
      return TUNO_STATUS_ERROR;
    }

    // init handler
    if (handler_->Init(context_)) {
      tunosetmsg2();
      return TUNO_STATUS_ERROR;
    }
  }

  //do handler request
  if (handler_.get()) {
    //feed to service routine
    int ret = handler_->DoRequest(context_);
    if (ret == TUNO_STATUS_DONE) {
      context_->Outstream()->AddWriteNotify();
    }
    return ret;
  }

  return TUNO_STATUS_NOT_DONE;
};

int HttpServer::Connection::DoWrite() {
  int ret;

  //check service
  if (handler_.get() == nullptr) {
    tunosetmsg("failed to get handler_ (null): '%s'", context_->GetURL()->Path().c_str());
    return TUNO_STATUS_ERROR;
  }

  //feed to service routine
  if ((ret = handler_->DoResponse(context_)) == TUNO_STATUS_NOT_DONE) {
    context_->Outstream()->AddWriteNotify();
  }
  return ret;
};

int HttpServer::Connection::Finish(int error) {
  //check service
  if (handler_.get() == nullptr) {
    tunosetmsg("failed to get handler_ (null)");
    return TUNO_STATUS_ERROR;
  }
  return handler_->Finish(context_, error);
};


/************************************************
* HttpServer::Server
***********************************************/
HttpServer::Server::Server() {
  
  protocol_cb_.open = nullptr;
  protocol_cb_.close = nullptr;
  protocol_cb_.init = _init;
  protocol_cb_.read = _read;
  protocol_cb_.write = _write;
  protocol_cb_.finish = _finish;

  protocol_.func = &protocol_cb_;
  protocol_.inst = static_cast<void*>(this);
  protocol_.lparam = nullptr;
  protocol_.rparam = nullptr;
  
  timeout_.tv_sec = 10;
  timeout_.tv_usec = 0;

};

HttpServer::Server::~Server() {
  ;
};

int HttpServer::Server::Init(struct event_base *ev_base, std::shared_ptr<Http::HandlerFactory> handler_factory 
    , int timeout_sec, int timeout_usec)
{
  ev_base_ = ev_base;
  handler_factory_ = handler_factory;
  if (timeout_sec || timeout_usec) {
    timeout_.tv_sec = timeout_sec;
    timeout_.tv_usec = timeout_usec;
  }
  return 0;
}

int HttpServer::Server::Listen(int port, std::string ssl_public_key, std::string ssl_private_key)
{
  int ret = -1;
  int flag = 0;
 
  if (!ssl_public_key.empty()) {
    flag = TUNO_SOCKET_FLAG_SSL;
    cert_crt = ssl_public_key;
    cert_key = ssl_private_key;
  }

  if ((listener_ = tuno_listener_new(&protocol_, ev_base_, nullptr
          , "0.0.0.0", port, flag, &timeout_, cert_key.c_str(), cert_crt.c_str(), NULL, NULL)) == NULL) {
    tunosetmsg2();
    goto finish;
  }

  ret = 0;
finish:
  return ret;
}

int HttpServer::Server::Size() {
  return (int) connection_map_.size();
};

// Cb function
int HttpServer::Server::_do(int _case, struct tuno_socket *sk, int error)
{
  Server *p = static_cast<Server*>(sk->protocol->inst);
  int ret = TUNO_STATUS_ERROR;
  auto it = p->connection_map_.find(sk);
  
  if (it == p->connection_map_.end()) {
    tunosetmsg("failed to to find sk %p", sk);
    goto finally;
  }

  switch(_case) {
    case 0:
      ret = it->second->DoRead();
      break;
    case 1:
      ret = it->second->DoWrite();
      break;
    case 2: 
    {
      ret = it->second->Finish(error);
      p->connection_map_.erase(it);
      tunolog("p->connection_map_.size:%d", p->connection_map_.size());
      break;
    }
    default:
      break;
    }
finally:
  return ret;
}

int HttpServer::Server::_init(struct tuno_socket *sk)
{
  HttpServer::Server *p = static_cast<HttpServer::Server*>(sk->protocol->inst);
  auto it = p->connection_map_.find(sk);

  if (it != p->connection_map_.end()) {
    tunosetmsg("sk %p already exist.", sk);
    return -1;
  }

  p->connection_map_[sk] = std::shared_ptr<Connection>(new Connection(sk, p->handler_factory_));
  return 0;
};

int HttpServer::Server::_read(struct tuno_socket *sk)
{
  return _do(0, sk);
};

int HttpServer::Server::_write(struct tuno_socket *sk)
{
  return _do(1, sk);
};

int HttpServer::Server::_finish(struct tuno_socket *sk, int error)
{
  return _do(2, sk, error);
};


/***************************************************
 * HttpServer::DefaultGetHandler
 **************************************************/
HttpServer::DefaultGetHandler::DefaultGetHandler(std::shared_ptr<Http::WriteContentHandler> write_content_handler) 
{
  write_content_handler_ = std::dynamic_pointer_cast<HttpServer::WriteContentHandler>(write_content_handler);
};

HttpServer::DefaultGetHandler::~DefaultGetHandler() 
{
  ;
};

int HttpServer::DefaultGetHandler::Init(std::shared_ptr<Http::Context> context)
{
  if (write_content_handler_.get() == nullptr) {
    tunosetmsg("write_content_handler_.get() is null");
    return -1;
  }

  if (write_content_handler_->Init(context)) {
    tunosetmsg2();
    return -1;
  }
  return 0;
};

int HttpServer::DefaultGetHandler::DoRequest(std::shared_ptr<Http::Context> context) {
  if (write_content_handler_.get() == nullptr) {
    tunosetmsg("write_content_handler_.get() is null");
    return TUNO_STATUS_ERROR;
  }
  return TUNO_STATUS_DONE;
};

int HttpServer::DefaultGetHandler::DoResponse(std::shared_ptr<Http::Context> context) 
{
  if (write_content_handler_.get() == nullptr) {
    tunosetmsg("write_content_handler_.get() is null");
    return TUNO_STATUS_ERROR;
  }

  if ((context->Outstream()->GetStatus()->GetStatus() & Http::Status::STATUS_HEAD_DONE) == 0) {
    context->Outstream()->WritePrintf("HTTP/1.1 %d OK\r\n", write_content_handler_->StatusCode(context));
    context->Outstream()->WritePrintf("Content-Type: %s\r\n", write_content_handler_->ContentType(context));
    context->Outstream()->WritePrintf("Content-Length: %" PRId64 "\r\n\r\n", write_content_handler_->ContentLength(context));
    context->Outstream()->GetStatus()->AppendStatus(Http::Status::STATUS_HEAD_DONE);
  }
  return write_content_handler_->DoWriteContent(context);
}

int HttpServer::DefaultGetHandler::Finish(std::shared_ptr<Http::Context> context, int error) 
{
  if (write_content_handler_.get() == nullptr) {
    tunosetmsg("write_content_handler_.get() is null");
    return TUNO_STATUS_ERROR;
  }
  return write_content_handler_->Finish(context, error);
}


/***************************************************
 * HttpServer::DefaultPutHandler
 **************************************************/
HttpServer::DefaultPutHandler::DefaultPutHandler(std::shared_ptr<Http::ReadContentHandler> read_content_handler) 
{
  read_content_handler_ = std::dynamic_pointer_cast<HttpServer::ReadContentHandler>(read_content_handler);
};

HttpServer::DefaultPutHandler::~DefaultPutHandler() 
{
  ;
};

int HttpServer::DefaultPutHandler::Init(std::shared_ptr<Http::Context> context)
{
  if (read_content_handler_.get() == nullptr) {
    tunosetmsg("read_content_handler_.get() is null");
    return -1;
  }

  if (read_content_handler_->Init(context)) {
    tunosetmsg2();
    return -1;
  }
  return 0;
};

int HttpServer::DefaultPutHandler::DoRequest(std::shared_ptr<Http::Context> context) {
  if (read_content_handler_.get() == nullptr) {
    tunosetmsg("read_content_handler_.get() is null");
    return TUNO_STATUS_ERROR;
  }
  return read_content_handler_->DoReadContent(context);
};

int HttpServer::DefaultPutHandler::DoResponse(std::shared_ptr<Http::Context> context) 
{
  if (read_content_handler_.get() == nullptr) {
    tunosetmsg("read_content_handler_.get() is null");
    return TUNO_STATUS_ERROR;
  }

  if ((context->Outstream()->GetStatus()->GetStatus() & Http::Status::STATUS_HEAD_DONE) == 0) {
    context->Outstream()->WritePrintf("HTTP/1.1 %d OK\r\n", read_content_handler_->StatusCode(context));
    context->Outstream()->WritePrintf("Content-Type: %s\r\n", read_content_handler_->ContentType(context));
    context->Outstream()->WritePrintf("Content-Length: %" PRId64 "\r\n\r\n", read_content_handler_->ContentLength(context));
    context->Outstream()->GetStatus()->AppendStatus(Http::Status::STATUS_HEAD_DONE);
  }
  return read_content_handler_->DoWriteContent(context);
}

int HttpServer::DefaultPutHandler::Finish(std::shared_ptr<Http::Context> context, int error) 
{
  if (read_content_handler_.get() == nullptr) {
    tunosetmsg("read_content_handler_.get() is null");
    return TUNO_STATUS_ERROR;
  }
  return read_content_handler_->Finish(context, error);
}


/************************************************
 * HttpServer::DefaultHandlerFactory
 ***********************************************/
HttpServer::DefaultHandlerFactory::DefaultHandlerFactory(std::shared_ptr<Http::ContentHandlerFactory> content_handler_factory) 
{
  content_handler_factory_ = content_handler_factory;
};

HttpServer::DefaultHandlerFactory::~DefaultHandlerFactory() 
{
  ;
};

std::shared_ptr<Http::Handler> HttpServer::DefaultHandlerFactory::FindHandler(std::shared_ptr<Http::URL> url)
{
  std::shared_ptr<Http::Handler> handler;

  switch(url->Method()) {
  case 0:
    handler = std::shared_ptr<Http::Handler>(
        new HttpServer::DefaultGetHandler(
          content_handler_factory_->FindWriteContentHandler(url)));
    break;
  case 1:
    handler = std::shared_ptr<Http::Handler>(
        new HttpServer::DefaultPutHandler(
          content_handler_factory_->FindReadContentHandler(url)));
    break;
  }

  return handler;
}

