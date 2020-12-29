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
#include "http_client.h"
#include "util/json_helper.h"

/***************************************************
 * URL
**************************************************/
HttpClient::URL::URL() {
};

HttpClient::URL::~URL() {
  ;
};

int HttpClient::URL::Init(Json::Value &json_obj) {
  json_obj_ = json_obj;
  host_ = json_obj_["host"].asString();
  path_ = json_obj_["path"].asString();
  file_for_upload_ = json_obj_["file_for_upload"].asString();
  return 0;
};

std::string& HttpClient::URL::Host() {
  return host_;
};

int HttpClient::URL::Port() {
  return json_obj_["port"].asInt();
};

bool HttpClient::URL::IsSSL() {
  return json_obj_["ssl"].asBool();
};

std::string &HttpClient::URL::Path() {
  return path_;
};

int HttpClient::URL::Method() {
  return json_obj_["method"].asInt(); //0 = GET, 1 = PUT
};

std::string &HttpClient::URL::FileForUpload()
{
  return file_for_upload_;
};

Json::Value &HttpClient::URL::JsonObj()
{
  return json_obj_;
};


/***************************************************
* URLFactory
**************************************************/
HttpClient::URLFactory::URLFactory() {
  ;
};

HttpClient::URLFactory::~URLFactory() {
  ;
};

int HttpClient::URLFactory::Init(std::string &json_str) 
{
  if (JsonParser::ParseFromString(json_str, json_obj_)) {
    tunosetmsg2();
    return -1;
  }

  if (!json_obj_.isArray()) {
    tunolog("failed to parse json_str\n\"%s\"", json_str.c_str());
    return -1;
  }

  index_ = 0;
  return 0;
};

std::shared_ptr<Http::URL> HttpClient::URLFactory::NextURL() {
  std::shared_ptr<HttpClient::URL> url;
  for (;index_ < (int)json_obj_.size();) {
    index_++;

    if (!json_obj_[index_-1]["url"].isObject()) {
      tunolog("failed to get url from json_str");
      continue;
    }
    
    url = std::shared_ptr<HttpClient::URL>(new HttpClient::URL());
    if (url->Init(json_obj_[index_-1]["url"])) {
      continue;
    }

    return url;
  }
  return url;
};


/************************************************
* HttpClient::Connection
***********************************************/
HttpClient::Connection::Connection(struct tuno_socket *sk, std::shared_ptr<Http::URL> url, std::shared_ptr<Http::Handler> handler) {
  context_ = std::shared_ptr<Http::Context>(new Http::Context(url));
  context_->SetSocket(sk);
  handler_ = handler;
};

HttpClient::Connection::~Connection() {;};

int HttpClient::Connection::DoRead() {
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
    }
  }

  //process response body
  if ((context_->Instream()->GetStatus()->GetStatus() & Http::Status::STATUS_HEAD_DONE) && len > 0) {
    return handler_->DoResponse(context_);
  }

  return TUNO_STATUS_NOT_DONE;
};

int HttpClient::Connection::DoWrite() {
  int ret;

  // init handler
  if ((context_->Outstream()->GetStatus()->GetStatus() & Http::Status::STATUS_HEAD_DONE) == 0) {
    if (handler_->Init(context_)) {
      tunosetmsg2();
      return TUNO_STATUS_ERROR;
    }
  }

  ret = handler_->DoRequest(context_);
  if (ret == TUNO_STATUS_NOT_DONE) {
    context_->Outstream()->AddWriteNotify();
  }
  return ret;
};

int HttpClient::Connection::Finish(int error) {
  return handler_->Finish(context_, error);
};


/************************************************
* HttpClient::Parallel
***********************************************/
HttpClient::Parallel::Parallel() {
  protocol_cb_.open = nullptr;
  protocol_cb_.close = nullptr;
  protocol_cb_.init = nullptr;
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

HttpClient::Parallel::~Parallel() {
  ;
};

int HttpClient::Parallel::Init(struct event_base *ev_base, std::shared_ptr<Http::HandlerFactory> handler_factory
    , int timeout_sec, int timeout_usec) 
{
  ev_base_ = ev_base;
  handler_factory_ = handler_factory;
  if (timeout_sec || timeout_usec) {
    timeout_.tv_sec = timeout_sec;
    timeout_.tv_usec = timeout_usec;
  }
  return 0;
};

int HttpClient::Parallel::Connect(std::shared_ptr<Http::URL> url)
{
  std::shared_ptr<Http::Handler> handler = handler_factory_->FindHandler(url);
  
  if (handler.get() == nullptr) {
    tunosetmsg2();
    return -1;
  }

  struct tuno_socket *sk = nullptr;  
  if ((sk = tuno_socket_connect(&protocol_, ev_base_, nullptr
      , (char *)url->Host().c_str(), url->Port()
      , url->IsSSL() ? TUNO_SOCKET_FLAG_SSL : 0
      , &timeout_, nullptr, nullptr)) == NULL) {
    tunosetmsg2();
    return -1;
  }
    
  connection_map_[sk] = std::shared_ptr<Connection>(new Connection(sk, url, handler));
  return 0;
};

int HttpClient::Parallel::Size() {
  return (int) connection_map_.size();
};

// Cb function
int HttpClient::Parallel::_do(int _case, struct tuno_socket *sk, int error)
{
  Parallel *p = static_cast<HttpClient::Parallel*>(sk->protocol->inst);
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
      break;
    }
    default:
      break;
    }

finally:
  return ret;
}

int HttpClient::Parallel::_read(struct tuno_socket *sk)
{
  return _do(0, sk);
};

int HttpClient::Parallel::_write(struct tuno_socket *sk)
{
  return _do(1, sk);
};

int HttpClient::Parallel::_finish(struct tuno_socket *sk, int error)
{
  return _do(2, sk, error);
};


/***************************************************
 * HttpClient::DefaultGetHandler
 **************************************************/
HttpClient::DefaultGetHandler::DefaultGetHandler(std::shared_ptr<Http::ReadContentHandler> read_content_handler) 
{
  read_content_handler_ = std::dynamic_pointer_cast<HttpClient::ReadContentHandler>(read_content_handler);
};

HttpClient::DefaultGetHandler::~DefaultGetHandler() 
{
  ;
};

int HttpClient::DefaultGetHandler::Init(std::shared_ptr<Http::Context> context)
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

int HttpClient::DefaultGetHandler::DoRequest(std::shared_ptr<Http::Context> context) {
  context->Outstream()->WritePrintf("GET %s HTTP/1.1\r\n", context->GetURL()->Path().c_str());
  context->Outstream()->WritePrintf("Host: %s\r\n\r\n", context->GetURL()->Host().c_str());
  return TUNO_STATUS_DONE;
};

int HttpClient::DefaultGetHandler::DoResponse(std::shared_ptr<Http::Context> context) 
{
  return read_content_handler_->DoReadContent(context);
}

int HttpClient::DefaultGetHandler::Finish(std::shared_ptr<Http::Context> context, int error) 
{
  return read_content_handler_->Finish(context, error);
}


/***************************************************
 * HttpClient::DefaultPutHandler
 **************************************************/
HttpClient::DefaultPutHandler::DefaultPutHandler(std::shared_ptr<Http::WriteContentHandler> write_content_handler) 
{
  write_content_handler_ = std::dynamic_pointer_cast<HttpClient::WriteContentHandler>(write_content_handler);
};

HttpClient::DefaultPutHandler::~DefaultPutHandler() 
{
  ;
};

int HttpClient::DefaultPutHandler::Init(std::shared_ptr<Http::Context> context)
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


int HttpClient::DefaultPutHandler::DoRequest(std::shared_ptr<Http::Context> context) {
  if ((context->Outstream()->GetStatus()->GetStatus() & Http::Status::STATUS_HEAD_DONE) == 0) {
    context->Outstream()->WritePrintf("PUT %s HTTP/1.1\r\n", context->GetURL()->Path().c_str());
    context->Outstream()->WritePrintf("Host: %s\r\n", context->GetURL()->Host().c_str());
    context->Outstream()->WritePrintf("Content-Disposition: attachment; filename=%s\r\n", write_content_handler_->FileName(context).c_str());
    context->Outstream()->WritePrintf("Content-Type: %s\r\n", write_content_handler_->ContentType(context));
    context->Outstream()->WritePrintf("Content-Length: %" PRId64 "\r\n\r\n", write_content_handler_->ContentLength(context));
    context->Outstream()->GetStatus()->AppendStatus(Http::Status::STATUS_HEAD_DONE);
  }
  return write_content_handler_->DoWriteContent(context);
};

int HttpClient::DefaultPutHandler::DoResponse(std::shared_ptr<Http::Context> context) 
{
  return write_content_handler_->DoReadContent(context);
}

int HttpClient::DefaultPutHandler::Finish(std::shared_ptr<Http::Context> context, int error) 
{
  return write_content_handler_->Finish(context, error);
}



/************************************************
 * HttpClient::DefaultHandlerFactory
 ***********************************************/
HttpClient::DefaultHandlerFactory::DefaultHandlerFactory(std::shared_ptr<Http::ContentHandlerFactory> content_handler_factory) 
{
  content_handler_factory_ = content_handler_factory;
};

HttpClient::DefaultHandlerFactory::~DefaultHandlerFactory() 
{
  ;
};

std::shared_ptr<Http::Handler> HttpClient::DefaultHandlerFactory::FindHandler(std::shared_ptr<Http::URL> url)
{
  std::shared_ptr<Http::Handler> handler;

  switch(url->Method()) {
  case 0:
    handler = std::shared_ptr<Http::Handler>(
        new HttpClient::DefaultGetHandler(
          content_handler_factory_->FindReadContentHandler(url)));
    break;
  case 1:
    handler = std::shared_ptr<Http::Handler>(
        new HttpClient::DefaultPutHandler(
          content_handler_factory_->FindWriteContentHandler(url)));
    break;
  }

  return handler;
}

