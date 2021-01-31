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
#ifndef _HTTP_SERVER_H_
#define _HTTP_SERVER_H_
#include "http.h"

namespace HttpServer {
enum {
  GET = 0,
  POST,
  PUT,
  DELETE,
};

/************************************************
* HttpServer::URL 
***********************************************/
class URL {
private:
  URL(int method, std::string host, int port, std::string path) {
    method_ = method;
    host_ = host;
    port_ = port;
    path_ = path;
  };

public:
  ~URL() {
    ;
  };

  static std::shared_ptr<URL> Parse(std::shared_ptr<Http::Header> header);

  int Method() {
    return method_;
  };

  std::string &Host() {
    return host_;
  };

  int Port() {
    return port_;
  };
  
  std::string &Path() {
    return path_;
  };

private:
  int method_ = 0;
  std::string host_;
  int port_ = 0;
  std::string path_;
};


/************************************************
 * HttpServer::Reader
 ***********************************************/
class Reader {
public:
  Reader(std::shared_ptr<Http::Context> context) {
    context_ = context;
  };
  ~Reader() {;};

  bool IsHeadDone() {
    return context_->Instream()->GetStatus()->IsHeadDone();
  };

  void HeadDone() {
    context_->Instream()->GetStatus()->HeadDone();
  };

  int ReadHead();

  bool IsBodyDone() {
    return context_->Instream()->GetStatus()->IsBodyDone();
  };

  void BodyDone() {
    context_->Instream()->GetStatus()->BodyDone();
  };

  int ReadBody(std::string &buf);

  bool ChunkedMode() {
    return chunked_mode_;
  };
  
  bool ContentLengthMode() {
    return !chunked_mode_;
  };

  int64_t ReadLength() {
    return read_length_;
  };

  int64_t ContentLength() {
    return content_length_;
  };

  std::shared_ptr<Http::Header> GetHeader() {
    return context_->Instream()->GetHeader();
  };

private:
  std::shared_ptr<Http::Context> context_;
  bool chunked_mode_ = false;
  int64_t read_length_ = 0;
  int64_t content_length_ = -2;
};



/************************************************
 * HttpServer::Writer
 ***********************************************/
class Writer {
public:
  Writer(std::shared_ptr<Http::Context> context) {
    context_ = context;
  };
  ~Writer() {;};

  bool IsHeadDone() {
    return context_->Outstream()->GetStatus()->IsHeadDone();
  };

  void HeadDone() {
    context_->Outstream()->GetStatus()->HeadDone();
  };

  bool IsBodyDone() {
    return context_->Outstream()->GetStatus()->IsBodyDone();
  };

  void BodyDone() {
    context_->Outstream()->GetStatus()->BodyDone();
  };

  std::shared_ptr<Http::OutputStream> Outstream() {
    return context_->Outstream();
  };

private:
  std::shared_ptr<Http::Context> context_;
};



/************************************************
 * HttpServer::Context
 ***********************************************/
class Context {
public:
  Context(std::shared_ptr<Http::Context> context) {
    context_ = context;
    writer_ = std::shared_ptr<Writer>(new Writer(context));
    reader_ = std::shared_ptr<Reader>(new Reader(context));
  };
  ~Context() {;};

  void SetURL(std::shared_ptr<URL> url) {
    url_ = url;
  };

  std::shared_ptr<URL> url() {
    return url_;
  };

  std::shared_ptr<Reader> reader() {
    return reader_;
  };

  std::shared_ptr<Writer> writer() {
    return writer_;
  };

  std::shared_ptr<Http::Context> context() {
    return context_;
  };

private:
  std::shared_ptr<Http::Context> context_;
  std::shared_ptr<URL> url_;  
  std::shared_ptr<Writer> writer_;
  std::shared_ptr<Reader> reader_;
};


/************************************************
 * HttpServer::HandlerCb
 ***********************************************/
typedef std::function<int(std::shared_ptr<Context> context, std::string &response)> HandlerCb;

/************************************************
 * HttpServer::Handler
 ***********************************************/
class Handler {
public:
  Handler(int method, const char *path, HandlerCb handler_cb = nullptr) {
    method_ = method;
    path_ = std::string(path);
    handler_cb_ = handler_cb;
  };

  virtual ~Handler() {
    ;
  };

  static std::shared_ptr<Handler> New(int method, const char *path, HandlerCb handler_cb = nullptr) {
    return std::shared_ptr<Handler>(new Handler(method, path, handler_cb));
  };

  virtual int Method() {
     return method_;
  };

  virtual std::string &Path() {
    return path_;
  };

  virtual HandlerCb GetHandlerCb() { 
    return handler_cb_;
  };
  
protected:
  int method_ = 0;
  std::string path_;
  HandlerCb handler_cb_ = nullptr;
};

/************************************************
 * HttpServer::HandlerFactory
 ***********************************************/
class HandlerFactory {
public:
  HandlerFactory(int method, const char *path) {
    method_ = method;
    path_ = std::string(path);
  };

  virtual ~HandlerFactory() {
    ;
  };

  virtual std::string &Path() {
    return path_;
  };

  virtual std::shared_ptr<Handler> NewHandler() = 0;

protected:
  int method_ = 0;
  std::string path_;
  //NewHandlerCb new_handler_cb_ = nullptr;
};


/************************************************
 * HttpServer::Router
 ***********************************************/
class Router {
public:
  Router() {
    ;
  };

  ~Router() {
    ;
  };

  /** HandlerCb */
  int AddHandlerCb(int method, const char *path, HandlerCb handler_cb = nullptr) {
    handler_cb_map_[std::string(path)] = handler_cb;
    prefix_len_map_[strlen(path)] = true;
    return 0;
  };

  HandlerCb FindHandlerCb(std::string &path) {
    for (auto it_len = prefix_len_map_.begin(); it_len != prefix_len_map_.end(); it_len++) {
      int prefix_len = it_len->first;
      std::string prefix = path.substr(0, prefix_len);
      tunolog("FindHandlerCb prefix:%s len:%d", prefix.c_str(), prefix_len);
      auto it = handler_cb_map_.find(prefix);
      if (it != handler_cb_map_.end()) {
        return it->second;
      }
    }
    return nullptr;
  };

  /** Handler instance */
  int Add(std::shared_ptr<HandlerFactory> handler_factory) {
    handler_factory_map_[handler_factory->Path()] = handler_factory;
    prefix_len_map_[handler_factory->Path().length()] = true;
    return 0;
  };

  std::shared_ptr<HandlerFactory> Find(std::string &path) {
    for (auto it_len = prefix_len_map_.begin(); it_len != prefix_len_map_.end(); it_len++) {
      int prefix_len = it_len->first;
      std::string prefix = path.substr(0, prefix_len);
      tunolog("Find prefix:%s len:%d", prefix.c_str(), prefix_len);
      auto it = handler_factory_map_.find(prefix);
      if (it != handler_factory_map_.end()) {
        tunolog("Find found prefix:%s len:%d", prefix.c_str(), prefix_len);
        return it->second;
      }
    }
    return std::shared_ptr<HandlerFactory>();
  };

  std::shared_ptr<Handler> NewHandler(std::string &path) {
    auto handler_factory = Find(path);
    if (handler_factory.get() == nullptr) {
      tunosetmsg("failed to find handler_factory %s", path.c_str());
      return std::shared_ptr<Handler>();
    }
    return handler_factory->NewHandler();
  };

public:
  std::map<int, bool> prefix_len_map_;
  //if no need persistence instance member variables, than should call handler_cb_ directly
  std::map<std::string, HandlerCb> handler_cb_map_;
  //if need persistence instance member variables eg., filereader/filewriter than need custom Handler
  std::map<std::string, std::shared_ptr<HandlerFactory>> handler_factory_map_;
};

/************************************************
 * HttpServer::Connection
 ***********************************************/
class Connection {
public:
  Connection(struct tuno_socket *sk, std::shared_ptr<Router> router);
  ~Connection();
  
  int DoRead();
  int DoWrite();
  int Finish(int error);

private:
  std::shared_ptr<Context> context_;
  std::shared_ptr<Router> router_;

  HandlerCb handler_cb_ = nullptr;
  std::shared_ptr<Handler> handler_;
};

/************************************************
 * HttpServer::Server
 ***********************************************/
class Server {
private:
  Server(struct event_base *ev_base
      , std::shared_ptr<Router> router
      , std::string ssl_public_key
      , std::string ssl_private_key
      , int timeout_sec = 0
      , int timeout_usec = 0);

public:
  ~Server();

  static std::shared_ptr<Server> Listen(struct event_base *ev_base
      , std::shared_ptr<Router> router
      , int port
      , std::string ssl_public_key
      , std::string ssl_private_key
      , int timeout_sec = 0
      , int timeout_usec = 0);

  void AddConnection(struct tuno_socket *sk);
  std::shared_ptr<Connection> FindConnection(struct tuno_socket *sk);
  int Size();

private:
  struct tuno_protocol_func protocol_cb_;
  struct tuno_protocol protocol_;
  std::shared_ptr<Router> router_;
  struct event_base *ev_base_ = nullptr;
  
  struct timeval timeout_;
  std::string cert_crt;
  std::string cert_key;
  struct tuno_listener *listener_ = nullptr;
  std::map<struct tuno_socket *, std::shared_ptr<Connection>> connection_map_;
};

};
#endif
