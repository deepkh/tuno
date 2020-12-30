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
/************************************************
 * Http::URL 
 ***********************************************/
class URL: public Http::URL {
public:
  URL(bool ssl, int port);
  ~URL();
  int Parse(std::shared_ptr<Http::Header> header);
  virtual std::string &Host() override;
  virtual int Port() override;
  virtual bool IsSSL() override;
  virtual std::string &Path() override;
  virtual int Method() override;      //0 = GET, 1 = POST

private:
  std::string host_;
  int port_ = 0;
  bool ssl_ = false;
  std::string path_;
  int method_ = 0;
};

/************************************************
 * HttpServer::Connection
 ***********************************************/
class Connection {
public:
  Connection(struct tuno_socket *sk, std::shared_ptr<Http::HandlerFactory> handler_factory);
  ~Connection();
  int DoRead();
  int DoWrite();
  int Finish(int error);

private:
  std::shared_ptr<Http::HandlerFactory> handler_factory_;
  std::shared_ptr<Http::Handler> handler_;
  std::shared_ptr<Http::Context> context_;
};

/************************************************
 * HttpServer::Server
 ***********************************************/
class Server {
public:
  Server();
  ~Server();
  int Init(struct event_base *ev_base, std::shared_ptr<Http::HandlerFactory> handler_factory
      , int timeout_sec = 0, int timeout_usec = 0);
  int Listen(int port, std::string ssl_public_key, std::string ssl_private_key);
  int Size();

  static int _do(int _case, struct tuno_socket *sk, int error = 0);
  static int _init(struct tuno_socket *sk);
  static int _read(struct tuno_socket *sk);
  static int _write(struct tuno_socket *sk);
  static int _finish(struct tuno_socket *sk, int error);

private:
  struct tuno_protocol_func protocol_cb_;
  struct tuno_protocol protocol_;
  struct event_base *ev_base_ = nullptr;
  std::string cert_crt;
  std::string cert_key;
  std::shared_ptr<Http::HandlerFactory> handler_factory_;
  struct timeval timeout_;
  struct tuno_listener *listener_ = nullptr;
  std::map<struct tuno_socket *, std::shared_ptr<Connection>> connection_map_;
};

/***************************************************
 * ReadContentHandler
 **************************************************/
class ReadContentHandler: public Http::ReadContentHandler {
public:
  virtual int StatusCode(std::shared_ptr<Http::Context> context) = 0;
  virtual int64_t ContentLength(std::shared_ptr<Http::Context> context) = 0;
  virtual const char *ContentType(std::shared_ptr<Http::Context> context) = 0;
  virtual int DoWriteContent(std::shared_ptr<Http::Context> context) = 0;         //still need to write response for server
};

/***************************************************
 * WriteContentHandler
 **************************************************/
class WriteContentHandler: public Http::WriteContentHandler {
public:
  virtual int StatusCode(std::shared_ptr<Http::Context> context) = 0;
  virtual int64_t ContentLength(std::shared_ptr<Http::Context> context) = 0;
  virtual const char *ContentType(std::shared_ptr<Http::Context> context) = 0;
};

/***************************************************
 * HttpServer::DefaultGetHandler
 **************************************************/
class DefaultGetHandler: public Http::Handler {
public:
  DefaultGetHandler(std::shared_ptr<Http::WriteContentHandler> write_content_handler);
  ~DefaultGetHandler();
  virtual int Init(std::shared_ptr<Http::Context> context) override;
  virtual int DoRequest(std::shared_ptr<Http::Context> context) override;
  virtual int DoResponse(std::shared_ptr<Http::Context> context) override;
  virtual int Finish(std::shared_ptr<Http::Context> context, int error) override;

private:
  std::shared_ptr<Http::ContentHandlerFactory> content_handler_factory_;
  std::shared_ptr<HttpServer::WriteContentHandler> write_content_handler_;
};

/***************************************************
 * HttpServer::DefaultPutHandler
 **************************************************/
class DefaultPutHandler: public Http::Handler {
public:
  DefaultPutHandler(std::shared_ptr<Http::ReadContentHandler> read_content_handler);
  ~DefaultPutHandler();
  virtual int Init(std::shared_ptr<Http::Context> context) override;
  virtual int DoRequest(std::shared_ptr<Http::Context> context) override;
  virtual int DoResponse(std::shared_ptr<Http::Context> context) override;
  virtual int Finish(std::shared_ptr<Http::Context> context, int error) override;

private:
  std::shared_ptr<Http::ContentHandlerFactory> content_handler_factory_;
  std::shared_ptr<HttpServer::ReadContentHandler> read_content_handler_;
  bool chunked_mode_ = false;
  int64_t read_length_ = 0;
  int64_t content_length_ = -2;
};

/************************************************
 * HttpServer::DefaultHandlerFactory
 ***********************************************/
class DefaultHandlerFactory: public Http::HandlerFactory {
public:
  DefaultHandlerFactory(std::shared_ptr<Http::ContentHandlerFactory> content_handler_factory);
  ~DefaultHandlerFactory();
  virtual std::shared_ptr<Http::Handler> FindHandler(std::shared_ptr<Http::URL> url) override;

private:
  std::shared_ptr<Http::ContentHandlerFactory> content_handler_factory_;
};

};
#endif
