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
#ifndef _HTTP_CLIENT_H_
#define _HTTP_CLIENT_H_
#include "http.h"
#include <json/json.h>

/************************************************
 * HttpClient::Connection
 ***********************************************/
namespace HttpClient {

/***************************************************
 * URL
 **************************************************/
class URL: public Http::URL {
public:
  URL();
  ~URL();

  int Init(Json::Value &json_obj/*, int handler_type*/);
  std::string& Host() override;
  int Port() override;
  bool IsSSL() override;
  std::string &Path() override;
  int Method() override;
  std::string &FileForUpload();
  Json::Value &JsonObj();

  bool SSLDoCertVerify();
  std::string &SSLCaCertFile();

private:
  std::string host_;
  std::string path_;
  std::string file_for_upload_;
  std::string ssl_ca_cert_file_;
  std::string ssl_verify_hostname_;
  Json::Value json_obj_;
};

/***************************************************
 * URLFactory
 **************************************************/
class URLFactory {
public:
  URLFactory();
  ~URLFactory();
  int Init(std::string &json_str);
  std::shared_ptr<Http::URL> NextURL();

private:
  Json::Value json_obj_;
  int index_ = 0;
};

class Connection {
public:
  Connection(struct tuno_socket *sk, std::shared_ptr<Http::URL> url, std::shared_ptr<Http::Handler> handler);
  ~Connection();
  int DoRead();
  int DoWrite();
  int Finish(int error);

private:
  std::shared_ptr<Http::Context> context_;
  std::shared_ptr<Http::Handler> handler_;
};

/************************************************
 * HttpClient::Parallel
 ***********************************************/
class Parallel {
public:
  Parallel();
  ~Parallel();
  int Init(struct event_base *ev_base, std::shared_ptr<Http::HandlerFactory> handler_factory
      , int timeout_sec = 0, int timeout_usec = 0);
  int Connect(std::shared_ptr<Http::URL> url);
  int Size();

  static int _do(int _case, struct tuno_socket *sk, int error = 0);
  static int _read(struct tuno_socket *sk);
  static int _write(struct tuno_socket *sk);
  static int _finish(struct tuno_socket *sk, int error);

private:
  std::shared_ptr<Http::HandlerFactory> handler_factory_;
  struct tuno_protocol_func protocol_cb_;
  struct tuno_protocol protocol_;
  struct event_base *ev_base_ = nullptr;
  struct timeval timeout_;
  std::map<struct tuno_socket *, std::shared_ptr<Connection>> connection_map_;
};

/***************************************************
 * ReadContentHandler
 **************************************************/
class ReadContentHandler: public Http::ReadContentHandler {
};

/***************************************************
 * WriteContentHandler
 **************************************************/
class WriteContentHandler: public Http::WriteContentHandler {
public:
  virtual std::string &FileName(std::shared_ptr<Http::Context> context) = 0;
  virtual int64_t ContentLength(std::shared_ptr<Http::Context> context) = 0;
  virtual const char *ContentType(std::shared_ptr<Http::Context> context) = 0;
  virtual int DoReadContent(std::shared_ptr<Http::Context> context) = 0;
};

/***************************************************
 * DefaultGetHandler
 **************************************************/
class DefaultGetHandler: public Http::Handler {
public:
  DefaultGetHandler(std::shared_ptr<Http::ReadContentHandler> read_content_handler);
  ~DefaultGetHandler();
  virtual int Init(std::shared_ptr<Http::Context> context) override;
  virtual int DoRequest(std::shared_ptr<Http::Context> context) override;
  virtual int DoResponse(std::shared_ptr<Http::Context> context) override;
  virtual int Finish(std::shared_ptr<Http::Context> context, int error) override;

private:
  std::shared_ptr<Http::ContentHandlerFactory> content_handler_factory_;
  std::shared_ptr<HttpClient::ReadContentHandler> read_content_handler_;
  bool chunked_mode_ = false;
  int64_t read_length_ = 0;
  int64_t content_length_ = -2;
};

/***************************************************
 * DefaultPutHandler
 **************************************************/
class DefaultPutHandler: public Http::Handler {
public:
  DefaultPutHandler(std::shared_ptr<Http::WriteContentHandler> write_content_handler_);
  ~DefaultPutHandler();
  virtual int Init(std::shared_ptr<Http::Context> context) override;
  virtual int DoRequest(std::shared_ptr<Http::Context> context) override;
  virtual int DoResponse(std::shared_ptr<Http::Context> context) override;
  virtual int Finish(std::shared_ptr<Http::Context> context, int error) override;

private:
  std::shared_ptr<Http::ContentHandlerFactory> content_handler_factory_;
  std::shared_ptr<HttpClient::WriteContentHandler> write_content_handler_;
};

/************************************************
 * HttpClient::DefaultHandlerFactory
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
