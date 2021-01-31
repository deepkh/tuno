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

namespace HttpClient {

/************************************************
* HttpClient::Handler
***********************************************/
class URL {
public:
  URL() {
    ;
  };
  URL(std::string host, int port, std::string path, bool ssl, std::string ssl_cert_file_path, bool ssl_cert_verify) {
    host_ = host;
    port_ = port;
    path_ = path;
    ssl_ = ssl;
    ssl_cert_file_path_ = ssl_cert_file_path;
    ssl_cert_verify_ = ssl_cert_verify;
  };

  URL(const URL &url) {
    host_ = url.host_;
    port_ = url.port_;
    path_ = url.path_;
    ssl_ = url.ssl_;
    ssl_cert_file_path_ = url.ssl_cert_file_path_;
    ssl_cert_verify_ = url.ssl_cert_verify_;
  };

  ~URL() {
    ;
  };

  static URL Parse(const std::string &uri, std::string ssl_cert_file_path = std::string(), bool ssl_cert_verify = false);

  std::string &Host() {
    return host_;
  };

  int Port() {
    return port_;
  };
  
  std::string &Path() {
    return path_;
  };

  bool SSL() {
    return ssl_;
  };
  
  std::string &SSLCertFilePah() {
    return ssl_cert_file_path_;
  };

  bool SSLCertVerify() {
    return ssl_cert_verify_;
  };

  void Dump() {
    printf("\nhost:%s\n", host_.c_str());
    printf("port:%d\n", port_); 
    printf("path:%s\n", path_.c_str());
    printf("ssl:%d\n", ssl_);
    printf("ssl_cert_file_path_:%s\n", ssl_cert_file_path_.c_str());
    printf("ssl_cert_verify_:%d\n", ssl_cert_verify_);
  };
  
private:
  std::string host_ = "127.0.0.1";
  int port_ = 0;
  std::string path_ = "/";
  bool ssl_ = false;
  std::string ssl_cert_file_path_;
  bool ssl_cert_verify_ = false;
};

/************************************************
 * HttpClient::Reader
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

private:
  std::shared_ptr<Http::Context> context_;
  bool chunked_mode_ = false;
  int64_t read_length_ = 0;
  int64_t content_length_ = -2;
};

/************************************************
 * HttpClient::Writer
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
 * HttpClient::Context
 ***********************************************/
class Context {
public:
  Context(std::shared_ptr<Http::Context> context) {
    context_ = context;
    writer_ = std::shared_ptr<Writer>(new Writer(context));
    reader_ = std::shared_ptr<Reader>(new Reader(context));
  };
  ~Context() {;};

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
  std::shared_ptr<Writer> writer_;
  std::shared_ptr<Reader> reader_;
};

/************************************************
 * HttpClient::Handler
 ***********************************************/
typedef std::function<int(std::shared_ptr<HttpClient::Context> context, std::string &response)> HandlerCb;
enum {
  GET = 0,
  POST,
  PUT,
  DELETE,
};

class Handler {
public:
  Handler(int method, URL url, HandlerCb handler_cb = nullptr) {
    method_ = method;
    url_ = url;
    handler_cb_ = handler_cb;
  };

  virtual ~Handler() {
    ;
  };

  static std::shared_ptr<Handler> New(int method, URL url, HandlerCb handler_cb) {
    return std::shared_ptr<Handler>(new Handler(method, url, handler_cb));
  };

  virtual const char *Method() {
     switch(method_) {
       case GET:
          return "GET";
       case PUT:
          return "PUT";
       case POST:
          return "POST";
       case DELETE:
          return "DELETE";
     }
     return "nulll_supported";

  };
  virtual URL &Url() { return url_;};
  virtual HandlerCb Handlercb() { 
    return handler_cb_;
  };

private:
  int method_ = 0;
  URL url_;
  HandlerCb handler_cb_ = nullptr;
};

/***************************************************
 * Connection
 **************************************************/
class Connection {
public:
  Connection(struct event_base *ev_base, std::shared_ptr<HttpClient::Handler> handler, int timeout_sec = 0, int timeout_usec = 0);
  ~Connection() {
    ;
  };
  
private:
  int DoRead();
  int DoWrite();
  int DoFinish(int error);

public:
  static std::shared_ptr<Connection> Connect(
      struct event_base *ev_base, std::shared_ptr<Handler> handler, int timeout_sec = 0, int timeout_usec = 0);

private:
  struct event_base *ev_base_ = nullptr;
  struct tuno_socket *sk_ = nullptr;
  struct tuno_protocol_func protocol_cb_;
  struct tuno_protocol protocol_;
  struct timeval timeout_;
  
  std::shared_ptr<HttpClient::Context> context_;  
  std::shared_ptr<Handler> handler_;
};
}; //HttpClient
#endif
