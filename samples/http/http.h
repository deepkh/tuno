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
#ifndef _HTTP_H_
#define _HTTP_H_
extern "C" {
#include <libtuno/tuno_socket.h>
}
#include <string>
#include <map>
#include <vector>
#include <memory>

#ifndef WIN32
#define _atoi64(val)     strtoll(val, NULL, 10)
#endif

/************************************************
 * HttpClient Wrapper Class
 ***********************************************/
namespace Http {

/************************************************
 * Http::Header
 ***********************************************/
class Header {
public:
  Header();
  ~Header();
  int SetHeaderString(char *buf, int size);
  std::string find_header_value(const char *key);
  
  std::string &GetHeaderString();
  int64_t GetContentLength();
  void AppendHeader(const char *fmt, ...);
  std::string GetAttachmentFilename();
  std::string GetTransferEncoding();
  bool IsChunkedEncoding();

private:
  std::string header_;
};

/************************************************
 * Http::Status
 ***********************************************/
class Status {
public:
  enum {
    STATUS_HEAD_DONE = 2,
    STATUS_BODY_DONE = 4,
  };
    
public:
  Status();
  ~Status();
  int GetStatus();
  void SetStatus(int new_status);
  void AppendStatus(int append_status);

  void HeadDone() {
    AppendStatus(STATUS_HEAD_DONE);
  };

  bool IsHeadDone() {
    return (status_ & STATUS_HEAD_DONE) ? true : false;
  };
  
  void BodyDone() {
    AppendStatus(STATUS_BODY_DONE);
  };

  bool IsBodyDone() {
    return (status_ & Http::Status::STATUS_BODY_DONE) ? true : false;
  };

private:
  int status_ = 0;
};

/************************************************
 * Http::InputStream
 ***********************************************/
class InputStream {
public:
  InputStream(struct tuno_socket *sk = nullptr);
  ~InputStream();
  void SetSocket(struct tuno_socket *sk);
  
  char *Buf(int len = 0);
  int BufLen();
  void BufRemove(int len);
  
  std::shared_ptr<Header> GetHeader();
  std::shared_ptr<Status> GetStatus();

  int ReadChunkString(std::string &chunk_str);

private:
  struct tuno_socket *sk_ = nullptr;
  std::shared_ptr<Header> header_;
  std::shared_ptr<Status> status_;
  std::string chunk_buf_;
};

/************************************************
 * Http::OutputStream
 ***********************************************/
class OutputStream {
public:
  OutputStream(struct tuno_socket *sk = nullptr);
  ~OutputStream();
  void SetSocket(struct tuno_socket *sk);
  
  int Write(char *buf, int size);
  void WritePrintf(const char *fmt, ...);
  void AddWriteNotify();

  std::shared_ptr<Header> GetHeader();
  std::shared_ptr<Status> GetStatus();

private:
  struct tuno_socket *sk_ = nullptr;
  bool write_header_done_ = false;
  std::shared_ptr<Header> header_;
  std::shared_ptr<Status> status_;
};

/************************************************
 * Http::Context
 ***********************************************/
class Context {
public:
  Context(struct tuno_socket *sk = nullptr);
  ~Context();
  void SetSocket(struct tuno_socket *sk);
  std::shared_ptr<InputStream> Instream();
  std::shared_ptr<OutputStream> Outstream();
  bool IsSSL();
  std::string LocalAddr();
  int LocalPort();
  std::string RemoteAddr();
  int RemotePort();

private:
  struct tuno_socket *sk_ = nullptr;
  std::shared_ptr<InputStream> input_stream_;
  std::shared_ptr<OutputStream> output_stream_;
};

};

#endif
