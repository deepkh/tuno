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
#include "http/http_server.h"
#include "util/json_helper.h"
#include "util/file_stream.h"

/************************************************
 * DownloadHandler 
 ***********************************************/
class DownloadHandler: public HttpServer::Handler {
public:
  DownloadHandler(int method, const char *path, const char *root_path)
    :HttpServer::Handler(method, path, nullptr) {
      root_path_ = std::string(root_path);
      tunolog("DownloadHandler '%s' '%s'", path, root_path);
  };

  virtual ~DownloadHandler() {
    ;
  };

  HttpServer::HandlerCb GetHandlerCb() {
    return [this](std::shared_ptr<HttpServer::Context> context
                , std::string &response) -> int {
      // Due to async operation, so this handler callback will call multi times when reader/writer is ready to read/write. 

      // open file for upload
      if (frs_.get() == nullptr) {
        std::string file_path = context->url()->Path();
        file_name_ = file_path.substr(this->path_.length(), file_path.length() - this->path_.length());

        file_path = this->root_path_ + file_name_;
        tunolog("file_path:'%s' file:'%s'", file_path.c_str(), file_name_.c_str());

        frs_ = std::shared_ptr<fs::FileReadStream>(new fs::FileReadStream());
        if (frs_->Open(file_path)) {
          tunosetmsg("failed to open %s", file_path.c_str());
          return -1;
        }

        buf_.resize(4096);
      }
   
      //write head
      if (!context->writer()->IsHeadDone()) {
        context->writer()->Outstream()->WritePrintf("HTTP/1.1 %d OK\r\n", 200);
        context->writer()->Outstream()->WritePrintf("Content-Type: %s\r\n", "application/octet-stream");
        context->writer()->Outstream()->WritePrintf("Content-Length: %lld\r\n\r\n", frs_->Length());
        context->writer()->HeadDone();
      }

      //write body
      size_t r = frs_->Read(&buf_[0], buf_.size());
      if (r == 0) {
        tunolog("writing (EOF) %lld/%lld" , frs_->ReadSize(), frs_->Length());
        context->writer()->BodyDone();
        return 0;
      }

      context->writer()->Outstream()->Write(&buf_[0], (int)r);
      tunolog("writing %s %lld/%lld" , file_name_.c_str(), frs_->ReadSize(), frs_->Length());

      if (frs_->ReadSize() >= frs_->Length()) {
        tunolog("writing DONE %s %lld/%lld" , file_name_.c_str(), frs_->ReadSize(), frs_->Length());
        context->writer()->BodyDone();
        return 0;
      }
      
      return 0;
    };
  };
private:
  std::string root_path_;
  std::shared_ptr<fs::FileReadStream> frs_;
  std::string file_name_;
  std::string buf_;
};

/************************************************
 * DownloadHandlerFactory
 ***********************************************/
class DownloadHandlerFactory: public HttpServer::HandlerFactory {
public:
  DownloadHandlerFactory(int method, const char *path, const char *root_path)
  :HttpServer::HandlerFactory(method, path) {
    root_path_ = root_path;
  };

  static std::shared_ptr<DownloadHandlerFactory> New(int method, const char *path, const char *root_path) {
    return std::shared_ptr<DownloadHandlerFactory>(
      new DownloadHandlerFactory(method, path, root_path));
  };

  virtual std::shared_ptr<HttpServer::Handler> NewHandler() { 
    return std::shared_ptr<HttpServer::Handler>(
        new DownloadHandler(method_, path_.c_str(), root_path_.c_str()));
  };

private:
  int method_ = 0;
  std::string root_path_;
};


/************************************************
 * UploadHandler 
 ***********************************************/
class UploadHandler: public HttpServer::Handler {
public:
  UploadHandler(int method, const char *path, const char *root_path)
    :HttpServer::Handler(method, path, nullptr) {
      root_path_ = std::string(root_path);
  };

  virtual ~UploadHandler() {
    ;
  };

  static std::shared_ptr<UploadHandler> New(int method, const char *path, const char *root_path) {
    return std::shared_ptr<UploadHandler>(new UploadHandler(method, path, root_path));
  };

  HttpServer::HandlerCb GetHandlerCb() {
    return [this](std::shared_ptr<HttpServer::Context> context
                , std::string &response) -> int {
      // Due to async operation, so this handler callback will call multi times when reader/writer is ready to read/write. 

      // open file for write
      if (fws_.get() == nullptr) {
        std::string file_name = context->reader()->GetHeader()->GetAttachmentFilename();
        if (file_name.empty()) {
          tunosetmsg("failed to get header of \"Content-Disposition: attachment; filename=\"");
          return -1;
        }
        file_name_ = file_name;

        fs::mkdir(root_path_.c_str());
        std::string file_path = root_path_ + "/" + file_name_;
        
        tunolog("file_path:'%s' file:'%s'", file_path.c_str(), file_name_.c_str());

        fws_ = std::shared_ptr<fs::FileWriteStream>(new fs::FileWriteStream());
        if (fws_->Open(file_path)) {
          tunosetmsg("failed to open %s", file_path.c_str());
          return -1;
        }
      }

      if (response.size() > 0) {
        fws_->Write(&response[0], response.size());
      }

      if (count_++%100 == 0) {
        tunolog("upload %s %lld/%lld %d" , file_name_.c_str(), fws_->WriteSize(), context->reader()->ContentLength(), count_);
      }
 
      if (fws_->WriteSize() >= context->reader()->ContentLength()) {
        tunolog("upload DONE %s %lld/%lld" , file_name_.c_str(), fws_->WriteSize(), context->reader()->ContentLength());
        context->writer()->Outstream()->WritePrintf("HTTP/1.1 %d OK\r\n", 200);
        context->writer()->Outstream()->WritePrintf("Content-Length: 0\r\n\r\n"); 
        context->writer()->HeadDone();
        context->writer()->BodyDone();
      }

      return 0;
    };
  };
private:
  int count_ = 0;
  std::string root_path_;
  std::shared_ptr<fs::FileWriteStream> fws_;
  std::string file_name_;
  std::string buf_;
};

/************************************************
 * UploadHandlerFactory
 ***********************************************/
class UploadHandlerFactory: public HttpServer::HandlerFactory {
public:
  UploadHandlerFactory(int method, const char *path, const char *root_path)
  :HttpServer::HandlerFactory(method, path) {
    root_path_ = root_path;
  };

  static std::shared_ptr<UploadHandlerFactory> New(int method, const char *path, const char *root_path) {
    return std::shared_ptr<UploadHandlerFactory>(
      new UploadHandlerFactory(method, path, root_path));
  };

  virtual std::shared_ptr<HttpServer::Handler> NewHandler() { 
    return std::shared_ptr<HttpServer::Handler>(
        new UploadHandler(method_, path_.c_str(), root_path_.c_str()));
  };

private:
  int method_ = 0;
  std::string root_path_;
};

int main(int argc, char* argv[]) {
  struct event_base *ev_base = NULL;

  if (tuno_sys_socket_init()) {
    tunolog("failed to socket_library_init()");
    return -1;
  }

  if ((ev_base = event_base_new()) == NULL) {
    tunolog("failed to event_base_new()");
    return -1;
  }

  /**
   * test commnad:
   *    ./runtime.linux/bin/http_client 1
   *    ./runtime.linux/bin/http_client 2
   *    curl https://127.0.0.1:1443/index.htm -k
   **/ 

  std::shared_ptr<HttpServer::Router> router(new HttpServer::Router());
  
  //with custom HandlerFactory. with custom Handler
  router->Add(DownloadHandlerFactory::New(HttpServer::GET, "/dwload", "."));
  
  //with custom HandlerFactory. with custom Handler
  router->Add(UploadHandlerFactory::New(HttpServer::GET, "/upload", "upload"));

  //without custom HandlerFactory and custom Handler
  const char *index_htm = "/index.htm";
  router->AddHandlerCb(HttpServer::GET, index_htm
    , [&](std::shared_ptr<HttpServer::Context> context, std::string &response) -> int {
   
      //write head
      if (!context->writer()->IsHeadDone()) {
        context->writer()->Outstream()->WritePrintf("HTTP/1.1 %d OK\r\n", 200);
        context->writer()->Outstream()->WritePrintf("Content-Type: %s\r\n", "text/html");
        context->writer()->Outstream()->WritePrintf("Content-Length: 13\r\n\r\n");
        context->writer()->HeadDone();
      }

      //write body
      if (!context->writer()->IsBodyDone()) {
        context->writer()->Outstream()->WritePrintf("HELLO WORLD!\n");
        context->writer()->HeadDone();
      }

      return 0;
    }
  );

  bool ssl = true;
  int port = 1443;
  std::string cert_crt = "x509.crt";
  std::string cert_key = "x509.key";
  int timeout_sec = 10;
  int timeout_usec = 0;

  auto server = HttpServer::Server::Listen(
        ev_base
        , router
        , port
        , ssl ? cert_crt : ""
        , ssl ? cert_key : ""
        , timeout_sec
        , timeout_usec);
  if (server.get() == nullptr) {
    tunosetmsg2();
    tunolog(tunogetmsg());
    return -1;
  }

  int ret;
  if ((ret = event_base_dispatch(ev_base))) {
    tunolog("ret NOT zero: %d", ret);
#ifdef __WIN32__
    tunolog("WSAGetLastError %d", WSAGetLastError());
#endif
  }

  if (ev_base) {
    event_base_free(ev_base);
  }
  tunolog("EXIT");
  return 0;
}

