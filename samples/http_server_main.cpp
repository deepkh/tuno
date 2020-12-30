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

/***************************************************
 * CustomFileDownloadContentHandler
 **************************************************/
class CustomFileDownloadContentHandler: public HttpServer::WriteContentHandler {
public:
  CustomFileDownloadContentHandler(std::string path_prefix, Json::Value &server_config) {
    path_prefix_ = path_prefix;
    server_config_ = server_config;
  };
  ~CustomFileDownloadContentHandler() {
    ;
  };

  virtual int Init(std::shared_ptr<Http::Context> context) override {
    std::string path = context->GetURL()->Path();
    path = path.substr(path_prefix_.length(), path.length() - path_prefix_.length());
    file_name_ = path;
    path = server_config_["http_server"]["file_download_path"].asString() + path;

    if (frs_.get() != nullptr) {
      frs_ = std::shared_ptr<fs::FileReadStream>();
    }

    frs_ = std::shared_ptr<fs::FileReadStream>(new fs::FileReadStream());
    if (frs_->Open(path)) {
      tunosetmsg("failed to open %s", path.c_str());
      return -1;
    }
    
    //tunolog("file:%s size: %" PRId64 "", path.c_str(), frs_->Length());
    return 0;
  };

  virtual int StatusCode(std::shared_ptr<Http::Context> context) override {
    return frs_->IsOpen() ? 200 : 404;
  }

  virtual int64_t ContentLength(std::shared_ptr<Http::Context> context) override {
    return frs_->Length();
  };

  virtual const char *ContentType(std::shared_ptr<Http::Context> context) override {
    return "application/octet-stream";
  };

  virtual int DoWriteContent(std::shared_ptr<Http::Context> context) override {

    if (!frs_->IsOpen()) {
      return TUNO_STATUS_DONE;
    }

    size_t r = frs_->Read(buf_, sizeof(buf_));
    if (r == 0) {
      tunolog("writing (EOF) %" PRId64 "/%" PRId64 , frs_->ReadSize(), frs_->Length());
      return TUNO_STATUS_DONE;
    }

    context->Outstream()->Write(buf_, (int)r);
    tunolog("writing %s %" PRId64 "/%" PRId64 , file_name_.c_str(), frs_->ReadSize(), frs_->Length());

    if (frs_->Length() > 0) {
      if (frs_->ReadSize() >= frs_->Length()) {
        tunolog("writing DONE %s %" PRId64 "/%" PRId64 , file_name_.c_str(), frs_->ReadSize(), frs_->Length());
        return TUNO_STATUS_DONE;
      }
    }

    return TUNO_STATUS_NOT_DONE;
  };

  virtual int Finish(std::shared_ptr<Http::Context> context, int error) override {
    if (frs_.get() != nullptr) {
      frs_ = std::shared_ptr<fs::FileReadStream>();
    }
    return 0;
  };

private:
  std::string path_prefix_;
  Json::Value server_config_;
  std::shared_ptr<fs::FileReadStream> frs_;
  std::string file_name_;
  char buf_[4096];
};


/***************************************************
 * CustomFileUploadContentHandler
 **************************************************/
class CustomFileUploadContentHandler: public HttpServer::ReadContentHandler {
public:
  CustomFileUploadContentHandler(std::string path_prefix, Json::Value &server_config) {
    server_config_ = server_config;
  };
  ~CustomFileUploadContentHandler() {
    ;
  };

  virtual int Init(std::shared_ptr<Http::Context> context) override {
    if (fws_.get() != nullptr) {
      fws_ = std::shared_ptr<fs::FileWriteStream>();
    }

    std::string file_name = context->Instream()->GetHeader()->GetAttachmentFilename();
    if (file_name.empty()) {
      tunosetmsg("failed to get header of \"Content-Disposition: attachment; filename=\"");
      return -1;
    }
    file_name_ = file_name;

    std::string path = server_config_["http_server"]["file_upload_path"].asString();
    fs::mkdir(path.c_str());
    path += "/";
    path += file_name;

    fws_ = std::shared_ptr<fs::FileWriteStream>(new fs::FileWriteStream());
    if (fws_->Open(path)) {
      tunosetmsg("failed to open %s", path.c_str());
      return -1;
    }

    return 0;
  };

  virtual int StatusCode(std::shared_ptr<Http::Context> context) override {
    return fws_->IsOpen() ? 200 : 501;
  };

  virtual int64_t ContentLength(std::shared_ptr<Http::Context> context) override {
    return 0;
  };

  virtual const char *ContentType(std::shared_ptr<Http::Context> context) override {
    return "text/html";
  };

  virtual int DoReadContentByLength(std::shared_ptr<Http::Context> context, char *buf, int size) override {
    if (content_length_ == -2) {
      content_length_ = context->Instream()->GetHeader()->GetContentLength();
    }
   
    fws_->Write(buf, size);
    //tunolog("\"%s\"", buf);
  
    tunolog("loading %s %" PRId64 "/%" PRId64 , file_name_.c_str(), fws_->WriteSize(), content_length_);
    if ((content_length_ >= 0 && fws_->WriteSize() >= content_length_)) {
      tunolog("loading DONE %s %" PRId64 "/%" PRId64 
          , file_name_.c_str(), fws_->WriteSize(), content_length_);
    }
    return 0;
  };

  virtual int DoReadContentByChunkString(std::shared_ptr<Http::Context> context, std::string &chunk_str) override {
    fws_->Write((char *)chunk_str.c_str(), chunk_str.size());
    tunolog("loading (chunk) %s %" PRId64 "", file_name_.c_str(), fws_->WriteSize());
    return 0;
  };

  virtual int DoWriteContent(std::shared_ptr<Http::Context> context) override {
    return TUNO_STATUS_DONE;
  };

  virtual int Finish(std::shared_ptr<Http::Context> context, int error) override {
    if (fws_.get() != nullptr) {
      fws_ = std::shared_ptr<fs::FileWriteStream>();
    }
    return 0;
  };

private:
  Json::Value server_config_;
  std::shared_ptr<fs::FileWriteStream> fws_;
  int64_t content_length_ = -2;
  std::string file_name_;
};



/***************************************************
 * CustomContentHandlerFactory
 **************************************************/
class CustomContentHandlerFactory: public Http::ContentHandlerFactory {
public:
  CustomContentHandlerFactory(Json::Value &server_config) {
    server_config_ = server_config;
  };
  ~CustomContentHandlerFactory() {
    ;
  };
  virtual std::shared_ptr<Http::ReadContentHandler> FindReadContentHandler(std::shared_ptr<Http::URL> url) override  {
    std::shared_ptr<Http::ReadContentHandler> read_content_handle;
    if (url->Path().compare("/upload") == 0) {
      read_content_handle = std::shared_ptr<Http::ReadContentHandler>(
          new CustomFileUploadContentHandler("/upload", server_config_));
    }
    return read_content_handle;
  };

  virtual std::shared_ptr<Http::WriteContentHandler> FindWriteContentHandler(std::shared_ptr<Http::URL> url) override {
    std::shared_ptr<Http::WriteContentHandler> write_content_handle;
    if (url->Path().compare(0, 7, "/dwload") == 0) {
      write_content_handle = std::shared_ptr<Http::WriteContentHandler>(
          new CustomFileDownloadContentHandler("/dwload", server_config_)
      );
    }
    return write_content_handle;
  };
private:
  Json::Value server_config_;
};



int main(int argc, char* argv[]) {
  std::string server_config = R"(
{
    "http_server": {
      "file_download_path" : ".",
      "file_upload_path" : "upload",
      "port" : 1443,
      "ssl" : 1,
      "cert_crt": "x509.crt",
      "cert_key": "x509.key"
    }
}
)";

  Json::Value json_config; 
  int ret = -1;
  int port = -1;
  int ssl = 0;
  struct event_base *ev_base = NULL;
  std::shared_ptr<HttpServer::DefaultHandlerFactory> default_handler_factory;
  std::shared_ptr<HttpServer::Server> server(new HttpServer::Server());

  if (JsonParser::ParseFromString(server_config, json_config)) {
    tunolog(tunogetmsg());
    goto finally;
  }

  default_handler_factory = std::shared_ptr<HttpServer::DefaultHandlerFactory>(
      new HttpServer::DefaultHandlerFactory(
        std::shared_ptr<Http::ContentHandlerFactory>(new CustomContentHandlerFactory(json_config))
  ));

  tunolog("json_config", json_config["http_server"]["static_file_path"].asString().c_str());
  tunolog("\tstatic_file_path: %s", json_config["http_server"]["static_file_path"].asString().c_str());
  tunolog("\tport: %d", json_config["http_server"]["port"].asInt());
  tunolog("\tssl: %d", json_config["http_server"]["ssl"].asInt());
  tunolog("\tcert_crt: %s", json_config["http_server"]["cert_crt"].asString().c_str());
  tunolog("\tcert_key: %s", json_config["http_server"]["cert_key"].asString().c_str());

  if (tuno_sys_socket_init()) {
    tunolog("failed to socket_library_init()");
    goto finally;
  }

  if (argc >= 2 && argc <= 3) {
    if (argc == 3) {
      ssl = atoi(argv[2]);
    }
    port = atoi(argv[1]);
  } else {
     ssl = json_config["http_server"]["ssl"].asInt();
     port = json_config["http_server"]["port"].asInt();
  }

  tunolog("ssl:%d port:%d\n", ssl, port);

  if ((ev_base = event_base_new()) == NULL) {
    tunolog("failed to event_base_new()");
    goto finally;
  }

  if (server->Init(ev_base, default_handler_factory)) {
    tunosetmsg2();
    tunolog(tunogetmsg());
    goto finally;
  }

  if (server->Listen(
        port
        , ssl ? json_config["http_server"]["cert_crt"].asString() : ""
        , ssl ? json_config["http_server"]["cert_key"].asString() : "")) {
    tunosetmsg2();
    tunolog(tunogetmsg());
    goto finally;
  }
  
  if ((ret = event_base_dispatch(ev_base))) {
    tunolog("ret NOT zero: %d", ret);
#ifdef __WIN32__
    tunolog("WSAGetLastError %d", WSAGetLastError());
#endif
  }
finally:
  if (ev_base) {
    event_base_free(ev_base);
  }
  tunolog("EXIT");
  return 0;
}

