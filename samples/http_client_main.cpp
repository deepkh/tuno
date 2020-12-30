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
#include "http/http_client.h"
#include "util/json_helper.h"
#include "util/file_stream.h"

/***************************************************
 * CustomFileDownloadContentHandler
 **************************************************/
class CustomFileDownloadContentHandler: public HttpClient::ReadContentHandler {
public:
  CustomFileDownloadContentHandler() {
    ;
  };
  ~CustomFileDownloadContentHandler() {
    ;
  };

  virtual int Init(std::shared_ptr<Http::Context> context) override {
    if (fws_.get() != nullptr) {
      fws_ = std::shared_ptr<fs::FileWriteStream>();
    }

    //create output file
    std::string path = context->GetURL()->Path();

    if (path.at(path.length()-1) == '/') {
      path = "/index.htm";
    }

    std::string file_name = path.substr(path.rfind("/")+1);
    file_name_ = file_name;
    file_name = std::string("download/") + file_name;
    fs::mkdir("download");

    fws_ = std::shared_ptr<fs::FileWriteStream>(new fs::FileWriteStream());
    if (fws_->Open(file_name)) {
      tunosetmsg("failed to open %s", path.c_str());
      return -1;
    }

    return 0;
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

  virtual int Finish(std::shared_ptr<Http::Context> context, int error) override {
    if (fws_.get() != nullptr) {
      fws_ = std::shared_ptr<fs::FileWriteStream>();
    }
    return 0;
  };

private:
  std::shared_ptr<fs::FileWriteStream> fws_;
  int64_t content_length_ = -2;
  bool is_checked_ = false;
  std::string file_name_;
};

/***************************************************
 * CustomFileUploadContentHandler
 **************************************************/
class CustomFileUploadContentHandler: public HttpClient::WriteContentHandler {
public:
  CustomFileUploadContentHandler() {
  };
  ~CustomFileUploadContentHandler() {
    ;
  };

  virtual int Init(std::shared_ptr<Http::Context> context) override {
    std::shared_ptr<HttpClient::URL> url = std::dynamic_pointer_cast<HttpClient::URL>(context->GetURL());
    file_path_ = url->FileForUpload();
    file_name_ = file_path_.substr(file_path_.rfind("/")+1);

    //tunolog("%s %s", file_path_.c_str(), file_name_.c_str());
    
    if (frs_.get() != nullptr) {
      frs_ = std::shared_ptr<fs::FileReadStream>();
    }

    frs_ = std::shared_ptr<fs::FileReadStream>(new fs::FileReadStream());
    if (frs_->Open(file_path_)) {
      tunosetmsg("failed to open %s", file_path_.c_str());
      return -1;
    }
    
    //tunolog("file:%s size: %" PRId64 "", file_path_.c_str(), frs_->Length());
    return 0;
  };

  virtual std::string &FileName(std::shared_ptr<Http::Context> context) override {
    return file_name_;
  };

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
        tunolog("writing %s DONE %" PRId64 "/%" PRId64 , file_name_.c_str(), frs_->ReadSize(), frs_->Length());
        return TUNO_STATUS_DONE;
      }
    }

    return TUNO_STATUS_NOT_DONE;
  };

  virtual int DoReadContent(std::shared_ptr<Http::Context> context) override {
    return TUNO_STATUS_DONE;
  };

  virtual int Finish(std::shared_ptr<Http::Context> context, int error) override {
    if (frs_.get() != nullptr) {
      frs_ = std::shared_ptr<fs::FileReadStream>();
    }
    return 0;
  };

private:
  std::string file_path_;
  std::string file_name_;
  std::shared_ptr<fs::FileReadStream> frs_;
  char buf_[4096];
};



/***************************************************
 * ContentHandlerFactory
 **************************************************/
class CustomContentHandlerFactory: public Http::ContentHandlerFactory {
public:
  CustomContentHandlerFactory() {
    ;
  };
  ~CustomContentHandlerFactory() {
    ;
  };
  virtual std::shared_ptr<Http::ReadContentHandler> FindReadContentHandler(std::shared_ptr<Http::URL> url) override  {
    std::shared_ptr<Http::ReadContentHandler> read_content_handle;
    read_content_handle = std::shared_ptr<Http::ReadContentHandler>(new CustomFileDownloadContentHandler());
    return read_content_handle;
  };

  virtual std::shared_ptr<Http::WriteContentHandler> FindWriteContentHandler(std::shared_ptr<Http::URL> url) override {
    std::shared_ptr<Http::WriteContentHandler> write_content_handle;
    write_content_handle = std::shared_ptr<Http::WriteContentHandler>(new CustomFileUploadContentHandler());
    return write_content_handle;
  };
};


int main(int argc, char* argv[]) {
  int index = -1;
  int end_index = -1;
  std::string json_str = R"(
[
  {
    "url": {
      "host" : "www.nginx.com",
      "path" : "/nginx-app-protect/admin-guide/install/",
      "port" : 443,
      "ssl" : true,
      "method": 0,
      "file_for_upload": "",
      "ssl_do_cert_verify": true,
      "ssl_ca_cert_file": "/etc/ssl/certs/ca-certificates.crt"
    }
  },

  {
    "url": {
      "host" : "netsync.tv",
      "path" : "/",
      "port" : 443,
      "ssl" : true,
      "method": 0,
      "file_for_upload": "",
      "ssl_do_cert_verify": true,
      "ssl_ca_cert_file": "/etc/ssl/certs/ca-certificates.crt"
    }
  },

  {
    "url": {
      "host" : "127.0.0.1",
      "path" : "/upload",
      "port" : 1443,
      "ssl" : true,
      "method": 1,
      "file_for_upload": "test_file/10m.bin",
      "ssl_do_cert_verify": true,
      "ssl_ca_cert_file": "x509.crt"
    }
  },

  {
    "url": {
      "host" : "127.0.0.1",
      "path" : "/dwload/test_file/10m.bin",
      "port" : 1443,
      "ssl" : true,
      "method": 0
    }
  },

  {
    "url": {
      "host" : "ftp.tku.edu.tw",
      "path" : "/ubuntu-releases/20.04.1/SHA256SUMS",
      "port" : 80,
      "ssl" : false,
      "method": 0
    }
  },
  {
    "url": {
      "host" : "saimei.ftp.acc.umu.se",
      "path" : "/debian-cd/10.7.0/amd64/iso-dvd/MD5SUMS",
      "port" : 443,
      "ssl" : true,
      "method": 0,
      "ssl_do_cert_verify": true,
      "ssl_ca_cert_file": "/etc/ssl/certs/ca-certificates.crt"
    }
  }
]
)";
  struct event_base *ev_base = NULL;
  std::shared_ptr<HttpClient::DefaultHandlerFactory> default_handler_factory(
      new HttpClient::DefaultHandlerFactory(
        std::shared_ptr<Http::ContentHandlerFactory>(new CustomContentHandlerFactory())
   ));
  std::shared_ptr<HttpClient::URLFactory> url_factory(new HttpClient::URLFactory());
  std::shared_ptr<HttpClient::URL> url;
  std::shared_ptr<HttpClient::Parallel> parallel(new HttpClient::Parallel());
  int i = 0;

  if (tuno_sys_socket_init()) {
    tunolog("failed to socket_library_init()");
    goto finally;
  }

  if (url_factory->Init(json_str)) {
    tunosetmsg2();
    tunolog("%s", tunogetmsg());
    goto finally;
  }

  if ((ev_base = event_base_new()) == NULL) {
    tunolog("failed to event_base_new()");
    goto finally;
  }

  if (parallel->Init(ev_base, default_handler_factory)) {
    tunosetmsg2();
    tunolog("%s", tunogetmsg());
    goto finally;
  }

  if (argc >= 2) {
    index = atoi(argv[1]);
  }
  
  if (argc == 3) {
    end_index = atoi(argv[2]);
  }

  tunolog("%d %d", index, end_index);
  while((url = std::dynamic_pointer_cast<HttpClient::URL>(url_factory->NextURL())).get() != nullptr) {
    if (index != -1 && end_index != -1) {
      if (!(i >= index && i <= end_index)) {
        i++;
        continue;
      }
    } else if (index != -1) {
      if (index != i) {
        i++;
        continue;
      }
    }

    tunolog("\n%d", i++);
    tunolog("\thost = %s", url->Host().c_str());
    tunolog("\tport = %d", url->Port());
    tunolog("\tssl = %d", url->IsSSL());
    tunolog("\tpath = %s", url->Path().c_str());
    tunolog("\tfile_for_upload = %s", url->FileForUpload().c_str());

    if (parallel->Connect(url)) {
      tunosetmsg2();
      tunolog(tunogetmsg());
      break;
    }
  }

  while(event_base_loop(ev_base, EVLOOP_ONCE | EVLOOP_NONBLOCK) == 0) {
  }
  //or loop forever by use
  //event_base_dispatch(ev_base);
finally:
  return 0;
}
