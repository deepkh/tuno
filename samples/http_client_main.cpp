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

/************************************************
 * DownloadHandler 
 ***********************************************/
class DownloadHandler: public HttpClient::Handler {
public:
  DownloadHandler(HttpClient::URL url, const char *save_path)
    :HttpClient::Handler(HttpClient::GET, url) {
      save_path_ = std::string(save_path);
  };

  virtual ~DownloadHandler() {
    ;
  };

  static std::shared_ptr<DownloadHandler> New(HttpClient::URL url, const char *save_path) {
    return std::shared_ptr<DownloadHandler>(new DownloadHandler(url, save_path));
  };

  HttpClient::HandlerCb Handlercb() {
    return [this](std::shared_ptr<HttpClient::Context> context, std::string &response) -> int {
      // Due to async operation, so this handler callback will call multi times when reader/writer is ready to read/write. 
      
      //request (could add custom request headers here)
      if (!context->writer()->IsHeadDone()) {
        context->writer()->Outstream()->WritePrintf("\r\n"); 
        context->writer()->HeadDone();
        context->writer()->BodyDone();
      }

      //response
      if (response.size() == 0) {
        return 0;
      }

      //create output file
      if (this->fws_.get() == nullptr) {
        this->file_name_ = "index.htm";
        std::size_t found = this->Url().Path().rfind("/");
        if (found!=std::string::npos) {
          this->file_name_ = this->Url().Path().substr(found);
          if (this->file_name_.size() == 1) {
            this->file_name_ += "index.htm";
          }
        }

        fs::mkdir(this->save_path_.c_str());
        std::string file = this->save_path_ + this->file_name_;
        this->fws_ = std::shared_ptr<fs::FileWriteStream>(new fs::FileWriteStream());
        if (this->fws_->Open(file)) {
          tunosetmsg("failed to open %s", file.c_str());
          return -1;
        }
      }

      if (context->reader()->ChunkedMode() || count_++%100 == 0) {
        tunolog("%s read %d %lld/%lld"
            , this->file_name_.substr(1).c_str()
            , response.size()
            , context->reader()->ReadLength()
            , context->reader()->ContentLength());
      }
     
      //write
      this->fws_->Write(&response[0], response.size());
      if (context->reader()->IsBodyDone()) {
        tunolog("%s read done %d %lld/%lld"
            , this->file_name_.substr(1).c_str()
            , response.size()
            , context->reader()->ReadLength()
            , context->reader()->ContentLength());
        this->fws_ = nullptr;
      }
      return 0;
    };
  };
private:
  int count_ = 0;
  std::string file_name_;
  std::string save_path_;
  std::shared_ptr<fs::FileWriteStream> fws_;
};


/************************************************
 * UploadHandler 
 ***********************************************/
class UploadHandler: public HttpClient::Handler {
public:
  UploadHandler(HttpClient::URL url, const char *upload_file)
    :HttpClient::Handler(HttpClient::PUT, url) {
      upload_file_ = std::string(upload_file);
      file_name_ = upload_file_.substr(upload_file_.rfind("/")+1);
      tunolog("%s %s", upload_file_.c_str(), file_name_.c_str());
  };

  virtual ~UploadHandler() {
    ;
  };

  static std::shared_ptr<UploadHandler> New(HttpClient::URL url, const char *upload_file) {
    return std::shared_ptr<UploadHandler>(new UploadHandler(url, upload_file));
  };

  HttpClient::HandlerCb Handlercb() {
    return [this](std::shared_ptr<HttpClient::Context> context, std::string &response) -> int {
      // Due to async operation, so this handler callback will call multi times when reader/writer is ready to read/write. 

      // open file for upload
      if (frs_.get() == nullptr) {
        frs_ = std::shared_ptr<fs::FileReadStream>(new fs::FileReadStream());
        if (frs_->Open(upload_file_)) {
          tunosetmsg("failed to open %s", upload_file_.c_str());
          return -1;
        }
      }
      
      //request header (could add custom request headers here)
      if (!context->writer()->IsHeadDone()) {
        context->writer()->Outstream()->WritePrintf(
            "Content-Disposition: attachment; filename=%s\r\n", file_name_.c_str());
        context->writer()->Outstream()->WritePrintf(
            "Content-Type: %s\r\n", "application/octet-stream");
        context->writer()->Outstream()->WritePrintf(
            "Content-Length: %lld\r\n", frs_->Length());
        context->writer()->Outstream()->WritePrintf("\r\n"); 
        context->writer()->HeadDone();
      }
  
      //request body
      if (frs_->ReadSize() < frs_->Length()) {
        int64_t remaining_size = frs_->Length() - frs_->ReadSize();
        buf_.resize(remaining_size < 4096 ? remaining_size : 4096);
        
        size_t r = frs_->Read(&buf_[0], buf_.size()); 
        if (r == 0) {
          tunolog("upload %s DONE 1 %lld/%lld", file_name_.c_str(), frs_->ReadSize(), frs_->Length());
          context->writer()->BodyDone();
          return 0;
        }
      
        context->writer()->Outstream()->Write(&buf_[0], r/*buf_.size()*/);
        tunolog("upload %s %lld/%lld", file_name_.c_str(), frs_->ReadSize(), frs_->Length());
      }
        
      if (frs_->ReadSize() >= frs_->Length()) {
        tunolog("upload %s DONE 2 %lld/%lld", file_name_.c_str(), frs_->ReadSize(), frs_->Length());
        context->writer()->BodyDone();
        return 0;
      }

      //response
      if (response.size() == 0) {
        return 0;
      }

      tunolog("upload %s response: %s", file_name_.c_str(), response.c_str());
      return 0;
    };
  };
private:
  int count_ = 0;
  std::string file_name_;
  std::string upload_file_;
  std::string buf_;
  std::shared_ptr<fs::FileReadStream> frs_;
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

  int test_case = -1;
  if (argc == 2) {
    test_case = atoi(argv[1]);
  }

  // These demo show how to use the async http client with SSL support and cert checking.
  // Due to all working on async operation, so you could create so many HttpClient::Connection at same time
  // and the libtuno will processing the HttpClient::Connection in parallel

  std::shared_ptr<HttpClient::Connection> download_index_htm;
  if (test_case == -1 
      || test_case == 0) {
     download_index_htm = HttpClient::Connection::Connect(ev_base, 
      HttpClient::Handler::New(
        HttpClient::PUT, HttpClient::URL::Parse("https://127.0.0.1:1443/index.htm"
                              , "/etc/ssl/certs/ca-certificates.crt"
                              , false)
        , [&](std::shared_ptr<HttpClient::Context> context, std::string &response) -> int {
      
          //request (could add custom request headers here)
          if (!context->writer()->IsHeadDone()) {
            context->writer()->Outstream()->WritePrintf("\r\n"); 
            context->writer()->HeadDone();
            context->writer()->BodyDone();
          }

          //response
          if (response.size() == 0) {
            return 0;
          }

          tunolog("%s", response.c_str());
          return 0;
        }
      )
    );

    if (download_index_htm.get() == nullptr) {
      tunosetmsg2();
      tunolog("%s", tunogetmsg());
      return -1;
    }
  }


  std::shared_ptr<HttpClient::Connection> download_by_content_length;
  if (test_case == -1 
      || test_case == 1) {
     download_by_content_length = HttpClient::Connection::Connect(ev_base, 
      DownloadHandler::New(
        HttpClient::URL::Parse("https://127.0.0.1:1443/dwload/test_file/10m.bin"
                              , "/etc/ssl/certs/ca-certificates.crt"
                              , false)
        , "download"
      )
    );

    if (download_by_content_length.get() == nullptr) {
      tunosetmsg2();
      tunolog("%s", tunogetmsg());
      return -1;
    }
  }

  std::shared_ptr<HttpClient::Connection> upload_by_content_length;
  if (test_case == -1 
      || test_case == 2) {
    upload_by_content_length = HttpClient::Connection::Connect(ev_base, 
      UploadHandler::New(
        HttpClient::URL::Parse("https://127.0.0.1:1443/upload"
                              , "/etc/ssl/certs/ca-certificates.crt"
                              , false)
        , "test_file/10m.bin"
      )
    );

    if (upload_by_content_length.get() == nullptr) {
      tunosetmsg2();
      tunolog("%s", tunogetmsg());
      return -1;
    }
  }
  
  std::shared_ptr<HttpClient::Connection> download_by_content_length_2;
  if (test_case == -1 
      || test_case == 3) {
    download_by_content_length_2 = HttpClient::Connection::Connect(ev_base, 
      DownloadHandler::New(
        HttpClient::URL::Parse("https://127.0.0.1:1443/dwload/test_file/10m.bin2"
                              , "/etc/ssl/certs/ca-certificates.crt"
                              , false)
        , "download"
      )
    );

    if (download_by_content_length_2.get() == nullptr) {
      tunosetmsg2();
      tunolog("%s", tunogetmsg());
      return -1;
    }
  }

  std::shared_ptr<HttpClient::Connection> download_by_chunked_str;
  if (test_case == -1 
      || test_case == 4) {
    download_by_chunked_str = HttpClient::Connection::Connect(ev_base, 
      DownloadHandler::New(HttpClient::URL::Parse(
                            "https://www.nginx.com/"
                            , "/etc/ssl/certs/ca-certificates.crt"
                            , true)
        , "download")
    );

    if (download_by_chunked_str.get() == nullptr) {
      tunosetmsg2();
      tunolog("%s", tunogetmsg());
      return -1;
    }
  }

  while(event_base_loop(ev_base, EVLOOP_ONCE | EVLOOP_NONBLOCK) == 0) {
    ;
  }
  //or loop forever by use
  //event_base_dispatch(ev_base);
  return 0;
}

