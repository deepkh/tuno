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
#include "http.h"

static int get_head_val(const char *head, const char *key, char *val)
{
	char *s = NULL;
	int val_len = 0;

	if ((s = strstr((char *)head, key)) == NULL) {
		return 0;
	}
	
	s += strlen(key);
	val_len = strstr(s, "\r\n") - s;

	memcpy(val, s, val_len);
  val[val_len] = 0;
	return 1;
}

#if 0
static int get_head_int_val(char *head, const char *key, int *val)
{
	char tmp[32];

	if (get_head_val(head, key, tmp) == 0) {
		return 0;
	}
	
	*val = atoi(tmp);
	return 1;
}
#endif

static int get_head_int64_val(const char *head, const char *key, int64_t *val)
{
	char tmp[256];

	if (get_head_val(head, key, tmp) == 0) {
		return 0;
	}

	*val = _atoi64(tmp);
	return 1;
}

/************************************************
 * Http::Header
 ***********************************************/
Http::Header::Header() {
  header_[0] = 0;
};

Http::Header::~Header() {
  ;
};

int Http::Header::SetHeaderString(char *buf, int size) {
  header_.assign(buf, size);
  return 0;
};

std::string &Http::Header::GetHeaderString() {
  return header_;
};

std::string Http::Header::find_header_value(const char *key)
{
  int key_len = strlen(key);
  std::string transfer_encoding = "";
  size_t pos_start;
  if ((pos_start = header_.find(key)) == std::string::npos) {
    return transfer_encoding;
  }

  size_t pos_end;
  if ((pos_end = header_.find("\r\n", pos_start)) == std::string::npos) {
    return transfer_encoding;
  }

  transfer_encoding = header_.substr(pos_start + key_len, pos_end - pos_start - key_len);
  return transfer_encoding;
}


int64_t Http::Header::GetContentLength() {
  int64_t content_length = -1;
  if (get_head_int64_val(header_.c_str(), "Content-Length: ", &content_length)) {
    //tunolog("content_size: %" PRId64 , content_length);
  }
  return content_length;
};

void Http::Header::AppendHeader(const char *fmt, ...) {
  char tmp[256];
  int len;
  va_list ap;
  va_start(ap, fmt);
  //len = vsnprintf(header_ + header_size_, sizeof(header_) - header_size_ - 1, fmt, ap);
  //header_size_ += len;
  len = vsnprintf(tmp, sizeof(tmp) - 1, fmt, ap);
  tmp[len] = 0;
  header_.append(tmp);
  va_end(ap);
};

std::string Http::Header::GetAttachmentFilename()
{
  return find_header_value("Content-Disposition: attachment; filename=");
}

std::string Http::Header::GetTransferEncoding()
{
  return find_header_value("Transfer-Encoding: ");
}

bool Http::Header::IsChunkedEncoding()
{
  std::string chunked = GetTransferEncoding();
  return chunked.compare("chunked") == 0 ? true : false;
}

/************************************************
 * Http::Status
 ***********************************************/
Http::Status::Status()
{

}

Http::Status::~Status()
{

}

int Http::Status::GetStatus()
{
  return status_;
}

void Http::Status::SetStatus(int new_status)
{
  status_ = new_status;
}

void Http::Status::AppendStatus(int append_status)
{
  status_ |= append_status;
}


/************************************************
 * Http::InputStream
 ***********************************************/
Http::InputStream::InputStream(struct tuno_socket *sk) {
  sk_ = sk;
  header_ = std::shared_ptr<Http::Header>(new Http::Header());
  status_ = std::shared_ptr<Http::Status>(new Http::Status());
};

Http::InputStream::~InputStream() {
  ;
};

void Http::InputStream::SetSocket(struct tuno_socket *sk) {
  sk_ = sk;
};

char *Http::InputStream::Buf(int len) {
  return (char *) tuno_socket_rbuf_pullup(sk_, len == 0 ? BufLen() : len);
};

int Http::InputStream::BufLen() {
  return tuno_socket_rbuf_length(sk_);
};

void Http::InputStream::BufRemove(int len) {
  tuno_socket_rbuf_remove(sk_, len);
};

std::shared_ptr<Http::Status> Http::InputStream::GetStatus() {
  return status_;
};

std::shared_ptr<Http::Header> Http::InputStream::GetHeader() {
  return header_;
};

static int parse_chunk_size(std::string &chunk_buf, int &chunk_size_str_length)
{
    int chunk_size;
    char *p;

    std::string chunk_size_str = chunk_buf.substr(0, chunk_buf.find("\r\n"));
    chunk_size_str_length = chunk_size_str.length();
    chunk_size = strtol( chunk_size_str.c_str(), & p, 16 );
    if (*p != 0) {
        tunolog("XX\n%s\n", chunk_size_str.c_str());
        return -1;
    }
    return chunk_size;
}

int Http::InputStream::ReadChunkString(std::string &chunk_str)
{
  char *buf = Buf();
  int len = BufLen();

  if (len == 0) {
    return TUNO_STATUS_DONE;
  }

  chunk_buf_.append(buf, len);
  BufRemove(len);

  if(chunk_buf_.length() > 0) {
    //parse chunk_size
    int chunk_size_str_length = 0;
    int chunk_size = parse_chunk_size(chunk_buf_, chunk_size_str_length);
    if (chunk_size == 0) {
      //tunolog("chunk_size:%d", chunk_size);
      return TUNO_STATUS_DONE;
    } else if (chunk_size < 0) {
      return TUNO_STATUS_ERROR;
    }

    //read chunk data
    if ((int)chunk_buf_.length() >= (chunk_size_str_length+2 + chunk_size+2)) {
      chunk_buf_.erase(0, chunk_size_str_length + 2);
      //tunolog("chunk_size:%d", chunk_size);
      
      chunk_str = chunk_buf_.substr(0, chunk_size);
      //tunolog("data:%s", chunk_str.c_str());
      chunk_buf_.erase(0, chunk_size+2);
      if (chunk_buf_.length() > 0) {
        //tunolog("remain:%d '%s'", chunk_buf_.length(), chunk_buf_.c_str());
      }
    }
  }

  return TUNO_STATUS_NOT_DONE;
}


/************************************************
 * Http::OutputStream
 ***********************************************/
Http::OutputStream::OutputStream(struct tuno_socket *sk) {
  sk_ = sk;
  header_ = std::shared_ptr<Http::Header>(new Http::Header());
  status_ = std::shared_ptr<Http::Status>(new Http::Status());
};

Http::OutputStream::~OutputStream() {
  ;
};

void Http::OutputStream::SetSocket(struct tuno_socket *sk) {
  sk_ = sk;
};

int Http::OutputStream::Write(char *buf, int size) {
  return tuno_socket_write(sk_, (uint8_t*) buf, size);
};

void Http::OutputStream::WritePrintf(const char *fmt, ...) {
  char buf[256];
  int len;
  va_list ap;
  va_start(ap, fmt);
  len = vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
  buf[len] = 0;
  if (strstr(buf, "\r\n")) {
    printf("%s", buf);
  } else {
    printf("%s\n", buf);
  }
  Write(buf, len);
  va_end(ap);
};

void Http::OutputStream::AddWriteNotify() {
  tuno_socket_add_notify_write(sk_, 0);
};

std::shared_ptr<Http::Status> Http::OutputStream::GetStatus() {
  return status_;
};

std::shared_ptr<Http::Header> Http::OutputStream::GetHeader() {
  return header_;
};


/************************************************
 * Http::Context
 ***********************************************/
Http::Context::Context(struct tuno_socket *sk) {
  sk_ = sk;
  input_stream_ = std::shared_ptr<Http::InputStream>(new Http::InputStream(sk_));
  output_stream_ = std::shared_ptr<Http::OutputStream>(new Http::OutputStream(sk_));
};

Http::Context::~Context() {
  ;
};

void Http::Context::SetSocket(struct tuno_socket *sk) {
  sk_ = sk;
  input_stream_->SetSocket(sk);
  output_stream_->SetSocket(sk);
};

std::shared_ptr<Http::InputStream> Http::Context::Instream() {
  return input_stream_;
};

std::shared_ptr<Http::OutputStream> Http::Context::Outstream() {
  return output_stream_;
};

bool Http::Context::IsSSL()
{
  return tuno_socket_is_ssl(sk_) ? true : false;
}

std::string Http::Context::LocalAddr()
{
  return std::string(sk_->addr.local_address);
}

int Http::Context::LocalPort() 
{
  return sk_->addr.local_port;
}

std::string Http::Context::RemoteAddr()
{
  return std::string(sk_->addr.peer_address);
}

int Http::Context::RemotePort()
{
  return sk_->addr.peer_port;
}

