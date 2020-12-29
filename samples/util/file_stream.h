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
#ifndef _FILE_STREAM_H_
#define _FILE_STREAM_H_
#include <stdio.h>
#include <stdint.h>

namespace fs {

static inline void mkdir(const char *dir) {
  char cmd[256];
  sprintf(cmd, "mkdir %s", dir);
  system(cmd);
};

/***************************************************
 * FileWriteStream
 **************************************************/
class FileWriteStream {
public:
  FileWriteStream() {
    ;
  };

  ~FileWriteStream() {
    Close();
  };

  int Open(std::string &file_path) {
    fp_ = fopen(file_path.c_str(), "wb");
    if (fp_ == nullptr) {
      tunosetmsg("failed to open %s", file_path.c_str());
      return -1;
    }

    write_size_ = 0;
    return 0;
  };

  void Close() {
    if (fp_ != nullptr) {
      fclose(fp_);
      fp_ = nullptr;
    }
  };

  bool IsOpen() {
    return fp_ == nullptr ? false : true;
  };

  int64_t WriteSize() {
    return write_size_;
  };

  size_t Write(char *buf, int size) {
    size_t w = fwrite(buf, 1, size, fp_);
    if (w == 0) {
      return 0;
    }
    write_size_ += w;
    return w;
  };

private:
  int64_t length_ = -1;
  int64_t write_size_ = 0;
  FILE *fp_ = nullptr;
};

/***************************************************
 * FileReadStream
 **************************************************/
class FileReadStream {
public:
  FileReadStream() {
    ;
  };

  ~FileReadStream() {
    Close();
  };

  int Open(std::string &file_path) {
    fp_ = fopen(file_path.c_str(), "rb");
    if (fp_ == nullptr) {
      tunosetmsg("failed to open %s", file_path.c_str());
      return -1;
    }

    length_ = -1;
    read_size_ = 0;
    return 0;
  };

  void Close() {
    if (fp_ != nullptr) {
      fclose(fp_);
      fp_ = nullptr;
    }
  };

  bool IsOpen() {
    return fp_ == nullptr ? false : true;
  };

  int64_t Length() {
    if (length_ == -1) {
      fseek(fp_, 0L, SEEK_END);
      length_ = (int64_t) ftell(fp_);
      fseek(fp_, 0L, SEEK_SET);
    }
    return length_;
  };

  int64_t ReadSize() {
    return read_size_;
  };

  size_t Read(char *buf, int size) {
    size_t r = fread(buf, 1, size, fp_);

    if (r == 0) {
      return 0;
    }

    read_size_ += r;
    return r;
  };

private:
  int64_t length_ = -1;
  int64_t read_size_ = 0;
  FILE *fp_ = nullptr;
};

};
#endif
