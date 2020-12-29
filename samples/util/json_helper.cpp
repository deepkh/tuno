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
#include "util/json_helper.h"

int JsonParser::ParseFromString(std::string &json_str, Json::Value &json_obj)
{
  bool res;
  JSONCPP_STRING errs;
  Json::CharReaderBuilder readerBuilder;
  std::unique_ptr<Json::CharReader> const jsonReader(readerBuilder.newCharReader());

  res = jsonReader->parse(json_str.c_str(), json_str.c_str()+json_str.length(), &json_obj, &errs);
  if (!res || !errs.empty()) {
    tunosetmsg("failed to parse json_str: errs:%s\n\"%s\"\n", errs.c_str(), json_str.c_str());
    return -1;
  }

  return 0;
}



