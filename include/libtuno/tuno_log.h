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

#ifndef _TUNO_LOG_H_
#define _TUNO_LOG_H_

#if defined(__WIN32__) || defined(_WIN32) || defined(_WIN32_WCE)
#include <winsock2.h>
#include <windows.h>
#else

#endif

#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <inttypes.h>
#include <time.h>
#include <sys/time.h>

#define DBG_MSG_LEN 40960
extern char _tunomsg[DBG_MSG_LEN];
extern char _tunomsg_2[DBG_MSG_LEN];

void tuno_set_msg(const char *file, int line, const char *fmt, ...);
#define tunosetmsg(fmt, ...) tuno_set_msg(__FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define tunosetmsg2() \
  snprintf(_tunomsg_2, sizeof(_tunomsg_2)-1, "%s", _tunomsg); \
  tunosetmsg("%s", _tunomsg_2);

char *tuno_get_msg();
#define tunogetmsg() tuno_get_msg()

int tunolog_line(const char *fmt, ...);
#define tunolog tunolog_line

#endif
