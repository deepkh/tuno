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

#include <libtuno/tuno_log.h>

char _tunomsg[DBG_MSG_LEN];
char _tunomsg_2[DBG_MSG_LEN];

void tuno_set_msg(const char *file, int line, const char *fmt, ...)
{
  va_list args;
  int n;
  if (strlen(fmt) == 0) {
    memset(_tunomsg, 0, sizeof(_tunomsg));
    return;
  }
  va_start(args, fmt);
  if (file && line) {
    snprintf(_tunomsg, sizeof(_tunomsg)-1, "%s(%d): ", file, line);
    n = strlen(_tunomsg);
    //vsprintf(strlen(_tunomsg)+_tunomsg, fmt, args);
    vsnprintf (_tunomsg+n, sizeof(_tunomsg)-n-1, fmt, args);
  } else {
    //vsprintf(_tunomsg, fmt, args);
    vsnprintf (_tunomsg, sizeof(_tunomsg)-1, fmt, args);
  }
  va_end(args);
  //printf("%s\n", _tunomsg);
  //fflush(stdout);
  //tunolog(_tunomsg);
}

static const char *loglabel = "";
static int logprttime = 1;
int tunolog_line(const char *fmt, ...)
{
  static char buf[DBG_MSG_LEN];
  va_list args;
  int n;
#ifdef __MINGW32__
  SYSTEMTIME st;
  GetLocalTime(&st);
  if (logprttime) {
    n = sprintf(buf, "%02d %02d:%02d:%02d.%03d %s",
      /*st.wMonth, */st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, loglabel);
  } else {
    n = sprintf(buf, "%s", loglabel);
  }
#else
  if (logprttime) {
#if 0
    time_t now = time(0);
    struct tm *tm = localtime (&now);
    n = sprintf(buf, "%02d%02d %02d:%02d:%02d.%03d %s"
      , tm->tm_mon+1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec
      , loglabel);
#else
    struct timeval tv;
    time_t curtime;

    gettimeofday(&tv, NULL);
    curtime=tv.tv_sec;
    n = strftime(buf,30,"%d %T",localtime(&curtime));
    n += sprintf(buf+strlen(buf), ".%d ", (int)tv.tv_usec/1000);
#endif
  } else {
    n = sprintf(buf, "%s", loglabel);
  }
#endif

#if 0
  va_start(args, fmt);
  vsprintf(buf+n, fmt, args);
  va_end(args);
  //sprintf(buf+strlen(buf), "\n");
#else
  va_start(args, fmt);
  vsnprintf (buf+n, sizeof(buf)-n-1, fmt, args);
  va_end(args);
#endif

  //logcb(buf, logarg);
  printf("%s\n", buf);
  fflush(stdout);
  return 0;
}

char *tuno_get_msg()
{
  snprintf(_tunomsg_2, sizeof(_tunomsg_2) - 1, "%s", _tunomsg);
  return _tunomsg_2;
}

