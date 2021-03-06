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
#!/bin/bash

if [ ! -z "$1" ]; then
	unset BINTCPPROXY_PHONY
	unset BINTCPPROXY_PHONY_CLEAN
	unset BINRTSPPROXY_PHONY
	unset BINRTSPPROXY_PHONY_CLEAN
	if [ "${HAVE_BIN_TUNOSAMPLES}" = "1" ]; then
		export TUNOSAMPLES="$1"
		export TUNOSAMPLES_PHONY="TUNOSAMPLES"
		export TUNOSAMPLES_PHONY_DEV="TUNOSAMPLES_DEV"
		export TUNOSAMPLES_PHONY_CLEAN="TUNOSAMPLES_CLEAN"
		echo "TUNOSAMPLES=${TUNOSAMPLES}"

		export BINTCPPROXY_NAME="tcp_proxy"
		export BINTCPPROXY="$1"
		export BINTCPPROXY_OBJS_DIR=${RUNTIME_OBJS}${BINTCPPROXY/${ROOT}/""}
		export BINTCPPROXY_BIN="${RUNTIME_BIN}/${BINTCPPROXY_NAME}${BINSUFFIX}"
		export BINTCPPROXY_BIN_CLEAN="${BINTCPPROXY_BIN}_clean"
		export BINTCPPROXY_PHONY="BINTCPPROXY"
		export BINTCPPROXY_PHONY_DEV="BINTCPPROXY_DEV"
		export BINTCPPROXY_PHONY_CLEAN="BINTCPPROXY_CLEAN"
		export BINTCPPROXY_CFLAGS=
		export BINTCPPROXY_LDFLAGS=
		echo "BINTCPPROXY=${BINTCPPROXY}"

		export BINRTSPPROXY_NAME="rtsp_proxy"
		export BINRTSPPROXY="$1"
		export BINRTSPPROXY_OBJS_DIR=${RUNTIME_OBJS}${BINRTSPPROXY/${ROOT}/""}
		export BINRTSPPROXY_BIN="${RUNTIME_BIN}/${BINRTSPPROXY_NAME}${BINSUFFIX}"
		export BINRTSPPROXY_BIN_CLEAN="${BINRTSPPROXY_BIN}_clean"
		export BINRTSPPROXY_PHONY="BINRTSPPROXY"
		export BINRTSPPROXY_PHONY_DEV="BINRTSPPROXY_DEV"
		export BINRTSPPROXY_PHONY_CLEAN="BINRTSPPROXY_CLEAN"
		export BINRTSPPROXY_CFLAGS=
		export BINRTSPPROXY_LDFLAGS=
		echo "BINRTSPPROXY=${BINRTSPPROXY}"

		export BINHTTPCLIENT_NAME="http_client"
		export BINHTTPCLIENT="$1"
		export BINHTTPCLIENT_OBJS_DIR=${RUNTIME_OBJS}${BINHTTPCLIENT/${ROOT}/""}
		export BINHTTPCLIENT_BIN="${RUNTIME_BIN}/${BINHTTPCLIENT_NAME}${BINSUFFIX}"
		export BINHTTPCLIENT_BIN_CLEAN="${BINHTTPCLIENT_BIN}_clean"
		export BINHTTPCLIENT_PHONY="BINHTTPCLIENT"
		export BINHTTPCLIENT_PHONY_DEV="BINHTTPCLIENT_DEV"
		export BINHTTPCLIENT_PHONY_CLEAN="BINHTTPCLIENT_CLEAN"
		export BINHTTPCLIENT_CFLAGS=
		export BINHTTPCLIENT_LDFLAGS=
		echo "BINHTTPCLIENT=${BINHTTPCLIENT}"

		export BINHTTPSERVER_NAME="http_server"
		export BINHTTPSERVER="$1"
		export BINHTTPSERVER_OBJS_DIR=${RUNTIME_OBJS}${BINHTTPSERVER/${ROOT}/""}
		export BINHTTPSERVER_BIN="${RUNTIME_BIN}/${BINHTTPSERVER_NAME}${BINSUFFIX}"
		export BINHTTPSERVER_BIN_CLEAN="${BINHTTPSERVER_BIN}_clean"
		export BINHTTPSERVER_PHONY="BINHTTPSERVER"
		export BINHTTPSERVER_PHONY_DEV="BINHTTPSERVER_DEV"
		export BINHTTPSERVER_PHONY_CLEAN="BINHTTPSERVER_CLEAN"
		export BINHTTPSERVER_CFLAGS=
		export BINHTTPSERVER_LDFLAGS=
		echo "BINHTTPSERVER=${BINHTTPSERVER}"

		export BINHOSTTOIPLIST_NAME="host_to_ip_list"
		export BINHOSTTOIPLIST="$1"
		export BINHOSTTOIPLIST_OBJS_DIR=${RUNTIME_OBJS}${BINHOSTTOIPLIST/${ROOT}/""}
		export BINHOSTTOIPLIST_BIN="${RUNTIME_BIN}/${BINHOSTTOIPLIST_NAME}${BINSUFFIX}"
		export BINHOSTTOIPLIST_BIN_CLEAN="${BINHOSTTOIPLIST_BIN}_clean"
		export BINHOSTTOIPLIST_PHONY="BINHOSTTOIPLIST"
		export BINHOSTTOIPLIST_PHONY_DEV="BINHOSTTOIPLIST_DEV"
		export BINHOSTTOIPLIST_PHONY_CLEAN="BINHOSTTOIPLIST_CLEAN"
		export BINHOSTTOIPLIST_CFLAGS=
		export BINHOSTTOIPLIST_LDFLAGS=
		echo "BINHOSTTOIPLIST=${BINHOSTTOIPLIST}"

	fi
fi

