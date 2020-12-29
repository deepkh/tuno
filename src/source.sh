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
	unset LIBTUNO_PHONY
	unset LIBTUNO_PHONY_CLEAN
	if [ "${HAVE_LIB_TUNO}" = "1" ]; then
		export LIBTUNO_NAME="libtuno"
		export LIBTUNO="$1"
		#export LIBTUNO_OBJS_DIR=${RUNTIME_OBJS}${LIBTUNO/${ROOT}/""}
		export LIBTUNO_OBJS_DIR=${RUNTIME_OBJS}/${LIBTUNO_NAME}
#		export LIBTUNO_LIB="${RUNTIME_LIB}/${LIBTUNO_NAME}.${LIBSUFFIX}"
#		export LIBTUNO_LIB_CLEAN="${LIBTUNO_LIB}_clean"
		export LIBTUNO_DLL="${RUNTIME_DLL}/${LIBTUNO_NAME}.${DLLSUFFIX}"
		export LIBTUNO_DLL_CLEAN="${LIBTUNO_DLL}_clean"
		export LIBTUNO_PHONY="LIBTUNO"
		export LIBTUNO_PHONY_DEV="LIBTUNO_DEV"
		export LIBTUNO_PHONY_CLEAN="LIBTUNO_CLEAN"
		export LIBTUNO_INCLUDE_DIR="${LIBTUNO}/../include"
		export LIBTUNO_CFLAGS="-I${LIBTUNO_INCLUDE_DIR}"
		export LIBTUNO_LDFLAGS="-ltuno"
		echo "LIBTUNO=${LIBTUNO}"
	fi
fi
