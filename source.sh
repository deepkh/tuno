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

if [ ! -z "$1" ]; then
  export HAVE_LIB_EXTERNAL=1

	unset TUNO 
	unset TUNO_PHONY 
	unset TUNO_PHONY_CLEAN

	if [ "${HAVE_PRJ_TUNO}" = "1" ]; then
		export TUNO="$1"
		export TUNO_PHONY="TUNO"
		export TUNO_PHONY_CLEAN="TUNO_CLEAN"
		echo "TUNO=${TUNO}"
	fi
else
	export HAVE_PRJ_TUNO=1

	# load global env
	source mk/source.sh
fi
