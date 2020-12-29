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

SHELL=/bin/sh

.DEFAULT_GOAL := all

include $(TUNO)/${MAKEFILE_DEP}

test_file/10m.bin:
	mkdir test_file 1> /dev/null 2> /dev/null
	head -c 10M </dev/urandom > $@
	md5sum $@ > $@.md5

http_server_test_file: test_file/10m.bin

x509.key:
	openssl req -nodes -new -x509 -keyout x509.key -days 365 -out x509.crt

http_server_x509_self_signed: x509.key

http_server_curl_dwload_test:
	curl -k -v -O https://127.0.0.1:1443/dwload/test_file/10m.bin
	md5sum download/10m.bin

http_server_curl_upload_test:
	curl -k -v -H "Content-Disposition: attachment; filename=10m.bin" https://127.0.0.1:1443/upload --upload-file ./test_file/10m.bin

all: $(TUNO_PHONY) http_server_x509_self_signed http_server_test_file

clean: $(TUNO_PHONY_CLEAN) $(TUNOSAMPLES_PHONY_CLEAN)


