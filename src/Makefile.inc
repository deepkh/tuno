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

LIBTUNO: ${LIBTUNO_DLL} #${LIBTUNO_LIB}
	@echo MAKE $@ 

LIBTUNO_DEV: LIBTUNO_DLL_DEV #LIBTUNO_LIB_DEV
	@echo MAKE $@ 

LIBTUNO_CLEAN: ${LIBTUNO_DLL_CLEAN} #${LIBTUNO_LIB_CLEAN}
	@echo MAKE $@

######## STATIC LIB
${LIBTUNO_LIB}:
	$(CD) ${LIBTUNO} && $(MAKE) -f Makefile.${LIBTUNO_NAME} $@

LIBTUNO_LIB_DEV: 
	$(CD) ${LIBTUNO} && $(MAKE) -f Makefile.${LIBTUNO_NAME} ${LIBTUNO_LIB}
	@echo MAKE $@ 

${LIBTUNO_LIB_CLEAN}:
	$(CD) ${LIBTUNO} && $(MAKE) -f Makefile.${LIBTUNO_NAME} $@

######## DYNAMIC LIB
${LIBTUNO_DLL}:
	$(CD) ${LIBTUNO} && $(MAKE) -f Makefile.${LIBTUNO_NAME}.dll $@

LIBTUNO_DLL_DEV: 
	$(CD) ${LIBTUNO} && $(MAKE) -f Makefile.${LIBTUNO_NAME}.dll ${LIBTUNO_DLL}
	@echo MAKE $@ 

${LIBTUNO_DLL_CLEAN}:
	$(CD) ${LIBTUNO} && $(MAKE) -f Makefile.${LIBTUNO_NAME}.dll $@

