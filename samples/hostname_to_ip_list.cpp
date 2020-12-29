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
extern "C" {
#include <libtuno/tuno_sys_socket.h>
}


int main(int argc, char* argv[]) {

	const char *host = "tw.yahoo.com";
	char *ipv4 = NULL;
	char *ipv6 = NULL;

	struct sockaddr_in6 addr_in6;
	struct sockaddr_in addr_in4;

	if (tuno_sys_socket_init()) {
		tunolog("failed to socket_library_init()");
		return -1;
	}

	if (argc == 2) {
		host = argv[1];
	//	tunolog("./%s www.yahoo.com", argv[0]);
	//	return -1;
	}

	tunolog("sizeof addr_in6 %d", sizeof(addr_in6));
	tunolog("sizeof addr_in %d", sizeof(addr_in4));

	tuno_sys_socket_show_ip_list(host);

	printf("\n\n----\n");

	ipv6 = tuno_sys_socket_hostname_to_ip(host, HOSTNAME_IPV6);
	if (ipv6 == NULL) {
		tunolog("ipv6: get failed!");
	} else {
		tunolog("ipv6: %s", ipv6);
		free(ipv6);
	}

	ipv4 = tuno_sys_socket_hostname_to_ip(host, HOSTNAME_IPV4);
	if (ipv4 == NULL) {
		tunolog("ipv4: get failed!");
	} else {
		tunolog("ipv4: %s", ipv4);
		free(ipv4);
	}

	return 0;
}
