/**************************************************************************
 *     _________
 *    /````````_\                  S N I F ~ e2e TLS trust for IoT
 *   /\     , / O\      ___
 *  | |     | \__|_____/  o\       e2e TLS SNI Forwarder
 *  | |     |  ``/`````\___/       e2e TLS CA Proxy
 *  | |     | . | <"""""""~~
 *  |  \___/ ``  \________/        https://snif.host
 *   \  '''  ``` /````````         (C) 2021 VESvault Corp
 *    \_________/                  Jim Zubov <jz@vesvault.com>
 *
 *
 * GNU General Public License v3
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 **************************************************************************/

#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "../snifl/tunl.h"
#include "../snifl/sock.h"
#include "../snifl/mgr.h"
#include "../snifl/v4.h"
#include "http.h"


int http_accept(snifl_sock *sock, const snifl_accept *ac) {
    return snifl_mgr_accept(sock, ac);
}

int http_recv(snifl_sock *sock, const void *buf, int len) {
    if (!buf) return 0;
    if (!len) return snifl_send(sock, buf, 0, 0);
    char rsp[2048];
    const unsigned char *raddr = (const unsigned char *)&((snifl_v4_sockaddr *) &sock->addr)->raddr;
    const unsigned char *laddr = (const unsigned char *)&((snifl_v4_sockaddr *) &sock->addr)->laddr;
    sprintf(rsp, "HTTP/1.0 200 Ok\r\nContent-Type: text/plain\r\n\r\nsnifl-demo http on %u.%u.%u.%u:%u\r\nResponding to %u.%u.%u.%u:%u:\r\n\r\n%.*s",
	laddr[0], laddr[1], laddr[2], laddr[3], snifl_a2h(sock->lport),
	raddr[0], raddr[1], raddr[2], raddr[3], snifl_a2h(sock->rport),
	len, buf
    );
    const char *s = rsp;
    const char *tail = s + strlen(rsp);
    while (s < tail) {
	int w = snifl_send(sock, s, tail - s, 0);
	if (w < 0) return w;
	s += w;
	if (s < tail) sleep(1);
    }
    snifl_shutdown(sock, SNIFL_SHUT_WR);
    return len;
}

