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
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include "../snifl/tunl.h"
#include "../snifl/v4.h"
#include "../snifl/tcp.h"
#include "../snifl/udp.h"
#include "../snifl/sock.h"
#include "../snifl/mgr.h"
#include "../snifl/dns.h"
#include "tun_tap.h"
#include "http.h"


void pktdump(const void *pkt, int len) {
    const unsigned char *s = pkt;
    int i;
    for (i = 0; i < len; i++) printf("%s%02x", (i & 3 ? " " : (i & 15 ? "  " : "\n")), *s++);
    printf("\n");
}

int snddump(const snifl *tunl, const snifl_func *func, const void *pkt, int len) {
#ifdef SNIFL_DUMP
    printf(">>>>");
    pktdump(pkt, len);
#endif
    return 0;
}

int rcvdump(const snifl *tunl, const snifl_func *func, const void *pkt, int len) {
#ifdef SNIFL_DUMP
    printf("<<<<");
    pktdump(pkt, len);
#endif
    return 0;
}

int tun_send(const snifl *tunl, const snifl_func *func, const void *pkt, int len) {
    int *pfd = func->arg;
    write(*pfd, pkt, len);
    return 1;
}


char dnsrsp_v4[] = {
    0xc0, 0x0c,			// ptr
    0x00, 0x01,			// qtype
    0x00, 0x01,			// qclass
    0x00, 0x00, 0x01, 0x2c,	// ttl
    0x00, 0x04,			// rlen
    0xc0, 0xa8, 0x05, 0x05	// addr
};

snifl_lstn udpfuncs[] = {
    {
	.func = &snifl_dns_lo,
	.lport = 53,
	.rport = 0,
	.addr = NULL,
	.arg = dnsrsp_v4
    },
    {
	.func = NULL
    }
};

snifl_mgr mgr = {
    .socks = NULL
};

snifl_accept http_acpt = {
    .accept = &http_accept,
    .recv = &http_recv,
    .arg = &mgr,
    .recvwin = 1536
};

snifl_lstn tcpfuncs[] = {
    {
	.func = &snifl_mgr_tcpin,
	.lport = 0,
	.rport = 0,
	.addr = NULL,
	.arg = &mgr
    },
    {
	.func = &snifl_tcp_accept,
	.lport = 80,
	.rport = 0,
	.addr = NULL,
	.arg = &http_acpt
    },
    {
	.func = &snifl_tcp_accept,
	.lport = 8080,
	.rport = 0,
	.addr = NULL,
	.arg = &http_acpt
    },
    {
	.func = &snifl_tcp_reset,
	.lport = 0,
	.rport = 0,
	.addr = NULL
    },
    {
	.func = NULL
    }
};

snifl_func recvfuncs[] = {
    {
	.func = &rcvdump
    },
    {
	.func = &snifl_v4_validate
    },
    {
	.func = &snifl_v4_recvudp,
	.protochain = udpfuncs
    },
    {
	.func = &snifl_v4_recvtcp,
	.protochain = tcpfuncs
    },
    {
	.func = NULL
    }
};

snifl_func sendfuncs[] = {
    {
	.func = &snddump
    },
    {
	.func = &tun_send,
	.arg = NULL	// &tun_fd
    },
    {
	.func = NULL
    }
};

snifl tunl = {
    .inchain = recvfuncs,
    .outchain = sendfuncs,
    .mtu = 1440
};




int main() {
    int tun_fd = tun_alloc("tun%d", "192.168.5.1", "255.255.255.248");
    printf("tun_fd = %d\n", tun_fd);
    if (tun_fd < 0) return 1;
    sendfuncs[1].arg = &tun_fd;
    printf("try http://192.168.5.5\n");
    char buf[4096];
    while (1) {
	int r = read(tun_fd, buf, sizeof(buf));
	if (r < 0) break;
	snifl_pktin(&tunl, buf, r);
    }
}
