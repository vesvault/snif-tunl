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
#include <string.h>
#include <stdlib.h>
#include "tunl.h"
#include "tcp.h"
#include "sock.h"

int snifl_send(snifl_sock *sock, const void *buf, int len, int flags) {
    if (!buf) return snifl_shutdown(sock, (len >= 0 ? SNIFL_SHUT_RDWR : SNIFL_SHUT_ERR));
    if (len <= 0 && sock->recvseq == sock->recvack) return 0;
    if (sock->flags & SNIFL_SOCKF_END) return SNIFL_E_SOCK;
    char pkt[SNIFL_MTU];
    snifl_tcp *tcp = snifl_sock2tcp(pkt, sock);
    void *data = snifl_tcp_data(tcp);
    int dl = (char *)data - pkt;
    if (len + dl > sock->tunl->mtu) {
	len = sock->tunl->mtu - dl;
    } else if (len > 0) {
	tcp->flags |= SNIFL_TCPF_PSH;
    }
    if (len + sock->sendgap > sock->sendwin) return 0;
    uint32_t ack = sock->recvseq;
    uint32_t seq = sock->sendseq;
    if (!(sock->flags & SNIFL_SOCKF_ACK)) {
	tcp->flags |= SNIFL_TCPF_SYN;
	sock->flags |= SNIFL_SOCKF_ACK;
	seq--;
	len = 0;
    }
    if (sock->flags & SNIFL_SOCKF_EOF) {
	sock->sendseq++;
	tcp->flags |= SNIFL_TCPF_FIN;
	sock->flags |= SNIFL_SOCKF_END;
    }
    if (sock->flags & SNIFL_SOCKF_ERR) {
	tcp->flags |= SNIFL_TCPF_RST;
	sock->flags |= SNIFL_SOCKF_END;
	len = 0;
    }
    if (len > 0) memcpy(data, buf, len);
    else len = 0;
    if ((sock->flags & SNIFL_SOCKF_END) && sock->recv) sock->recv(sock, NULL, (sock->flags & (SNIFL_SOCKF_ERR | SNIFL_SOCKF_RST) ? -1 : 0));
    if (sock->flags & SNIFL_SOCKF_RST) return SNIFL_E_SOCK;
    if (sock->flags & SNIFL_SOCKF_SYN) {
	snifl_l2a(tcp->ack, ack);
	tcp->flags |= SNIFL_TCPF_ACK;
    } else tcp->ack = 0;
    snifl_l2a(tcp->seq, seq);
    unsigned short win = sock->recvwin > sock->recvgap ? sock->recvwin - sock->recvgap : 0;
    snifl_h2a(tcp->win, win);
    sock->sendseq += len;
    sock->sendgap += len;
    int r = sock->sendtcp(sock, tcp, len, pkt);
    if (r > 0) {
	sock->recvack = ack;
	return len;
    }
    sock->sendseq -= len;
    sock->sendgap -= len;
    return r;
}

int snifl_sock_sendtcp(snifl_sock *sock, snifl_tcp *tcp, int len, void *pkt) {
    return snifl_sendtcp(sock->tunl, tcp, len, pkt, sock->af);
}

int snifl_shutdown(snifl_sock *sock, int mode) {
    sock->recvack = sock->recvseq - 1;
    switch (mode) {
	case SNIFL_SHUT_RD:
	case SNIFL_SHUT_RDWR:
	    sock->recvwin = 0;
	    if (mode != SNIFL_SHUT_RDWR) break;
	case SNIFL_SHUT_WR:
	    sock->flags |= SNIFL_SOCKF_EOF;
	    break;
	default:
	    sock->flags |= SNIFL_SOCKF_ERR;
	    break;
    }
    return snifl_send(sock, "", 0, 0);
}

#define	snifl_sock_freeq(q)	free(q)

void snifl_sock_addq(snifl_sock *sock, snifl_sock_q *q) {
    snifl_sock_q **pq;
    snifl_sock_q *c;
    for (pq = &sock->queue; (c = *pq); pq = &(*pq)->chain) {
	int d = q->seq - c->seq;
	if (d >= c->len) continue;
	if (-d > q->len) break;
	*pq = c->chain;
	snifl_sock_freeq(c);
    }
    q->chain = *pq;
    *pq = q;
}

static int snifl_sock_recvdata(snifl_sock *sock, const void *data, int dlen) {
    if (!sock->recv) return 0;
    sock->recvseq += dlen;
    sock->recvgap += dlen;
    int r = sock->recv(sock, data, dlen);
    if (r < 0) return r;
    if (r >= sock->recvgap) sock->recvgap = 0;
    else sock->recvgap -= r;
    return 1;
}

static int snifl_sock_recvtcp(snifl_sock *sock, const snifl_tcp *tcp, int len) {
    if (tcp->flags & SNIFL_TCPF_RST) {
	if (sock->recv) {
	    if (!(sock->flags & SNIFL_SOCKF_RST)) sock->recv(sock, NULL, -1);
	    sock->flags |= SNIFL_SOCKF_RST;
	}
	return 1;
    }
    if (sock->flags & (SNIFL_SOCKF_FIN | SNIFL_SOCKF_ERR)) return 1;
    uint32_t seq = snifl_a2l(tcp->seq);
    if (tcp->flags & SNIFL_TCPF_SYN) {
	sock->recvack = seq;
	sock->recvseq = ++seq;
	sock->flags |= SNIFL_SOCKF_SYN;
	sock->flags &= ~SNIFL_SOCKF_ACK;
	sock->sendseq = seq ^ 0x80000000;
    } else if (!(sock->flags & SNIFL_SOCKF_SYN)) return 0;
    if (tcp->flags & SNIFL_TCPF_ACK) {
	int sd = sock->sendseq - snifl_a2l(tcp->ack);
	if (sd >= 0 && sd < sock->sendgap) sock->sendgap = sd;
    }
    int d = seq - sock->recvseq;
    if (d < 0) return 1;
    int hlen = snifl_tcp_hdrlen(tcp);
    int dlen = len - hlen;
    if (d + dlen + sock->recvgap > sock->recvwin) return 1;
    const void *data = (const char *)tcp + hlen;
    if (d > 0) {
	if (dlen <= 0) return 1;
	snifl_sock_q *q = malloc(offsetof(snifl_sock_q, data) + dlen);
	q->seq = seq;
	q->len = dlen;
	memcpy(q->data, data, dlen);
	snifl_sock_addq(sock, q);
	return 1;
    }
    sock->sendwin = snifl_a2h(tcp->win);
    int r = snifl_sock_recvdata(sock, data, dlen);
    if ((tcp->flags & SNIFL_TCPF_FIN) && sock->recv) {
	sock->flags |= SNIFL_SOCKF_FIN;
	sock->recvseq = seq + 1;
	int r2 = sock->recv(sock, NULL, 0);
	if (r2 < 0) return r2;
    }
    return r;
}

int snifl_sock_flushq(snifl_sock *sock) {
    snifl_sock_q *q;
    while ((q = sock->queue)) {
	int d = q->seq - sock->recvseq;
	if (d > 0) break;
	if (!d) {
	    int r = snifl_sock_recvdata(sock, q->data, q->len);
	    if (r <= 0) return r;
	}
	sock->queue = q->chain;
	snifl_sock_freeq(q);
    }
    return 0;
}

int snifl_sock_tcpin(snifl_sock *sock, const snifl_tcp *tcp, int len) {
    int r = snifl_sock_recvtcp(sock, tcp, len);
    if (r < 0) return r;
    if (r > 0) {
	int r2 = snifl_sock_flushq(sock);
	if (r2 < 0) return r2;
	r2 = snifl_send(sock, "", 0, 0);
	if (r2 < 0) return r2;
    }
    return r;
}

int snifl_sock_cmptcp(const snifl_sock *sock, const snifl_tcp *tcp, const void *pkt, const snifl_af *af) {
    if (af != sock->af) return af < sock->af ? 1 : -1;
    if (sock->lport != tcp->dstport) return tcp->dstport < sock->lport ? 1 : -1;
    if (sock->rport != tcp->srcport) return tcp->srcport < sock->rport ? 1 : -1;
    return af->matchpkt(sock->addr, pkt);
}

int snifl_sock_cmpsock(const snifl_sock *sock, const snifl_sock *s) {
    if (s->af != sock->af) return s->af < sock->af ? 1 : -1;
    if (sock->lport != s->lport) return s->lport < sock->lport ? 1 : -1;
    if (sock->rport != s->rport) return s->rport < sock->rport ? 1 : -1;
    return s->af->cmpaddr(s->addr, sock->addr);
}

void snifl_sock_free(snifl_sock *sock) {
    snifl_sock_q *q;
    while ((q = sock->queue)) {
	sock->queue = q->chain;
	snifl_sock_freeq(q);
    }
    free(sock);
}
