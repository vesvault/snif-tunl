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
#include "sock.h"
#include "tcp.h"


snifl_sock *snifl_tcp2sock(const snifl_tcp *srctcp, const void *srcpkt, const snifl_af *af) {
    snifl_sock *sock = af->pkt2sock(srcpkt);
    sock->flags = 0;
    sock->sendwin = sock->sendgap = 0;
    sock->sendseq = 0;
    sock->recvwin = sock->recvgap = 0;
    sock->lport = srctcp->dstport;
    sock->rport = srctcp->srcport;
    sock->af = af;
    return sock;
}

void snifl_inittcp(snifl_tcp *tcp) {
    tcp->lenflg = 0x50;
    tcp->flags = 0;
    tcp->urg = 0;
}

snifl_tcp *snifl_sock2tcp(void *pkt, const snifl_sock *sock) {
    snifl_tcp *tcp = sock->af->sock2pkt(pkt, sock);
    snifl_inittcp(tcp);
    tcp->srcport = sock->lport;
    tcp->dstport = sock->rport;
    return tcp;
}

snifl_tcp *snifl_tcp2tcp(void *pkt, const snifl_tcp *srctcp, const void *srcpkt, const snifl_af *af) {
    snifl_tcp *tcp = af->pkt2pkt(pkt, srcpkt);
    snifl_inittcp(tcp);
    tcp->srcport = srctcp->dstport;
    tcp->dstport = srctcp->srcport;
    return tcp;
}

int snifl_sendtcp(const snifl *tunl, snifl_tcp *tcp, int datalen, void *pkt, const snifl_af *af) {
    int tcplen = datalen + snifl_tcp_hdrlen(tcp);
    tcp->chksum = 0;
    tcp->chksum = ~af->pchksum(tcp, pkt, tcplen);
    return af->sendpkt(tunl, pkt, tcplen);
}

int snifl_tcp_accept(const snifl *tunl, const snifl_lstn *lstn, const void *payload, int paylen, const void *pk, const snifl_af *af) {
    const snifl_tcp *tcp = payload;
    const snifl_accept *ac = lstn->arg;
    if (!(tcp->flags & SNIFL_TCPF_SYN)) return 0;
    snifl_sock *sock = snifl_tcp2sock(tcp, pk, af);
    sock->tunl = tunl;
    sock->queue = NULL;
    sock->recv = ac->recv;
    sock->sendtcp = &snifl_sock_sendtcp;
    int r = ac->accept(sock, ac);
    if (r < 0) return r;
    return snifl_sock_tcpin(sock, tcp, paylen);
}

int snifl_tcp_reset(const snifl *tunl, const snifl_lstn *lstn, const void *payload, int paylen, const void *pk, const snifl_af *af) {
    const snifl_tcp *src = payload;
    if (src->flags & SNIFL_TCPF_RST) return 1;
    char re[256];
    snifl_tcp *tcp = snifl_tcp2tcp(re, payload, pk, af);
    tcp->flags |= SNIFL_TCPF_RST;
    tcp->seq = (src->flags & SNIFL_TCPF_ACK) ? src->ack : 0;
    if (src->flags & (SNIFL_TCPF_SYN | SNIFL_TCPF_FIN)) {
	tcp->flags |= SNIFL_TCPF_ACK;
	uint32_t ack = snifl_a2l(src->seq) + 1;
	snifl_l2a(tcp->ack, ack);
    } else tcp->ack = 0;
    tcp->win = 0;
    return snifl_sendtcp(tunl, tcp, 0, re, af);
}
