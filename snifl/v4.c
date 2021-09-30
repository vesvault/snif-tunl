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
#include "tunl.h"
#include "udp.h"
#include "tcp.h"
#include "sock.h"
#include "v4.h"



unsigned short snifl_v4_pchksum(const void *pdata, const void *pkt, int len) {
    const snifl_v4 *v4 = pkt;
    unsigned char pseudo[4];
    pseudo[0] = 0;
    pseudo[1] = v4->proto;
    snifl_h2a(pseudo[2], len);
    return snifl_chksum(snifl_chksum(snifl_chksum(0, &v4->srcaddr, 8), pseudo, 4), pdata, len);
}

unsigned short snifl_v4_nextid = 0;

void snifl_v4_initpkt(snifl_v4 *v4) {
    v4->verlen = 0x45;
    v4->ttl = 0xff;
    v4->dscp = 0;
    snifl_h2a(v4->foffs, SNIFL_V4F_DF);
    unsigned short id = snifl_v4_nextid++;
    snifl_h2a(v4->id, id);
}

void *snifl_v4_pkt2pkt(void *pkt, const void *src) {
    const snifl_v4 *sv4 = src;
    snifl_v4 *dv4 = pkt;
    snifl_v4_initpkt(dv4);
    dv4->srcaddr = sv4->dstaddr;
    dv4->dstaddr = sv4->srcaddr;
    dv4->proto = sv4->proto;
    return snifl_v4_data(dv4);
}

int snifl_v4_sendpkt(const struct snifl *tunl, void *pkt, int protolen) {
    snifl_v4 *v4 = pkt;
    int hl = snifl_v4_hdrlen(v4);
    int len = hl + protolen;
    snifl_h2a(v4->len, len);
    v4->chksum = 0;
    v4->chksum = ~snifl_chksum(0, v4, hl);
    return snifl_pktout(tunl, v4, len);
}

snifl_sock *snifl_v4_pkt2sock(const void *pkt) {
    const snifl_v4 *v4 = pkt;
    snifl_sock *sock = malloc(offsetof(snifl_sock, addr) + sizeof(snifl_v4_sockaddr));
    ((snifl_v4_sockaddr *)&sock->addr)->laddr = v4->dstaddr;
    ((snifl_v4_sockaddr *)&sock->addr)->raddr = v4->srcaddr;
    sock->proto = v4->proto;
    return sock;
}

void *snifl_v4_sock2pkt(void *pkt, const snifl_sock *sock) {
    snifl_v4 *v4 = pkt;
    snifl_v4_initpkt(v4);
    v4->dstaddr = ((snifl_v4_sockaddr *)&sock->addr)->raddr;
    v4->srcaddr = ((snifl_v4_sockaddr *)&sock->addr)->laddr;
    v4->proto = sock->proto;
    return snifl_v4_data(v4);
}

int snifl_v4_cmpaddr(const void *addr1, const void *addr2) {
    const snifl_v4_sockaddr *a1 = addr1;
    const snifl_v4_sockaddr *a2 = addr2;
    if (a1->laddr != a2->laddr) return a1->laddr > a2->laddr ? 1 : -1;
    if (a1->raddr != a2->raddr) return a1->raddr > a2->raddr ? 1 : -1;
    return 0;
}

int snifl_v4_matchpkt(const void *addr, const void *pkt) {
    const snifl_v4_sockaddr *a1 = addr;
    const snifl_v4 *v4 = pkt;
    if (a1->raddr && (a1->raddr != v4->srcaddr)) return a1->raddr > v4->srcaddr ? 1 : -1;
    if (a1->laddr && (a1->laddr != v4->dstaddr)) return a1->laddr > v4->dstaddr ? 1 : -1;
    return 0;
}

const snifl_af snifl_v4_af = {
    .pkt2pkt = &snifl_v4_pkt2pkt,
    .pkt2sock = &snifl_v4_pkt2sock,
    .sock2pkt = &snifl_v4_sock2pkt,
    .sendpkt = &snifl_v4_sendpkt,
    .cmpaddr = &snifl_v4_cmpaddr,
    .matchpkt = &snifl_v4_matchpkt,
    .pchksum = &snifl_v4_pchksum
};


int snifl_v4_validate(const snifl *tunl, const snifl_func *func, const void *pk, int len) {
    const snifl_v4 *v4 = pk;
    if (len < 20 || !snifl_v4_ok(v4)) return func->arg ? snifl_chain(tunl, func->arg, pk, len) : SNIFL_E_IPHDR;
    int hl = (v4->verlen & 0x0f) << 2;
    int l = snifl_a2h(v4->len);
    if (l < hl || l < 20 || l > len) return SNIFL_E_IPHDR;
    if (snifl_a2h(v4->foffs) & ~SNIFL_V4F_DF) return SNIFL_E_FRAG;
    unsigned short cs = ~snifl_chksum(0, pk, hl);
    if (cs) return SNIFL_E_IPHDR;
    return 0;
}

int snifl_v4_recvudp(const snifl *tunl, const snifl_func *func, const void *pk, int len) {
    const snifl_v4 *v4 = pk;
    if (!snifl_v4_isudp(v4)) return 0;
    snifl_udp *udp = snifl_v4_data(v4);
    int dl = snifl_v4_datalen(v4);
    if (dl < sizeof(snifl_udp) || dl < snifl_a2h(udp->len)) return SNIFL_E_THDR;
    if (udp->chksum && snifl_v4_pchksum(udp, v4, snifl_a2h(udp->len)) != 0xffff) return SNIFL_E_THDR;
    return snifl_protochain(tunl, func->protochain, udp, dl, pk, snifl_a2h(udp->dstport), snifl_a2h(udp->srcport), &snifl_v4_af);
}

int snifl_v4_recvtcp(const snifl *tunl, const snifl_func *func, const void *pk, int len) {
    const snifl_v4 *v4 = pk;
    if (!snifl_v4_istcp(v4)) return 0;
    snifl_tcp *tcp = snifl_v4_data(v4);
    int dl = snifl_v4_datalen(v4);
    if (dl < sizeof(snifl_tcp) || dl < snifl_tcp_hdrlen(tcp)) return SNIFL_E_THDR;
    if (snifl_v4_pchksum(tcp, v4, dl) != 0xffff) return SNIFL_E_THDR;
    return snifl_protochain(tunl, func->protochain, tcp, dl, pk, snifl_a2h(tcp->dstport), snifl_a2h(tcp->srcport), &snifl_v4_af);
}
