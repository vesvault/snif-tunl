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
#include "jTree.h"
#include "tunl.h"
#include "sock.h"
#include "tcp.h"
#include "mgr.h"


struct snifl_mgr_pkt {
    const struct snifl_tcp *tcp;
    const void *pkt;
    const struct snifl_af *af;
};

static int snifl_mgr_cmpsock(void *obj, void *term, void *arg) {
    return snifl_sock_cmpsock(obj, term);
}

static int snifl_mgr_cmppkt(void *obj, void *term, void *arg) {
    const struct snifl_mgr_pkt *p = term;
    return snifl_sock_cmptcp(obj, p->tcp, p->pkt, p->af);
}

int snifl_mgr_accept(snifl_sock *sock, const snifl_accept *ac) {
    snifl_mgr *mgr = ac->arg;
    snifl_mgr_cleanup(mgr);
    unsigned char depth;
    void **psk = jTree_seek(&mgr->socks, sock, NULL, &snifl_mgr_cmpsock, &depth);
    if (!psk || *psk) {
	snifl_sock_free(sock);
	return SNIFL_E_SOCK;
    }
    sock->recvwin = ac->recvwin;
    *psk = sock;
    return 1;
}

int snifl_mgr_tcpin(const snifl *tunl, const snifl_lstn *lstn, const void *payload, int paylen, const void *pk, const snifl_af *af) {
    snifl_mgr *mgr = lstn->arg;
    const snifl_tcp *tcp = payload;
    struct snifl_mgr_pkt p = {
	.af = af,
	.pkt = pk,
	.tcp = payload
    };
    void **psk = jTree_seek(&mgr->socks, &p, NULL, &snifl_mgr_cmppkt, NULL);
    if (!psk || !*psk) return 0;
    return snifl_sock_tcpin(*psk, tcp, paylen);
}

void snifl_mgr_cleanup(snifl_mgr *mgr) {
    void **psk, **pnext;
    for (psk = jTree_first(mgr->socks); psk; psk = pnext) {
	pnext = jTree_next(psk);
	snifl_sock *sk = *psk;
	if (!sk || (sk->flags & SNIFL_SOCKF_END)) {
	    if (sk) snifl_sock_free(sk);
	    jTree_delete(&mgr->socks, psk);
	}
    }
}

void snifl_mgr_done(snifl_mgr *mgr) {
    void **psk, **pnext;
    for (psk = jTree_first(mgr->socks); psk; psk = pnext) {
	pnext = jTree_next(psk);
	snifl_sock *sk = *psk;
	if (!(sk->flags & SNIFL_SOCKF_END)) {
	    snifl_shutdown(sk, SNIFL_SHUT_ERR);
	}
	snifl_sock_free(sk);
    }
    jTree_collapse(&mgr->socks);
}
