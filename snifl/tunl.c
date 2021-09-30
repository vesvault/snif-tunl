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

int snifl_chain(const snifl *tunl, const snifl_func *chain, const void *pk, int len) {
    const snifl_func *f;
    for (f = chain; f->func; f++) {
	int r = f->func(tunl, f, pk, len);
	if (r) return r;
    }
    return 0;
}

int snifl_pktin(const snifl *tunl, const void *pk, int len) {
    return snifl_chain(tunl, tunl->inchain, pk, len);
}

int snifl_pktout(const snifl *tunl, const void *pk, int len) {
    return snifl_chain(tunl, tunl->outchain, pk, len);
}

int snifl_protochain(const snifl *tunl, const snifl_lstn *chain, const void *payload, int paylen, const void *pk, unsigned short lport, unsigned short rport, const snifl_af *af) {
    const snifl_lstn *p;
    for (p = chain; p->func; p++) {
	if ((p->lport && p->lport != lport) || (p->rport && p->rport != rport)) continue;
	int r = p->func(tunl, p, payload, paylen, pk, af);
	if (r) return r;
    }
    return 0;
}

unsigned short snifl_chksum(unsigned short init, const void *data, int len) {
    unsigned long cs = init;
    while (len > 0) {
	if (len == 1) {
	    unsigned short last = 0;
	    snifl_a2v(last)[0] = *((unsigned char *)data);
	    cs += last;
	    len = 0;
	} else {
	    cs += *((unsigned short *)data);
	    data += 2;
	    len -= 2;
	}
	if (cs & 0xffff0000) cs -= 0xffff;
    }
    return cs;
}

