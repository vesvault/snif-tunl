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
#include "v4.h"
#include "udp.h"
#include "dns.h"


int snifl_dns_lo(const snifl *tunl, const snifl_lstn *lstn, const void *payload, int paylen, const void *pk, const snifl_af *af) {
    const snifl_udp *udp = payload;
    int len = snifl_a2h(udp->len);
    if (len < sizeof(snifl_udp) + sizeof(snifl_dns)) return SNIFL_E_APP;
    const snifl_dns *dns = (const snifl_dns *) udp->data;
    int flags = snifl_a2h(dns->flags);
    int qdcount = snifl_a2h(dns->qdcount);
    if ((flags & 0x8000) || !qdcount) return 0;
    const char *s = dns->data;
    const char *tail = s + len - sizeof(snifl_udp) - sizeof(snifl_dns);
    while (s < tail) {
	unsigned char c = *s++;
	if (c & 0xc0) return SNIFL_E_APP;
	if (c > 0) {
	    s += c;
	} else {
	    s += 4;
	    if (s > tail) return SNIFL_E_APP;
	    char re[800];
	    int qdlen = s - dns->data;
	    if (qdlen > sizeof(re) - 256) return SNIFL_E_APP;
	    const char *an = lstn->arg;
	    snifl_udp *reudp = snifl_udp2udp(re, udp, pk, af);
	    snifl_dns *redns = snifl_udp_data(reudp);
	    redns->id = dns->id;
	    snifl_h2a(redns->flags, 0x8000);
	    snifl_h2a(redns->qdcount, 1);
	    snifl_h2a(redns->ancount, 1);
	    redns->nscount = redns->arcount = 0;
	    memcpy(redns->data, dns->data, qdlen);
	    int anlen = snifl_a2h(an[10]) + 12;
	    memcpy(redns->data + qdlen, an, anlen);
	    return snifl_sendudp(tunl, reudp, qdlen + anlen + sizeof(*redns), re, af);
	}
    }
    return SNIFL_E_APP;
}
