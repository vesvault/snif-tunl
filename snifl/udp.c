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
#include "udp.h"


snifl_udp *snifl_udp2udp(void *pkt, const snifl_udp *srcudp, const void *srcpkt, const snifl_af *af) {
    snifl_udp *udp = af->pkt2pkt(pkt, srcpkt);
    udp->srcport = srcudp->dstport;
    udp->dstport = srcudp->srcport;
    return udp;
}

int snifl_sendudp(const snifl *tunl, snifl_udp *udp, int datalen, void *pkt, const snifl_af *af) {
    int udplen = datalen + snifl_udp_hdrlen(udp);
    snifl_h2a(udp->len, udplen);
    udp->chksum = 0;
    udp->chksum = ~af->pchksum(udp, pkt, udplen);
    return af->sendpkt(tunl, pkt, udplen);
}
