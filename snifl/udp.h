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

typedef struct snifl_udp {
    uint16_t srcport;
    uint16_t dstport;
    uint16_t len;
    uint16_t chksum;
    char data[0];
} snifl_udp;

#define	snifl_udp_hdrlen(udp)	offsetof(snifl_udp, data)
#define	snifl_udp_data(udp)		((void*)(udp)->data)

struct snifl_udp *snifl_udp2udp(void *pkt, const struct snifl_udp *srcudp, const void *srcpkt, const struct snifl_af *af);
int snifl_sendudp(const struct snifl *tunl, struct snifl_udp *udp, int datalen, void *pkt, const struct snifl_af *af);
