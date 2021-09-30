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

typedef struct snifl_mgr {
    struct jTree *socks;
    void *arg;
} snifl_mgr;

struct snifl;
struct snifl_lstn;
struct snifl_sock;
struct snifl_accept;
struct snifl_af;

int snifl_mgr_accept(struct snifl_sock *sock, const struct snifl_accept *ac);
int snifl_mgr_tcpin(const struct snifl *tunl, const struct snifl_lstn *lstn, const void *payload, int paylen, const void *pk, const struct snifl_af *af);
void snifl_mgr_cleanup(struct snifl_mgr *mgr);
void snifl_mgr_done(struct snifl_mgr *mgr);
