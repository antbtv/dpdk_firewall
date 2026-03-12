#ifndef FW_PIPELINE_H
#define FW_PIPELINE_H

#include <stdint.h>

/** Maximum packets processed per burst. */
#define MAX_BURST 32

/** Arguments passed to pipeline_lcore_main() via rte_eal_remote_launch(). */
struct pipeline_args {
    uint16_t port_in;      /* RX port: 0 = WAN (lcore 1), 1 = LAN (lcore 2) */
    uint16_t port_out;     /* TX port: 1 = LAN (lcore 1), 0 = WAN (lcore 2) */
    int      src_is_afxdp; /* 1 if port_in is AF_XDP (zero-copy mode):
                            * mbufs are UMEM-backed → must deep-copy to g_mbuf_pool
                            * before TX on AF_PACKET port to return UMEM frames. */
};

/**
 * pipeline_lcore_main() — per-lcore packet forwarding loop.
 *
 * Phase 1: minimal RX→TX forwarding (no filtering).
 * Phase 2: adds CLASSIFIER + RULE ENGINE.
 * Phase 3: adds BLACKLIST CHECK, RATE LIMIT, DDOS UPDATE.
 *
 * @param arg  Pointer to struct pipeline_args.
 * @return     Always 0 (lcore exit value).
 */
int pipeline_lcore_main(void *arg);

#endif /* FW_PIPELINE_H */
