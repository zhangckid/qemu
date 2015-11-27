/*
 * COarse-grain LOck-stepping Virtual Machines for Non-stop Service (COLO)
 * (a.k.a. Fault Tolerance or Continuous Replication)
 *
 * Copyright (c) 2015 HUAWEI TECHNOLOGIES CO., LTD.
 * Copyright (c) 2015 FUJITSU LIMITED
 * Copyright (c) 2015 Intel Corporation
 *
 * Author: Zhang Chen <zhangchen.fnst@cn.fujitsu.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 */


#ifndef QEMU_COLO_PROXY_H
#define QEMU_COLO_PROXY_H

#include "net/filter.h"
#include "net/queue.h"
#include "qemu-common.h"
#include "qemu/iov.h"
#include "qapi/qmp/qerror.h"
#include "qapi-visit.h"
#include "qom/object.h"
#include "qemu/sockets.h"
#include "qemu/main-loop.h"
#include <netinet/if_ether.h>
#include "qemu/jhash.h"
#include "qemu/coroutine.h"

#define FILTER_COLO_PROXY(obj) \
    OBJECT_CHECK(ColoProxyState, (obj), TYPE_FILTER_COLO_PROXY)

#define TYPE_FILTER_COLO_PROXY "colo-proxy"
#define PRIMARY_MODE "primary"
#define SECONDARY_MODE "secondary"

typedef enum {
    COLO_PRIMARY_MODE,               /* primary mode  */
    COLO_SECONDARY_MODE,             /* secondary mode */
} mode_type;

typedef struct ColoProxyState {
    NetFilterState parent_obj;
    NetQueue *incoming_queue;        /* guest normal net queue */
    NetFilterDirection direction;    /* packet direction */
    mode_type colo_mode;             /* colo mode (primary or
                                      * secondary)
                                      */
    char *addr;                       /* primary colo connect addr
                                      * or secondary server addr
                                      */
    int sockfd;                      /* primary client socket fd or
                                      * secondary server socket fd
                                      */
    bool has_failover;               /* colo failover flag */
    GHashTable *unprocessed_packets; /* hashtable to save connection */
    GQueue unprocessed_connections;  /* to save unprocessed_connections */
    Coroutine *co;
} ColoProxyState;

struct ip {
#ifdef HOST_WORDS_BIGENDIAN
    uint8_t  ip_v:4,                 /* version */
             ip_hl:4;                /* header length */
#else
    uint8_t  ip_hl:4,                /* header length */
             ip_v:4;                 /* version */
#endif
    uint8_t  ip_tos;                 /* type of service */
    uint16_t ip_len;                 /* total length */
    uint16_t ip_id;                  /* identification */
    uint16_t ip_off;                 /* fragment offset field */
#define    IP_DF 0x4000              /* don't fragment flag */
#define    IP_MF 0x2000              /* more fragments flag */
#define    IP_OFFMASK 0x1fff
/* mask for fragmenting bits */
    uint8_t  ip_ttl;                 /* time to live */
    uint8_t  ip_p;                   /* protocol */
    uint16_t ip_sum;                 /* checksum */
    uint32_t ip_src, ip_dst;         /* source and dest address */
} QEMU_PACKED;

typedef struct Packet {
    void *data;
    union {
        uint8_t *network_layer;
        struct ip *ip;
    };
    uint8_t *transport_layer;
    int size;
    ColoProxyState *s;
    bool should_be_sent;
    NetClientState *sender;
} Packet;

typedef struct Connection_key {
    /* (src, dst) must be grouped, in the same way than in IP header */
    uint32_t src;
    uint32_t dst;
    union {
        uint32_t ports;
        uint16_t port16[2];
    };
    uint8_t ip_proto;
} QEMU_PACKED Connection_key;

typedef struct Connection {
    /* connection primary send queue */
    GQueue primary_list;
    /* connection secondary send queue */
    GQueue secondary_list;
     /* flag to enqueue unprocessed_connections */
    bool processing;
} Connection;

typedef enum {
    PRIMARY_OUTPUT,           /* primary output packet queue */
    PRIMARY_INPUT,            /* primary input packet queue */
    SECONDARY_OUTPUT,         /* secondary output packet queue */
} packet_type;

#endif /* QEMU_COLO_PROXY_H */
