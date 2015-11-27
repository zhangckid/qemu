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

#endif /* QEMU_COLO_PROXY_H */
