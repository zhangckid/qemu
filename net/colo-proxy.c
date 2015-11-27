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

#include "colo-proxy.h"

#define __DEBUG__

#ifdef __DEBUG__
#define DEBUG(format, ...) printf(format, ##__VA_ARGS__)
#else
#define DEBUG(format, ...)
#endif


static ssize_t colo_proxy_receive_iov(NetFilterState *nf,
                                         NetClientState *sender,
                                         unsigned flags,
                                         const struct iovec *iov,
                                         int iovcnt,
                                         NetPacketSent *sent_cb)
{
    /*
     * We return size when buffer a packet, the sender will take it as
     * a already sent packet, so sent_cb should not be called later.
     *
     */
    ColoProxyState *s = FILTER_COLO_PROXY(nf);
    if (s->colo_mode == COLO_PRIMARY_MODE) {
         /* colo_proxy_primary_handler */
    } else {
         /* colo_proxy_primary_handler */
    }
    return iov_size(iov, iovcnt);
}

static void colo_proxy_cleanup(NetFilterState *nf)
{
     /* cleanup */
}


static void colo_proxy_setup(NetFilterState *nf, Error **errp)
{
    ColoProxyState *s = FILTER_COLO_PROXY(nf);
    if (!s->addr) {
        error_setg(errp, "filter colo_proxy needs 'addr' \
                     property set!");
        return;
    }

    if (nf->direction != NET_FILTER_DIRECTION_ALL) {
        printf("colo need queue all packet,\
                    please startup colo-proxy with queue=all\n");
        return;
    }

    s->sockfd = -1;
    s->has_failover = false;
    colo_do_checkpoint = false;
    g_queue_init(&s->unprocessed_connections);

    if (!strcmp(mode, PRIMARY_MODE)) {
        s->colo_mode = COLO_PRIMARY_MODE;
    } else if (!strcmp(mode, SECONDARY_MODE)) {
        s->colo_mode = COLO_SECONDARY_MODE;
    } else {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE, "mode",
                    "primary or secondary");
        return;
    }
}

static void colo_proxy_class_init(ObjectClass *oc, void *data)
{
    NetFilterClass *nfc = NETFILTER_CLASS(oc);

    nfc->setup = colo_proxy_setup;
    nfc->cleanup = colo_proxy_cleanup;
    nfc->receive_iov = colo_proxy_receive_iov;
}

static char *colo_proxy_get_mode(Object *obj, Error **errp)
{
    return g_strdup(mode);
}

static void colo_proxy_set_mode(Object *obj, const char *value, Error **errp)
{
    g_free(mode);
    mode = g_strdup(value);
}

static char *colo_proxy_get_addr(Object *obj, Error **errp)
{
    ColoProxyState *s = FILTER_COLO_PROXY(obj);

    return g_strdup(s->addr);
}

static void colo_proxy_set_addr(Object *obj, const char *value, Error **errp)
{
    ColoProxyState *s = FILTER_COLO_PROXY(obj);
    g_free(s->addr);
    s->addr = g_strdup(value);
}

static void colo_proxy_init(Object *obj)
{
    object_property_add_str(obj, "mode", colo_proxy_get_mode,
                            colo_proxy_set_mode, NULL);
    object_property_add_str(obj, "addr", colo_proxy_get_addr,
                            colo_proxy_set_addr, NULL);
}

static const TypeInfo colo_proxy_info = {
    .name = TYPE_FILTER_COLO_PROXY,
    .parent = TYPE_NETFILTER,
    .class_init = colo_proxy_class_init,
    .instance_init = colo_proxy_init,
    .instance_size = sizeof(ColoProxyState),
};

static void register_types(void)
{
    type_register_static(&colo_proxy_info);
}

type_init(register_types);
