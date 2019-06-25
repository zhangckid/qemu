/*
 * COarse-grain LOck-stepping Virtual Machines for Non-stop Service (COLO)
 * (a.k.a. Fault Tolerance or Continuous Replication)
 *
 * Copyright (c) 2019 Intel Corporation
 *
 * Author: Zhang Chen <chen.zhang@intel.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "trace.h"
#include "qemu-common.h"
#include "qapi/error.h"
#include "net/net.h"
#include "qom/object_interfaces.h"
#include "qom/object.h"
#include "chardev/char-fe.h"
#include "qemu/sockets.h"
#include "migration/colo.h"
#include "migration/migration.h"
#include "sysemu/iothread.h"
#include "migration/failover.h"
#include "util.h"

#define TYPE_HEARTBEAT "heartbeat"
#define HEARTBEAT(obj) \
    OBJECT_CHECK(HeartbeatState, (obj), TYPE_HEARTBEAT)

#define HEARTBEAT_READ_LEN_MAX NET_BUFSIZE
/* Default heartbeat pulse interval */
#define HEARTBEAT_PULSE_INTERVAL_DEFAULT 5000
/* Default heartbeat timeout */
#define HEARTBEAT_TIMEOUT_DEFAULT 2000

typedef struct HeartbeatState {
    Object parent;

    bool server;
    char *heartbeat_node;
    uint32_t pulse_interval;
    uint32_t timeout;
    CharBackend chr_heartbeat_node;
    SocketReadState heartbeat_rs;

    QEMUTimer *pulse_timer;
    QEMUTimer *timeout_timer;
    IOThread *iothread;
    GMainContext *worker_context;
} HeartbeatState;

typedef struct HeartbeatClass {
    ObjectClass parent_class;
} HeartbeatClass;

static int heartbeat_chr_send(HeartbeatState *s,
                              const uint8_t *buf,
                              uint32_t size)
{
    int ret = 0;
    uint32_t len = htonl(size);

    if (!size) {
        return 0;
    }

    ret = qemu_chr_fe_write_all(&s->chr_heartbeat_node, (uint8_t *)&len,
                                sizeof(len));
    if (ret != sizeof(len)) {
        goto err;
    }

    ret = qemu_chr_fe_write_all(&s->chr_heartbeat_node, (uint8_t *)buf,
                                size);
    if (ret != size) {
        goto err;
    }

    return 0;

err:
    return ret < 0 ? ret : -EIO;
}

static int heartbeat_chr_can_read(void *opaque)
{
    return HEARTBEAT_READ_LEN_MAX;
}

static void heartbeat_node_in(void *opaque, const uint8_t *buf, int size)
{
    HeartbeatState *s = HEARTBEAT(opaque);
    int ret;

    ret = net_fill_rstate(&s->heartbeat_rs, buf, size);
    if (ret == -1) {
        qemu_chr_fe_set_handlers(&s->chr_heartbeat_node, NULL, NULL, NULL, NULL,
                                 NULL, NULL, true);
        error_report("heartbeat get pulse error");
    }
}

static void heartbeat_send_pulse(void *opaque)
{
    HeartbeatState *s = opaque;
    char buf[] = "heartbeat pulse";

    heartbeat_chr_send(s, (uint8_t *)buf, sizeof(buf));
}

static void heartbeat_regular_pulse(void *opaque)
{
    HeartbeatState *s = opaque;

    heartbeat_send_pulse(s);
    timer_mod(s->pulse_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) +
              s->pulse_interval);
}

static void heartbeat_timeout(void *opaque)
{
    failover_request_active(NULL);
}

static void heartbeat_timer_init(HeartbeatState *s)
{
    AioContext *ctx = iothread_get_aio_context(s->iothread);

    s->timeout_timer = aio_timer_new(ctx, QEMU_CLOCK_VIRTUAL, SCALE_MS,
                                     heartbeat_timeout, s);

    s->pulse_timer = aio_timer_new(ctx, QEMU_CLOCK_VIRTUAL, SCALE_MS,
                                      heartbeat_regular_pulse, s);

    if (!s->pulse_interval) {
        s->pulse_interval = HEARTBEAT_PULSE_INTERVAL_DEFAULT;
    }

    if (!s->timeout) {
        s->timeout = HEARTBEAT_TIMEOUT_DEFAULT;
    }

    timer_mod(s->pulse_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) +
              s->pulse_interval);
}

static void heartbeat_timer_del(HeartbeatState *s)
{
    if (s->pulse_timer) {
        timer_del(s->pulse_timer);
        timer_free(s->pulse_timer);
        s->pulse_timer = NULL;
    }

    if (s->timeout_timer) {
        timer_del(s->timeout_timer);
        timer_free(s->timeout_timer);
        s->timeout_timer = NULL;
    }
 }

static char *heartbeat_get_node(Object *obj, Error **errp)
{
    HeartbeatState *s = HEARTBEAT(obj);

    return g_strdup(s->heartbeat_node);
}

static void heartbeat_set_node(Object *obj, const char *value, Error **errp)
{
    HeartbeatState *s = HEARTBEAT(obj);

    g_free(s->heartbeat_node);
    s->heartbeat_node = g_strdup(value);
}

static bool heartbeat_get_server(Object *obj, Error **errp)
{
    HeartbeatState *s = HEARTBEAT(obj);

    return s->server;
}

static void heartbeat_set_server(Object *obj, bool value, Error **errp)
{
    HeartbeatState *s = HEARTBEAT(obj);

    s->server = value;
}

static void heartbeat_get_interval(Object *obj, Visitor *v,
                                   const char *name, void *opaque,
                                   Error **errp)
{
    HeartbeatState *s = HEARTBEAT(obj);
    uint32_t value = s->pulse_interval;

    visit_type_uint32(v, name, &value, errp);
}

static void heartbeat_set_interval(Object *obj, Visitor *v,
                                   const char *name, void *opaque,
                                   Error **errp)
{
    HeartbeatState *s = HEARTBEAT(obj);
    Error *local_err = NULL;
    uint32_t value;

    visit_type_uint32(v, name, &value, &local_err);
    if (local_err) {
        goto out;
    }
    if (!value) {
        error_setg(&local_err, "Property '%s.%s' requires a positive value",
                   object_get_typename(obj), name);
        goto out;
    }
    s->pulse_interval = value;

out:
    error_propagate(errp, local_err);
}

static void heartbeat_get_timeout(Object *obj, Visitor *v,
                                  const char *name, void *opaque,
                                  Error **errp)
{
    HeartbeatState *s = HEARTBEAT(obj);
    uint32_t value = s->timeout;

    visit_type_uint32(v, name, &value, errp);
}

static void heartbeat_set_timeout(Object *obj, Visitor *v,
                                  const char *name, void *opaque,
                                  Error **errp)
{
    HeartbeatState *s = HEARTBEAT(obj);
    Error *local_err = NULL;
    uint32_t value;

    visit_type_uint32(v, name, &value, &local_err);
    if (local_err) {
        goto out;
    }
    if (!value) {
        error_setg(&local_err, "Property '%s.%s' requires a positive value",
                   object_get_typename(obj), name);
        goto out;
    }
    s->timeout = value;

out:
    error_propagate(errp, local_err);
}

static void heartbeat_rs_finalize(SocketReadState *heartbeat_rs)
{
    HeartbeatState *s = container_of(heartbeat_rs, HeartbeatState,
                                     heartbeat_rs);

    if (!s->server) {
        char buf[] = "heartbeat reply pulse";

        heartbeat_chr_send(s, (uint8_t *)buf, sizeof(buf));
    }

    timer_mod(s->timeout_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) +
              s->timeout);

    error_report("heartbeat got message : %s", heartbeat_rs->buf);
}

static int find_and_check_chardev(Chardev **chr,
                                  char *chr_name,
                                  Error **errp)
{
    *chr = qemu_chr_find(chr_name);
    if (*chr == NULL) {
        error_setg(errp, "Device '%s' not found",
                   chr_name);
        return 1;
    }

    if (!qemu_chr_has_feature(*chr, QEMU_CHAR_FEATURE_RECONNECTABLE)) {
        error_setg(errp, "chardev \"%s\" is not reconnectable",
                   chr_name);
        return 1;
    }

    return 0;
}

static void heartbeat_iothread(HeartbeatState *s)
{
    object_ref(OBJECT(s->iothread));
    s->worker_context = iothread_get_g_main_context(s->iothread);

    qemu_chr_fe_set_handlers(&s->chr_heartbeat_node, heartbeat_chr_can_read,
                             heartbeat_node_in, NULL, NULL,
                             s, s->worker_context, true);

    heartbeat_timer_init(s);
}

static void heartbeat_complete(UserCreatable *uc, Error **errp)
{
    HeartbeatState *s = HEARTBEAT(uc);
    Chardev *chr;

    if (!s->heartbeat_node || !s->iothread) {
        error_setg(errp, "heartbeat needs 'heartbeat_node' and 'server' "
                   " property set");
        return;
    }

    if (find_and_check_chardev(&chr, s->heartbeat_node, errp) ||
        !qemu_chr_fe_init(&s->chr_heartbeat_node, chr, errp)) {
        return;
    }

    net_socket_rs_init(&s->heartbeat_rs, heartbeat_rs_finalize, false);

    heartbeat_iothread(s);

    return;
}

static void heartbeat_class_init(ObjectClass *oc, void *data)
{
    UserCreatableClass *ucc = USER_CREATABLE_CLASS(oc);

    ucc->complete = heartbeat_complete;
}

static void heartbeat_init(Object *obj)
{
    HeartbeatState *s = HEARTBEAT(obj);

    object_property_add_str(obj, "heartbeat_node",
                            heartbeat_get_node, heartbeat_set_node,
                            NULL);

    object_property_add_bool(obj, "server",
                             heartbeat_get_server,
                             heartbeat_set_server, NULL);

    object_property_add(obj, "pulse_interval", "uint32",
                        heartbeat_get_interval,
                        heartbeat_set_interval, NULL, NULL, NULL);

    object_property_add(obj, "timeout", "uint32",
                        heartbeat_get_timeout,
                        heartbeat_set_timeout, NULL, NULL, NULL);

    object_property_add_link(obj, "iothread", TYPE_IOTHREAD,
                            (Object **)&s->iothread,
                            object_property_allow_set_link,
                            OBJ_PROP_LINK_STRONG, NULL);
}

static void heartbeat_finalize(Object *obj)
{
    HeartbeatState *s = HEARTBEAT(obj);

    qemu_chr_fe_deinit(&s->chr_heartbeat_node, false);

    if (s->iothread) {
        heartbeat_timer_del(s);
    }

    g_free(s->heartbeat_node);
}

static const TypeInfo heartbeat_info = {
    .name = TYPE_HEARTBEAT,
    .parent = TYPE_OBJECT,
    .instance_size = sizeof(HeartbeatState),
    .instance_init = heartbeat_init,
    .instance_finalize = heartbeat_finalize,
    .class_size = sizeof(HeartbeatClass),
    .class_init = heartbeat_class_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_USER_CREATABLE },
        { }
    }
};

static void register_types(void)
{
    type_register_static(&heartbeat_info);
}

type_init(register_types);
