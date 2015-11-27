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

static char *mode;
static bool colo_do_checkpoint;
static void packet_destroy(void *opaque, void *user_data);

static uint32_t connection_key_hash(const void *opaque)
{
    const Connection_key *key = opaque;
    uint32_t a, b, c;

    /* Jenkins hash */
    a = b = c = JHASH_INITVAL + sizeof(*key);
    a += key->src;
    b += key->dst;
    c += key->ports;
    __jhash_mix(a, b, c);

    a += key->ip_proto;
    __jhash_final(a, b, c);

    return c;
}

static int connection_key_equal(const void *opaque1, const void *opaque2)
{
    return memcmp(opaque1, opaque2, sizeof(Connection_key)) == 0;
}

static void connection_destroy(void *opaque)
{
    Connection *connection = opaque;
    g_queue_foreach(&connection->primary_list, packet_destroy, NULL);
    g_queue_free(&connection->primary_list);
    g_queue_foreach(&connection->secondary_list, packet_destroy, NULL);
    g_queue_free(&connection->secondary_list);
    g_slice_free(Connection, connection);
}

static Connection *connection_new(void)
{
    Connection *connection = g_slice_new(Connection);

    g_queue_init(&connection->primary_list);
    g_queue_init(&connection->secondary_list);
    connection->processing = false;

    return connection;
}

/* Return 0 on success, or return -1 if the pkt is corrpted */
static int parse_packet_early(Packet *pkt, Connection_key *key)
{
    int network_length;
    uint8_t *data = pkt->data;

    pkt->network_layer = data + ETH_HLEN;
    if (ntohs(*(uint16_t *)(data + 12)) != ETH_P_IP) {
        if (ntohs(*(uint16_t *)(data + 12)) == ETH_P_ARP) {
            return -1;
        }
        return 0;
    }

    network_length = pkt->ip->ip_hl * 4;
    pkt->transport_layer = pkt->network_layer + network_length;
    key->ip_proto = pkt->ip->ip_p;
    key->src = pkt->ip->ip_src;
    key->dst = pkt->ip->ip_dst;

    switch (key->ip_proto) {
    case IPPROTO_TCP:
    case IPPROTO_UDP:
    case IPPROTO_DCCP:
    case IPPROTO_ESP:
    case IPPROTO_SCTP:
    case IPPROTO_UDPLITE:
        key->ports = *(uint32_t *)(pkt->transport_layer);
        break;
    case IPPROTO_AH:
        key->ports = *(uint32_t *)(pkt->transport_layer + 4);
        break;
    default:
        break;
    }

    return 0;
}

static Packet *packet_new(ColoProxyState *s, const void *data,
                          int size, Connection_key *key, NetClientState *sender)
{
    Packet *pkt = g_slice_new(Packet);

    pkt->data = g_malloc(size);
    memcpy(pkt->data, data, size);
    pkt->size = size;
    pkt->s = s;
    pkt->sender = sender;
    pkt->should_be_sent = false;

    if (parse_packet_early(pkt, key)) {
        packet_destroy(pkt, NULL);
        pkt = NULL;
    }

    return pkt;
}

static void packet_destroy(void *opaque, void *user_data)
{
    Packet *pkt = opaque;
    g_free(pkt->data);
    g_slice_free(Packet, pkt);
}

static Connection *colo_proxy_enqueue_packet(GHashTable *unprocessed_packets,
                                          Connection_key *key,
                                          Packet *pkt, packet_type type)
{
    Connection *connection;
    Packet *tmppkt;
    connection = g_hash_table_lookup(unprocessed_packets, key);
    if (connection == NULL) {
        Connection_key *new_key = g_malloc(sizeof(*key));

        connection = connection_new();
        memcpy(new_key, key, sizeof(*key));
        key = new_key;

        g_hash_table_insert(unprocessed_packets, key, connection);
    }
    switch (type) {
    case PRIMARY_OUTPUT:
        if (g_queue_get_length(&connection->secondary_list) > 0) {
            tmppkt = g_queue_pop_head(&connection->secondary_list);
            DEBUG("g_queue_get_length(&connection->primary_list)=%d\n",
                        g_queue_get_length(&connection->primary_list));
            DEBUG("g_queue_get_length(&connection->secondary_list)=%d\n",
                        g_queue_get_length(&connection->secondary_list));
            if (colo_packet_compare(pkt, tmppkt)) {
                DEBUG("packet same and release packet\n");
                pkt->should_be_sent = true;
                break;
            } else {
                DEBUG("packet different\n");
                colo_proxy_notify_checkpoint();
                pkt->should_be_sent = false;
                break;
            }
        } else {
            g_queue_push_tail(&connection->primary_list, pkt);
            pkt->should_be_sent = false;
        }

        break;
    case SECONDARY_OUTPUT:
        g_queue_push_tail(&connection->secondary_list, pkt);
        DEBUG("secondary pkt data=%s,  pkt->ip->ipsrc=%x,pkt->ip->ipdst=%x\n",
                    (char *)pkt->data, pkt->ip->ip_src, pkt->ip->ip_dst);
        break;
    default:
        abort();
    }

    return connection;
}


/*
 * Packets to be sent by colo forward to
 * another colo
 * return:          >= 0        success
 *                  < 0        failed
 */
static ssize_t colo_forward2another(NetFilterState *nf,
                                         NetClientState *sender,
                                         unsigned flags,
                                         const struct iovec *iov,
                                         int iovcnt,
                                         NetPacketSent *sent_cb,
                                         mode_type mode)
{
    ColoProxyState *s = FILTER_COLO_PROXY(nf);
    ssize_t ret = 0;
    ssize_t size = 0;
    struct iovec sizeiov = {
        .iov_base = &size,
        .iov_len = 8
    };
    size = iov_size(iov, iovcnt);
    if (!size) {
        return 0;
    }

    if (mode == COLO_PRIMARY_MODE) {
        qemu_net_queue_send_iov(s->incoming_queue, sender, flags,
                           iov, iovcnt, NULL);
    }
    ret = iov_send(s->sockfd, &sizeiov, 8, 0, 8);
    if (ret < 0) {
        return ret;
    }
    ret = iov_send(s->sockfd, iov, iovcnt, 0, size);
    return ret;
}

/*
 * recv and handle colo secondary
 * forward packets in colo primary
 */
static void colo_proxy_primary_forward_handler(NetFilterState *nf)
{
    ColoProxyState *s = FILTER_COLO_PROXY(nf);
    ssize_t len = 0;
    ssize_t ret = 0;
    struct iovec sizeiov = {
        .iov_base = &len,
        .iov_len = 8
    };
    if (s->sockfd < 0) {
        printf("secondary forward disconnected\n");
        return;
    }
    iov_recv(s->sockfd, &sizeiov, 8, 0, 8);
    DEBUG("primary_forward_handler recv lensbuf lens=%zu\n", len);

    if (len > 0) {
        char *recvbuf;
        recvbuf = g_malloc0(len);
        struct iovec iov = {
            .iov_base = recvbuf,
            .iov_len = len
        };
        iov_recv(s->sockfd, &iov, len, 0, len);
        DEBUG("primary_forward_handler primary recvbuf=%s\n", recvbuf);
        ret = colo_enqueue_secondary_packet(nf, recvbuf, len);
        if (ret) {
            DEBUG("colo_enqueue_secondary_packet succese\n");
        } else {
            DEBUG("colo_enqueue_secondary_packet failed\n");
        }
        g_free(recvbuf);
    }
}

/*
 * recv and handle colo primary
 * forward packets in colo secondary
 */
static void colo_proxy_secondary_forward_handler(NetFilterState *nf)
{
    ColoProxyState *s = FILTER_COLO_PROXY(nf);
    ssize_t len = 0;
    struct iovec sizeiov = {
        .iov_base = &len,
        .iov_len = 8
    };
    iov_recv(s->sockfd, &sizeiov, 8, 0, 8);
    if (len > 0) {
        char *buf;
        buf = g_malloc0(len);
        struct iovec iov = {
            .iov_base = buf,
            .iov_len = len
        };
        iov_recv(s->sockfd, &iov, len, 0, len);
        qemu_net_queue_send(s->incoming_queue, nf->netdev,
                    0, (const uint8_t *)buf, len, NULL);
        g_free(buf);
    }
}

/*
 * colo primary handle host's normal send and
 * recv packets to primary guest
 * return:          >= 0      success
 *                  < 0       failed
 */
static ssize_t colo_proxy_primary_handler(NetFilterState *nf,
                                         NetClientState *sender,
                                         unsigned flags,
                                         const struct iovec *iov,
                                         int iovcnt,
                                         NetPacketSent *sent_cb)
{
    ssize_t ret = 0;
    int direction;

    if (sender == nf->netdev) {
        /* This packet is sent by netdev itself */
        direction = NET_FILTER_DIRECTION_TX;
    } else {
        direction = NET_FILTER_DIRECTION_RX;
    }
    /*
     * if packet's direction=rx
     * enqueue packets to primary queue
     * and wait secondary queue to compare
     * if packet's direction=tx
     * enqueue packets then send packets to
     * secondary and flush  queued packets
    */

    if (colo_do_checkpoint) {
        colo_proxy_do_checkpoint(nf);
    }

    if (direction == NET_FILTER_DIRECTION_RX) {
        ret = colo_enqueue_primary_packet(nf, sender, flags, iov,
                    iovcnt, sent_cb);
    } else {
        ret = colo_forward2another(nf, sender, flags, iov, iovcnt,
                    sent_cb, COLO_PRIMARY_MODE);
    }

    return ret;
}

/*
 * colo secondary handle host's normal send and
 * recv packets to secondary guest
 * return:          >= 0      success
 *                  < 0       failed
 */
static ssize_t colo_proxy_secondary_handler(NetFilterState *nf,
                                         NetClientState *sender,
                                         unsigned flags,
                                         const struct iovec *iov,
                                         int iovcnt,
                                         NetPacketSent *sent_cb)
{
    ColoProxyState *s = FILTER_COLO_PROXY(nf);
    int direction;
    ssize_t ret = 0;

    if (sender == nf->netdev) {
        /* This packet is sent by netdev itself */
        direction = NET_FILTER_DIRECTION_TX;
    } else {
        direction = NET_FILTER_DIRECTION_RX;
    }
    /*
     * if packet's direction=rx
     * enqueue packets and send to
     * primary QEMU
     * if packet's direction=tx
     * record PVM's packet inital seq & adjust
     * client's ack,send adjusted packets to SVM(next version will be do)
     */

    if (direction == NET_FILTER_DIRECTION_RX) {
        if (colo_has_failover(nf)) {
            qemu_net_queue_send_iov(s->incoming_queue, sender, flags, iov,
                            iovcnt, NULL);
            return 1;
        } else {
            ret = colo_forward2another(nf, sender, flags, iov, iovcnt,
                        sent_cb, COLO_SECONDARY_MODE);
        }

    } else {
        if (colo_has_failover(nf)) {
            qemu_net_queue_send_iov(s->incoming_queue, sender, flags, iov,
                            iovcnt, NULL);
        }
        return 1;
    }
    return ret;
}

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
    ssize_t ret = 0;
    if (s->colo_mode == COLO_PRIMARY_MODE) {
        ret = colo_proxy_primary_handler(nf, sender, flags,
                    iov, iovcnt, sent_cb);
    } else {
        ret = colo_proxy_secondary_handler(nf, sender, flags,
                    iov, iovcnt, sent_cb);
    }
    if (ret < 0) {
        DEBUG("colo_proxy_receive_iov running failed\n");
    }
    return iov_size(iov, iovcnt);
}

static void colo_proxy_cleanup(NetFilterState *nf)
{
    ColoProxyState *s = FILTER_COLO_PROXY(nf);
    close(s->sockfd);
    s->sockfd = -1;
    g_free(mode);
    g_free(s->addr);
}

static void colo_accept_incoming(ColoProxyState *s)
{
    DEBUG("into colo_accept_incoming\n");
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    int acceptsock, err;

    do {
        acceptsock = qemu_accept(s->sockfd, (struct sockaddr *)&addr, &addrlen);
        err = socket_error();
    } while (acceptsock < 0 && err == EINTR);
    qemu_set_fd_handler(s->sockfd, NULL, NULL, NULL);
    closesocket(s->sockfd);

    DEBUG("accept colo proxy\n");

    if (acceptsock < 0) {
        printf("could not accept colo connection (%s)\n",
                     strerror(err));
        return;
    }
    s->sockfd = acceptsock;
    qemu_set_fd_handler(s->sockfd,
                (IOHandler *)colo_proxy_secondary_forward_handler, NULL,
                (void *)s);
    return;
}

/* Return 1 on success, or return -1 if failed */
static ssize_t colo_start_incoming(ColoProxyState *s)
{
    int serversock;
    serversock = inet_listen(s->addr, NULL, 256, SOCK_STREAM, 0, NULL);
    if (serversock < 0) {
        g_free(s->addr);
        return -1;
    }
    s->sockfd = serversock;
    qemu_set_fd_handler(serversock, (IOHandler *)colo_accept_incoming, NULL,
                        (void *)s);
    g_free(s->addr);
    return 1;
}

/* Return 1 on success, or return -1 if setup failed */
static ssize_t colo_proxy_primary_setup(NetFilterState *nf)
{
    ColoProxyState *s = FILTER_COLO_PROXY(nf);
    int sock;
    sock = inet_connect(s->addr, NULL);
    if (sock < 0) {
        printf("colo proxy connect failed\n");
        g_free(s->addr);
        return -1;
    }
    DEBUG("colo proxy connect success\n");
    s->sockfd = sock;
    qemu_set_fd_handler(s->sockfd,
                (IOHandler *)colo_proxy_primary_forward_handler,
                NULL, (void *)s);
    g_free(s->addr);
    return 1;
}

/* Return 1 on success, or return -1 if setup failed */
static ssize_t colo_proxy_secondary_setup(NetFilterState *nf)
{
    ColoProxyState *s = FILTER_COLO_PROXY(nf);
    return colo_start_incoming(s);
}

static void colo_proxy_setup(NetFilterState *nf, Error **errp)
{
    ColoProxyState *s = FILTER_COLO_PROXY(nf);
    ssize_t ret = 0;
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
    s->incoming_queue = qemu_new_net_queue(qemu_netfilter_pass_to_next, nf);
    s->unprocessed_packets = g_hash_table_new_full(connection_key_hash,
                                                       connection_key_equal,
                                                       g_free,
                                                       connection_destroy);
    g_queue_init(&s->unprocessed_connections);

    if (!strcmp(mode, PRIMARY_MODE)) {
        s->colo_mode = COLO_PRIMARY_MODE;
        ret = colo_proxy_primary_setup(nf);
    } else if (!strcmp(mode, SECONDARY_MODE)) {
        s->colo_mode = COLO_SECONDARY_MODE;
        ret = colo_proxy_secondary_setup(nf);
    } else {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE, "mode",
                    "primary or secondary");
        return;
    }
    if (ret) {
        DEBUG("colo_proxy_setup success\n");
    } else {
        DEBUG("colo_proxy_setup failed\n");
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
