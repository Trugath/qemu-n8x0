/*
 * Maemo umac scan/join frames and a tiny IPv4 forwarder.
 *
 * Included from cx3110x.c. umac_frame_rx treats a negative first halfword as
 * fw_ctrl and a non-negative one as a data frame. Bit 0 must be set or the
 * frame is dropped. The 802.11 header is read at payload+20. RSSI dBm is
 * (payload[8] >> 1) - 110. A scan trap (bit 0 and bit 15, halfword +8 == 2,
 * event 0 at +12) advances scan_fsm.
 *
 * CX3110X_NO_NET drops the socket forwarder so the host smoke harness can
 * compile this file without the QEMU main loop.
 */

static const struct {
    const char *ssid;
    uint8_t bssid[6];
    uint8_t rssi;
    bool locked;
} cx_aps[2] = {
    { "QEMU-N8x0", { 0x02, 0x00, 0x00, 0x11, 0x22, 0x33 }, CX_RSSI_STRONG, false },
    { "QEMU-Locked", { 0x02, 0x00, 0x00, 0xaa, 0xbb, 0xcc }, CX_RSSI_WEAK, true },
};

static const uint8_t cx_gw_mac[6] = { 0x02, 0x00, 0x00, 0x11, 0x22, 0x02 };

static const uint8_t cx_wpa_ie[] = {
    0xdd, 0x16,
    0x00, 0x50, 0xf2, 0x01,
    0x01, 0x00,
    0x00, 0x50, 0xf2, 0x02,
    0x01, 0x00,
    0x00, 0x50, 0xf2, 0x02,
    0x01, 0x00,
    0x00, 0x50, 0xf2, 0x02,
};

static const uint8_t cx_rsn_ie[] = {
    0x30, 0x14,
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x02,
    0x00, 0x00,
};

static const uint8_t cx_rates_ie[] = {
    0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24,
};

#ifndef CX3110X_NO_NET
struct cx_flow {
    bool used;
    uint8_t proto;
    uint32_t dip;
    uint32_t real_dip;
    uint16_t gport;
    uint16_t dport;
    int fd;
    uint32_t snd_nxt;
    uint32_t rcv_nxt;
    bool tcp_up;
    uint8_t hold[1400];
    size_t hold_len;
    struct cx3110x_s *hold_owner;
};
#endif

static void cx_put_le16(uint8_t *p, uint16_t v)
{
    p[0] = v & 0xff;
    p[1] = v >> 8;
}

#ifndef CX3110X_NO_NET
static uint32_t cx_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void cx_put_be32(uint8_t *p, uint32_t v)
{
    p[0] = v >> 24;
    p[1] = v >> 16;
    p[2] = v >> 8;
    p[3] = v;
}

static uint16_t cx_be16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static void cx_put_be16(uint8_t *p, uint16_t v)
{
    p[0] = v >> 8;
    p[1] = v;
}

static uint32_t cx_sum(const uint8_t *p, size_t n, uint32_t sum)
{
    size_t i;

    for (i = 0; i + 1 < n; i += 2) {
        sum += ((uint16_t)p[i] << 8) | p[i + 1];
    }
    if (n & 1) {
        sum += (uint16_t)p[n - 1] << 8;
    }
    return sum;
}

static uint16_t cx_fold(uint32_t sum)
{
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t)~sum;
}
#endif

/*
 * umac reads (dma_len - 24) bytes from payload+20. dma_len = dlen + 24
 * makes that read cover exactly the 802.11 frame.
 */
static void cx_queue_dot11(struct cx3110x_s *s, const uint8_t *dot11, size_t dlen,
                           uint8_t rssi)
{
    uint8_t frame[CX3110X_RX_MAX];
    size_t n = dlen + 24;

    if (n + 2 > sizeof(frame)) {
        return;
    }
    memset(frame, 0, sizeof(frame));
    frame[0] = 0x01;
    cx_put_le16(frame + 4, 2412);
    frame[8] = rssi;
    memcpy(frame + 20, dot11, dlen);
    if (n & 1) {
        n++;
    }
    cx3110x_rx_queue(s, frame, n);
}

static void cx_mac_hdr(uint8_t *mac, uint8_t fc0, const uint8_t *da,
                       const uint8_t *sa, const uint8_t *bssid, uint16_t seq)
{
    memset(mac, 0, 24);
    mac[0] = fc0;
    memcpy(mac + 4, da, 6);
    memcpy(mac + 10, sa, 6);
    memcpy(mac + 16, bssid, 6);
    cx_put_le16(mac + 22, (seq << 4) & 0xfff0);
}

static void cx_queue_beacon(struct cx3110x_s *s, int idx, bool probe)
{
    uint8_t dot11[320];
    uint8_t da[6];
    size_t ssid_len = strlen(cx_aps[idx].ssid);
    size_t n;
    uint16_t cap = cx_aps[idx].locked ? 0x0011 : 0x0001;

    memset(da, 0xff, sizeof(da));
    memset(dot11, 0, sizeof(dot11));
    cx_mac_hdr(dot11, probe ? 0x50 : 0x80, da, cx_aps[idx].bssid,
               cx_aps[idx].bssid, s->dot11_seq++);
    n = 24;
    /* timestamp, interval, capability */
    n += 8;
    cx_put_le16(dot11 + n, 100);
    n += 2;
    cx_put_le16(dot11 + n, cap);
    n += 2;
    dot11[n++] = 0;
    dot11[n++] = ssid_len;
    memcpy(dot11 + n, cx_aps[idx].ssid, ssid_len);
    n += ssid_len;
    memcpy(dot11 + n, cx_rates_ie, sizeof(cx_rates_ie));
    n += sizeof(cx_rates_ie);
    dot11[n++] = 3;
    dot11[n++] = 1;
    dot11[n++] = 1;
    if (cx_aps[idx].locked) {
        memcpy(dot11 + n, cx_wpa_ie, sizeof(cx_wpa_ie));
        n += sizeof(cx_wpa_ie);
        memcpy(dot11 + n, cx_rsn_ie, sizeof(cx_rsn_ie));
        n += sizeof(cx_rsn_ie);
    }
    cx_queue_dot11(s, dot11, n, cx_aps[idx].rssi);
}

static void cx_queue_trap(struct cx3110x_s *s)
{
    uint8_t trap[16];

    memset(trap, 0, sizeof(trap));
    trap[0] = 0x01;
    trap[1] = 0x80;
    trap[8] = 2;
    cx3110x_rx_queue(s, trap, sizeof(trap));
}

static void cx_announce(struct cx3110x_s *s)
{
    if (s->bss_announced || s->joined >= 0) {
        return;
    }
    cx_queue_beacon(s, 0, false);
    cx_queue_beacon(s, 1, false);
    cx_queue_trap(s);
    s->bss_announced = true;
    info_report("cx3110x: AP QEMU-N8x0 (open, internet) and QEMU-Locked (WPA, weaker)");
}

static void cx_reply_auth(struct cx3110x_s *s, int ap, const uint8_t *sta)
{
    uint8_t dot11[30];

    cx_mac_hdr(dot11, 0xb0, sta, cx_aps[ap].bssid, cx_aps[ap].bssid,
               s->dot11_seq++);
    cx_put_le16(dot11 + 24, 0);
    cx_put_le16(dot11 + 26, 2);
    cx_put_le16(dot11 + 28, cx_aps[ap].locked ? 1 : 0);
    cx_queue_dot11(s, dot11, sizeof(dot11), cx_aps[ap].rssi);
}

static void cx_reply_assoc(struct cx3110x_s *s, int ap, const uint8_t *sta)
{
    uint8_t dot11[48];
    size_t n;

    cx_mac_hdr(dot11, 0x10, sta, cx_aps[ap].bssid, cx_aps[ap].bssid,
               s->dot11_seq++);
    cx_put_le16(dot11 + 24, cx_aps[ap].locked ? 0x0011 : 0x0001);
    cx_put_le16(dot11 + 26, cx_aps[ap].locked ? 1 : 0);
    cx_put_le16(dot11 + 28, cx_aps[ap].locked ? 0 : 0xc001);
    n = 30;
    memcpy(dot11 + n, cx_rates_ie, sizeof(cx_rates_ie));
    n += sizeof(cx_rates_ie);
    cx_queue_dot11(s, dot11, n, cx_aps[ap].rssi);
    if (!cx_aps[ap].locked) {
        s->joined = ap;
        memcpy(s->sta, sta, 6);
        s->sta_known = true;
        info_report("cx3110x: associated %02x:%02x:%02x:%02x:%02x:%02x to %s",
                    sta[0], sta[1], sta[2], sta[3], sta[4], sta[5],
                    cx_aps[ap].ssid);
    }
}

static int cx_ap_index(const uint8_t *mac)
{
    int i;

    for (i = 0; i < 2; i++) {
        if (!memcmp(mac, cx_aps[i].bssid, 6)) {
            return i;
        }
    }
    return -1;
}

static int cx_match_dot11(const uint8_t *p, size_t len)
{
    uint8_t fc;

    if (len < 24) {
        return -1;
    }
    fc = p[0];
    if (fc != 0x00 && fc != 0x40 && fc != 0xb0 && fc != 0x08 && fc != 0x88) {
        return -1;
    }
    if ((p[4] == 0xff && p[5] == 0xff) || cx_ap_index(p + 4) >= 0) {
        return 0;
    }
    return -1;
}

#ifndef CX3110X_NO_NET
static uint16_t cx_ip_id;

static void cx_queue_eth(struct cx3110x_s *s, const uint8_t *dst,
                         const uint8_t *src, uint16_t etype,
                         const uint8_t *payload, size_t plen)
{
    uint8_t dot11[1800];
    size_t n;

    if (!s->sta_known || plen + 32 > sizeof(dot11) - 24) {
        return;
    }
    cx_mac_hdr(dot11, 0x08, dst, cx_aps[0].bssid, src, s->dot11_seq++);
    dot11[1] = 0x02; /* From DS */
    dot11[24] = 0xaa;
    dot11[25] = 0xaa;
    dot11[26] = 0x03;
    dot11[27] = dot11[28] = dot11[29] = 0;
    dot11[30] = etype >> 8;
    dot11[31] = etype;
    memcpy(dot11 + 32, payload, plen);
    n = 32 + plen;
    cx_queue_dot11(s, dot11, n, CX_RSSI_STRONG);
}

static void cx_send_ipv4(struct cx3110x_s *s, uint32_t src, uint32_t dst,
                         uint8_t proto, const uint8_t *l4, size_t l4len)
{
    uint8_t ip[1600];
    uint16_t total;

    if (l4len + 20 > sizeof(ip)) {
        return;
    }
    total = 20 + l4len;
    memset(ip, 0, 20);
    ip[0] = 0x45;
    cx_put_be16(ip + 2, total);
    cx_put_be16(ip + 4, cx_ip_id++);
    cx_put_be16(ip + 6, 0x4000);
    ip[8] = 64;
    ip[9] = proto;
    cx_put_be32(ip + 12, src);
    cx_put_be32(ip + 16, dst);
    cx_put_be16(ip + 10, cx_fold(cx_sum(ip, 20, 0)));
    memcpy(ip + 20, l4, l4len);
    cx_queue_eth(s, s->sta, cx_gw_mac, 0x0800, ip, total);
}

static void cx_dhcp_reply(struct cx3110x_s *s, const uint8_t *dhcp, size_t dlen,
                          uint8_t msg)
{
    uint8_t reply[320];
    uint8_t udp[340];
    uint16_t ulen;
    uint32_t sum;

    if (dlen < 240) {
        return;
    }
    memset(reply, 0, sizeof(reply));
    reply[0] = 2;
    reply[1] = 1;
    reply[2] = 6;
    memcpy(reply + 4, dhcp + 4, 4);
    cx_put_be16(reply + 10, cx_be16(dhcp + 10));
    cx_put_be32(reply + 16, CX_GUEST_IP);
    cx_put_be32(reply + 20, CX_GW_IP);
    memcpy(reply + 28, dhcp + 28, 16);
    reply[236] = 0x63;
    reply[237] = 0x82;
    reply[238] = 0x53;
    reply[239] = 0x63;
    reply[240] = 53;
    reply[241] = 1;
    reply[242] = msg;
    reply[243] = 54;
    reply[244] = 4;
    cx_put_be32(reply + 245, CX_GW_IP);
    reply[249] = 51;
    reply[250] = 4;
    cx_put_be32(reply + 251, 86400);
    reply[255] = 1;
    reply[256] = 4;
    cx_put_be32(reply + 257, 0xffffff00);
    reply[261] = 3;
    reply[262] = 4;
    cx_put_be32(reply + 263, CX_GW_IP);
    reply[267] = 6;
    reply[268] = 4;
    cx_put_be32(reply + 269, CX_DNS_IP);
    reply[273] = 255;

    if (!s->sta_known && dhcp[28] != 0) {
        memcpy(s->sta, dhcp + 28, 6);
        s->sta_known = true;
    }
    ulen = 8 + 274;
    memset(udp, 0, 8);
    cx_put_be16(udp + 0, 67);
    cx_put_be16(udp + 2, 68);
    cx_put_be16(udp + 4, ulen);
    memcpy(udp + 8, reply, 274);
    sum = cx_sum(udp, ulen, 0);
    sum += (CX_GW_IP >> 16) + (CX_GW_IP & 0xffff);
    sum += 0xffff; /* 255.255.255.255 */
    sum += 0xffff;
    sum += 17 + ulen;
    cx_put_be16(udp + 6, cx_fold(sum));
    cx_send_ipv4(s, CX_GW_IP, 0xffffffffU, 17, udp, ulen);
    info_report("cx3110x: DHCP %s for 10.0.2.15", msg == 2 ? "offer" : "ack");
}

static void cx_arp_reply(struct cx3110x_s *s, const uint8_t *eth)
{
    uint8_t arp[28];
    uint32_t tpa = cx_be32(eth + 38);

    if ((tpa & 0xffffff00U) != 0x0a000200U || tpa == CX_GUEST_IP) {
        return;
    }
    memset(arp, 0, sizeof(arp));
    cx_put_be16(arp + 0, 1);
    cx_put_be16(arp + 2, 0x0800);
    arp[4] = 6;
    arp[5] = 4;
    cx_put_be16(arp + 6, 2);
    memcpy(arp + 8, cx_gw_mac, 6);
    cx_put_be32(arp + 14, tpa);
    memcpy(arp + 18, eth + 22, 6);
    memcpy(arp + 24, eth + 28, 4);
    if (!s->sta_known) {
        memcpy(s->sta, eth + 22, 6);
        s->sta_known = true;
    }
    cx_queue_eth(s, eth + 22, cx_gw_mac, 0x0806, arp, sizeof(arp));
}

static struct cx_flow *cx_flow_new(struct cx3110x_s *s, uint8_t proto,
                                   uint32_t dip, uint32_t real,
                                   uint16_t gport, uint16_t dport)
{
    int i;
    struct cx_flow *f;

    for (i = 0; i < CX3110X_FLOWS; i++) {
        f = &s->flows[i];
        if (!f->used) {
            memset(f, 0, sizeof(*f));
            f->used = true;
            f->proto = proto;
            f->dip = dip;
            f->real_dip = real;
            f->gport = gport;
            f->dport = dport;
            f->fd = -1;
            return f;
        }
    }
    return NULL;
}

static struct cx_flow *cx_flow_find(struct cx3110x_s *s, uint8_t proto,
                                    uint16_t gport, uint32_t dip, uint16_t dport)
{
    int i;

    for (i = 0; i < CX3110X_FLOWS; i++) {
        struct cx_flow *f = &s->flows[i];

        if (f->used && f->proto == proto && f->gport == gport &&
            f->dip == dip && f->dport == dport) {
            return f;
        }
    }
    return NULL;
}

static void cx_flow_close(struct cx_flow *f)
{
    if (!f->used) {
        return;
    }
    if (f->fd >= 0) {
        qemu_set_fd_handler(f->fd, NULL, NULL, NULL);
        close(f->fd);
    }
    f->used = false;
    f->fd = -1;
}

static void cx_flows_reset(struct cx3110x_s *s)
{
    int i;

    if (!s->flows) {
        return;
    }
    for (i = 0; i < CX3110X_FLOWS; i++) {
        cx_flow_close(&s->flows[i]);
    }
}

static int cx_nb_socket(int type)
{
    int fd = qemu_socket(AF_INET, type, 0);
    int fl;

    if (fd < 0) {
        return -1;
    }
    fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) {
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    }
    return fd;
}

static void cx_udp_readable(void *opaque)
{
    struct cx_flow *f = opaque;
    uint8_t buf[1500];
    uint8_t udp[1520];
    ssize_t n;
    uint32_t sum;
    uint16_t ulen;
    struct cx3110x_s *s = f->hold_owner;

    n = recv(f->fd, buf, sizeof(buf), 0);
    if (n <= 0) {
        return;
    }
    ulen = 8 + n;
    memset(udp, 0, 8);
    cx_put_be16(udp + 0, f->dport);
    cx_put_be16(udp + 2, f->gport);
    cx_put_be16(udp + 4, ulen);
    memcpy(udp + 8, buf, n);
    sum = cx_sum(udp, ulen, 0);
    sum += (f->dip >> 16) + (f->dip & 0xffff);
    sum += (CX_GUEST_IP >> 16) + (CX_GUEST_IP & 0xffff);
    sum += 17 + ulen;
    cx_put_be16(udp + 6, cx_fold(sum));
    cx_send_ipv4(s, f->dip, CX_GUEST_IP, 17, udp, ulen);
}

static void cx_tcp_send(struct cx3110x_s *s, struct cx_flow *f,
                        uint8_t flags, const uint8_t *data, size_t dlen)
{
    uint8_t tcp[1500];
    uint32_t sum;
    uint16_t tlen;

    if (dlen + 20 > sizeof(tcp)) {
        dlen = sizeof(tcp) - 20;
    }
    tlen = 20 + dlen;
    memset(tcp, 0, 20);
    cx_put_be16(tcp + 0, f->dport);
    cx_put_be16(tcp + 2, f->gport);
    cx_put_be32(tcp + 4, f->snd_nxt);
    cx_put_be32(tcp + 8, f->rcv_nxt);
    tcp[12] = 5 << 4;
    tcp[13] = flags;
    cx_put_be16(tcp + 14, 65535);
    if (dlen) {
        memcpy(tcp + 20, data, dlen);
    }
    sum = cx_sum(tcp, tlen, 0);
    sum += (f->dip >> 16) + (f->dip & 0xffff);
    sum += (CX_GUEST_IP >> 16) + (CX_GUEST_IP & 0xffff);
    sum += 6 + tlen;
    cx_put_be16(tcp + 16, cx_fold(sum));
    cx_send_ipv4(s, f->dip, CX_GUEST_IP, 6, tcp, tlen);
    if (flags & 0x02) {
        f->snd_nxt++;
    }
    f->snd_nxt += dlen;
    if (flags & 0x01) {
        f->snd_nxt++;
    }
}

static void cx_tcp_readable(void *opaque)
{
    struct cx_flow *f = opaque;
    struct cx3110x_s *s = f->hold_owner;
    uint8_t buf[1400];
    ssize_t n;

    n = recv(f->fd, buf, sizeof(buf), 0);
    if (n < 0) {
        return;
    }
    if (n == 0) {
        cx_tcp_send(s, f, 0x11, NULL, 0);
        cx_flow_close(f);
        return;
    }
    cx_tcp_send(s, f, 0x18, buf, n);
}

static void cx_tcp_connected(void *opaque)
{
    struct cx_flow *f = opaque;
    struct cx3110x_s *s = f->hold_owner;
    int err = 0;
    socklen_t elen = sizeof(err);

    if (getsockopt(f->fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0 || err) {
        cx_tcp_send(s, f, 0x14, NULL, 0);
        cx_flow_close(f);
        return;
    }
    f->tcp_up = true;
    f->snd_nxt = (uint32_t)qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    cx_tcp_send(s, f, 0x12, NULL, 0);
    qemu_set_fd_handler(f->fd, cx_tcp_readable, NULL, f);
    if (f->hold_len) {
        if (send(f->fd, f->hold, f->hold_len, MSG_NOSIGNAL) >= 0) {
            f->hold_len = 0;
        }
    }
}

static void cx_udp_open(struct cx3110x_s *s, struct cx_flow *f,
                        const uint8_t *payload, size_t plen)
{
    struct sockaddr_in in;
    int fd = cx_nb_socket(SOCK_DGRAM);

    if (fd < 0) {
        cx_flow_close(f);
        return;
    }
    f->fd = fd;
    f->hold_owner = s;
    qemu_set_fd_handler(fd, cx_udp_readable, NULL, f);
    memset(&in, 0, sizeof(in));
    in.sin_family = AF_INET;
    in.sin_port = htons(f->dport);
    in.sin_addr.s_addr = htonl(f->real_dip);
    sendto(fd, payload, plen, 0, (struct sockaddr *)&in, sizeof(in));
}

static void cx_tcp_open(struct cx3110x_s *s, struct cx_flow *f)
{
    struct sockaddr_in in;
    int fd = cx_nb_socket(SOCK_STREAM);
    int rc;

    if (fd < 0) {
        cx_flow_close(f);
        return;
    }
    f->fd = fd;
    f->hold_owner = s;
    memset(&in, 0, sizeof(in));
    in.sin_family = AF_INET;
    in.sin_port = htons(f->dport);
    in.sin_addr.s_addr = htonl(f->real_dip);
    rc = connect(fd, (struct sockaddr *)&in, sizeof(in));
    if (rc < 0 && errno != EINPROGRESS) {
        cx_tcp_send(s, f, 0x14, NULL, 0);
        cx_flow_close(f);
        return;
    }
    qemu_set_fd_handler(fd, NULL, cx_tcp_connected, f);
}

static void cx_on_udp(struct cx3110x_s *s, uint32_t dip, uint16_t gport,
                      uint16_t dport, const uint8_t *payload, size_t plen,
                      const uint8_t *udp, size_t ulen)
{
    struct cx_flow *f;
    uint32_t real = dip;

    if (dport == 67 && gport == 68 && plen >= 240 && udp[8] == 1) {
        uint8_t msg = 1;
        size_t i;

        for (i = 240; i + 2 < plen && udp[8 + i] != 255; ) {
            uint8_t opt = udp[8 + i];
            uint8_t ol = udp[8 + i + 1];

            if (opt == 53 && ol >= 1) {
                msg = udp[8 + i + 2];
            }
            if (opt == 0) {
                i++;
                continue;
            }
            i += 2 + ol;
        }
        cx_dhcp_reply(s, udp + 8, plen, msg == 3 ? 5 : 2);
        return;
    }
    if (dip == CX_DNS_IP && dport == 53) {
        real = s->dns_host ? s->dns_host : 0x01010101U;
    }
    f = cx_flow_find(s, 17, gport, dip, dport);
    if (!f) {
        f = cx_flow_new(s, 17, dip, real, gport, dport);
        if (!f) {
            return;
        }
        cx_udp_open(s, f, payload, plen);
        return;
    }
    if (f->fd >= 0) {
        struct sockaddr_in in;

        memset(&in, 0, sizeof(in));
        in.sin_family = AF_INET;
        in.sin_port = htons(f->dport);
        in.sin_addr.s_addr = htonl(f->real_dip);
        sendto(f->fd, payload, plen, 0, (struct sockaddr *)&in, sizeof(in));
    }
}

static void cx_on_tcp(struct cx3110x_s *s, uint32_t dip, const uint8_t *tcp,
                      size_t tlen)
{
    uint16_t gport, dport, hlen;
    uint32_t seq, ack;
    uint8_t flags;
    struct cx_flow *f;
    size_t doff;

    if (tlen < 20) {
        return;
    }
    gport = cx_be16(tcp + 0);
    dport = cx_be16(tcp + 2);
    seq = cx_be32(tcp + 4);
    ack = cx_be32(tcp + 8);
    hlen = (tcp[12] >> 4) * 4;
    flags = tcp[13];
    if (hlen < 20 || hlen > tlen) {
        return;
    }
    doff = tlen - hlen;
    f = cx_flow_find(s, 6, gport, dip, dport);
    if (flags & 0x02) {
        if (f) {
            cx_flow_close(f);
        }
        f = cx_flow_new(s, 6, dip, dip, gport, dport);
        if (!f) {
            return;
        }
        f->rcv_nxt = seq + 1;
        if (doff && doff <= sizeof(f->hold)) {
            memcpy(f->hold, tcp + hlen, doff);
            f->hold_len = doff;
            f->rcv_nxt += doff;
        }
        cx_tcp_open(s, f);
        return;
    }
    if (!f || !f->tcp_up) {
        return;
    }
    if (flags & 0x04) {
        cx_flow_close(f);
        return;
    }
    (void)ack;
    if (seq == f->rcv_nxt && doff) {
        if (f->fd >= 0) {
            send(f->fd, tcp + hlen, doff, MSG_NOSIGNAL);
        }
        f->rcv_nxt += doff;
        cx_tcp_send(s, f, 0x10, NULL, 0);
    } else if (doff == 0 && (flags & 0x10)) {
        /* bare ACK */
    }
    if (flags & 0x01) {
        if (f->fd >= 0) {
            shutdown(f->fd, SHUT_WR);
        }
        f->rcv_nxt++;
        cx_tcp_send(s, f, 0x11, NULL, 0);
        cx_flow_close(f);
    }
}

static void cx_on_ipv4(struct cx3110x_s *s, const uint8_t *ip, size_t len)
{
    unsigned ihl, total;
    uint8_t proto;
    uint32_t dst;
    const uint8_t *l4;
    size_t l4len;

    if (len < 20 || (ip[0] >> 4) != 4) {
        return;
    }
    ihl = (ip[0] & 0xf) * 4;
    total = cx_be16(ip + 2);
    if (ihl < 20 || total < ihl || total > len) {
        return;
    }
    proto = ip[9];
    dst = cx_be32(ip + 16);
    l4 = ip + ihl;
    l4len = total - ihl;
    if (proto == 1 && l4len >= 8 && l4[0] == 8 && dst == CX_GW_IP) {
        uint8_t echo[1600];

        if (l4len > sizeof(echo)) {
            return;
        }
        memcpy(echo, l4, l4len);
        echo[0] = 0;
        cx_put_be16(echo + 2, 0);
        cx_put_be16(echo + 2, cx_fold(cx_sum(echo, l4len, 0)));
        cx_send_ipv4(s, CX_GW_IP, cx_be32(ip + 12) ? cx_be32(ip + 12) : CX_GUEST_IP,
                     1, echo, l4len);
        return;
    }
    if (proto == 17 && l4len >= 8) {
        cx_on_udp(s, dst, cx_be16(l4 + 0), cx_be16(l4 + 2),
                  l4 + 8, l4len - 8, l4, l4len);
        return;
    }
    if (proto == 6) {
        cx_on_tcp(s, dst, l4, l4len);
    }
}

static void cx_from_guest_eth(struct cx3110x_s *s, const uint8_t *eth, size_t len)
{
    uint16_t etype;

    if (len < 14 || s->joined != 0) {
        return;
    }
    etype = cx_be16(eth + 12);
    if (etype == 0x0806 && len >= 42 && cx_be16(eth + 20) == 1) {
        cx_arp_reply(s, eth);
        return;
    }
    if (etype == 0x0800) {
        cx_on_ipv4(s, eth + 14, len - 14);
    }
}

static uint32_t cx_read_dns(void)
{
    FILE *fp = fopen("/etc/resolv.conf", "r");
    char line[128];
    uint32_t ip = 0x01010101U;

    if (!fp) {
        return ip;
    }
    while (fgets(line, sizeof(line), fp)) {
        unsigned a, b, c, d;

        if (sscanf(line, "nameserver %u.%u.%u.%u", &a, &b, &c, &d) == 4 &&
            a < 256 && b < 256 && c < 256 && d < 256) {
            ip = (a << 24) | (b << 16) | (c << 8) | d;
            break;
        }
    }
    fclose(fp);
    return ip;
}

static void cx_announce_tick(void *opaque)
{
    struct cx3110x_s *s = opaque;

    if (s->announce_left <= 0 || s->joined >= 0) {
        return;
    }
    s->bss_announced = false;
    cx_announce(s);
    s->announce_left--;
    if (s->announce_left > 0 && s->announce_timer) {
        timer_mod(s->announce_timer,
                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 500000000LL);
    }
}
#else
static void cx_from_guest_eth(struct cx3110x_s *s, const uint8_t *eth, size_t len)
{
    (void)s;
    (void)eth;
    (void)len;
}

static void cx_flows_reset(struct cx3110x_s *s)
{
    (void)s;
}
#endif

static void cx_on_dot11(struct cx3110x_s *s, const uint8_t *mac, size_t len)
{
    int ap;
    int hdr = 24;
    const uint8_t *llc;
    uint8_t eth[1800];
    size_t elen;

    if (len < 24) {
        return;
    }
    memcpy(s->sta, mac + 10, 6);
    s->sta_known = true;
    ap = cx_ap_index(mac + 4);
    if (mac[0] == 0x40) {
        int i;

        for (i = 0; i < 2; i++) {
            if (ap < 0 || ap == i) {
                cx_queue_beacon(s, i, true);
            }
        }
        return;
    }
    if (ap < 0) {
        return;
    }
    if (mac[0] == 0xb0) {
        cx_reply_auth(s, ap, mac + 10);
        return;
    }
    if (mac[0] == 0x00) {
        cx_reply_assoc(s, ap, mac + 10);
        return;
    }
    if (mac[0] != 0x08 && mac[0] != 0x88) {
        return;
    }
    if (mac[0] & 0x80) {
        hdr = 26;
    }
    if ((unsigned)hdr + 8 > len) {
        return;
    }
    llc = mac + hdr;
    if (llc[0] != 0xaa || llc[1] != 0xaa) {
        return;
    }
    memcpy(eth, mac + 16, 6);
    memcpy(eth + 6, mac + 10, 6);
    eth[12] = llc[6];
    eth[13] = llc[7];
    elen = 14 + (len - hdr - 8);
    if (elen > sizeof(eth)) {
        return;
    }
    memcpy(eth + 14, llc + 8, elen - 14);
    cx_from_guest_eth(s, eth, elen);
}

static void cx_announce_arm(struct cx3110x_s *s)
{
#ifndef CX3110X_NO_NET
    s->announce_left = 8;
    if (!s->announce_timer || s->joined >= 0) {
        return;
    }
    timer_mod(s->announce_timer,
              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 500000000LL);
#else
    (void)s;
#endif
}

static void cx_scan_tx(struct cx3110x_s *s)
{
    static const unsigned offs[] = { 0, 8, 12, 16, 20, 24, 28, 32 };
    unsigned i;

    for (i = 0; i < 8; i++) {
        unsigned off = offs[i];

        if (off >= s->tx_len) {
            break;
        }
        if (cx_match_dot11(s->tx_buf + off, s->tx_len - off) == 0) {
            cx_on_dot11(s, s->tx_buf + off, s->tx_len - off);
            return;
        }
    }
}
