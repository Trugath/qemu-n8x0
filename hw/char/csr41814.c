/*
 * CSR BC4 / CSR41814 Bluetooth controller, H4+ UART transport.
 *
 * RX-44 hci_h4p (Diablo drivers/bluetooth/hci_h4p) brings the chip up
 * on OMAP UART1: reset GPIO 92 low then high, wake GPIO 61 high, then
 * CTS, the bc4fw.bin negotiation packet, an alive check, and vendor
 * opcode 0xfc00 firmware. This is that sequence with no peer radio.
 * Inquiry completes empty. Do not replace this with virtio-bt.
 *
 * Packet framing follows QEMU 4.2 hw/bt/hci-csr.c. Vendor 0xfc00 is one
 * byte longer than the HCI length and then rounded up to an even size.
 * The last bc4fw.bin command is four bytes short of that; do not wait
 * for those bytes or the following HCI command is swallowed and the
 * startup wizard's phone scan never finishes.
 */

#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "chardev/char.h"
#include "chardev/char-serial.h"
#include "hw/irq.h"
#include "hw/char/csr41814.h"

#define TYPE_CHARDEV_CSR41814 "chardev-csr41814"
#define CSR41814(obj) OBJECT_CHECK(Csr41814State, (obj), TYPE_CHARDEV_CSR41814)

#define FIFO_LEN 4096
#define OUT_MAX  1024

enum {
    H4_CMD_PKT   = 1,
    H4_ACL_PKT   = 2,
    H4_SCO_PKT   = 3,
    H4_EVT_PKT   = 4,
    H4_NEG_PKT   = 6,
    H4_ALIVE_PKT = 7,
};

enum {
    CSR_HDR_LEN,
    CSR_DATA_LEN,
    CSR_DATA,
};

typedef struct Csr41814State {
    Chardev parent;
    int enable;
    qemu_irq *pins;
    int pin_state;
    int modem_state;
    int out_len;
    uint8_t out[OUT_MAX];
    uint8_t inpkt[FIFO_LEN];
    int in_state;
    int in_len;
    int in_hdr;
    int in_needed;
    QEMUTimer *out_tm;
    int64_t baud_delay;
    uint8_t bd_addr[6];
    uint8_t loc_name[248];
    uint8_t dev_class[3];
    uint8_t scan_enable;
    bool logged_neg;
    bool logged_fw;
    bool logged_reset;
    int flushing;
    /* Completed 0xfc00 commands since the last reset. bc4fw.bin's last
     * command is four bytes shorter than the H4+ length rule. */
    int fw_cmds;
} Csr41814State;

static const uint8_t csr_neg_packet[] = {
    H4_NEG_PKT, 10,
    0x00, 0xa0, 0x01, 0x00, 0x00,
    0x4c, 0x00, 0x96, 0x00, 0x00,
};

/*
 * Last bc4fw.bin command. HCI length says 20 data bytes; the file has 16.
 * Waiting for the missing four swallows the next HCI command (Read Local
 * Name is four bytes) and the phone wizard times out.
 */
static const uint8_t csr_short_fw[] = {
    0x01, 0x00, 0xfc, 0x13, 0xc2, 0x02, 0x00, 0x09,
    0x00, 0x00, 0x00, 0x02, 0x40, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};

/* 2.0+EDR feature page, no LE. */
static const uint8_t csr_features[8] = {
    0xff, 0xff, 0x8d, 0xfe, 0x9b, 0xf9, 0x00, 0x80,
};

static void csr_out_tick(void *opaque);

/*
 * Push every queued byte the UART FIFO will take before returning to
 * the guest. A baud timer used to hold the first byte; hci_h4p's GPIO
 * reset (128 jiffies) then cleared the queue and Read Local Name timed
 * out. Retry in 1 ns if the FIFO is still full so the rest follows as
 * soon as the guest drains it.
 */
static void csr_flush(Csr41814State *s)
{
    Chardev *chr = CHARDEV(s);
    int room, n;

    if (s->flushing || !s->enable || !s->out_len) {
        return;
    }
    s->flushing = 1;
    timer_del(s->out_tm);
    /*
     * One UART-FIFO chunk per tick. Dumping a 256-byte Read Local Name
     * in a single be_write overflows the OMAP RX FIFO and desyncs H4+,
     * which shows up as hcid EIO before any firmware command is parsed.
     * 16 bytes at the 50 µs cap still finishes a name reply in under 1 ms,
     * inside the 128-jiffy HCI timeout and before GPIO reset.
     */
    room = qemu_chr_be_can_write(chr);
    n = room < 16 ? room : 16;
    if (n > s->out_len) {
        n = s->out_len;
    }
    if (n > 0) {
        qemu_chr_be_write(chr, s->out, n);
        s->out_len -= n;
        memmove(s->out, s->out + n, s->out_len);
    }
    if (s->out_len) {
        timer_mod(s->out_tm,
                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + s->baud_delay);
    }
    s->flushing = 0;
}

static void csr_kick(Csr41814State *s)
{
    csr_flush(s);
}

static void csr_queue(Csr41814State *s, const uint8_t *bytes, int len)
{
    if (s->out_len + len > OUT_MAX) {
        error_report("csr41814: reply queue full (%d)", len);
        return;
    }
    memcpy(s->out + s->out_len, bytes, len);
    s->out_len += len;
    csr_kick(s);
}

/* hci_h4p discards one extra byte when the event body length is even. */
static void csr_queue_evt(Csr41814State *s, uint8_t evt,
                          const uint8_t *payload, int plen)
{
    uint8_t frame[1 + 2 + 255 + 1];
    int skb_len = 2 + plen;
    int n = 0;

    frame[n++] = H4_EVT_PKT;
    frame[n++] = evt;
    frame[n++] = plen;
    if (plen) {
        memcpy(frame + n, payload, plen);
        n += plen;
    }
    if ((skb_len & 1) == 0) {
        frame[n++] = 0x00;
    }
    csr_queue(s, frame, n);
}

static void csr_cmd_complete(Csr41814State *s, uint16_t opcode,
                             const uint8_t *ret, int ret_len)
{
    uint8_t body[3 + 255];

    body[0] = 1;
    stw_le_p(body + 1, opcode);
    if (ret_len) {
        memcpy(body + 3, ret, ret_len);
    }
    csr_queue_evt(s, 0x0e, body, 3 + ret_len);
}

static void csr_cmd_status(Csr41814State *s, uint16_t opcode, uint8_t status)
{
    uint8_t body[4];

    body[0] = status;
    body[1] = 1;
    stw_le_p(body + 2, opcode);
    csr_queue_evt(s, 0x0f, body, 4);
}

static void csr_ready(Csr41814State *s)
{
    s->in_state = CSR_HDR_LEN;
    s->in_len = 0;
    s->in_needed = 2;
    s->in_hdr = INT_MAX;
}

static void csr_reset_chip(Csr41814State *s)
{
    s->out_len = 0;
    timer_del(s->out_tm);
    csr_ready(s);
    s->enable = 0;
    s->scan_enable = 0;
    s->fw_cmds = 0;
    s->baud_delay = 50000;
    s->modem_state = CHR_TIOCM_CTS | CHR_TIOCM_DSR | CHR_TIOCM_CAR;
}

static void csr_vendor(Csr41814State *s, uint16_t ocf,
                       const uint8_t *data, int len)
{
    uint8_t payload[11];
    int offset;

    if (ocf != 0x000) {
        error_report("csr41814: vendor ocf 0x%03x ignored", ocf);
        return;
    }

    /* Same layout hci_h4p writes into the bd_address firmware command. */
    if (len >= 18 + 8 && data[12] == 0x01 && data[13] == 0x00) {
        offset = 18;
        s->bd_addr[0] = data[offset + 7];
        s->bd_addr[1] = data[offset + 6];
        s->bd_addr[2] = data[offset + 4];
        s->bd_addr[3] = data[offset + 0];
        s->bd_addr[4] = data[offset + 3];
        s->bd_addr[5] = data[offset + 2];
    }

    s->fw_cmds++;
    if (!s->logged_fw) {
        s->logged_fw = true;
        info_report("csr41814: BC4 firmware command");
    }

    /*
     * hci_h4p_bc4_parse_fw_event requires evt 0xff and zeros at
     * skb->data[11] and [12], which are payload bytes 9 and 10.
     */
    memset(payload, 0, sizeof(payload));
    csr_queue_evt(s, 0xff, payload, sizeof(payload));
}

static void csr_hci_cmd(Csr41814State *s, uint16_t opcode,
                        const uint8_t *data, int plen)
{
    uint16_t ogf = opcode >> 10;
    uint8_t ret[252];

    if (ogf == 0x3f) {
        csr_vendor(s, opcode & 0x3ff, data, plen);
        return;
    }

    /* Link control uses Command Status, then a later event or nothing. */
    if (ogf == 0x01) {
        if (opcode == 0x0401) {
            info_report("csr41814: Inquiry");
            csr_cmd_status(s, opcode, 0x00);
            ret[0] = 0x00;
            csr_queue_evt(s, 0x01, ret, 1);
        } else if (opcode == 0x0402) {
            ret[0] = 0x00;
            csr_cmd_complete(s, opcode, ret, 1);
        } else {
            csr_cmd_status(s, opcode, 0x0c);
        }
        return;
    }

    memset(ret, 0, sizeof(ret));
    switch (opcode) {
    case 0x0c03: /* Reset */
        s->scan_enable = 0;
        ret[0] = 0x00;
        csr_cmd_complete(s, opcode, ret, 1);
        if (!s->logged_reset) {
            s->logged_reset = true;
            info_report("csr41814: HCI Reset");
        }
        break;
    case 0x0c14: /* Read Local Name */
        info_report("csr41814: Read Local Name");
        ret[0] = 0x00;
        memcpy(ret + 1, s->loc_name, 248);
        csr_cmd_complete(s, opcode, ret, 249);
        break;
    case 0x0c13: /* Write Local Name */
        memcpy(s->loc_name, data, MIN(plen, 248));
        ret[0] = 0x00;
        csr_cmd_complete(s, opcode, ret, 1);
        break;
    case 0x0c19: /* Read Scan Enable */
        ret[0] = 0x00;
        ret[1] = s->scan_enable;
        csr_cmd_complete(s, opcode, ret, 2);
        break;
    case 0x0c1a: /* Write Scan Enable */
        if (plen >= 1) {
            s->scan_enable = data[0];
        }
        ret[0] = 0x00;
        csr_cmd_complete(s, opcode, ret, 1);
        break;
    case 0x0c23: /* Read Class of Device */
        ret[0] = 0x00;
        memcpy(ret + 1, s->dev_class, 3);
        csr_cmd_complete(s, opcode, ret, 4);
        break;
    case 0x0c24: /* Write Class of Device */
        if (plen >= 3) {
            memcpy(s->dev_class, data, 3);
        }
        ret[0] = 0x00;
        csr_cmd_complete(s, opcode, ret, 1);
        break;
    case 0x0c25: /* Read Voice Setting */
        ret[0] = 0x00;
        stw_le_p(ret + 1, 0x0060);
        csr_cmd_complete(s, opcode, ret, 3);
        break;
    case 0x1001: /* Read Local Version Information */
        ret[0] = 0x00;
        ret[1] = 0x03;          /* HCI 2.0 */
        stw_le_p(ret + 2, 0x0001);
        ret[4] = 0x03;
        stw_le_p(ret + 5, 0x000a); /* CSR */
        stw_le_p(ret + 7, 0x0c5c);
        csr_cmd_complete(s, opcode, ret, 9);
        break;
    case 0x1003: /* Read Local Supported Features */
        ret[0] = 0x00;
        memcpy(ret + 1, csr_features, 8);
        csr_cmd_complete(s, opcode, ret, 9);
        break;
    case 0x1004: /* Read Local Extended Features */
        ret[0] = 0x00;
        ret[1] = plen ? data[0] : 0;
        ret[2] = 0x00;
        if (ret[1] == 0) {
            memcpy(ret + 3, csr_features, 8);
        }
        csr_cmd_complete(s, opcode, ret, 11);
        break;
    case 0x1005: /* Read Buffer Size */
        ret[0] = 0x00;
        stw_le_p(ret + 1, 1021);
        ret[3] = 64;
        stw_le_p(ret + 4, 8);
        stw_le_p(ret + 6, 8);
        csr_cmd_complete(s, opcode, ret, 8);
        break;
    case 0x1009: /* Read BD_ADDR */
        ret[0] = 0x00;
        memcpy(ret + 1, s->bd_addr, 6);
        csr_cmd_complete(s, opcode, ret, 7);
        break;
    default:
        ret[0] = 0x00;
        csr_cmd_complete(s, opcode, ret, 1);
        break;
    }
}

static void csr_in_packet(Csr41814State *s, uint8_t *pkt)
{
    uint8_t reply[12];
    uint16_t opcode;
    uint8_t plen;

    switch (*pkt++) {
    case H4_CMD_PKT:
        opcode = lduw_le_p(pkt);
        plen = pkt[2];
        csr_hci_cmd(s, opcode, pkt + 3, plen);
        break;
    case H4_ACL_PKT:
    case H4_SCO_PKT:
        break;
    case H4_NEG_PKT:
        if (s->in_hdr != sizeof(csr_neg_packet) ||
            memcmp(pkt - 1, csr_neg_packet, s->in_hdr)) {
            error_report("csr41814: bad NEG packet");
            return;
        }
        pkt += 2;
        reply[0] = H4_NEG_PKT;
        reply[1] = 10;
        reply[2] = 0x20;
        memcpy(reply + 3, pkt, 7);
        reply[10] = 0xff;
        reply[11] = 0xff;
        csr_queue(s, reply, sizeof(reply));
        if (!s->logged_neg) {
            s->logged_neg = true;
            info_report("csr41814: H4+ negotiation ok");
        }
        break;
    case H4_ALIVE_PKT:
        if (s->in_hdr != 4 || pkt[1] != 0x55 || pkt[2] != 0x00) {
            error_report("csr41814: bad ALIVE packet");
            return;
        }
        reply[0] = H4_ALIVE_PKT;
        reply[1] = 2;
        reply[2] = 0xcc;
        reply[3] = 0x00;
        csr_queue(s, reply, 4);
        break;
    default:
        error_report("csr41814: bad packet type 0x%02x", pkt[-1]);
        break;
    }
}

static int csr_header_len(const uint8_t *pkt)
{
    switch (pkt[0]) {
    case H4_CMD_PKT:
        return 3;
    case H4_EVT_PKT:
        return 2;
    case H4_ACL_PKT:
        return 4;
    case H4_SCO_PKT:
        return 3;
    case H4_NEG_PKT:
        return pkt[1] + 1;
    case H4_ALIVE_PKT:
        return 3;
    default:
        return -1;
    }
}

static int csr_data_len(const uint8_t *pkt)
{
    switch (*pkt++) {
    case H4_CMD_PKT:
        /*
         * H4+ vendor firmware commands are one byte longer than the HCI
         * length, then padded to an even count. See bc4fw.bin.
         */
        if (lduw_le_p(pkt) == 0xfc00) {
            return (pkt[2] + 1) & ~1;
        }
        return pkt[2];
    case H4_EVT_PKT:
        return pkt[1];
    case H4_ACL_PKT:
        return lduw_le_p(pkt + 2);
    case H4_SCO_PKT:
        return pkt[2];
    case H4_NEG_PKT:
    case H4_ALIVE_PKT:
        return 0;
    default:
        return 0;
    }
}

static int csr_write(Chardev *chr, const uint8_t *buf, int len)
{
    Csr41814State *s = CSR41814(chr);
    int total = 0;

    if (!s->enable) {
        return 0;
    }

    /*
     * A one-byte UART write often completes a packet with len == 0 left.
     * Keep parsing until the buffer is short of the next header, matching
     * the historical H4+ state machine.
     */
    for (;;) {
        int cnt = MIN(len, s->in_needed - s->in_len);
        int hdr;

        /* Stop at the truncated firmware word so its tail is not the
         * next HCI command. If these 20 bytes are not that word, the
         * next iteration reads the rest of in_needed. */
        if (s->in_state == CSR_DATA &&
            s->in_needed > (int)sizeof(csr_short_fw) &&
            s->in_len < (int)sizeof(csr_short_fw)) {
            int room = sizeof(csr_short_fw) - s->in_len;

            if (cnt > room) {
                cnt = room;
            }
        }

        if (cnt > 0) {
            memcpy(s->inpkt + s->in_len, buf, cnt);
            s->in_len += cnt;
            buf += cnt;
            len -= cnt;
            total += cnt;
        }
        /*
         * The truncated firmware word is exactly csr_short_fw. Finish it
         * here even if the H4+ length rule still wants four more bytes.
         */
        if (s->in_state == CSR_DATA &&
            s->in_len >= (int)sizeof(csr_short_fw) &&
            s->in_needed > (int)sizeof(csr_short_fw) &&
            !memcmp(s->inpkt, csr_short_fw, sizeof(csr_short_fw))) {
            s->in_needed = sizeof(csr_short_fw);
            info_report("csr41814: short firmware command");
        }
        if (s->in_len < s->in_needed) {
            break;
        }

        if (s->in_state == CSR_HDR_LEN) {
            hdr = csr_header_len(s->inpkt);
            if (hdr < 0) {
                memmove(s->inpkt, s->inpkt + 1, s->in_len - 1);
                s->in_len--;
                s->in_needed = 2;
                continue;
            }
            s->in_hdr = hdr + 1;
            s->in_needed = s->in_hdr;
            s->in_state = CSR_DATA_LEN;
            continue;
        }
        if (s->in_state == CSR_DATA_LEN) {
            int dlen = csr_data_len(s->inpkt);

            /*
             * bc4fw.bin packet 37 (the last 0xfc00, HCI length 0x13)
             * is four bytes shorter than (len + 1) & ~1. Waiting for
             * those bytes eats the next alive or HCI command, and
             * BlueZ then times out Read Local Name. The phone wizard
             * sits on that timeout.
             */
            if (s->inpkt[0] == H4_CMD_PKT &&
                lduw_le_p(s->inpkt + 1) == 0xfc00 &&
                s->inpkt[3] == 0x13 && s->fw_cmds == 36 && dlen >= 4) {
                dlen -= 4;
            }
            s->in_needed += dlen;
            if (s->in_needed > (int)sizeof(s->inpkt)) {
                error_report("csr41814: packet too long");
                csr_ready(s);
                break;
            }
            s->in_state = CSR_DATA;
            continue;
        }
        csr_in_packet(s, s->inpkt);
        csr_ready(s);
    }
    return total;
}

static void csr_out_tick(void *opaque)
{
    csr_flush(opaque);
}

static void csr_accept_input(Chardev *chr)
{
    csr_flush(CSR41814(chr));
}

static int csr_ioctl(Chardev *chr, int cmd, void *arg)
{
    Csr41814State *s = CSR41814(chr);
    QEMUSerialSetParams *ssp;
    int prev = s->modem_state;

    switch (cmd) {
    case CHR_IOCTL_SERIAL_SET_PARAMS:
        ssp = arg;
        if (ssp->speed > 0) {
            s->baud_delay = NANOSECONDS_PER_SECOND / ssp->speed;
        }
        if (s->baud_delay < 1) {
            s->baud_delay = 1;
        }
        /* 128-jiffy HCI timeout is 1s. A 256-byte reply must finish well
         * inside that even when the divisor is still the reset default. */
        if (s->baud_delay > 50000) {
            s->baud_delay = 50000;
        }
        /* hci_h4p waits for CTS after every speed change. */
        s->modem_state |= CHR_TIOCM_CTS;
        break;
    case CHR_IOCTL_SERIAL_GET_TIOCM:
        *(int *)arg = s->modem_state;
        break;
    case CHR_IOCTL_SERIAL_SET_TIOCM:
        /*
         * CTS tracks edges of RTS. A falling edge is the H4+ speed
         * switch (host waits for CTS low, then SET_PARAMS raises it).
         * A rising edge must bring CTS back, or the first BlueZ command
         * after pm_enabled never leaves the UART.
         * RTS staying low must not clear CTS: reset waits for CTS while
         * RTS is still down.
         */
        s->modem_state = *(int *)arg;
        if ((prev & CHR_TIOCM_RTS) && !(s->modem_state & CHR_TIOCM_RTS)) {
            s->modem_state &= ~CHR_TIOCM_CTS;
        } else if (!(prev & CHR_TIOCM_RTS) && (s->modem_state & CHR_TIOCM_RTS)) {
            s->modem_state |= CHR_TIOCM_CTS;
        }
        break;
    default:
        return -ENOTSUP;
    }
    return 0;
}

static void csr_pins(void *opaque, int line, int level)
{
    Csr41814State *s = opaque;
    int state = s->pin_state;

    s->pin_state &= ~(1 << line);
    s->pin_state |= (!!level) << line;

    if ((state & ~s->pin_state) & (1 << CSR41814_PIN_RESET)) {
        csr_reset_chip(s);
    }
    if (s->pin_state == 3 && state != 3) {
        s->enable = 1;
        csr_kick(s);
        info_report("csr41814: reset released, wake high");
    }
}

qemu_irq *csr41814_pins_get(Chardev *chr)
{
    return CSR41814(chr)->pins;
}

static void csr_open(Chardev *chr, ChardevBackend *backend,
                     bool *be_opened, Error **errp)
{
    Csr41814State *s = CSR41814(chr);

    s->out_tm = timer_new_ns(QEMU_CLOCK_VIRTUAL, csr_out_tick, s);
    s->pins = qemu_allocate_irqs(csr_pins, s, CSR41814_NPINS);
    s->bd_addr[0] = 0x00;
    s->bd_addr[1] = 0x1a;
    s->bd_addr[2] = 0x89;
    s->bd_addr[3] = 0x9e;
    s->bd_addr[4] = 0x3e;
    s->bd_addr[5] = 0x81;
    memcpy(s->loc_name, "QEMU-N810", 9);
    s->dev_class[0] = 0x10;
    s->dev_class[1] = 0x01;
    s->dev_class[2] = 0x0c;
    csr_reset_chip(s);
    *be_opened = false;
    (void)backend;
    (void)errp;
}

static void csr_class_init(ObjectClass *oc, void *data)
{
    ChardevClass *cc = CHARDEV_CLASS(oc);

    cc->internal = true;
    cc->open = csr_open;
    cc->chr_write = csr_write;
    cc->chr_ioctl = csr_ioctl;
    cc->chr_accept_input = csr_accept_input;
    (void)data;
}

static const TypeInfo csr_type_info = {
    .name = TYPE_CHARDEV_CSR41814,
    .parent = TYPE_CHARDEV,
    .instance_size = sizeof(Csr41814State),
    .class_init = csr_class_init,
};

Chardev *uart_csr41814_init(void)
{
    return qemu_chardev_new(NULL, TYPE_CHARDEV_CSR41814,
                            NULL, NULL, &error_abort);
}

static void csr_register_types(void)
{
    type_register_static(&csr_type_info);
}

type_init(csr_register_types);
