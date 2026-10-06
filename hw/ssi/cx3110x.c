/*
 * Conexant CX3110x / STLC4550 SPI SoftMAC (Prism54 p54spi).
 *
 * RX-44 WLAN sits on OMAP McSPI2 chip-select 0 with IRQ GPIO 87 and
 * power GPIO 97 (OMAP_TAG_WLAN_CX3110X). Stock Maemo cx3110x.ko uploads
 * 3826.arm through the p54 SPI register window; without a slave that
 * raises HOST_ALLOWED the guest spins in fw_upload for seconds and the
 * connectivity UI looks hung.
 *
 * This stub implements the SPI address/data framing from Linux
 * drivers/net/wireless/intersil/p54/p54spi.c, accepts firmware DMA
 * writes, latches HOST_INT_READY after RAM_BOOT, and answers Maemo
 * SoftMAC scans with two access points (QEMU-WLAN-CX3110X-001). The
 * open AP forwards IPv4 after association. The weaker AP advertises
 * WPA and rejects joins. Real 3826.arm is not executed.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "hw/irq.h"
#include "hw/ssi/cx3110x.h"
#ifndef CX3110X_NO_NET
#include "qemu/timer.h"
#include "qemu/main-loop.h"
#include "qemu/sockets.h"
#include <fcntl.h>
#include <errno.h>
#endif

/* p54spi.h register addresses (byte offsets in the SPI window) */
#define SPI_ADRS_ARM_INTERRUPTS     0x00
#define SPI_ADRS_ARM_INT_EN         0x04
#define SPI_ADRS_HOST_INTERRUPTS    0x08
#define SPI_ADRS_HOST_INT_EN        0x0c
#define SPI_ADRS_HOST_INT_ACK       0x10
#define SPI_ADRS_GEN_PURP_1         0x14
#define SPI_ADRS_GEN_PURP_2         0x18
#define SPI_ADRS_DEV_CTRL_STAT      0x26
#define SPI_ADRS_DMA_DATA           0x28
#define SPI_ADRS_DMA_WRITE_CTRL     0x2c
#define SPI_ADRS_DMA_WRITE_LEN      0x2e
#define SPI_ADRS_DMA_WRITE_BASE     0x30
#define SPI_ADRS_DMA_READ_CTRL      0x34
#define SPI_ADRS_DMA_READ_LEN       0x36
#define SPI_ADRS_DMA_READ_BASE      0x38

#define SPI_ADRS_READ_BIT_15        0x8000

#define SPI_CTRL_STAT_HOST_OVERRIDE 0x8000
#define SPI_CTRL_STAT_START_HALTED  0x4000
#define SPI_CTRL_STAT_RAM_BOOT      0x2000
#define SPI_CTRL_STAT_HOST_RESET    0x1000
#define SPI_CTRL_STAT_HOST_CPU_EN   0x0800

#define SPI_DMA_WRITE_CTRL_ENABLE   0x0001
#define HOST_ALLOWED                (1 << 7)

#define SPI_HOST_INT_READY          0x00000001
#define SPI_HOST_INT_WR_READY       0x00000002
#define SPI_HOST_INT_SW_UPDATE     0x00000004
#define SPI_HOST_INT_UPDATE        0x10000000

/* SoftMAC control header (LE) — enough to spot SCAN and echo req_id. */
#define P54_HDR_FLAG_CONTROL        0x8000
#define P54_CONTROL_TYPE_SCAN       1

#define CX3110X_RX_MAX              2048
#define CX3110X_TX_CAP              4096
#define CX3110X_RX_QUEUE            8
#define CX3110X_FLOWS               24

/* umac_frame_rx: dBm = (payload[8] >> 1) - 110. */
#define CX_RSSI_STRONG              140 /* -40 dBm */
#define CX_RSSI_WEAK                70  /* -75 dBm */
#define CX_GUEST_IP                 0x0a00020fU /* 10.0.2.15 */
#define CX_GW_IP                    0x0a000202U /* 10.0.2.2 */
#define CX_DNS_IP                   0x0a000203U /* 10.0.2.3 */

struct cx3110x_rx_frame {
    uint8_t data[CX3110X_RX_MAX];
    uint32_t len;
};

struct cx_flow;

struct cx3110x_s {
    qemu_irq irq;

    /* 16-bit view of the SPI register window (enough for DMA_* 32-bit). */
    uint16_t win[0x40];

    int selected;
    int have_addr;
    uint8_t addr;
    int is_read;
    int data_words; /* words transferred after address */

    uint32_t dma_wr_remaining;
    uint8_t tx_buf[CX3110X_TX_CAP];
    uint32_t tx_len;
    bool booted;
    bool bss_announced;
    int tx_logged;
    int joined; /* index into cx_aps, or -1 */
    uint8_t sta[6];
    bool sta_known;
    uint16_t dot11_seq;
#ifndef CX3110X_NO_NET
    QEMUTimer *announce_timer;
    int announce_left;
    uint32_t dns_host;
    struct cx_flow *flows;
#endif

    /* SoftMAC RX queue: each entry is [u16 le length][payload…] */
    struct cx3110x_rx_frame rxq[CX3110X_RX_QUEUE];
    unsigned rx_head;
    unsigned rx_tail;
    unsigned rx_count;
    uint32_t rx_pos;
};

static uint32_t cx3110x_host_int(struct cx3110x_s *s)
{
    return ((uint32_t)s->win[SPI_ADRS_HOST_INTERRUPTS + 2] << 16) |
           s->win[SPI_ADRS_HOST_INTERRUPTS];
}

static uint32_t cx3110x_host_int_en(struct cx3110x_s *s)
{
    return ((uint32_t)s->win[SPI_ADRS_HOST_INT_EN + 2] << 16) |
           s->win[SPI_ADRS_HOST_INT_EN];
}

static void cx3110x_set_host_int(struct cx3110x_s *s, uint32_t val)
{
    s->win[SPI_ADRS_HOST_INTERRUPTS] = val & 0xffff;
    s->win[SPI_ADRS_HOST_INTERRUPTS + 2] = val >> 16;
}

static void cx3110x_irq_update(struct cx3110x_s *s)
{
    uint32_t pending = cx3110x_host_int(s) & cx3110x_host_int_en(s);

    /* Active-high GPIO IRQ into OMAP (guest uses falling/rising as needed). */
    qemu_set_irq(s->irq, !!pending);
}

static void cx3110x_raise(struct cx3110x_s *s, uint32_t bits)
{
    cx3110x_set_host_int(s, cx3110x_host_int(s) | bits);
    cx3110x_irq_update(s);
}

static void cx3110x_ack(struct cx3110x_s *s, uint32_t bits)
{
    cx3110x_set_host_int(s, cx3110x_host_int(s) & ~bits);
    cx3110x_irq_update(s);
}

static void cx3110x_rx_queue(struct cx3110x_s *s, const uint8_t *payload,
                             uint16_t plen)
{
    struct cx3110x_rx_frame *f;
    uint16_t total;

    if (plen == 0 || plen + 2 > CX3110X_RX_MAX) {
        return;
    }
    if (s->rx_count == CX3110X_RX_QUEUE) {
        /* Drop oldest. */
        s->rx_head = (s->rx_head + 1) % CX3110X_RX_QUEUE;
        s->rx_count--;
        s->rx_pos = 0;
    }
    f = &s->rxq[s->rx_tail];
    total = plen;
    f->data[0] = total & 0xff;
    f->data[1] = total >> 8;
    memcpy(f->data + 2, payload, plen);
    f->len = plen + 2;
    s->rx_tail = (s->rx_tail + 1) % CX3110X_RX_QUEUE;
    s->rx_count++;
    if (s->rx_count == 1) {
        s->rx_pos = 0;
    }
    cx3110x_raise(s, SPI_HOST_INT_UPDATE | SPI_HOST_INT_SW_UPDATE);
    s->win[SPI_ADRS_GEN_PURP_1] = plen;
}

static void cx3110x_rx_advance(struct cx3110x_s *s)
{
    if (s->rx_count == 0) {
        return;
    }
    s->rx_head = (s->rx_head + 1) % CX3110X_RX_QUEUE;
    s->rx_count--;
    s->rx_pos = 0;
    if (s->rx_count == 0) {
        cx3110x_ack(s, SPI_HOST_INT_UPDATE | SPI_HOST_INT_SW_UPDATE);
        s->win[SPI_ADRS_GEN_PURP_1] = 0;
    } else {
        s->win[SPI_ADRS_GEN_PURP_1] =
            (s->rxq[s->rx_head].len >= 2) ? (s->rxq[s->rx_head].len - 2) : 0;
        cx3110x_raise(s, SPI_HOST_INT_UPDATE | SPI_HOST_INT_SW_UPDATE);
    }
}

/*
 * Maemo umac does the scan on the host. Each channel step is an
 * fw_ctrl submit: DMA_WRITE_BASE is the kernel request object, and the
 * payload's first halfword is negative. prism_interconnect_message_handle
 * only calls fw_ctrl_accept when bit 0 is set on that halfword, and the
 * accept path matches the request via the word at payload offset 4.
 * Without 0x8001 the FSM stalls after one channel, the 512-jiffy timer
 * fires, and sm_drv_close prints "shut down softmac".
 */
static void cx3110x_complete_ctrl(struct cx3110x_s *s)
{
    uint32_t req;
    uint16_t flags;
    uint8_t resp[12];

    if (s->tx_len < 2) {
        return;
    }
    flags = s->tx_buf[0] | ((uint16_t)s->tx_buf[1] << 8);
    if (!(flags & 0x8000)) {
        return;
    }
    req = (uint32_t)s->win[SPI_ADRS_DMA_WRITE_BASE] |
          ((uint32_t)s->win[SPI_ADRS_DMA_WRITE_BASE + 2] << 16);
    if (req < 0xc0000000u) {
        return;
    }
    memset(resp, 0, sizeof(resp));
    /* Negative halfword with bit 0 set → fw_ctrl_accept. */
    resp[0] = 0x01;
    resp[1] = 0x80;
    resp[4] = req & 0xff;
    resp[5] = (req >> 8) & 0xff;
    resp[6] = (req >> 16) & 0xff;
    resp[7] = (req >> 24) & 0xff;
    cx3110x_rx_queue(s, resp, sizeof(resp));
}

#include "cx3110x-wlan.inc"

static void cx3110x_handle_host_tx(struct cx3110x_s *s)
{
    uint16_t flags, type;
    uint32_t req_id;

    if (!s->booted || s->tx_len < 2) {
        return;
    }
    if (s->tx_logged < 4) {
        info_report("cx3110x: host tx %u bytes %02x %02x %02x %02x base=%08x",
                    s->tx_len,
                    s->tx_buf[0],
                    s->tx_len > 1 ? s->tx_buf[1] : 0,
                    s->tx_len > 2 ? s->tx_buf[2] : 0,
                    s->tx_len > 3 ? s->tx_buf[3] : 0,
                    (uint32_t)s->win[SPI_ADRS_DMA_WRITE_BASE] |
                    ((uint32_t)s->win[SPI_ADRS_DMA_WRITE_BASE + 2] << 16));
        s->tx_logged++;
    }
    flags = s->tx_buf[0] | ((uint16_t)s->tx_buf[1] << 8);
    if ((flags & P54_HDR_FLAG_CONTROL) && s->tx_len >= 12) {
        req_id = s->tx_buf[4] | ((uint32_t)s->tx_buf[5] << 8) |
                 ((uint32_t)s->tx_buf[6] << 16) |
                 ((uint32_t)s->tx_buf[7] << 24);
        type = s->tx_buf[8] | ((uint16_t)s->tx_buf[9] << 8);
        if (type == P54_CONTROL_TYPE_SCAN) {
            qemu_log("cx3110x: SoftMAC SCAN req_id=0x%x — umac BSS\n",
                     req_id);
        }
    }
    /* Accept must precede beacons so fw_ctrl unblocks the scan FSM first. */
    cx3110x_complete_ctrl(s);
    if ((flags & 0x8000) && s->joined < 0) {
        s->bss_announced = false;
        cx_announce(s);
        cx_announce_arm(s);
    }
    cx_scan_tx(s);
}

static uint16_t cx3110x_read16(struct cx3110x_s *s, uint8_t addr)
{
    if (addr == SPI_ADRS_DMA_WRITE_CTRL) {
        /* Ready for firmware / frame DMA unless the host cleared it. */
        return s->win[addr] | HOST_ALLOWED;
    }
    if (addr == SPI_ADRS_DMA_DATA) {
        uint16_t word = 0;
        struct cx3110x_rx_frame *f;

        if (s->rx_count > 0) {
            f = &s->rxq[s->rx_head];
            if (s->rx_pos + 1 < f->len) {
                word = f->data[s->rx_pos] |
                       ((uint16_t)f->data[s->rx_pos + 1] << 8);
                s->rx_pos += 2;
                if (s->rx_pos >= f->len) {
                    cx3110x_rx_advance(s);
                }
            }
        }
        return word;
    }
    if (addr + 1 < ARRAY_SIZE(s->win)) {
        return s->win[addr];
    }
    return 0;
}

static void cx3110x_write16(struct cx3110x_s *s, uint8_t addr, uint16_t val)
{
    uint16_t prev;

    if (addr >= ARRAY_SIZE(s->win)) {
        return;
    }

    switch (addr) {
    case SPI_ADRS_HOST_INT_ACK:
        /* Low half of a 32-bit ACK; apply when the high half arrives. */
        s->win[addr] = val;
        break;

    case SPI_ADRS_HOST_INT_ACK + 2:
        s->win[addr] = val;
        cx3110x_ack(s, s->win[SPI_ADRS_HOST_INT_ACK] | ((uint32_t)val << 16));
        break;

    case SPI_ADRS_HOST_INT_EN:
    case SPI_ADRS_HOST_INT_EN + 2:
        s->win[addr] = val;
        cx3110x_irq_update(s);
        break;

    case SPI_ADRS_ARM_INTERRUPTS:
        s->win[addr] = val;
        /* TARGET_INT_WAKEUP — firmware answers with HOST_INT_READY. */
        if (val & 0x1) {
            cx3110x_raise(s, SPI_HOST_INT_READY);
        }
        break;

    case SPI_ADRS_ARM_INTERRUPTS + 2:
        s->win[addr] = val;
        break;

    case SPI_ADRS_DEV_CTRL_STAT:
        prev = s->win[addr];
        s->win[addr] = val;
        /*
         * After RAM_BOOT the real firmware asserts INT_READY. Signal that
         * so SoftMAC bring-up can leave FW_STATE_BOOTING.
         */
        if ((val & SPI_CTRL_STAT_RAM_BOOT) &&
            !(prev & SPI_CTRL_STAT_RAM_BOOT)) {
            s->booted = true;
            s->bss_announced = false;
            s->joined = -1;
            s->sta_known = false;
            cx_flows_reset(s);
#ifndef CX3110X_NO_NET
            s->announce_left = 8;
            if (s->announce_timer) {
                timer_del(s->announce_timer);
            }
#endif
            info_report("cx3110x: RAM_BOOT — HOST_INT_READY");
            cx3110x_raise(s, SPI_HOST_INT_READY);
        }
        if (val & SPI_CTRL_STAT_HOST_RESET) {
            s->dma_wr_remaining = 0;
            s->tx_len = 0;
            if (!(val & SPI_CTRL_STAT_RAM_BOOT)) {
                s->booted = false;
            }
        }
        break;

    case SPI_ADRS_DMA_WRITE_CTRL:
        s->win[addr] = val;
        if ((val & SPI_DMA_WRITE_CTRL_ENABLE) &&
            s->win[SPI_ADRS_DMA_WRITE_LEN]) {
            s->dma_wr_remaining = s->win[SPI_ADRS_DMA_WRITE_LEN];
            s->tx_len = 0;
        }
        break;

    case SPI_ADRS_DMA_WRITE_LEN:
        s->win[addr] = val;
        if (s->win[SPI_ADRS_DMA_WRITE_CTRL] & SPI_DMA_WRITE_CTRL_ENABLE) {
            s->dma_wr_remaining = val;
            s->tx_len = 0;
        }
        break;

    case SPI_ADRS_DMA_WRITE_BASE:
    case SPI_ADRS_DMA_WRITE_BASE + 2:
        s->win[addr] = val;
        break;

    case SPI_ADRS_DMA_DATA:
        if (s->dma_wr_remaining >= 2) {
            if (s->tx_len + 2 <= CX3110X_TX_CAP) {
                s->tx_buf[s->tx_len] = val & 0xff;
                s->tx_buf[s->tx_len + 1] = val >> 8;
                s->tx_len += 2;
            }
            s->dma_wr_remaining -= 2;
        } else {
            s->dma_wr_remaining = 0;
        }
        if (s->dma_wr_remaining == 0 &&
            (s->win[SPI_ADRS_DMA_WRITE_CTRL] & SPI_DMA_WRITE_CTRL_ENABLE)) {
            s->win[SPI_ADRS_DMA_WRITE_CTRL] &= ~SPI_DMA_WRITE_CTRL_ENABLE;
            if (s->booted) {
                cx3110x_handle_host_tx(s);
            } else if (s->tx_len >= 1024) {
                info_report("cx3110x: firmware DMA chunk %u bytes", s->tx_len);
            }
            cx3110x_raise(s, SPI_HOST_INT_WR_READY);
        }
        break;

    default:
        s->win[addr] = val;
        break;
    }
}

static int cx3110x_looks_like_addr(uint16_t word)
{
    uint8_t reg;

    if ((word & 0xff) != 0 || (word >> 8) == 0) {
        return 0;
    }
    reg = (word >> 8) & 0x7f;
    return reg <= 0x3a;
}

static int cx3110x_reg_words(uint8_t addr)
{
    switch (addr) {
    case SPI_ADRS_ARM_INTERRUPTS:
    case SPI_ADRS_ARM_INT_EN:
    case SPI_ADRS_HOST_INTERRUPTS:
    case SPI_ADRS_HOST_INT_EN:
    case SPI_ADRS_HOST_INT_ACK:
    case SPI_ADRS_DMA_WRITE_BASE:
        return 2;
    default:
        return 1;
    }
}

void cx3110x_setcs(void *opaque, int selected)
{
    struct cx3110x_s *s = opaque;

    s->selected = selected;
    if (!selected) {
        s->have_addr = 0;
        s->data_words = 0;
        s->is_read = 0;
    }
}

uint32_t cx3110x_txrx(void *opaque, uint32_t tx, int len)
{
    struct cx3110x_s *s = opaque;
    uint16_t word = tx & 0xffff;
    uint16_t rx = 0;
    uint8_t reg;

    if (!s->selected) {
        /* Some guests leave FORCE set; still accept traffic. */
        s->selected = 1;
    }

    /*
     * McSPI only drops CS when FORCE changes. Once the current register has
     * taken its 16- or 32-bit word, the next address-shaped word starts a
     * new access. Do not resync mid-word (the high half of 0x10000004 is
     * 0x1000), mid-DMA write, or mid-DMA_DATA stream read (payload halfwords
     * ride the same CS after one address phase).
     */
    if (s->have_addr && s->dma_wr_remaining == 0 &&
        s->addr != SPI_ADRS_DMA_DATA &&
        s->data_words >= cx3110x_reg_words(s->addr) &&
        cx3110x_looks_like_addr(word)) {
        s->have_addr = 0;
        s->data_words = 0;
    }

    if (!s->have_addr) {
        /*
         * Address phase: (reg << 8) [| SPI_ADRS_READ_BIT_15]. Low byte is 0
         * for control accesses; DMA payloads use the DMA_DATA address first.
         */
        if ((word & 0x00ff) == 0) {
            reg = (word >> 8) & 0x7f;
            s->addr = reg;
            s->is_read = !!(word & SPI_ADRS_READ_BIT_15);
            s->have_addr = 1;
            s->data_words = 0;
            return 0;
        }
        /* Mid-DMA word without a fresh address — treat as DMA_DATA write. */
        cx3110x_write16(s, SPI_ADRS_DMA_DATA, word);
        return 0;
    }

    if (s->is_read) {
        /*
         * Multi-word reads assemble LE 16-bit chunks. For a 32-bit register
         * at even addr, words are [addr+0], [addr+2]. DMA_DATA is a stream
         * window: every word after the address phase must stay at 0x28
         * (spi_dma_read ships address once, then N payload halfwords).
         */
        if (s->addr == SPI_ADRS_DMA_DATA) {
            reg = SPI_ADRS_DMA_DATA;
        } else {
            reg = s->addr + s->data_words * 2;
        }
        rx = cx3110x_read16(s, reg);
        s->data_words++;
        return rx;
    }

    reg = s->addr;
    if (reg == SPI_ADRS_DMA_DATA) {
        cx3110x_write16(s, SPI_ADRS_DMA_DATA, word);
    } else {
        /*
         * 16-bit register write, or low/high half of a 32-bit register.
         * Host sends consecutive halves for 32-bit stores.
         */
        if (s->data_words == 0) {
            cx3110x_write16(s, reg, word);
        } else {
            cx3110x_write16(s, reg + 2, word);
        }
        s->data_words++;
    }
    return 0;
}

struct cx3110x_s *cx3110x_init(qemu_irq irq)
{
    struct cx3110x_s *s = g_new0(struct cx3110x_s, 1);

    s->irq = irq;
    s->joined = -1;
    /* Idle device is ready for DMA. */
    s->win[SPI_ADRS_DMA_WRITE_CTRL] = HOST_ALLOWED;
#ifndef CX3110X_NO_NET
    s->flows = g_new0(struct cx_flow, CX3110X_FLOWS);
    s->dns_host = cx_read_dns();
    s->announce_left = 8;
    s->announce_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, cx_announce_tick, s);
#endif
    return s;
}
