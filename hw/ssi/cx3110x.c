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
 * writes, latches HOST_INT_READY after RAM_BOOT, and answers SoftMAC
 * LMAC traffic with a synthetic BSS so wlancond can list a network
 * (QEMU-WLAN-CX3110X-001). It does not run the real ARM firmware image.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "hw/irq.h"
#include "hw/ssi/cx3110x.h"

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

/* p54 LMAC control header (LE) — enough to spot SCAN and echo req_id. */
#define P54_HDR_FLAG_CONTROL        0x8000
#define P54_HDR_FLAG_CONTROL_OPSET  0x8001
#define P54_CONTROL_TYPE_SCAN       1
#define P54_CONTROL_TYPE_TRAP       2
#define P54_TRAP_SCAN               0

#define CX3110X_RX_MAX              512
#define CX3110X_TX_CAP              4096
#define CX3110X_RX_QUEUE            4

struct cx3110x_rx_frame {
    uint8_t data[CX3110X_RX_MAX];
    uint32_t len;
};

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
    } else {
        cx3110x_raise(s, SPI_HOST_INT_UPDATE | SPI_HOST_INT_SW_UPDATE);
    }
}

static void cx3110x_synth_scan_trap(struct cx3110x_s *s, uint32_t req_id)
{
    /*
     * Minimal p54 control trap: SCAN complete on channel 2412 MHz.
     * Maemo SoftMAC / Linux p54 both key off CONTROL|TRAP + P54_TRAP_SCAN.
     * A follow-up data RX with a beacon is future work if the UI still
     * shows an empty list after the trap.
     */
    uint8_t frame[16];
    uint16_t flags = P54_HDR_FLAG_CONTROL;
    uint16_t len = sizeof(frame);
    uint16_t type = P54_CONTROL_TYPE_TRAP;
    uint16_t event = P54_TRAP_SCAN;
    uint16_t freq = 2412;

    memset(frame, 0, sizeof(frame));
    frame[0] = flags & 0xff;
    frame[1] = flags >> 8;
    frame[2] = len & 0xff;
    frame[3] = len >> 8;
    frame[4] = req_id & 0xff;
    frame[5] = (req_id >> 8) & 0xff;
    frame[6] = (req_id >> 16) & 0xff;
    frame[7] = (req_id >> 24) & 0xff;
    frame[8] = type & 0xff;
    frame[9] = type >> 8;
    frame[12] = event & 0xff;
    frame[13] = event >> 8;
    frame[14] = freq & 0xff;
    frame[15] = freq >> 8;
    cx3110x_rx_queue(s, frame, sizeof(frame));
}

static void cx3110x_synth_bss_rx(struct cx3110x_s *s, uint32_t req_id)
{
    /*
     * Synthetic 802.11 beacon-like LMAC RX: p54_hdr (data) + p54_rx_data
     * + a short beacon body with SSID "QEMU-N8x0".
     */
    uint8_t frame[128];
    uint16_t flags = 0; /* data frame */
    uint16_t hdr_len;
    const char *ssid = "QEMU-N8x0";
    size_t ssid_len = strlen(ssid);
    uint8_t *p;
    size_t beacon_len;

    memset(frame, 0, sizeof(frame));
    /* p54_hdr */
    frame[0] = flags & 0xff;
    frame[1] = flags >> 8;
    /* len filled below */
    frame[4] = req_id & 0xff;
    frame[5] = (req_id >> 8) & 0xff;
    frame[6] = (req_id >> 16) & 0xff;
    frame[7] = (req_id >> 24) & 0xff;
    /* type unused for data */
    /* p54_rx_data at offset 12 */
    p = frame + 12;
    p[0] = 0x08; /* DATA_IN_BEACON | FCS_GOOD-ish */
    p[1] = 0x00;
    p[2] = 20; /* len of 802.11 hdr+body approx, filled later */
    p[3] = 0;
    p[4] = 0x6c; /* freq 2412 */
    p[5] = 0x09;
    p[6] = 1; /* antenna */
    p[7] = 0; /* rate */
    p[8] = 40; /* rssi */
    p[9] = 70; /* quality */
    p[14] = 0x42; /* tsf lo */
    p[15] = 0x00;
    /* align[] then 802.11 mac hdr + tagged SSID */
    p = frame + 12 + 20;
    /* Frame Control: beacon */
    p[0] = 0x80;
    p[1] = 0x00;
    /* duration */
    p[2] = 0;
    p[3] = 0;
    /* addr1 broadcast */
    memset(p + 4, 0xff, 6);
    /* addr2 / addr3 BSSID */
    p[10] = 0x02;
    p[11] = 0x00;
    p[12] = 0x00;
    p[13] = 0x11;
    p[14] = 0x22;
    p[15] = 0x33;
    memcpy(p + 16, p + 10, 6);
    /* seq */
    p[22] = 0x10;
    p[23] = 0x00;
    /* fixed beacon params: timestamp(8) beacon_int(2) cap(2) */
    memset(p + 24, 0, 8);
    p[32] = 100; /* 100 TU */
    p[33] = 0;
    p[34] = 0x01; /* ESS */
    p[35] = 0x00;
    /* SSID IE */
    p[36] = 0;
    p[37] = ssid_len;
    memcpy(p + 38, ssid, ssid_len);
    /* DS param IE: channel 1 */
    p[38 + ssid_len] = 3;
    p[39 + ssid_len] = 1;
    p[40 + ssid_len] = 1;

    beacon_len = 41 + ssid_len;
    hdr_len = 12 + 20 + beacon_len;
    if (hdr_len > sizeof(frame)) {
        return;
    }
    frame[2] = hdr_len & 0xff;
    frame[3] = hdr_len >> 8;
    frame[12 + 2] = beacon_len & 0xff;
    frame[12 + 3] = beacon_len >> 8;
    cx3110x_rx_queue(s, frame, hdr_len);
}

static void cx3110x_handle_host_tx(struct cx3110x_s *s)
{
    uint16_t flags, type;
    uint32_t req_id;

    if (!s->booted || s->tx_len < 12) {
        return;
    }
    flags = s->tx_buf[0] | ((uint16_t)s->tx_buf[1] << 8);
    if (!(flags & P54_HDR_FLAG_CONTROL)) {
        return;
    }
    req_id = s->tx_buf[4] | ((uint32_t)s->tx_buf[5] << 8) |
             ((uint32_t)s->tx_buf[6] << 16) | ((uint32_t)s->tx_buf[7] << 24);
    type = s->tx_buf[8] | ((uint16_t)s->tx_buf[9] << 8);

    if (type == P54_CONTROL_TYPE_SCAN) {
        qemu_log("cx3110x: SoftMAC SCAN req_id=0x%x — synthetic BSS\n",
                 req_id);
        cx3110x_synth_bss_rx(s, req_id);
        cx3110x_synth_scan_trap(s, req_id);
    }
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
            qemu_log("cx3110x: RAM_BOOT — HOST_INT_READY\n");
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
                qemu_log("cx3110x: firmware DMA chunk %u bytes\n", s->tx_len);
            }
            cx3110x_raise(s, SPI_HOST_INT_WR_READY);
        }
        break;

    default:
        s->win[addr] = val;
        break;
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
         * at even addr, words are [addr+0], [addr+2].
         */
        reg = s->addr + s->data_words * 2;
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
    /* Idle device is ready for DMA. */
    s->win[SPI_ADRS_DMA_WRITE_CTRL] = HOST_ALLOWED;
    return s;
}
