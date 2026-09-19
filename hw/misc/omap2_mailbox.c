/*
 * TI OMAP2 mailbox (IPC) emulation.
 *
 * OMAP2420 exposes this block at L4 0x48094000 with six hardware FIFOs
 * and four interrupt users. MPU-facing lines are MAIL_U0_MPU (DSP) and
 * MAIL_U3_MPU (IVA). Register layout follows Linux drivers/mailbox/omap-mailbox.c
 * (OMAP2 type) and arch/arm/mach-omap2 mailbox platform data.
 *
 * This models the MMIO FIFOs, status, and IRQ bits only. It does not
 * execute C55x code or fabricate DSP Gateway mailbox words. MESSAGE
 * accepts 16-bit DSP stores: a first half at +0 occupies a FIFO slot
 * (MSGSTATUS counts it) without raising NEWMSG. A following +2 write
 * is the SPRU374 LSW of `MOV ACx, dbl`; the first half becomes the
 * protocol MSW and NEWMSG fires once so stock `_mbx_send` (`7070`
 * then `0019`) yields one ARM little-endian `0x70700019`. Raising
 * NEWMSG on the first half lets Linux pop `0x00007070` between the
 * two C55x write16s. The DSP IRQ user is pulsed on FIFO 0 NEWMSG
 * (ARM→DSP). NEWMSG(1) is the DSP's own TX complete and must not
 * re-enter `_mbx_send`. NOTFULL(1) must reach INT5: a full TX FIFO
 * makes `_mbx_send` OR IRQENABLE(1) with bit 3 and SEM_pend
 * `_SEM_mbox_notfull` (word `0x81c12`) until `_mbx_notfull`.
 */

#include "qemu/osdep.h"
#include "hw/irq.h"
#include "hw/arm/omap.h"
#include "qemu/log.h"
#include "qemu/timer.h"

#define OMAP2_MBOX_FIFOS        6
#define OMAP2_MBOX_USERS        4
#define OMAP2_MBOX_DEPTH        4
#define OMAP2_MBOX_REV          0x10 /* RX-34 hwtest measured after EN_MAILBOXES */

#define OMAP2_MBOX_REVISION     0x000
#define OMAP2_MBOX_SYSCONFIG    0x010
#define OMAP2_MBOX_SYSSTATUS    0x014
#define OMAP2_MBOX_MESSAGE(m)   (0x040 + 4 * (m))
#define OMAP2_MBOX_FIFOSTATUS(m) (0x080 + 4 * (m))
#define OMAP2_MBOX_MSGSTATUS(m) (0x0c0 + 4 * (m))
#define OMAP2_MBOX_IRQSTATUS(u) (0x100 + 8 * (u))
#define OMAP2_MBOX_IRQENABLE(u) (0x104 + 8 * (u))

#define OMAP2_MBOX_SYSCONFIG_SOFTRESET (1u << 1)
#define OMAP2_MBOX_CMD_POLL     0x32u

static uint32_t omap2_mbox_last_d2a;
static uint64_t omap2_mbox_last_d2a_ms;
static unsigned omap2_mbox_last_d2a_valid;
static uint32_t omap2_mbox_last_a2d;
static uint64_t omap2_mbox_last_a2d_ms;
static unsigned omap2_mbox_last_a2d_valid;
#define OMAP2_MBOX_A2D_HIST 20
static struct {
    uint64_t t_ms;
    uint32_t word;
} omap2_mbox_a2d_hist[OMAP2_MBOX_A2D_HIST];
static unsigned omap2_mbox_a2d_hist_n;
static unsigned omap2_mbox_a2d_hist_i;

static uint64_t omap2_mailbox_virt_ms(void)
{
    return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) / 1000000ull;
}

static void omap2_mailbox_log_word(const char *what, unsigned m,
                                   uint32_t word, unsigned depth)
{
    unsigned cmd_h = (word >> 24) & 0x7f;
    uint64_t now = omap2_mailbox_virt_ms();

    qemu_log_mask(LOG_UNIMP,
                  "omap2_mailbox: t=%llu ms %s fifo=%u word=%08x seq=%u "
                  "cmd_h=%02x cmd_l=%02x data=%04x depth=%u%s\n",
                  (unsigned long long)now,
                  what, m, word, (word >> 31) & 1u, cmd_h,
                  (word >> 16) & 0xffu, word & 0xffffu, depth,
                  cmd_h == OMAP2_MBOX_CMD_POLL ? " POLL" : "");
    if (m == 0 && cmd_h == OMAP2_MBOX_CMD_POLL && strcmp(what, "pop") == 0) {
        qemu_log_mask(LOG_UNIMP,
                      "A2D 32:00\n"
                      "  FIFO pop t=%llu ms word=%08x depth=%u\n",
                      (unsigned long long)now, word, depth);
    }
    /*
     * 16-bit first halves are not protocol words. Track completed
     * FIFO1 (D2A) and non-POLL FIFO0 (A2D) only.
     */
    if (m == 1 && (strcmp(what, "complete") == 0 ||
                   (strcmp(what, "push") == 0 && cmd_h != 0))) {
        omap2_mbox_last_d2a = word;
        omap2_mbox_last_d2a_ms = now;
        omap2_mbox_last_d2a_valid = 1;
    }
    if (m == 0 && cmd_h != OMAP2_MBOX_CMD_POLL &&
        (strcmp(what, "complete") == 0 ||
         (strcmp(what, "push") == 0 && cmd_h != 0))) {
        omap2_mbox_last_a2d = word;
        omap2_mbox_last_a2d_ms = now;
        omap2_mbox_last_a2d_valid = 1;
        omap2_mbox_a2d_hist[omap2_mbox_a2d_hist_i].t_ms = now;
        omap2_mbox_a2d_hist[omap2_mbox_a2d_hist_i].word = word;
        omap2_mbox_a2d_hist_i = (omap2_mbox_a2d_hist_i + 1u) %
                                OMAP2_MBOX_A2D_HIST;
        if (omap2_mbox_a2d_hist_n < OMAP2_MBOX_A2D_HIST) {
            omap2_mbox_a2d_hist_n++;
        }
    }
    if (m == 0 && cmd_h == OMAP2_MBOX_CMD_POLL && strcmp(what, "push") == 0) {
        uint64_t age = omap2_mbox_last_a2d_valid ?
                       now - omap2_mbox_last_a2d_ms : 0;
        unsigned i, n, idx;

        qemu_log_mask(LOG_UNIMP,
                      "ARM WATCHDOG\n"
                      "  trigger_cmd = %02x:%02x seq=%u data=%04x word=%08x\n"
                      "  trigger_age = %llu ms\n"
                      "  last_d2a    = %s word=%08x t=%llu ms\n"
                      "A2D 32:00\n"
                      "  FIFO push t=%llu ms\n",
                      omap2_mbox_last_a2d_valid ?
                      (omap2_mbox_last_a2d >> 24) & 0x7f : 0,
                      omap2_mbox_last_a2d_valid ?
                      (omap2_mbox_last_a2d >> 16) & 0xff : 0,
                      omap2_mbox_last_a2d_valid ?
                      (omap2_mbox_last_a2d >> 31) & 1u : 0,
                      omap2_mbox_last_a2d_valid ?
                      omap2_mbox_last_a2d & 0xffffu : 0,
                      omap2_mbox_last_a2d,
                      (unsigned long long)age,
                      omap2_mbox_last_d2a_valid ? "" : "(none)",
                      omap2_mbox_last_d2a,
                      (unsigned long long)omap2_mbox_last_d2a_ms,
                      (unsigned long long)now);
        n = omap2_mbox_a2d_hist_n;
        idx = (omap2_mbox_a2d_hist_i + OMAP2_MBOX_A2D_HIST - n) %
              OMAP2_MBOX_A2D_HIST;
        qemu_log_mask(LOG_UNIMP,
                      "A2D last-%u before 32:00\n", n);
        for (i = 0; i < n; i++) {
            uint32_t w = omap2_mbox_a2d_hist[idx].word;

            qemu_log_mask(LOG_UNIMP,
                          "  [%u] t=%llu ms word=%08x seq=%u cmd=%02x:%02x "
                          "data=%04x\n",
                          i, (unsigned long long)omap2_mbox_a2d_hist[idx].t_ms,
                          w, (w >> 31) & 1u, (w >> 24) & 0x7f,
                          (w >> 16) & 0xffu, w & 0xffffu);
            idx = (idx + 1u) % OMAP2_MBOX_A2D_HIST;
        }
    }
}

#define OMAP2_MBOX_SYSSTATUS_RESETDONE (1u << 0)
#define OMAP2_MBOX_IRQ_NEWMSG(m)  (1u << (2 * (m)))
#define OMAP2_MBOX_IRQ_NOTFULL(m) (1u << (2 * (m) + 1))

struct omap2_mailbox_fifo {
    uint32_t msg[OMAP2_MBOX_DEPTH];
    unsigned count;
    unsigned ridx;
};

struct omap2_mailbox_s {
    MemoryRegion iomem;
    qemu_irq irq[OMAP2_MBOX_USERS];
    uint32_t sysconfig;
    uint32_t irqstatus[OMAP2_MBOX_USERS];
    uint32_t irqenable[OMAP2_MBOX_USERS];
    struct omap2_mailbox_fifo fifo[OMAP2_MBOX_FIFOS];
    /* Last 16-bit low-half MESSAGE push may still accept a high half. */
    uint8_t msg_partial[OMAP2_MBOX_FIFOS];
    /* MOV dbl pops once: +0 returns MSW, +2 returns the latched LSW. */
    uint32_t msg_latched[OMAP2_MBOX_FIFOS];
    uint8_t msg_read_half[OMAP2_MBOX_FIFOS];
};

static void omap2_mailbox_irq_update(struct omap2_mailbox_s *s)
{
    int i;

    for (i = 0; i < OMAP2_MBOX_USERS; i++) {
        uint32_t mask = s->irqstatus[i] & s->irqenable[i];

        /*
         * DSP INT5 is the user-1 line. tokliBIOS `_mailbox_interrupt`
         * (`0x131fb0`) posts SWI_newmsg on NEWMSG(0) and SWI_notfull
         * on NOTFULL(1) when that enable bit is set. NEWMSG(1) is the
         * DSP TX complete and re-enters `_mbx_send` with INTM=0.
         */
        if (i == 1) {
            mask &= (OMAP2_MBOX_IRQ_NEWMSG(0) | OMAP2_MBOX_IRQ_NOTFULL(0) |
                     OMAP2_MBOX_IRQ_NOTFULL(1));
        }
        if (i == 1 && mask) {
            qemu_log_mask(LOG_UNIMP,
                          "omap2_mailbox: dsp-irq status=%08x enable=%08x "
                          "mask=%08x\n",
                          s->irqstatus[1], s->irqenable[1], mask);
        }
        qemu_set_irq(s->irq[i], !!mask);
    }
}

static void omap2_mailbox_set_all_users(struct omap2_mailbox_s *s, uint32_t bit)
{
    int i;

    for (i = 0; i < OMAP2_MBOX_USERS; i++) {
        s->irqstatus[i] |= bit;
    }
}

static uint32_t omap2_mailbox_idle_notfull_mask(void)
{
    /* RX-34 Phase D: empty FIFOs leave NOTFULL sticky = 0xaaa (bits 1,3,5,7,9,11). */
    uint32_t mask = 0;
    int m;

    for (m = 0; m < OMAP2_MBOX_FIFOS; m++) {
        mask |= OMAP2_MBOX_IRQ_NOTFULL(m);
    }
    return mask;
}

static void omap2_mailbox_reset(struct omap2_mailbox_s *s)
{
    int i;
    uint32_t idle_notfull = omap2_mailbox_idle_notfull_mask();

    s->sysconfig = 0;
    for (i = 0; i < OMAP2_MBOX_USERS; i++) {
        /* Silicon golden: IRQSTATUS idle = 0xaaa after EN_MAILBOXES; not 0. */
        s->irqstatus[i] = idle_notfull;
        s->irqenable[i] = 0;
    }
    memset(s->fifo, 0, sizeof(s->fifo));
    memset(s->msg_partial, 0, sizeof(s->msg_partial));
    memset(s->msg_latched, 0, sizeof(s->msg_latched));
    memset(s->msg_read_half, 0, sizeof(s->msg_read_half));
    omap2_mbox_a2d_hist_n = 0;
    omap2_mbox_a2d_hist_i = 0;
    omap2_mbox_last_a2d_valid = 0;
    omap2_mbox_last_d2a_valid = 0;
    omap2_mailbox_irq_update(s);
}

static uint32_t omap2_mailbox_pop(struct omap2_mailbox_s *s, unsigned m)
{
    struct omap2_mailbox_fifo *f = &s->fifo[m];
    uint32_t value;
    unsigned was_full;

    if (!f->count) {
        return 0;
    }
    was_full = f->count == OMAP2_MBOX_DEPTH;
    value = f->msg[f->ridx];
    f->ridx = (f->ridx + 1) % OMAP2_MBOX_DEPTH;
    f->count--;
    omap2_mailbox_log_word("pop", m, value, f->count);
    if (was_full) {
        omap2_mailbox_set_all_users(s, OMAP2_MBOX_IRQ_NOTFULL(m));
        omap2_mailbox_irq_update(s);
        /*
         * `_mbx_send` may already have INTM=0 and be SEM_pending the
         * not-full object. A level that never dropped (NEWMSG(0)
         * still latched) would not set IFR0; pulse FIFO 1 NOTFULL
         * the same way FIFO 0 NEWMSG is pulsed.
         */
        if (m == 1 && s->irq[1] &&
            (s->irqstatus[1] & s->irqenable[1] &
             OMAP2_MBOX_IRQ_NOTFULL(1))) {
            qemu_set_irq(s->irq[1], 0);
            qemu_set_irq(s->irq[1], 1);
        }
    }
    return value;
}

static void omap2_mailbox_notify_newmsg(struct omap2_mailbox_s *s, unsigned m)
{
    omap2_mailbox_set_all_users(s, OMAP2_MBOX_IRQ_NEWMSG(m));
    omap2_mailbox_irq_update(s);
    /*
     * OMAP2 NEWMSG is sticky, but tokliBIOS ACKs it in `_mbx_newmsg`
     * after MSGSTATUS hits 0. A later ARM word (TCFG) on FIFO 0 must
     * raise INT5 again even if the line never dropped. Do not pulse
     * the DSP user on FIFO 1: that is the DSP's own TX path.
     */
    if (m == 0 && s->irq[1] && (s->irqstatus[1] & s->irqenable[1])) {
        qemu_set_irq(s->irq[1], 0);
        qemu_set_irq(s->irq[1], 1);
    }
}

static void omap2_mailbox_push(struct omap2_mailbox_s *s, unsigned m,
                               uint32_t value, bool notify)
{
    struct omap2_mailbox_fifo *f = &s->fifo[m];
    unsigned widx;

    if (f->count >= OMAP2_MBOX_DEPTH) {
        return;
    }
    widx = (f->ridx + f->count) % OMAP2_MBOX_DEPTH;
    f->msg[widx] = value;
    f->count++;
    if (notify) {
        omap2_mailbox_notify_newmsg(s, m);
    }
    omap2_mailbox_log_word("push", m, value, f->count);
}

static void omap2_mailbox_write_message(struct omap2_mailbox_s *s,
                                        unsigned m, unsigned offset,
                                        uint64_t value, unsigned size)
{
    struct omap2_mailbox_fifo *f = &s->fifo[m];
    uint32_t half = (uint32_t)value;

    if (size == 4 && offset == 0) {
        omap2_mailbox_push(s, m, (uint32_t)value, true);
        s->msg_partial[m] = 0;
        return;
    }
    if (size == 2 && offset == 0) {
        /* Slot reserved; NEWMSG waits for the LSW (or a lone +2). */
        omap2_mailbox_push(s, m, half & 0xffff, false);
        s->msg_partial[m] = 1;
        return;
    }
    if (size == 2 && offset == 2) {
        if (s->msg_partial[m] && f->count) {
            unsigned widx = (f->ridx + f->count - 1) % OMAP2_MBOX_DEPTH;
            uint32_t first = f->msg[widx] & 0xffffu;

            /* Stock MOV dbl: first 16-bit write is MSW, second is LSW. */
            f->msg[widx] = (first << 16) | (half & 0xffffu);
            s->msg_partial[m] = 0;
            omap2_mailbox_log_word("complete", m, f->msg[widx], f->count);
            omap2_mailbox_notify_newmsg(s, m);
            return;
        }
        omap2_mailbox_push(s, m, (half & 0xffffu) << 16, true);
        s->msg_partial[m] = 0;
        return;
    }
    qemu_log_mask(LOG_GUEST_ERROR,
                  "omap2-mailbox: MESSAGE(%u) write size %u at +%u\n",
                  m, size, offset);
}

static uint64_t omap2_mailbox_read_message(struct omap2_mailbox_s *s,
                                           unsigned m, unsigned offset,
                                           unsigned size)
{
    if (size == 4 && offset == 0) {
        s->msg_read_half[m] = 0;
        return omap2_mailbox_pop(s, m);
    }
    if (size == 2 && offset == 0) {
        if (!s->msg_read_half[m]) {
            s->msg_latched[m] = omap2_mailbox_pop(s, m);
            s->msg_read_half[m] = 1;
        }
        /* SPRU374 MOV dbl: first Lmem half is the protocol MSW. */
        return s->msg_latched[m] >> 16;
    }
    if (size == 2 && offset == 2) {
        uint32_t value;

        if (s->msg_read_half[m]) {
            value = s->msg_latched[m];
            s->msg_read_half[m] = 0;
        } else {
            value = omap2_mailbox_pop(s, m);
        }
        return value & 0xffffu;
    }
    return omap_badwidth_read32(s, OMAP2_MBOX_MESSAGE(m) + offset);
}

static uint64_t omap2_mailbox_read(void *opaque, hwaddr addr, unsigned size)
{
    struct omap2_mailbox_s *s = opaque;
    unsigned index;

    if (addr >= OMAP2_MBOX_MESSAGE(0) && addr <= OMAP2_MBOX_MESSAGE(5) + 2) {
        index = (addr - OMAP2_MBOX_MESSAGE(0)) / 4;
        if (index < OMAP2_MBOX_FIFOS) {
            return omap2_mailbox_read_message(s, index, addr & 3, size);
        }
    }

    if (size != 4) {
        return omap_badwidth_read32(opaque, addr);
    }

    switch (addr) {
    case OMAP2_MBOX_REVISION:
        return OMAP2_MBOX_REV;
    case OMAP2_MBOX_SYSCONFIG:
        return s->sysconfig;
    case OMAP2_MBOX_SYSSTATUS:
        return OMAP2_MBOX_SYSSTATUS_RESETDONE;
    }

    if (addr >= OMAP2_MBOX_FIFOSTATUS(0) && addr <= OMAP2_MBOX_FIFOSTATUS(5)) {
        index = (addr - OMAP2_MBOX_FIFOSTATUS(0)) / 4;
        return s->fifo[index].count >= OMAP2_MBOX_DEPTH;
    }
    if (addr >= OMAP2_MBOX_MSGSTATUS(0) && addr <= OMAP2_MBOX_MSGSTATUS(5)) {
        index = (addr - OMAP2_MBOX_MSGSTATUS(0)) / 4;
        return s->fifo[index].count;
    }
    if (addr >= OMAP2_MBOX_IRQSTATUS(0) && addr <= OMAP2_MBOX_IRQENABLE(3)) {
        index = (addr - OMAP2_MBOX_IRQSTATUS(0)) / 8;
        if (((addr - OMAP2_MBOX_IRQSTATUS(0)) & 7) == 0) {
            return s->irqstatus[index];
        }
        return s->irqenable[index];
    }

    OMAP_BAD_REG(addr);
    return 0;
}

static void omap2_mailbox_write(void *opaque, hwaddr addr,
                                uint64_t value, unsigned size)
{
    struct omap2_mailbox_s *s = opaque;
    unsigned index;

    if (addr >= OMAP2_MBOX_MESSAGE(0) && addr < OMAP2_MBOX_FIFOSTATUS(0)) {
        index = (addr - OMAP2_MBOX_MESSAGE(0)) / 4;
        if (index < OMAP2_MBOX_FIFOS) {
            omap2_mailbox_write_message(s, index, addr & 3, value, size);
            return;
        }
    }

    if (size != 4) {
        omap_badwidth_write32(opaque, addr, value);
        return;
    }

    switch (addr) {
    case OMAP2_MBOX_SYSCONFIG:
        s->sysconfig = value & 0x11d;
        if (value & OMAP2_MBOX_SYSCONFIG_SOFTRESET) {
            omap2_mailbox_reset(s);
            s->sysconfig = value & 0x11d & ~OMAP2_MBOX_SYSCONFIG_SOFTRESET;
        }
        return;
    case OMAP2_MBOX_REVISION:
    case OMAP2_MBOX_SYSSTATUS:
        OMAP_RO_REG(addr);
        return;
    }
    if (addr >= OMAP2_MBOX_FIFOSTATUS(0) && addr <= OMAP2_MBOX_MSGSTATUS(5)) {
        OMAP_RO_REG(addr);
        return;
    }
    if (addr >= OMAP2_MBOX_IRQSTATUS(0) && addr <= OMAP2_MBOX_IRQENABLE(3)) {
        index = (addr - OMAP2_MBOX_IRQSTATUS(0)) / 8;
        if (((addr - OMAP2_MBOX_IRQSTATUS(0)) & 7) == 0) {
            s->irqstatus[index] &= ~value;
        } else {
            s->irqenable[index] = value;
        }
        omap2_mailbox_irq_update(s);
        return;
    }

    OMAP_BAD_REG(addr);
}

static const MemoryRegionOps omap2_mailbox_ops = {
    .read = omap2_mailbox_read,
    .write = omap2_mailbox_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl.min_access_size = 1,
    .impl.max_access_size = 4,
    .valid.min_access_size = 1,
    .valid.max_access_size = 4,
};

struct omap2_mailbox_s *omap2_mailbox_init(struct omap_target_agent_s *ta,
                                           qemu_irq irq_mpu_dsp,
                                           qemu_irq irq_mpu_iva)
{
    struct omap2_mailbox_s *s = g_new0(struct omap2_mailbox_s, 1);

    s->irq[0] = irq_mpu_dsp;
    s->irq[3] = irq_mpu_iva;
    omap2_mailbox_reset(s);

    memory_region_init_io(&s->iomem, NULL, &omap2_mailbox_ops, s,
                          "omap2.mailbox", omap_l4_region_size(ta, 0));
    omap_l4_attach(ta, 0, &s->iomem);
    return s;
}

void omap2_mailbox_set_dsp_irq(struct omap2_mailbox_s *s, qemu_irq irq)
{
    s->irq[1] = irq;
}

uint32_t omap2_mailbox_peek(struct omap2_mailbox_s *s, unsigned fifo,
                             unsigned *count)
{
    struct omap2_mailbox_fifo *f;

    if (fifo >= OMAP2_MBOX_FIFOS) {
        if (count) {
            *count = 0;
        }
        return 0;
    }
    f = &s->fifo[fifo];
    if (count) {
        *count = f->count;
    }
    if (!f->count) {
        return 0;
    }
    return f->msg[f->ridx];
}

uint32_t omap2_mailbox_find_cmd(struct omap2_mailbox_s *s, unsigned fifo,
                                unsigned cmd_h, unsigned *count,
                                unsigned *slot)
{
    struct omap2_mailbox_fifo *f;
    unsigned i;

    if (fifo >= OMAP2_MBOX_FIFOS) {
        if (count) {
            *count = 0;
        }
        if (slot) {
            *slot = 0;
        }
        return 0;
    }
    f = &s->fifo[fifo];
    if (count) {
        *count = f->count;
    }
    for (i = 0; i < f->count; i++) {
        unsigned idx = (f->ridx + i) % OMAP2_MBOX_DEPTH;
        uint32_t word = f->msg[idx];

        if (((word >> 24) & 0x7f) == cmd_h) {
            if (slot) {
                *slot = i;
            }
            return word;
        }
    }
    if (slot) {
        *slot = 0;
    }
    return 0;
}
