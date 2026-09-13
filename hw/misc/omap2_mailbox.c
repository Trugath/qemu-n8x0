/*
 * TI OMAP2 mailbox (IPC) emulation.
 *
 * OMAP2420 exposes this block at L4 0x48094000 with six hardware FIFOs
 * and four interrupt users. MPU-facing lines are MAIL_U0_MPU (DSP) and
 * MAIL_U3_MPU (IVA). Register layout follows Linux drivers/mailbox/omap-mailbox.c
 * (OMAP2 type) and arch/arm/mach-omap2 mailbox platform data.
 *
 * This models the MMIO FIFOs, status, and IRQ bits only. It does not
 * execute C55x code or fabricate DSP Gateway mailbox words.
 */

#include "qemu/osdep.h"
#include "hw/irq.h"
#include "hw/arm/omap.h"
#include "qemu/log.h"

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
};

static void omap2_mailbox_irq_update(struct omap2_mailbox_s *s)
{
    int i;

    for (i = 0; i < OMAP2_MBOX_USERS; i++) {
        qemu_set_irq(s->irq[i], !!(s->irqstatus[i] & s->irqenable[i]));
    }
}

static void omap2_mailbox_set_all_users(struct omap2_mailbox_s *s, uint32_t bit)
{
    int i;

    for (i = 0; i < OMAP2_MBOX_USERS; i++) {
        s->irqstatus[i] |= bit;
    }
}

static void omap2_mailbox_reset(struct omap2_mailbox_s *s)
{
    int i;

    s->sysconfig = 0;
    for (i = 0; i < OMAP2_MBOX_USERS; i++) {
        s->irqstatus[i] = 0;
        s->irqenable[i] = 0;
    }
    memset(s->fifo, 0, sizeof(s->fifo));
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
    if (was_full) {
        omap2_mailbox_set_all_users(s, OMAP2_MBOX_IRQ_NOTFULL(m));
        omap2_mailbox_irq_update(s);
    }
    return value;
}

static void omap2_mailbox_push(struct omap2_mailbox_s *s, unsigned m,
                               uint32_t value)
{
    struct omap2_mailbox_fifo *f = &s->fifo[m];
    unsigned widx;

    if (f->count >= OMAP2_MBOX_DEPTH) {
        return;
    }
    widx = (f->ridx + f->count) % OMAP2_MBOX_DEPTH;
    f->msg[widx] = value;
    if (!f->count) {
        omap2_mailbox_set_all_users(s, OMAP2_MBOX_IRQ_NEWMSG(m));
    }
    f->count++;
    omap2_mailbox_irq_update(s);
}

static uint64_t omap2_mailbox_read(void *opaque, hwaddr addr, unsigned size)
{
    struct omap2_mailbox_s *s = opaque;
    unsigned index;

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

    if (addr >= OMAP2_MBOX_MESSAGE(0) && addr <= OMAP2_MBOX_MESSAGE(5)) {
        index = (addr - OMAP2_MBOX_MESSAGE(0)) / 4;
        return omap2_mailbox_pop(s, index);
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

    if (addr >= OMAP2_MBOX_MESSAGE(0) && addr <= OMAP2_MBOX_MESSAGE(5)) {
        omap2_mailbox_push(s, (addr - OMAP2_MBOX_MESSAGE(0)) / 4, value);
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
