/*
 * OMAP2420 IVA Level-2 interrupt controller.
 *
 * Register layout is the OMAP2 INTC (QEMU hw/intc/omap_intc.c omap2-intc,
 * Linux drivers/irqchip/irq-omap-intc.c). C55x word addresses are
 * HWI.INTC_BASE 0x7e4800 plus byte_offset/2 (SPRU404Q; bios2420
 * _C55_l2Init). 32-bit registers use SPRU374 dbl packing: even word is
 * MSW, odd word is LSW. Do not treat those words as ARM little-endian
 * 32-bit halves.
 *
 * Parent FIQ is C55x INT2; parent IRQ is INT3. DSP/BIOS routes all 32
 * L2 sources onto FIQ. Mailbox/IVA events enter as source 14
 * (logical id 46 / T0=46 at 0x101b48 → MIR_CLEAR bit 14).
 *
 * NEW_FIQ_AGR / NEW_IRQ_AGR must be written before another L2 source
 * is selected. Do not shortcut "if source 14: raise INT2".
 */

#include "c55x.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define L2_REVISION     0x21u
#define L2_SOFTRESET    0x2u
#define L2_NEW_IRQ_AGR  0x1u
#define L2_NEW_FIQ_AGR  0x2u
#define L2_GLOBALMASK   0x4u

static void l2_log(const C55xL2Intc *l2, const char *fmt, ...)
    __attribute__((format(gnu_printf, 2, 3)));
static void l2_log(const C55xL2Intc *l2, const char *fmt, ...)
{
    va_list ap;
    char buf[512];

    if (!l2 || !l2->cpu || !l2->cpu->bus.log) {
        return;
    }
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    l2->cpu->bus.log(l2->cpu->bus.opaque, "%s", buf);
}

static unsigned l2_ctz(uint32_t x)
{
    unsigned n = 0;

    if (x == 0) {
        return 32;
    }
    while ((x & 1u) == 0) {
        x >>= 1;
        n++;
    }
    return n;
}

static uint32_t l2_byte_off(uint32_t word_addr)
{
    return ((word_addr - C55X_L2INTC_BASE) & ~1u) * 2u;
}

static int l2_is_lsw(uint32_t word_addr)
{
    return (int)(word_addr & 1u);
}

static uint16_t l2_half(uint32_t value, int lsw)
{
    return lsw ? (uint16_t)value : (uint16_t)(value >> 16);
}

static uint32_t l2_deposit(uint32_t old, uint16_t half, int lsw)
{
    if (lsw) {
        return (old & 0xffff0000u) | half;
    }
    return (old & 0x0000ffffu) | ((uint32_t)half << 16);
}

static uint32_t l2_written(uint16_t half, int lsw)
{
    return lsw ? (uint32_t)half : ((uint32_t)half << 16);
}

static uint32_t l2_eligible(const C55xL2Intc *l2, int is_fiq)
{
    return l2->itr & ~l2->mir & (is_fiq ? l2->fiq : ~l2->fiq);
}

static void l2_sir_update(C55xL2Intc *l2, int is_fiq)
{
    uint32_t level = l2_eligible(l2, is_fiq);
    int sir = 0;
    int p_intr = 255;

    while (level) {
        unsigned i = l2_ctz(level);
        int p = l2->priority[i];

        if (p <= p_intr) {
            p_intr = p;
            sir = (int)i;
        }
        level &= level - 1u;
    }
    if (is_fiq) {
        l2->sir_fiq = sir;
    } else {
        l2->sir_irq = sir;
    }
}

static void l2_set_parent(C55xL2Intc *l2, int is_fiq, int level)
{
    int *parent = is_fiq ? &l2->parent_fiq : &l2->parent_irq;
    uint16_t bit = is_fiq ? (uint16_t)C55X_IFR_INT2 : (uint16_t)C55X_IFR_INT3;

    if (*parent == level) {
        return;
    }
    l2_log(l2, "L2 %s output: %d -> %d sir=%d pend=%08x mir=%08x pc=%06x\n",
           is_fiq ? "FIQ" : "IRQ", *parent, level,
           is_fiq ? l2->sir_fiq : l2->sir_irq, l2->itr, l2->mir,
           l2->cpu ? (l2->cpu->pc & C55X_PC_MASK) : 0);
    *parent = level;
    if (level && l2->cpu && (l2->cpu->ifr0 & bit) == 0) {
        l2->cpu->ifr0 |= bit;
        l2_log(l2, "C55 INT%u/IFR0.%u: 0 -> 1 IER0=%04x IFR0=%04x INTM=%u\n",
               is_fiq ? 2u : 3u, is_fiq ? 2u : 3u,
               l2->cpu->ier0, l2->cpu->ifr0,
               !!(l2->cpu->st1 & C55X_ST1_INTM));
    }
}

static void l2_update(C55xL2Intc *l2, int is_fiq)
{
    uint32_t has = l2_eligible(l2, is_fiq);
    uint32_t *agr = is_fiq ? &l2->new_agr_fiq : &l2->new_agr_irq;

    if (*agr & has & l2->global) {
        *agr = 0;
        l2_sir_update(l2, is_fiq);
        l2_set_parent(l2, is_fiq, 1);
    }
}

static void l2_update_both(C55xL2Intc *l2)
{
    l2_update(l2, 0);
    l2_update(l2, 1);
}

static void l2_apply_ilr(C55xL2Intc *l2, unsigned line, uint32_t value)
{
    if (line >= 32) {
        return;
    }
    l2->ilr[line] = value;
    l2->priority[line] = (uint8_t)((value >> 2) & 0x3f);
    l2->fiq &= ~(1u << line);
    l2->fiq |= (value & 1u) << line;
}

void c55x_l2intc_reset(C55xL2Intc *l2)
{
    C55xCPU *cpu;
    unsigned i;

    if (!l2) {
        return;
    }
    cpu = l2->cpu;
    memset(l2, 0, sizeof(*l2));
    l2->cpu = cpu;
    l2->mir = 0xffffffffu;
    /*
     * MPU omap2-intc reset leaves ILR FIQ=0 (IRQ). DSP/BIOS maps every
     * IVA L2 source onto the FIQ parent (INT2). Start there so a
     * source can wake `_issue_idle` before the ILR copy at 0x7e4880;
     * firmware stores still override.
     */
    l2->fiq = 0xffffffffu;
    for (i = 0; i < 32; i++) {
        l2->ilr[i] = 1;
    }
    l2->new_agr_irq = ~0u;
    l2->new_agr_fiq = ~0u;
    l2->global = ~0u;
}

int c55x_l2intc_owns(uint32_t word_addr)
{
    uint32_t a = word_addr & C55X_WORD_MASK;

    return a >= C55X_L2INTC_BASE &&
           a < C55X_L2INTC_BASE + C55X_L2INTC_WORDS;
}

static uint32_t l2_read_reg(const C55xL2Intc *l2, uint32_t off)
{
    unsigned line;

    switch (off) {
    case 0x00:
        return L2_REVISION;
    case 0x10:
        return (l2->autoidle >> 2) & 1u;
    case 0x14:
        return 1u;
    case 0x40:
        return (uint32_t)l2->sir_irq;
    case 0x44:
        return (uint32_t)l2->sir_fiq;
    case 0x48:
        return (l2->global == 0) ? 0 : 4u;
    case 0x4c:
        return 0;
    case 0x50:
        return l2->autoidle & 3u;
    case 0x80:
        return l2->inputs;
    case 0x84:
        return l2->mir;
    case 0x88:
    case 0x8c:
    case 0x94:
        return 0;
    case 0x90:
        return l2->swi;
    case 0x98:
        return l2_eligible(l2, 0);
    case 0x9c:
        return l2_eligible(l2, 1);
    default:
        break;
    }
    if (off >= 0x100u && off < 0x180u && (off & 3u) == 0) {
        line = (off - 0x100u) >> 2;
        return l2->ilr[line];
    }
    return 0;
}

static int l2_is_ilr(uint32_t off)
{
    return off >= 0x100u && off < 0x180u && (off & 3u) == 0;
}

int c55x_l2intc_read16(C55xL2Intc *l2, uint32_t word_addr, uint16_t *out)
{
    uint32_t off;

    if (!l2 || !out || !c55x_l2intc_owns(word_addr)) {
        return -1;
    }
    off = l2_byte_off(word_addr);
    if (l2_is_ilr(off)) {
        return 1;
    }
    *out = l2_half(l2_read_reg(l2, off), l2_is_lsw(word_addr));
    return 0;
}

int c55x_l2intc_write16(C55xL2Intc *l2, uint32_t word_addr, uint16_t value)
{
    uint32_t off;
    uint32_t written;
    int lsw;
    unsigned line;

    if (!l2 || !c55x_l2intc_owns(word_addr)) {
        return -1;
    }
    off = l2_byte_off(word_addr);
    lsw = l2_is_lsw(word_addr);
    written = l2_written(value, lsw);

    switch (off) {
    case 0x10:
        l2->sysconfig = l2_deposit(l2->sysconfig, value, lsw);
        l2->autoidle &= 4u;
        l2->autoidle |= (l2->sysconfig & 1u) << 2;
        if (l2->sysconfig & L2_SOFTRESET) {
            l2_log(l2, "L2 SYSCONFIG SOFTRESET pc=%06x\n",
                   l2->cpu ? (l2->cpu->pc & C55X_PC_MASK) : 0);
            c55x_l2intc_reset(l2);
        }
        return 0;
    case 0x48: {
        uint32_t control = l2_deposit(0, value, lsw);

        l2->global = (control & L2_GLOBALMASK) ? 0 : ~0u;
        if (control & L2_NEW_FIQ_AGR) {
            l2_log(l2, "L2 NEW_FIQ_AGR sir=%d pend=%08x mir=%08x pc=%06x\n",
                   l2->sir_fiq, l2->itr, l2->mir,
                   l2->cpu ? (l2->cpu->pc & C55X_PC_MASK) : 0);
            l2_set_parent(l2, 1, 0);
            l2->new_agr_fiq = ~0u;
            l2_update(l2, 1);
        }
        if (control & L2_NEW_IRQ_AGR) {
            l2_set_parent(l2, 0, 0);
            l2->new_agr_irq = ~0u;
            l2_update(l2, 0);
        }
        return 0;
    }
    case 0x4c:
    case 0x50:
        if (off == 0x50) {
            l2->autoidle = l2_deposit(l2->autoidle, value, lsw) & 3u;
        }
        return 0;
    case 0x84: {
        uint32_t old = l2->mir;

        l2->mir = l2_deposit(l2->mir, value, lsw);
        if (old != l2->mir) {
            l2_log(l2, "L2 MIR %08x -> %08x pc=%06x\n",
                   old, l2->mir,
                   l2->cpu ? (l2->cpu->pc & C55X_PC_MASK) : 0);
        }
        l2_update_both(l2);
        return 0;
    }
    case 0x88: {
        uint32_t old = l2->mir;

        l2->mir &= ~written;
        if (old != l2->mir) {
            l2_log(l2, "L2 MIR_CLEAR %08x MIR %08x -> %08x pc=%06x\n",
                   written, old, l2->mir,
                   l2->cpu ? (l2->cpu->pc & C55X_PC_MASK) : 0);
        }
        l2_update_both(l2);
        return 0;
    }
    case 0x8c:
        l2->mir |= written;
        return 0;
    case 0x90:
        l2->swi |= written;
        l2->itr |= written;
        l2_update_both(l2);
        return 0;
    case 0x94:
        l2->swi &= ~written;
        l2->itr = l2->swi | l2->inputs;
        return 0;
    case 0x00:
    case 0x14:
    case 0x40:
    case 0x44:
    case 0x80:
    case 0x98:
    case 0x9c:
        return 0;
    default:
        break;
    }
    if (l2_is_ilr(off)) {
        line = (off - 0x100u) >> 2;
        l2_apply_ilr(l2, line, l2_deposit(l2->ilr[line], value, lsw));
        return 1;
    }
    return 1;
}

void c55x_l2intc_set_irq(C55xL2Intc *l2, unsigned src, int level)
{
    uint32_t bit;

    if (!l2 || src >= 32) {
        return;
    }
    bit = 1u << src;
    if (level) {
        uint32_t rise = ~l2->inputs & bit;

        if (rise) {
            l2->inputs |= rise;
            l2->itr |= rise;
            l2_log(l2, "L2[%u]: 0 -> 1 pend=%08x mir=%08x fiq=%08x "
                       "agr_fiq=%u pc=%06x\n",
                   src, l2->itr, l2->mir, l2->fiq,
                   l2->new_agr_fiq != 0,
                   l2->cpu ? (l2->cpu->pc & C55X_PC_MASK) : 0);
            l2_update_both(l2);
        }
    } else {
        l2->inputs &= ~bit;
        l2->itr = (l2->itr & ~bit) | (l2->swi & bit);
    }
}

void c55x_l2intc_log_state(const C55xCPU *cpu, const char *why)
{
    const C55xL2Intc *l2;

    if (!cpu) {
        return;
    }
    l2 = &cpu->l2;
    l2_log(l2,
           "L2IC %s pend=%08x mir=%08x sir_fiq=%d sir_irq=%d "
           "fiq_out=%d irq_out=%d agr_fiq=%u src14=%u IER0=%04x "
           "IFR0=%04x INTM=%u halt=%d pc=%06x insn=%llu\n",
           why ? why : "?", l2->itr, l2->mir, l2->sir_fiq, l2->sir_irq,
           l2->parent_fiq, l2->parent_irq, l2->new_agr_fiq != 0,
           !!(l2->itr & (1u << C55X_L2INTC_MAIL_SRC)),
           cpu->ier0, cpu->ifr0, !!(cpu->st1 & C55X_ST1_INTM),
           (int)cpu->halt, cpu->pc & C55X_PC_MASK,
           (unsigned long long)cpu->insn_count);
}
