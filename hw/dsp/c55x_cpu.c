#include "c55x.h"

#include <stdio.h>
#include <string.h>

static const char *const c55x_reg_names[16] = {
    "AC0", "AC1", "AC2", "AC3",
    "T0", "T1", "T2", "T3",
    "AR0", "AR1", "AR2", "AR3",
    "AR4", "AR5", "AR6", "AR7"
};

static const char *c55x_op_names[] = {
    "UNDEF", "NOP", "mmap", "port()", "port(Smem)",
    "MOV", "MOV", "MOV", "MOV", "MOV", "MOV", "MOV",
    "MOV", "MOV", "MOV", "MOV", "MOV", "MOV", "MOV", "MOV", "MOV",
    "ADD", "SUB", "AND", "OR", "XOR",
    "NOT", "NEG", "ABS", "MAX", "MIN",
    "ADD", "SUB", "AND", "OR", "XOR", "ADD", "OR",
    "AND", "OR", "XOR", "ADD", "SUB",
    "BSET", "BCLR", "BSET", "BCLR", "BNOT", "BTST", "AMAR",
    "B", "B", "B", "B", "CALL", "CALL", "CALL", "CALLCC",
    "BCC", "BCC", "BCC", "RET", "RETI",
    "PSH", "POP",
    "AADD", "AADD", "AMOV", "ASUB",
    "AADD", "AMOV", "ASUB", "AMOV",
    "RPT", "RPT", "RPTB", "IDLE", "INTR", "TRAP", "RESET",
    "MOV", "MOV",
    "AND", "OR", "XOR", "ADD", "SUB", "SFTS", "SFTL",
    "AND", "OR", "XOR",
    "RPT",     "MOV", "MOV", "PSHBOTH", "POPBOTH", "PSH", "POP", "MOV",
    "MOV", "MOV", "MOV",
    "XCC", "XCCPART", "ADD",
    "ADD", "SUB", "AND", "XOR",
    "PSH", "POP", "AMAR", "PSH", "POP",
    "MOV", "SUB", "AND", "OR", "XOR",
    "CMP", "CMPAND", "CMPOR", "MOV", "MOV", "CMP",
    "ADD", "SUB", "SUB",
    "MOV", "MOV", "SFTS", "SFTL",     "BTST", "RPTBLOCAL", "MPYK",
    "MOV", "BCC", "SFTS",
    "EXP", "MPYMK", "MACMK", "MOV",
    "IVEC", "MOV", "PSH", "POP",
    "MPY", "MAC", "MAS", "MPY",
    "SQA", "SQS", "SQR", "ADDV", "RND", "SAT",
    "BSET", "BCLR", "BNOT",
    "MPYM", "SQRM",
    "MACM", "MASM", "SQAM", "SQSM",
    "MPYM", "MACM", "MASM",
    "BAND",
    "ADD", "SUB", "MOV",
    "MACK", "BFXTR", "BFXPA", "ADD",
    "MOV", "MOV",
    "MACMZ", "MPYM", "MACM", "MASM",
    "MAC", "AMAR", "FIRSADD", "FIRSSUB",
    "LMS", "SQDST", "ABDST", "MAC",
    "MOV",
    "SUBC", "ADDSUBCC", "ADDSUB", "SUBADD",
    "ADD", "MOV",
    "RETCC", "CALLCC", "RPTCC", "RPTADD", "RPTSUB",
    "SWAP", "DELAY", "MANT", "NEXP", "BCNT", "MAXDIFF",
    "ROL", "ROR", "MOV",
    "BTST", "PSH", "POP", "BCC"
};

const char *c55x_reg_name(unsigned fsss)
{
    return c55x_reg_names[fsss & 15];
}

void c55x_cond_name(unsigned cond, char *buf, size_t len)
{
    static const char *const rel[6] = {
        "== #0", "!= #0", "< #0", "<= #0", "> #0", ">= #0"
    };
    unsigned top = (cond >> 4) & 7;
    unsigned fsss = cond & 0x0f;

    if (!buf || !len) {
        return;
    }
    /* SPRU374 Table 1–3 / XCC examples: ARx tests are written *ARx. */
    if (top <= 5) {
        if (fsss >= 8) {
            snprintf(buf, len, "*AR%u %s", fsss - 8, rel[top]);
        } else {
            snprintf(buf, len, "%s %s", c55x_reg_name(fsss), rel[top]);
        }
        return;
    }
    switch (cond) {
    case 0x64:
        snprintf(buf, len, "TC1");
        break;
    case 0x65:
        snprintf(buf, len, "TC2");
        break;
    case 0x66:
        snprintf(buf, len, "CARRY");
        break;
    case 0x74:
        snprintf(buf, len, "!TC1");
        break;
    case 0x75:
        snprintf(buf, len, "!TC2");
        break;
    case 0x76:
        snprintf(buf, len, "!CARRY");
        break;
    default:
        snprintf(buf, len, "cond 0x%02x", cond);
        break;
    }
}

static const char *const c55x_xreg_names[16] = {
    "AC0", "AC1", "AC2", "AC3",
    "XSP", "XSSP", "XDP", "XCDP",
    "XAR0", "XAR1", "XAR2", "XAR3",
    "XAR4", "XAR5", "XAR6", "XAR7"
};

const char *c55x_xreg_name(unsigned xsss)
{
    return c55x_xreg_names[xsss & 15];
}

uint32_t c55x_get_xreg(const C55xCPU *cpu, unsigned xsss)
{
    xsss &= 15;
    if (xsss < 4) {
        if (cpu->pkt_src_valid) {
            return (uint32_t)(cpu->pkt_ac[xsss] & C55X_WORD_MASK);
        }
        return (uint32_t)(cpu->ac[xsss] & C55X_WORD_MASK);
    }
    if (xsss == 4) {
        return (cpu->pkt_src_valid ? cpu->pkt_xsp : cpu->xsp) & C55X_WORD_MASK;
    }
    if (xsss == 5) {
        return (cpu->pkt_src_valid ? cpu->pkt_xssp : cpu->xssp) &
               C55X_WORD_MASK;
    }
    if (xsss == 6) {
        return (cpu->pkt_src_valid ? cpu->pkt_xdp : cpu->xdp) & C55X_WORD_MASK;
    }
    if (xsss == 7) {
        return (cpu->pkt_src_valid ? cpu->pkt_xcdp : cpu->xcdp) &
               C55X_WORD_MASK;
    }
    if (cpu->pkt_src_valid) {
        return cpu->pkt_xar[xsss - 8] & C55X_WORD_MASK;
    }
    return cpu->xar[xsss - 8] & C55X_WORD_MASK;
}

/*
 * SPRU371F: SPH (mmap 0x4e) is the shared 7-bit page for both XSP and
 * XSSP. MOV XSP / MOV XSSP write that page; SP and SSP stay 16-bit.
 */
static void c55x_set_sph(C55xCPU *cpu, uint32_t page)
{
    uint32_t high = (page & 0x7fu) << 16;

    cpu->xsp = high | (cpu->xsp & 0xffffu);
    cpu->xssp = high | (cpu->xssp & 0xffffu);
}

void c55x_set_xreg(C55xCPU *cpu, unsigned xsss, uint32_t value)
{
    value &= C55X_WORD_MASK;
    xsss &= 15;
    if (xsss < 4) {
        cpu->ac[xsss] = value;
        return;
    }
    if (xsss == 4) {
        c55x_set_sph(cpu, value >> 16);
        cpu->xsp = (cpu->xsp & ~0xffffu) | (value & 0xffffu);
        cpu->sp_written = 1;
        return;
    }
    if (xsss == 5) {
        c55x_set_sph(cpu, value >> 16);
        cpu->xssp = (cpu->xssp & ~0xffffu) | (value & 0xffffu);
        cpu->ssp_written = 1;
        return;
    }
    if (xsss == 6) {
        cpu->xdp = value;
        return;
    }
    if (xsss == 7) {
        cpu->xcdp = value;
        return;
    }
    cpu->xar[xsss - 8] = value;
}

const char *c55x_op_name(C55xOpKind kind)
{
    unsigned n = (unsigned)kind;

    if (n >= sizeof(c55x_op_names) / sizeof(c55x_op_names[0])) {
        return "UNDEF";
    }
    return c55x_op_names[n];
}

void c55x_init(C55xCPU *cpu, const C55xBus *bus)
{
    memset(cpu, 0, sizeof(*cpu));
    if (bus) {
        cpu->bus = *bus;
    }
    c55x_reset(cpu);
}

void c55x_reset(C55xCPU *cpu)
{
    unsigned i;

    c55x_poll_trace_reset(cpu);
    cpu->pc = 0;
    cpu->ret_pc = 0;
    for (i = 0; i < 4; i++) {
        cpu->ac[i] = 0;
        cpu->t[i] = 0;
    }
    for (i = 0; i < 8; i++) {
        cpu->xar[i] = 0;
    }
    cpu->xsp = 0;
    cpu->xssp = 0;
    cpu->xdp = 0;
    cpu->xcdp = 0;
    cpu->st0 = C55X_ST0_CARRY;
    cpu->st1 = C55X_ST1_INTM;
    cpu->st2 = C55X_ST2_DBGM;
    cpu->st3 = 0;
    cpu->ier0 = 0;
    cpu->ifr0 = 0;
    cpu->ier1 = 0;
    cpu->ifr1 = 0;
    cpu->dbier0 = 0;
    cpu->dbier1 = 0;
    cpu->ivpd = 0;
    cpu->ivph = 0;
    cpu->brc0 = 0;
    cpu->brc1 = 0;
    cpu->brs1 = 0;
    cpu->csr = 0;
    cpu->rptc = 0;
    cpu->rsa0 = 0;
    cpu->rea0 = 0;
    cpu->rsa1 = 0;
    cpu->rea1 = 0;
    cpu->bk03 = 0;
    cpu->bk47 = 0;
    cpu->bkc = 0;
    cpu->bsa01 = 0;
    cpu->bsa23 = 0;
    cpu->bsa45 = 0;
    cpu->bsa67 = 0;
    cpu->bsac = 0;
    cpu->trn0 = 0;
    cpu->trn1 = 0;
    cpu->pdp = 0;
    cpu->rpt_left = 0;
    cpu->rpt_active = 0;
    cpu->rpt_armed = 0;
    cpu->rpt_cc = 0;
    cpu->rptb0_active = 0;
    cpu->rptb1_active = 0;
    cpu->xcc_pending = 0;
    cpu->pkt_src_valid = 0;
    cpu->pkt_wr_n = 0;
    cpu->mem_init_logged = 0;
    cpu->xcc_cond_true = 0;
    cpu->sp_written = 0;
    cpu->ssp_written = 0;
    cpu->reta = 0;
    cpu->cfct = 0;
    cpu->dbstat = 0;
    /* Default until c55x_apply_reset_vector() latches bits 29:28. */
    cpu->fast_return = 1;
    cpu->irq_ret_slow = 0;
    cpu->irq_nest = 0;
    cpu->irq_rpt_saved = 0;
    memset(cpu->irq_rpt_left, 0, sizeof(cpu->irq_rpt_left));
    cpu->br_delay_target = 0;
    cpu->br_delay_pending = 0;
    cpu->br_delay_fire = 0;
    memset(cpu->mmr_unk, 0, sizeof(cpu->mmr_unk));
    cpu->halt = C55X_OK;
    cpu->undef_pc = 0;
    cpu->undef_length = 0;
    memset(cpu->undef_bytes, 0, sizeof(cpu->undef_bytes));
    memset(&cpu->undef_insn, 0, sizeof(cpu->undef_insn));
    memset(cpu->hist, 0, sizeof(cpu->hist));
    cpu->hist_count = 0;
    cpu->hist_next = 0;
    cpu->last_irq_from = 0;
    cpu->last_irq_vec = 0;
    cpu->last_irq_bit = 0xff;
    cpu->last_reti_from = 0;
    cpu->last_reti_to = 0;
    cpu->audio_isr_n = 0;
    cpu->in_audio_isr = 0;
    cpu->snap_1012fb = 0;
    cpu->host_tc_n = 0;
    cpu->host_clnk_n = 0;
    cpu->insn_count = 0;
    cpu->flow_verbose = 0;
    cpu->flow_mismatch_n = 0;
    cpu->flow_escape_logged = 0;
    cpu->flow_depth = 0;
    cpu->flow_seq = 0;
    memset(cpu->flow_id, 0, sizeof(cpu->flow_id));
    memset(cpu->flow_expect, 0, sizeof(cpu->flow_expect));
    memset(cpu->flow_caller, 0, sizeof(cpu->flow_caller));
    memset(cpu->flow_kind, 0, sizeof(cpu->flow_kind));
    memset(cpu->dev_watch, 0, sizeof(cpu->dev_watch));
    cpu->dev_watch_n = 0;
    cpu->xar3_prev = 0;
    cpu->lmem_word = 0;
    cpu->lmem_even = 0;
    cpu->lmem_odd = 0;
    cpu->lmem_msw = 0;
    cpu->lmem_lsw = 0;
    cpu->xar3_nlogged = 0;
    cpu->ac0_prev = 0;
    cpu->ac0_nlogged = 0;
    cpu->l2.cpu = cpu;
    c55x_l2intc_reset(&cpu->l2);
}

void c55x_apply_reset_vector(C55xCPU *cpu, uint32_t vector)
{
    unsigned cfg = (vector >> 28) & 3u;

    cpu->pc = vector & C55X_PC_MASK;
    cpu->reta = 0;
    cpu->cfct = 0;
    cpu->vector_bit25 = (uint8_t)((vector >> 25) & 1u);
    /*
     * SPRU371F Table 4-2:
     *   00 = dual 16-bit, fast return (RETA/CFCT used)
     *   01 = dual 16-bit, slow return
     *   10 = 32-bit stack, slow return
     *   11 = reserved — treat as fast (Linux SETRSTVECT high bits are 0)
     */
    switch (cfg) {
    case 1:
    case 2:
        cpu->fast_return = 0;
        break;
    default:
        cpu->fast_return = 1;
        break;
    }
}

const char *c55x_stack_config_name(const C55xCPU *cpu)
{
    if (!cpu->fast_return) {
        /* Distinguishing SLOW16 vs SLOW32 needs SSP coupling; CALL/RET
         * already share the slow path. */
        return "SLOW";
    }
    return "FAST16";
}

/*
 * AR post-modify currently page-wraps (xar_plus). Whether OMAP2420
 * reset-vector bit25 selects flat 23-bit DAGEN is unconfirmed; report
 * UNKNOWN until a hardware-backed test distinguishes the modes.
 */
const char *c55x_dagen_mode_name(const C55xCPU *cpu)
{
    (void)cpu;
    return "UNKNOWN";
}

uint64_t c55x_get_reg(const C55xCPU *cpu, unsigned fsss)
{
    fsss &= 15;
    if (fsss < 4) {
        if (cpu->pkt_src_valid) {
            return cpu->pkt_ac[fsss] & C55X_AC_MASK;
        }
        return cpu->ac[fsss] & C55X_AC_MASK;
    }
    if (fsss < 8) {
        return cpu->pkt_src_valid ? cpu->pkt_t[fsss - 4] : cpu->t[fsss - 4];
    }
    if (cpu->pkt_src_valid) {
        return (uint16_t)cpu->pkt_xar[fsss - 8];
    }
    return c55x_ar(cpu, fsss - 8);
}

int64_t c55x_get_reg_signed(const C55xCPU *cpu, unsigned fsss)
{
    uint64_t value = c55x_get_reg(cpu, fsss);

    fsss &= 15;
    if (fsss < 4) {
        /*
         * SPRU371F: M40=0 (and not C54CM) is a 32-bit accumulator.
         * The sign bit is 31; bits 39–32 are guard bits and are not
         * part of BCC / NEG / ABS. HWI_F_dispatch clears M40 and then
         * does SUB AC0, AC1 / BCC AC1<=#0. A 32-bit negative difference
         * must take that branch. Sign-extending only from bit 39 makes
         * it look positive, switches to the ISR stack, and RETI returns
         * to 0.
         */
        int wide = (cpu->st1 & (C55X_ST1_M40 | C55X_ST1_C54CM)) != 0;
        unsigned signbit = wide ? 39u : 31u;
        uint64_t keep = wide ? C55X_AC_MASK : 0xffffffffull;

        value &= keep;
        if (value & (1ull << signbit)) {
            value |= ~keep;
        }
        return (int64_t)value;
    }
    return (int16_t)(uint16_t)value;
}

void c55x_set_reg(C55xCPU *cpu, unsigned fsss, uint64_t value)
{
    fsss &= 15;
    if (fsss < 4) {
        /* M40=0: keep GU clear (32-bit AC image; silicon mailbox is 32-bit). */
        if (!(cpu->st1 & (C55X_ST1_M40 | C55X_ST1_C54CM))) {
            value &= 0xffffffffull;
        }
        cpu->ac[fsss] = value & C55X_AC_MASK;
        return;
    }
    if (fsss < 8) {
        cpu->t[fsss - 4] = (uint16_t)value;
        return;
    }
    cpu->xar[fsss - 8] = (cpu->xar[fsss - 8] & ~0xffffu) | (value & 0xffffu);
}

void c55x_st3_write(C55xCPU *cpu, uint16_t value)
{
    /*
     * SPRU371F ST3_55 CACLR: software sets the bit; cache hardware
     * clears it when the invalidate completes. This interpreter has
     * no I-cache (fetches always read the backing store), so the
     * clear completes in the same write. CAEN is recorded only.
     */
    cpu->st3 = value & (uint16_t)~C55X_ST3_CACLR;
}

uint16_t c55x_mmr_read(C55xCPU *cpu, unsigned addr)
{
    addr &= 0x7f;
    switch (addr) {
    case C55X_MMR_IER0:
        return cpu->ier0;
    case C55X_MMR_IFR0:
        return cpu->ifr0;
    case C55X_MMR_ST0:
    case 0x06:
        return cpu->st0;
    case C55X_MMR_ST1:
    case 0x07:
        return cpu->st1;
    case C55X_MMR_ST3:
    case 0x1d:
        return cpu->st3;
    case 0x08:
        return (uint16_t)cpu->ac[0];
    case 0x09:
        return (uint16_t)(cpu->ac[0] >> 16);
    case 0x0a:
        return (uint16_t)(cpu->ac[0] >> 32);
    case 0x0b:
        return (uint16_t)cpu->ac[1];
    case 0x0c:
        return (uint16_t)(cpu->ac[1] >> 16);
    case 0x0d:
        return (uint16_t)(cpu->ac[1] >> 32);
    case 0x0e:
    case 0x23:
        return cpu->t[3];
    case 0x0f:
        return cpu->trn0;
    case 0x10:
    case 0x11:
    case 0x12:
    case 0x13:
    case 0x14:
    case 0x15:
    case 0x16:
    case 0x17:
        return c55x_ar(cpu, addr - 0x10);
    case 0x18:
    case C55X_MMR_SP:
        return (uint16_t)cpu->xsp;
    case 0x19:
        return cpu->bk03;
    case 0x1a:
        return cpu->brc0;
    case 0x1b:
        return (uint16_t)cpu->rsa0;
    case 0x1c:
        return (uint16_t)cpu->rea0;
    case 0x20:
        return cpu->t[0];
    case 0x21:
        return cpu->t[1];
    case 0x22:
        return cpu->t[2];
    case 0x24:
        return (uint16_t)cpu->ac[2];
    case 0x25:
        return (uint16_t)(cpu->ac[2] >> 16);
    case 0x26:
        return (uint16_t)(cpu->ac[2] >> 32);
    case 0x27:
        return (uint16_t)cpu->xcdp;
    case 0x28:
        return (uint16_t)cpu->ac[3];
    case 0x29:
        return (uint16_t)(cpu->ac[3] >> 16);
    case 0x2a:
        return (uint16_t)(cpu->ac[3] >> 32);
    case 0x2b:
        return (uint16_t)(cpu->xdp >> 16);
    case 0x2e:
        return (uint16_t)cpu->xdp;
    case 0x2f:
        return cpu->pdp;
    case 0x30:
        return cpu->bk47;
    case 0x31:
        return cpu->bkc;
    case 0x32:
        return cpu->bsa01;
    case 0x33:
        return cpu->bsa23;
    case 0x34:
        return cpu->bsa45;
    case 0x35:
        return cpu->bsa67;
    case 0x36:
        return cpu->bsac;
    case 0x38:
        return cpu->trn1;
    case 0x39:
        return cpu->brc1;
    case 0x3a:
        return cpu->brs1;
    case 0x3b:
        return cpu->csr;
    case 0x3c:
        return (uint16_t)(cpu->rsa0 >> 16);
    case 0x3d:
        return (uint16_t)cpu->rsa0;
    case 0x3e:
        return (uint16_t)(cpu->rea0 >> 16);
    case 0x3f:
        return (uint16_t)cpu->rea0;
    case 0x40:
        return (uint16_t)(cpu->rsa1 >> 16);
    case 0x41:
        return (uint16_t)cpu->rsa1;
    case 0x42:
        return (uint16_t)(cpu->rea1 >> 16);
    case 0x43:
        return (uint16_t)cpu->rea1;
    case 0x44:
        return cpu->rptc;
    case C55X_MMR_IER1:
        return cpu->ier1;
    case C55X_MMR_IFR1:
        return cpu->ifr1;
    case 0x47:
        return cpu->dbier0;
    case 0x48:
        return cpu->dbier1;
    case 0x49:
        return cpu->ivpd;
    case 0x4a:
        return cpu->ivph;
    case C55X_MMR_ST2:
        return cpu->st2;
    case C55X_MMR_SSP:
        return (uint16_t)cpu->xssp;
    case 0x4e:
        return (uint16_t)(cpu->xsp >> 16);
    case 0x4f:
        return (uint16_t)(cpu->xcdp >> 16);
    default:
        return cpu->mmr_unk[addr];
    }
}

void c55x_mmr_write(C55xCPU *cpu, unsigned addr, uint16_t value)
{
    addr &= 0x7f;
    switch (addr) {
    case C55X_MMR_IER0:
        /*
         * HWI_F_dispatch masks INT5 for the ISR (002c↔000c). Log the
         * other writes: after TCFG the idle TSK drops IER0 to 0004 so
         * mailbox INT5 can no longer exit IDLE.
         */
        if (cpu->ier0 != value && cpu->bus.log &&
            !((cpu->ier0 == 0x002cu && value == 0x000cu) ||
              (cpu->ier0 == 0x000cu && value == 0x002cu))) {
            cpu->bus.log(cpu->bus.opaque,
                         "IER0 %04x -> %04x pc=%06x INTM=%u IFR0=%04x\n",
                         cpu->ier0, value, cpu->pc & C55X_PC_MASK,
                         !!(cpu->st1 & C55X_ST1_INTM), cpu->ifr0);
        }
        cpu->ier0 = value;
        break;
    case C55X_MMR_IFR0:
        cpu->ifr0 &= ~value;
        break;
    case C55X_MMR_ST0:
    case 0x06:
        cpu->st0 = value;
        break;
    case C55X_MMR_ST1:
    case 0x07:
        cpu->st1 = value;
        break;
    case C55X_MMR_ST3:
    case 0x1d:
        c55x_st3_write(cpu, value);
        break;
    case 0x08:
        cpu->ac[0] = (cpu->ac[0] & ~0xffffull) | value;
        break;
    case 0x09:
        cpu->ac[0] = (cpu->ac[0] & ~0xffff0000ull) | ((uint64_t)value << 16);
        break;
    case 0x0a:
        cpu->ac[0] = (cpu->ac[0] & ~0xff00000000ull) | ((uint64_t)(value & 0xff) << 32);
        break;
    case 0x0b:
        cpu->ac[1] = (cpu->ac[1] & ~0xffffull) | value;
        break;
    case 0x0c:
        cpu->ac[1] = (cpu->ac[1] & ~0xffff0000ull) | ((uint64_t)value << 16);
        break;
    case 0x0d:
        cpu->ac[1] = (cpu->ac[1] & ~0xff00000000ull) | ((uint64_t)(value & 0xff) << 32);
        break;
    case 0x0e:
    case 0x23:
        cpu->t[3] = value;
        break;
    case 0x0f:
        cpu->trn0 = value;
        break;
    case 0x10:
    case 0x11:
    case 0x12:
    case 0x13:
    case 0x14:
    case 0x15:
    case 0x16:
    case 0x17:
        cpu->xar[addr - 0x10] = (cpu->xar[addr - 0x10] & ~0xffffu) | value;
        break;
    case 0x18:
    case C55X_MMR_SP:
        cpu->xsp = (cpu->xsp & ~0xffffu) | value;
        cpu->sp_written = 1;
        break;
    case 0x19:
        cpu->bk03 = value;
        break;
    case 0x1a:
        cpu->brc0 = value;
        break;
    case 0x1b:
        cpu->rsa0 = (cpu->rsa0 & ~0xffffu) | value;
        break;
    case 0x1c:
        cpu->rea0 = (cpu->rea0 & ~0xffffu) | value;
        break;
    case 0x20:
        cpu->t[0] = value;
        break;
    case 0x21:
        cpu->t[1] = value;
        break;
    case 0x22:
        cpu->t[2] = value;
        break;
    case 0x24:
        cpu->ac[2] = (cpu->ac[2] & ~0xffffull) | value;
        break;
    case 0x25:
        cpu->ac[2] = (cpu->ac[2] & ~0xffff0000ull) | ((uint64_t)value << 16);
        break;
    case 0x26:
        cpu->ac[2] = (cpu->ac[2] & ~0xff00000000ull) | ((uint64_t)(value & 0xff) << 32);
        break;
    case 0x27:
        cpu->xcdp = (cpu->xcdp & ~0xffffu) | value;
        break;
    case 0x28:
        cpu->ac[3] = (cpu->ac[3] & ~0xffffull) | value;
        break;
    case 0x29:
        cpu->ac[3] = (cpu->ac[3] & ~0xffff0000ull) | ((uint64_t)value << 16);
        break;
    case 0x2a:
        cpu->ac[3] = (cpu->ac[3] & ~0xff00000000ull) | ((uint64_t)(value & 0xff) << 32);
        break;
    case 0x2b:
        cpu->xdp = ((uint32_t)(value & 0x7f) << 16) | (cpu->xdp & 0xffffu);
        break;
    case 0x2e:
        cpu->xdp = (cpu->xdp & ~0xffffu) | value;
        break;
    case 0x2f:
        cpu->pdp = value & 0x1ff;
        break;
    case 0x30:
        cpu->bk47 = value;
        break;
    case 0x31:
        cpu->bkc = value;
        break;
    case 0x32:
        cpu->bsa01 = value;
        break;
    case 0x33:
        cpu->bsa23 = value;
        break;
    case 0x34:
        cpu->bsa45 = value;
        break;
    case 0x35:
        cpu->bsa67 = value;
        break;
    case 0x36:
        cpu->bsac = value;
        break;
    case 0x38:
        cpu->trn1 = value;
        break;
    case 0x39:
        cpu->brc1 = value;
        break;
    case 0x3a:
        cpu->brs1 = value;
        break;
    case 0x3b:
        cpu->csr = value;
        break;
    case 0x3c:
        cpu->rsa0 = ((uint32_t)(value & 0xff) << 16) | (cpu->rsa0 & 0xffffu);
        break;
    case 0x3d:
        cpu->rsa0 = (cpu->rsa0 & ~0xffffu) | value;
        break;
    case 0x3e:
        cpu->rea0 = ((uint32_t)(value & 0xff) << 16) | (cpu->rea0 & 0xffffu);
        break;
    case 0x3f:
        cpu->rea0 = (cpu->rea0 & ~0xffffu) | value;
        break;
    case 0x40:
        cpu->rsa1 = ((uint32_t)(value & 0xff) << 16) | (cpu->rsa1 & 0xffffu);
        break;
    case 0x41:
        cpu->rsa1 = (cpu->rsa1 & ~0xffffu) | value;
        break;
    case 0x42:
        cpu->rea1 = ((uint32_t)(value & 0xff) << 16) | (cpu->rea1 & 0xffffu);
        break;
    case 0x43:
        cpu->rea1 = (cpu->rea1 & ~0xffffu) | value;
        break;
    case 0x44:
        cpu->rptc = value;
        break;
    case C55X_MMR_IER1:
        cpu->ier1 = value;
        break;
    case C55X_MMR_IFR1:
        cpu->ifr1 &= ~value;
        break;
    case 0x47:
        cpu->dbier0 = value;
        break;
    case 0x48:
        cpu->dbier1 = value;
        break;
    case 0x49:
        cpu->ivpd = value;
        break;
    case 0x4a:
        cpu->ivph = value;
        break;
    case C55X_MMR_ST2:
        cpu->st2 = value;
        break;
    case C55X_MMR_SSP:
        cpu->xssp = (cpu->xssp & ~0xffffu) | value;
        cpu->ssp_written = 1;
        break;
    case 0x4e:
        c55x_set_sph(cpu, value);
        break;
    case 0x4f:
        cpu->xcdp = ((uint32_t)(value & 0x7f) << 16) | (cpu->xcdp & 0xffffu);
        break;
    default:
        cpu->mmr_unk[addr] = value;
        break;
    }
}

void c55x_history_add(C55xCPU *cpu, const C55xDecodedInsn *in)
{
    C55xHist *h = &cpu->hist[cpu->hist_next];

    h->pc = cpu->pc;
    memcpy(h->bytes, in->bytes, C55X_FETCH_MAX);
    h->length = in->length;
    h->kind = in->op[0].kind;
    cpu->hist_next = (cpu->hist_next + 1) % C55X_HISTORY;
    if (cpu->hist_count < C55X_HISTORY) {
        cpu->hist_count++;
    }
}

static const C55xHist *c55x_hist_last(const C55xCPU *cpu)
{
    if (!cpu->hist_count) {
        return NULL;
    }
    return &cpu->hist[(cpu->hist_next + C55X_HISTORY - 1) % C55X_HISTORY];
}

static int hist_kind_bcc(C55xOpKind k)
{
    return k == C55X_OP_BCC_L8 || k == C55X_OP_BCC_L16 ||
           k == C55X_OP_BCC_P24 || k == C55X_OP_BCC_SRC_K8 ||
           k == C55X_OP_BCC_ARN;
}

static int hist_kind_call(C55xOpKind k)
{
    return k == C55X_OP_CALL_P24 || k == C55X_OP_CALL_AC ||
           k == C55X_OP_CALL_L16 || k == C55X_OP_CALLCC_L16 ||
           k == C55X_OP_CALLCC_P24;
}

static int hist_kind_b(C55xOpKind k)
{
    return k == C55X_OP_B_L7 || k == C55X_OP_B_L16 ||
           k == C55X_OP_B_P24 || k == C55X_OP_B_AC;
}

static const char *c55x_pc_transition(const C55xCPU *cpu, uint32_t pc)
{
    const C55xHist *h = c55x_hist_last(cpu);
    uint32_t fall;

    if (!h) {
        if (cpu->last_irq_vec == pc) {
            return "IRQ";
        }
        return "unknown";
    }
    fall = (h->pc + h->length) & C55X_PC_MASK;
    if (h->length && pc != h->pc) {
        if (h->pc < fall) {
            if (pc > h->pc && pc < fall) {
                return "packet-second";
            }
        } else if (pc > h->pc || pc < fall) {
            return "packet-second";
        }
    }
    if (pc == h->pc) {
        return "RPT";
    }
    if (pc == fall) {
        return "fallthrough";
    }
    if (h->kind == C55X_OP_RETI) {
        return "RETI";
    }
    if (h->kind == C55X_OP_RET || h->kind == C55X_OP_RETCC) {
        return "RET";
    }
    if (hist_kind_call(h->kind)) {
        return "CALL";
    }
    if (hist_kind_bcc(h->kind)) {
        return "BCC";
    }
    if (hist_kind_b(h->kind)) {
        return "B";
    }
    if (h->kind == C55X_OP_RPT_K8 || h->kind == C55X_OP_RPT_K16 ||
        h->kind == C55X_OP_RPTCC) {
        return "RPT";
    }
    if (cpu->last_irq_vec == pc) {
        return "IRQ";
    }
    return "other";
}

static uint16_t dump_read16(const C55xCPU *cpu, uint32_t word)
{
    uint16_t v = 0;

    if (cpu->bus.read16) {
        cpu->bus.read16(cpu->bus.opaque, word, &v);
    }
    return v;
}

void c55x_dump(const C55xCPU *cpu, const C55xDecodedInsn *in,
               char *buf, size_t len)
{
    char dis[160];
    char hex[48];
    char around[96];
    char hist[6144];
    uint8_t win[32];
    unsigned i, n, start, win_n;
    uint32_t pc, prev, win_at, curtask;
    const C55xHist *last;
    size_t used;

    if (!buf || !len) {
        return;
    }
    pc = cpu->pc & C55X_PC_MASK;
    hex[0] = '\0';
    n = 0;
    if (in) {
        for (i = 0; i < in->length && i < C55X_FETCH_MAX && n + 3 < sizeof(hex); i++) {
            n += (unsigned)snprintf(hex + n, sizeof(hex) - n, "%s%02x",
                                    i ? "" : "", in->bytes[i]);
        }
        c55x_disasm(in, dis, sizeof(dis));
    } else {
        snprintf(dis, sizeof(dis), "(no insn)");
    }
    last = c55x_hist_last(cpu);
    prev = last ? (last->pc & C55X_PC_MASK) : 0xffffffffu;
    around[0] = '\0';
    win_at = (pc >= 16u) ? (pc - 16u) : 0;
    win_n = 0;
    if (c55x_fetch((C55xCPU *)cpu, win_at, win, sizeof(win)) == 0) {
        win_n = sizeof(win);
    }
    n = 0;
    for (i = 0; i < win_n && n + 3 < sizeof(around); i++) {
        n += (unsigned)snprintf(around + n, sizeof(around) - n, "%s%02x",
                                i ? " " : "", win[i]);
    }
    hist[0] = '\0';
    used = 0;
    start = (cpu->hist_count < C55X_HISTORY) ? 0 : cpu->hist_next;
    for (i = 0; i < cpu->hist_count && used + 72 < sizeof(hist); i++) {
        const C55xHist *h = &cpu->hist[(start + i) % C55X_HISTORY];
        unsigned b, hn = 0;
        char hb[24];

        hb[0] = '\0';
        for (b = 0; b < h->length && b < C55X_FETCH_MAX && hn + 3 < sizeof(hb); b++) {
            hn += (unsigned)snprintf(hb + hn, sizeof(hb) - hn, "%s%02x",
                                    b ? "" : "", h->bytes[b]);
        }
        used += (size_t)snprintf(hist + used, sizeof(hist) - used,
                                 "  %06x %s raw=%s\n",
                                 h->pc, c55x_op_name(h->kind), hb);
    }
    curtask = ((uint32_t)dump_read16(cpu, 0x09cc1cu) << 16) |
              dump_read16(cpu, 0x09cc1du);
    used = 0;
    if (cpu->halt == C55X_HALT_UNDEF) {
        used = (size_t)snprintf(buf, len,
                                "FAULT pc=%06x\n"
                                "previous_pc=%06x\n"
                                "transition=%s\n"
                                "raw=%s\n"
                                "packet=%s\n"
                                "around %06x: %s\n",
                                pc, prev, c55x_pc_transition(cpu, pc),
                                hex, dis, win_at, around);
    }
    if (used >= len) {
        return;
    }
    snprintf(buf + used, len - used,
             "C55x halt=%d pc=%06x raw=%s %s\n"
             "  AC0=%010llx AC1=%010llx AC2=%010llx AC3=%010llx\n"
             "  T0=%04x T1=%04x T2=%04x T3=%04x\n"
             "  XAR0=%06x XAR1=%06x XAR2=%06x XAR3=%06x\n"
             "  XAR4=%06x XAR5=%06x XAR6=%06x XAR7=%06x\n"
             "  XSP=%06x XSSP=%06x XDP=%06x XCDP=%06x\n"
             "  ST0=%04x ST1=%04x ST2=%04x ST3=%04x\n"
             "  IER0=%04x IFR0=%04x IER1=%04x IFR1=%04x\n"
             "  RETA=%06x CFCT=%02x IVPD=%04x IVPH=%04x\n"
             "  rpt armed=%u active=%u cc=%u left=%u rptc=%04x\n"
             "  RPTB0=%u RSA0=%06x REA0=%06x BRC0=%04x\n"
             "  RPTB1=%u RSA1=%06x REA1=%06x BRC1=%04x BRS1=%04x\n"
             "  curtask=%06x nest=%u audio_isr_n=%u\n"
             "  last_irq bit=%u from=%06x vec=%06x\n"
             "  last_reti %06x -> %06x\n"
             "  insn_count=%llu\n"
             "recent:\n%s",
             (int)cpu->halt, pc, hex, dis,
             (unsigned long long)cpu->ac[0],
             (unsigned long long)cpu->ac[1],
             (unsigned long long)cpu->ac[2],
             (unsigned long long)cpu->ac[3],
             cpu->t[0], cpu->t[1], cpu->t[2], cpu->t[3],
             c55x_xar(cpu, 0), c55x_xar(cpu, 1),
             c55x_xar(cpu, 2), c55x_xar(cpu, 3),
             c55x_xar(cpu, 4), c55x_xar(cpu, 5),
             c55x_xar(cpu, 6), c55x_xar(cpu, 7),
             cpu->xsp & C55X_WORD_MASK, cpu->xssp & C55X_WORD_MASK,
             cpu->xdp & C55X_WORD_MASK, cpu->xcdp & C55X_WORD_MASK,
             cpu->st0, cpu->st1, cpu->st2, cpu->st3,
             cpu->ier0, cpu->ifr0, cpu->ier1, cpu->ifr1,
             cpu->reta & C55X_PC_MASK, cpu->cfct & 0xff, cpu->ivpd, cpu->ivph,
             cpu->rpt_armed, cpu->rpt_active, cpu->rpt_cc, cpu->rpt_left,
             cpu->rptc,
             cpu->rptb0_active, cpu->rsa0 & C55X_PC_MASK,
             cpu->rea0 & C55X_PC_MASK, cpu->brc0,
             cpu->rptb1_active, cpu->rsa1 & C55X_PC_MASK,
             cpu->rea1 & C55X_PC_MASK, cpu->brc1, cpu->brs1,
             curtask & C55X_WORD_MASK, cpu->irq_nest, cpu->audio_isr_n,
             cpu->last_irq_bit, cpu->last_irq_from, cpu->last_irq_vec,
             cpu->last_reti_from, cpu->last_reti_to,
             (unsigned long long)cpu->insn_count,
             hist);
}
