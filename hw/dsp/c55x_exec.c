#include "c55x.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void c55x_log(C55xCPU *cpu, const char *fmt, ...)
    __attribute__((format(gnu_printf, 2, 3)));
static void bios_watch_arm(void);
static uint16_t peek16(C55xCPU *cpu, uint32_t word);
static void note_dev_store(C55xCPU *cpu, uint32_t word, uint16_t old,
                           uint16_t value);
static const char *bios_pc_name(uint32_t pc);
static uint8_t eapq_flow;
static uint8_t eapq_parked4;
static void eapq_note_mmio(C55xCPU *cpu, uint32_t word, uint16_t value);
static void eapq_note_call(C55xCPU *cpu, uint32_t from, uint32_t dest);
static void eap_note_cssa(C55xCPU *cpu);
static void eap_pcm_stat(const char *fmt, ...)
    __attribute__((format(gnu_printf, 1, 2)));
static uint32_t eap_cssa_src;
/* *AR6 in _SRC_TII_convert: shared output budget. */
static uint32_t src_budget_word;
/* Output pointer at SRC entry; the RET scan is the buffer IODMA reads. */
static uint32_t src_out_base;
static uint16_t src_out_n;
static int src_out_armed;
/* Set once the submix slot at word 0x5d2 holds a real sample. */
static int mix_slot_hot;
static int swap_seen;
static uint16_t eap_cssa_len;
static void eapq_note_irq(C55xCPU *cpu, unsigned bit);
static void eapq_note_bcc(C55xCPU *cpu, uint32_t from, uint32_t dest,
                         int taken);
static int knlq_hold_int5(C55xCPU *cpu, unsigned bit, uint32_t from);
static int knlq_hold_nest(C55xCPU *cpu, unsigned bit, uint32_t from);
static int knlq_arm_snap(C55xCPU *cpu, unsigned bit, uint32_t from);
static void knlq_note_accept(C55xCPU *cpu);
static void knlq_note_irq(C55xCPU *cpu, unsigned bit, uint32_t from);
static void knlq_note_reti(C55xCPU *cpu);
static void knlq_note_before(C55xCPU *cpu);
static void knlq_note_after(C55xCPU *cpu, uint32_t from, uint32_t next);
static void knlq_note_work_store(C55xCPU *cpu, uint16_t old, uint16_t value);
static void knlq_note_link(C55xCPU *cpu, uint32_t word, uint16_t old,
                           uint16_t value);
static int knlq_take_skip(C55xCPU *cpu);
static void knlq_note_call0(C55xCPU *cpu);
static void knlq_flush(C55xCPU *cpu, const char *why);
static void c55x_log(C55xCPU *cpu, const char *fmt, ...)
{
    va_list ap;
    char buf[8192];

    if (!cpu->bus.log) {
        return;
    }
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    cpu->bus.log(cpu->bus.opaque, "%s", buf);
}

static void set_undef(C55xCPU *cpu, const C55xDecodedInsn *in)
{
    cpu->halt = C55X_HALT_UNDEF;
    cpu->undef_pc = cpu->pc;
    cpu->undef_length = in->length;
    memcpy(cpu->undef_bytes, in->bytes, C55X_FETCH_MAX);
    cpu->undef_insn = *in;
    if (cpu->bus.log) {
        char dump[8192];

        c55x_dump(cpu, in, dump, sizeof(dump));
        c55x_log(cpu, "%s", dump);
    }
    knlq_flush(cpu, "UNDEF");
}

static int shiftw6(unsigned enc)
{
    int sh = (int)(enc & 0x3f);

    if (sh & 32) {
        sh -= 64;
    }
    return sh;
}

static uint64_t ac_shift(uint64_t value, int sh, int arith)
{
    int64_t s;

    value &= C55X_AC_MASK;
    if (sh >= 0) {
        return (value << sh) & C55X_AC_MASK;
    }
    sh = -sh;
    if (arith) {
        s = (int64_t)(value << 24) >> 24;
        return (uint64_t)(s >> sh) & C55X_AC_MASK;
    }
    return (value >> sh) & C55X_AC_MASK;
}

static void ac_shift_carry(C55xCPU *cpu, uint64_t value, int sh)
{
    unsigned bit;

    value &= C55X_AC_MASK;
    if (sh > 0 && sh <= 40) {
        bit = (unsigned)(40 - sh);
        if ((value >> bit) & 1ull) {
            cpu->st0 |= C55X_ST0_CARRY;
        } else {
            cpu->st0 &= (uint16_t)~C55X_ST0_CARRY;
        }
    } else if (sh < 0 && -sh <= 40) {
        bit = (unsigned)(-sh - 1);
        if ((value >> bit) & 1ull) {
            cpu->st0 |= C55X_ST0_CARRY;
        } else {
            cpu->st0 &= (uint16_t)~C55X_ST0_CARRY;
        }
    }
}

static uint32_t xar_plus(uint32_t xar, int32_t delta)
{
    uint32_t high = xar & ~0xffffu;
    uint16_t low = (uint16_t)((int)(uint16_t)xar + delta);

    return (high | low) & C55X_WORD_MASK;
}

static uint16_t pkt_read_st2(const C55xCPU *cpu);

/*
 * SPRU371F 6.11.2: BK is the buffer length. The example loads BK03
 * with 3 for a 3-word buffer and wraps index 2 back to 0. ARn is
 * the index (MOV #0,AR3 then *AR3); XARn[22:16] stay the page.
 * Length 0 is not a buffer. _SRC_TII_asmDoubleStageConvert ORs
 * ST2 #0x0138 (AR3LC|AR4LC|AR5LC) and loads BK47 with the delay
 * length. Treating that as length+1 wraps the last delay sample
 * onto BSA23, and the next AADD uses that sample as a pointer.
 */
static uint16_t circ_index(uint16_t index, int32_t delta, uint16_t bk)
{
    int32_t size = bk ? (int32_t)bk : 65536;
    int32_t v;

    v = (int32_t)index + delta;
    v %= size;
    if (v < 0) {
        v += size;
    }
    return (uint16_t)v;
}

static int ar_circular(const C55xCPU *cpu, unsigned ar)
{
    return !!(pkt_read_st2(cpu) & (C55X_ST2_AR0LC << (ar & 7)));
}

static uint16_t ar_bk(const C55xCPU *cpu, unsigned ar)
{
    /*
     * SPRU371F 6.11.3: C54CM=1 (silicon reset ST1 0x2920) sizes every
     * ARn from BK03 and does not consult BK47. AR4 ±1 wrapped when
     * BK03 was 5 and did not wrap on the BK47 value which=5 stored.
     */
    if (cpu->st1 & C55X_ST1_C54CM) {
        return cpu->bk03;
    }
    return ((ar & 7) < 4) ? cpu->bk03 : cpu->bk47;
}

static uint16_t ar_bsa(const C55xCPU *cpu, unsigned ar)
{
    switch (ar & 7) {
    case 0:
    case 1:
        return cpu->bsa01;
    case 2:
    case 3:
        return cpu->bsa23;
    case 4:
    case 5:
        return cpu->bsa45;
    default:
        return cpu->bsa67;
    }
}

static uint32_t ar_ea(const C55xCPU *cpu, unsigned ar, uint32_t xar,
                     int32_t off)
{
    uint16_t index;

    xar &= C55X_WORD_MASK;
    if (!ar_circular(cpu, ar)) {
        return xar_plus(xar, off);
    }
    index = circ_index((uint16_t)xar, off, ar_bk(cpu, ar));
    return (xar & ~0xffffu) | (uint16_t)(ar_bsa(cpu, ar) + index);
}

static void ar_modify(C55xCPU *cpu, unsigned ar, int32_t delta)
{
    uint32_t xar = cpu->xar[ar & 7] & C55X_WORD_MASK;

    if (ar_circular(cpu, ar)) {
        cpu->xar[ar & 7] = (xar & ~0xffffu) |
                           circ_index((uint16_t)xar, delta, ar_bk(cpu, ar));
        return;
    }
    cpu->xar[ar & 7] = xar_plus(xar, delta);
}

static int cdp_circular(const C55xCPU *cpu)
{
    return !!(pkt_read_st2(cpu) & C55X_ST2_CDPLC);
}

static uint32_t cdp_ea(const C55xCPU *cpu, uint32_t xcdp, int32_t off)
{
    uint16_t index;

    xcdp &= C55X_WORD_MASK;
    if (!cdp_circular(cpu)) {
        return xar_plus(xcdp, off);
    }
    index = circ_index((uint16_t)xcdp, off, cpu->bkc);
    return (xcdp & ~0xffffu) | (uint16_t)(cpu->bsac + index);
}

static void cdp_modify(C55xCPU *cpu, int32_t delta)
{
    uint32_t xcdp = cpu->xcdp & C55X_WORD_MASK;

    if (cdp_circular(cpu)) {
        cpu->xcdp = (xcdp & ~0xffffu) |
                    circ_index((uint16_t)xcdp, delta, cpu->bkc);
        return;
    }
    cpu->xcdp = xar_plus(xcdp, delta);
}

static void tax_add_imm(C55xCPU *cpu, unsigned dst, int32_t delta)
{
    unsigned fsss = dst & 15;

    if (fsss >= 8 && ar_circular(cpu, fsss - 8)) {
        unsigned ar = fsss - 8;
        uint16_t idx = circ_index((uint16_t)c55x_get_reg(cpu, fsss),
                                  delta, ar_bk(cpu, ar));

        c55x_set_reg(cpu, fsss, idx);
        return;
    }
    c55x_set_reg(cpu, fsss, (uint16_t)(c55x_get_reg(cpu, fsss) + delta));
}

static uint64_t pkt_read_ac(const C55xCPU *cpu, unsigned n)
{
    n &= 3;
    return (cpu->pkt_src_valid ? cpu->pkt_ac[n] : cpu->ac[n]) & C55X_AC_MASK;
}

static uint16_t pkt_read_t(const C55xCPU *cpu, unsigned n)
{
    n &= 3;
    return cpu->pkt_src_valid ? cpu->pkt_t[n] : cpu->t[n];
}

static uint32_t pkt_read_xar(const C55xCPU *cpu, unsigned n)
{
    n &= 7;
    return (cpu->pkt_src_valid ? cpu->pkt_xar[n] : cpu->xar[n]) &
           C55X_WORD_MASK;
}

/*
 * SPRU371F 6.5.3.6 and 6.5.3.8: C54CM=0 uses T0, C54CM=1 uses AR0.
 * Post-modify adds that value after the access. Indexed *(ARn±T0)
 * uses it only as the offset and does not write ARn.
 */
static int16_t smem_t0_step(const C55xCPU *cpu)
{
    if (cpu->st1 & C55X_ST1_C54CM) {
        return (int16_t)pkt_read_xar(cpu, 0);
    }
    return (int16_t)pkt_read_t(cpu, 0);
}

static uint32_t pkt_read_xsp(const C55xCPU *cpu)
{
    return (cpu->pkt_src_valid ? cpu->pkt_xsp : cpu->xsp) & C55X_WORD_MASK;
}

static uint32_t pkt_read_xdp(const C55xCPU *cpu)
{
    return (cpu->pkt_src_valid ? cpu->pkt_xdp : cpu->xdp) & C55X_WORD_MASK;
}

static uint32_t pkt_read_xcdp(const C55xCPU *cpu)
{
    return (cpu->pkt_src_valid ? cpu->pkt_xcdp : cpu->xcdp) & C55X_WORD_MASK;
}

static uint16_t pkt_read_st0(const C55xCPU *cpu)
{
    return cpu->pkt_src_valid ? cpu->pkt_st0 : cpu->st0;
}

static uint16_t pkt_read_st2(const C55xCPU *cpu)
{
    return cpu->pkt_src_valid ? cpu->pkt_st2 : cpu->st2;
}

static void pkt_begin(C55xCPU *cpu, int parallel)
{
    unsigned i;

    cpu->pkt_src_valid = 0;
    cpu->pkt_wr_n = 0;
    if (!parallel) {
        return;
    }
    for (i = 0; i < 4; i++) {
        cpu->pkt_ac[i] = cpu->ac[i];
        cpu->pkt_t[i] = cpu->t[i];
    }
    for (i = 0; i < 8; i++) {
        cpu->pkt_xar[i] = cpu->xar[i];
    }
    cpu->pkt_xsp = cpu->xsp;
    cpu->pkt_xssp = cpu->xssp;
    cpu->pkt_xdp = cpu->xdp;
    cpu->pkt_xcdp = cpu->xcdp;
    cpu->pkt_st0 = cpu->st0;
    cpu->pkt_st2 = cpu->st2;
    cpu->pkt_csr = cpu->csr;
    cpu->pkt_src_valid = 1;
}

static void pkt_abort(C55xCPU *cpu)
{
    cpu->pkt_wr_n = 0;
    cpu->pkt_src_valid = 0;
}

static int data_word_is_ram(uint32_t word)
{
    word &= C55X_WORD_MASK;
    /*
     * DEV_Fxns lives in DARAM/SARAM / loaded-task data. Never peek
     * IVA MMIO: mailbox FIFO reads are destructive, and a
     * peek-before-write on _mbx_send pops the reply.
     */
    if (word >= 0x7e0000u && word <= 0x7fffffu) {
        return 0;
    }
    return 1;
}

/*
 * pcm1 write-handler (avs 0x124c5c). libesd dsp_init writes cmd 8 and
 * treats ARM +10 as the stream type (*0x9cf34 at *AR6(short(#5))).
 * Stock cinit copies *0x9cf34=4, so cmd 8 reports type 4 and ARM
 * writes cmd 1 then blocking read(10). The cmd-1 fill at 0x125c6a
 * _bksnds 10 bytes (T1=5) with *AR6(1)=1; libesd then MAP_SHARED
 * mmaps pcm1 (len=0x2000). 0x125ca0 is CALL #_bksnd || MOV T2,T0 —
 * restore T0 from T2 before the callee. No FIFO1 POLL.
 */
#define PCM1_WORD_MODE       0x09cf34u
#define PCM1_PC_MODE4        0x125346u
#define PCM1_PC_CMD1_STAT    0x124d60u
#define PCM1_PC_CMD1_B       0x124d63u
#define PCM1_PC_CMD1_SEND10  0x125c9bu
#define PCM1_PC_BKSND_SYNC   0x1266b3u
#define PCM1_BID_NULL        0xffffu

static int pcm1_cmd_at_ar6(C55xCPU *cpu)
{
    return (int)peek16(cpu, cpu->xar[6] & C55X_WORD_MASK);
}

static int pcm1_filter_store(C55xCPU *cpu, uint32_t word, uint16_t *value)
{
    uint32_t pc = cpu->pc & C55X_PC_MASK;

    word &= C55X_WORD_MASK;
    if (pc == PCM1_PC_MODE4 && word == PCM1_WORD_MODE && *value == 4) {
        eap_pcm_stat("pcm1-mode4-hold pc=%06x old=%04x\n",
                     pc, peek16(cpu, word));
        return 1;
    }
    if (pc == PCM1_PC_CMD1_STAT && *value == 2 &&
        pcm1_cmd_at_ar6(cpu) == 1) {
        *value = 1;
        eap_pcm_stat("pcm1-cmd1-status1 pc=%06x AR6=%06x\n",
                     pc, cpu->xar[6] & C55X_WORD_MASK);
    }
    /*
     * A2: _bksnd is Gateway BKSND (CMD_H=0x20), not WDSND (0x10).
     * Fig 2-7 header is count, IPBLINK, ARM lock/sync, DSP lock/sync.
     * Stock 0x1266b3 writes DSP sync (word 5) = tid and count at
     * word 0, but leaves IPBLINK (word 1) as leftover. ARM's read
     * chain follows that next-BID; leftover != 0xffff made cmd2
     * read(4) wait (line[1]=1 blocked, 20260921T113801Z). Terminate
     * the link and plant DSP lock = tid. Do not rewrite @0x6 to T0,
     * copy AR6 into the header, rewrite *line T1=2 to 4, or store
     * into node 09fd76.
     */
    if (pc == PCM1_PC_BKSND_SYNC && cpu->bus.write16 && *value == 2) {
        uint32_t line = (word - 5u) & C55X_WORD_MASK;
        uint16_t tid = *value;

        uint32_t pay = (line + 6u) & C55X_WORD_MASK;
        uint16_t cmd = peek16(cpu, pay);
        uint16_t st = peek16(cpu, (pay + 1u) & C55X_WORD_MASK);

        cpu->bus.write16(cpu->bus.opaque,
                         (line + 1u) & C55X_WORD_MASK, PCM1_BID_NULL);
        cpu->bus.write16(cpu->bus.opaque,
                         (line + 4u) & C55X_WORD_MASK, tid);
        /*
         * A3: libesd checks the halfword at the read buffer +2.
         * _bksnd can clobber that payload word after the call-site
         * snapshot. Put status 1 back before the mailbox send.
         * Do not rewrite BKSND @0x6, *line, or node 09fd76.
         */
        if ((cmd == 1u || cmd == 2u || cmd == 7u || cmd == 13u) &&
            st != 1u) {
            cpu->bus.write16(cpu->bus.opaque,
                             (pay + 1u) & C55X_WORD_MASK, 1);
            eap_pcm_stat("pcm1-bksnd-status1 line=%06x cmd=%04x "
                         "%04x->0001\n",
                         line, cmd, st);
            st = 1;
        }
        eap_pcm_stat("pcm1-bksnd-hdr line=%06x link=ffff lock=%04x "
                     "sync=%04x cnt=%04x cmd=%04x st=%04x\n",
                     line, tid, tid, peek16(cpu, line), cmd, st);
    }
    return 0;
}

static int pkt_commit(C55xCPU *cpu)
{
    unsigned i;
    int rc = 0;

    if (cpu->pkt_src_valid && cpu->bus.write16) {
        for (i = 0; i < cpu->pkt_wr_n; i++) {
            uint32_t word = cpu->pkt_wr_word[i];
            uint16_t value = cpu->pkt_wr_value[i];
            uint16_t old = 0;
            int watch = data_word_is_ram(word);

            if (watch && cpu->bus.read16) {
                cpu->bus.read16(cpu->bus.opaque, word, &old);
            }
            if (cpu->bus.write16(cpu->bus.opaque, word, value)) {
                rc = -1;
            } else if (watch) {
                note_dev_store(cpu, word, old, value);
                if ((word & C55X_WORD_MASK) == 0x66bau &&
                    (cpu->pc & C55X_PC_MASK) >= 0x134af3u &&
                    (cpu->pc & C55X_PC_MASK) <= 0x134fdcu) {
                    c55x_log(cpu,
                             "MUMDRC-T2SLOT-WR pc=%06x word=%06x old=%04x "
                             "new=%04x XAR2=%06x T0=%04x T1=%04x "
                             "ST2=%04x BSA23=%04x BK03=%04x "
                             "XSP=%06x pkt=1 insn=%llu\n",
                             cpu->pc & C55X_PC_MASK, word & C55X_WORD_MASK,
                             old, value,
                             cpu->xar[2] & C55X_WORD_MASK, cpu->t[0],
                             cpu->t[1], cpu->st2, cpu->bsa23, cpu->bk03,
                             cpu->xsp & C55X_WORD_MASK,
                             (unsigned long long)cpu->insn_count);
                }
            } else if (eapq_flow) {
                eapq_note_mmio(cpu, word, value);
            }
        }
    }
    pkt_abort(cpu);
    return rc;
}

/* One IODMA block: who writes 0007 into the CSSA ping-pong. */
static int data_write16(C55xCPU *cpu, uint32_t word, uint16_t value)
{
    uint16_t old = 0;
    int watch;

    if (pcm1_filter_store(cpu, word, &value)) {
        return 0;
    }
    if (cpu->pkt_src_valid) {
        if (cpu->pkt_wr_n >= 8) {
            return -1;
        }
        cpu->pkt_wr_word[cpu->pkt_wr_n] = word;
        cpu->pkt_wr_value[cpu->pkt_wr_n] = value;
        cpu->pkt_wr_n++;
        return 0;
    }
    if (!cpu->bus.write16) {
        return -1;
    }
    watch = data_word_is_ram(word);
    if (watch && cpu->bus.read16) {
        cpu->bus.read16(cpu->bus.opaque, word, &old);
    }
    if (cpu->bus.write16(cpu->bus.opaque, word, value)) {
        return -1;
    }
    if (watch) {
        note_dev_store(cpu, word, old, value);
        if (src_budget_word &&
            (word & C55X_WORD_MASK) == src_budget_word && old != value) {
            static unsigned budget_logs;

            if (budget_logs < 24u) {
                eap_pcm_stat("t=budg pc=%06x %04x->%04x\n",
                             cpu->pc & C55X_PC_MASK, old, value);
                budget_logs++;
            }
        }
        /* First loud sample written into the mix buffer the audible
         * SRC reads (word 0x5d2). Early 0x00e8 fills are the soft
         * clipper's first bin and are not the tune. */
        if (((word & C55X_WORD_MASK) == 0xf03bu ||
             (word & C55X_WORD_MASK) == 0xf05du ||
             (word & C55X_WORD_MASK) == 0xf0a1u) && old != value) {
            static unsigned slot_logs;

            if (slot_logs < 16u) {
                eap_pcm_stat("t=slot pc=%06x w=%06x %04x->%04x\n",
                             cpu->pc & C55X_PC_MASK, word & C55X_WORD_MASK,
                             old, value);
                slot_logs++;
            }
        }
        if ((word & C55X_WORD_MASK) >= 0x218000u &&
            (word & C55X_WORD_MASK) < 0x218040u && value != 0) {
            static unsigned zstuff_logs;

            if (zstuff_logs < 8u) {
                eap_pcm_stat("t=zstuf pc=%06x w=%06x %04x->%04x\n",
                             cpu->pc & C55X_PC_MASK, word & C55X_WORD_MASK,
                             old, value);
                zstuff_logs++;
            }
        }
        if ((word & C55X_WORD_MASK) == 0x5d2u && old != value &&
            abs((int16_t)value) >= 1000) {
            static unsigned scratch_logs;

            if ((cpu->pc & C55X_PC_MASK) == 0x133139u) {
                mix_slot_hot = 1;
            }
            if (scratch_logs < 6u) {
                eap_pcm_stat(
                    "t=scratch pc=%06x %04x->%04x ac0=%010llx "
                    "xar0=%06x xar1=%06x xar2=%06x xar3=%06x t0=%04x t1=%04x\n",
                    cpu->pc & C55X_PC_MASK, old, value,
                    (unsigned long long)(cpu->ac[0] & C55X_AC_MASK),
                    cpu->xar[0] & C55X_WORD_MASK,
                    cpu->xar[1] & C55X_WORD_MASK,
                    cpu->xar[2] & C55X_WORD_MASK,
                    cpu->xar[3] & C55X_WORD_MASK,
                    cpu->t[0], cpu->t[1]);
                scratch_logs++;
            }
        }
        /* Who clears the mix slot after the loud sample lands. */
        if ((word & C55X_WORD_MASK) == 0x5d2u &&
            abs((int16_t)old) >= 1000 && abs((int16_t)value) < 100) {
            static unsigned clear_logs;

            if (clear_logs < 6u) {
                eap_pcm_stat("t=clr pc=%06x %04x->%04x\n",
                             cpu->pc & C55X_PC_MASK, old, value);
                clear_logs++;
            }
        }
        if ((word & C55X_WORD_MASK) == 0x66bau &&
            (cpu->pc & C55X_PC_MASK) >= 0x134af3u &&
            (cpu->pc & C55X_PC_MASK) <= 0x134fdcu) {
            c55x_log(cpu,
                     "MUMDRC-T2SLOT-WR pc=%06x word=%06x old=%04x "
                     "new=%04x XAR2=%06x T0=%04x T1=%04x "
                     "ST2=%04x BSA23=%04x BK03=%04x "
                     "XSP=%06x insn=%llu\n",
                     cpu->pc & C55X_PC_MASK, word & C55X_WORD_MASK, old,
                     value, cpu->xar[2] & C55X_WORD_MASK, cpu->t[0],
                     cpu->t[1], cpu->st2, cpu->bsa23, cpu->bk03,
                     cpu->xsp & C55X_WORD_MASK,
                     (unsigned long long)cpu->insn_count);
        }
    } else if (eapq_flow) {
        eapq_note_mmio(cpu, word, value);
    }
    return 0;
}

static void smem_alias_mmr(uint32_t word, int is_io, int *is_mmr)
{
    if (is_io || *is_mmr) {
        return;
    }
    if ((word & C55X_WORD_MASK) < C55X_MMR_WORDS) {
        *is_mmr = 1;
    }
}

static int resolve_smem(C55xCPU *cpu, const C55xSmem *sm, int mmap, int port,
                        uint32_t *word_out, int *is_mmr, int *is_io,
                        uint16_t *io_port, int32_t *post)
{
    uint32_t addr;

    *is_mmr = 0;
    *is_io = port;
    *io_port = 0;
    *post = 0;

    switch (sm->kind) {
    case C55X_AM_DIRECT:
        if (mmap) {
            *is_mmr = 1;
            *word_out = (uint32_t)sm->off & 0x7f;
            return 0;
        }
        if (cpu->st1 & C55X_ST1_CPL) {
            addr = xar_plus(pkt_read_xsp(cpu), sm->off);
        } else {
            addr = ((pkt_read_xdp(cpu) + (uint32_t)sm->off) & C55X_WORD_MASK);
        }
        *word_out = addr;
        smem_alias_mmr(*word_out, *is_io, is_mmr);
        return 0;
    case C55X_AM_ABS16:
        addr = ((pkt_read_xdp(cpu) & ~0xffffu) | (sm->abs & 0xffffu)) &
               C55X_WORD_MASK;
        if (mmap) {
            *is_mmr = 1;
            *word_out = sm->abs & 0x7f;
            return 0;
        }
        *word_out = addr;
        smem_alias_mmr(*word_out, *is_io, is_mmr);
        return 0;
    case C55X_AM_ABS23:
        if (mmap) {
            *is_mmr = 1;
            *word_out = sm->abs & 0x7f;
            return 0;
        }
        *word_out = sm->abs & C55X_WORD_MASK;
        smem_alias_mmr(*word_out, *is_io, is_mmr);
        return 0;
    case C55X_AM_PORT16:
        *is_io = 1;
        *io_port = (uint16_t)sm->abs;
        *word_out = sm->abs;
        return 0;
    case C55X_AM_CDP: {
        uint32_t xcdp = pkt_read_xcdp(cpu);
        int32_t access_off = 0;
        int pre = 0;

        if (sm->mod == C55X_MOD_K16 || sm->mod == C55X_MOD_INDEX_T0 ||
            sm->mod == C55X_MOD_INDEX_T1) {
            access_off = sm->off;
        } else if (sm->mod == C55X_MOD_PRE_K16) {
            pre = 1;
            access_off = sm->off;
        } else if (sm->mod == C55X_MOD_PLUS_T0) {
            access_off = (int16_t)pkt_read_t(cpu, 0);
        } else if (sm->mod == C55X_MOD_POSTINC) {
            *post = 1;
        } else if (sm->mod == C55X_MOD_POSTDEC) {
            *post = -1;
        }
        if (pre) {
            cdp_modify(cpu, access_off);
            xcdp = cpu->xcdp;
            access_off = 0;
        }
        addr = cdp_ea(cpu, xcdp, access_off);
        if (mmap) {
            *is_mmr = 1;
        }
        *word_out = addr;
        smem_alias_mmr(*word_out, *is_io, is_mmr);
        return 0;
    }
    case C55X_AM_AR: {
        uint32_t xar = pkt_read_xar(cpu, sm->ar);
        int32_t access_off = 0;
        int pre = 0;

        /*
         * SPRU374G table 6-2: PPP1 operands are mode-dependent.  In
         * control mode (ST2_55.ARMS=1), 0x13..0x1f select compact
         * positive offsets #1..#7 and do not modify ARn.
         */
        if ((pkt_read_st2(cpu) & C55X_ST2_ARMS) &&
            (sm->field & 0x10) && (sm->field & 1)) {
            access_off = ((sm->field & 0x0e) >> 1);
        } else {
            switch (sm->mod) {
            case C55X_MOD_PREINC:
                pre = 1;
                access_off = 1;
                break;
            case C55X_MOD_PREDEC:
                pre = 1;
                access_off = -1;
                break;
            case C55X_MOD_PRE_K16:
                pre = 1;
                access_off = sm->off;
                break;
            case C55X_MOD_K16:
            case C55X_MOD_INDEX_T0:
                access_off = (sm->mod == C55X_MOD_INDEX_T0) ?
                             smem_t0_step(cpu) : sm->off;
                break;
            case C55X_MOD_INDEX_T1:
                access_off = (int16_t)pkt_read_t(cpu, 1);
                break;
            case C55X_MOD_ARMS_T1:
                if (pkt_read_st2(cpu) & C55X_ST2_ARMS) {
                    access_off = 1;
                } else {
                    *post = (int16_t)pkt_read_t(cpu, 1);
                }
                break;
            case C55X_MOD_INDEX_MINUS_T0:
                access_off = (int16_t)-smem_t0_step(cpu);
                break;
            case C55X_MOD_INDEX_MINUS_T1:
                access_off = -(int16_t)pkt_read_t(cpu, 1);
                break;
            case C55X_MOD_POSTINC:
                *post = 1;
                break;
            case C55X_MOD_POSTDEC:
                *post = -1;
                break;
            case C55X_MOD_PLUS_T0:
                *post = smem_t0_step(cpu);
                break;
            case C55X_MOD_MINUS_T0:
                *post = (int16_t)-smem_t0_step(cpu);
                break;
            case C55X_MOD_PLUS_T1:
                /*
                 * SPRU374 table 6-2 DSP mode (ARMS=0): *ARn+T1 posts
                 * ARn by T1 after the access. Control mode (ARMS=1)
                 * already remapped this field to *ARn(short(#1))
                 * above. Forcing +1 here left SRC's
                 * 8b534c1270 / bc53 store (BCLR ARMS) writing AR2+1
                 * every sample without walking the PCM pointer.
                 * 8e||eb Ymem uses C55X_MOD_ARMS_T1, not this case.
                 */
                *post = (int16_t)pkt_read_t(cpu, 1);
                break;
            case C55X_MOD_MINUS_T1:
                *post = -(int16_t)pkt_read_t(cpu, 1);
                break;
            default:
                break;
            }
        }
        if (pre) {
            ar_modify(cpu, sm->ar, access_off);
            xar = cpu->xar[sm->ar & 7];
            access_off = 0;
        }
        addr = ar_ea(cpu, sm->ar, xar, access_off);
        if (mmap) {
            *is_mmr = 1;
            *word_out = addr & 0x7f;
            return 0;
        }
        if (port) {
            *is_io = 1;
            *io_port = (uint16_t)addr;
        }
        *word_out = addr;
        smem_alias_mmr(*word_out, *is_io, is_mmr);
        return 0;
    }
    default:
        return -1;
    }
}

static uint32_t dual_ar_addr(const C55xCPU *cpu, const C55xSmem *sm)
{
    int32_t idx = 0;

    switch (sm->mod) {
    case C55X_MOD_INDEX_T0:
        idx = smem_t0_step(cpu);
        break;
    case C55X_MOD_INDEX_T1:
        idx = (int16_t)pkt_read_t(cpu, 1);
        break;
    case C55X_MOD_INDEX_MINUS_T0:
        idx = (int16_t)-smem_t0_step(cpu);
        break;
    case C55X_MOD_INDEX_MINUS_T1:
        idx = -(int16_t)pkt_read_t(cpu, 1);
        break;
    default:
        break;
    }
    return ar_ea(cpu, sm->ar, pkt_read_xar(cpu, sm->ar), idx);
}

static void dual_ar_commit(C55xCPU *cpu, const C55xSmem *sm, int32_t step)
{
    int32_t delta;

    switch (sm->mod) {
    case C55X_MOD_POSTINC:
        delta = step;
        break;
    case C55X_MOD_POSTDEC:
        delta = -step;
        break;
    case C55X_MOD_PLUS_T0:
        delta = smem_t0_step(cpu);
        break;
    case C55X_MOD_MINUS_T0:
        delta = (int16_t)-smem_t0_step(cpu);
        break;
    case C55X_MOD_PLUS_T1:
        delta = (int16_t)pkt_read_t(cpu, 1);
        break;
    case C55X_MOD_MINUS_T1:
        delta = -(int16_t)pkt_read_t(cpu, 1);
        break;
    default:
        return;
    }
    ar_modify(cpu, sm->ar, delta);
}

static void apply_post(C55xCPU *cpu, const C55xSmem *sm, int32_t post, int dbl)
{
    if (!post) {
        return;
    }
    /*
     * SPRU371 Table 6-4 / 6-6: *ARn+ / *ARn- (and *CDP±) step by the
     * access size — +1 word or +2 for dbl/Lmem.  *(ARn±Tx) always
     * adjusts by Tx itself; do not scale Tx by the access size.
     */
    if (dbl && (sm->mod == C55X_MOD_POSTINC || sm->mod == C55X_MOD_POSTDEC)) {
        post *= 2;
    }
    if (sm->kind == C55X_AM_CDP) {
        cdp_modify(cpu, post);
        return;
    }
    if (sm->kind == C55X_AM_AR) {
        ar_modify(cpu, sm->ar, post);
    }
}

/* SPRU374 §2.4 / Table 5–2: Cmem EA is CDP plus the 2-bit mm modifier. */
static void cmem_from_mm(C55xSmem *cmem, unsigned mm)
{
    memset(cmem, 0, sizeof(*cmem));
    cmem->kind = C55X_AM_CDP;
    if ((mm & 3) == 1) {
        cmem->mod = C55X_MOD_POSTINC;
    } else if ((mm & 3) == 2) {
        cmem->mod = C55X_MOD_POSTDEC;
    } else if ((mm & 3) == 3) {
        cmem->mod = C55X_MOD_PLUS_T0;
    }
}

static int smem_read16(C55xCPU *cpu, const C55xSmem *sm, int mmap, int port,
                       uint16_t *out, int dbl)
{
    uint32_t word;
    int is_mmr, is_io;
    uint16_t io_port;
    int32_t post;

    if (resolve_smem(cpu, sm, mmap, port, &word, &is_mmr, &is_io, &io_port,
                     &post)) {
        return -1;
    }
    if (is_mmr) {
        *out = c55x_mmr_read(cpu, word);
    } else if (is_io) {
        if (!cpu->bus.io_read ||
            cpu->bus.io_read(cpu->bus.opaque, io_port, out)) {
            return -1;
        }
    } else if (!cpu->bus.read16 ||
               cpu->bus.read16(cpu->bus.opaque, word, out)) {
        return -1;
    }
    apply_post(cpu, sm, post, dbl);
    return 0;
}

static int smem_write16(C55xCPU *cpu, const C55xSmem *sm, int mmap, int port,
                        uint16_t value, int dbl)
{
    uint32_t word;
    int is_mmr, is_io;
    uint16_t io_port;
    int32_t post;

    if (resolve_smem(cpu, sm, mmap, port, &word, &is_mmr, &is_io, &io_port,
                     &post)) {
        return -1;
    }
    if (is_mmr) {
        c55x_mmr_write(cpu, word, value);
    } else if (is_io) {
        if (!cpu->bus.io_write ||
            cpu->bus.io_write(cpu->bus.opaque, io_port, value)) {
            return -1;
        }
    } else if (data_write16(cpu, word, value)) {
        return -1;
    }
    apply_post(cpu, sm, post, dbl);
    return 0;
}

static void lmem_pair(uint32_t addr, uint32_t *even, uint32_t *odd)
{
    /* RETA only: even word is always the lower address. */
    if (addr & 1u) {
        *odd = addr;
        *even = addr ^ 1u;
    } else {
        *even = addr;
        *odd = addr ^ 1u;
    }
}

/*
 * SPRU374 dbl(Lmem) for AC / XAR / register-pair / MOV dbl XY:
 * MSW is at the addressed word; LSW is at the pair (A ^ 1).
 * even A: [A]=MSW, [A+1]=LSW
 * odd  A: [A]=MSW, [A-1]=LSW
 */
static void lmem_dbl_pair(uint32_t addr, uint32_t *msw_addr, uint32_t *lsw_addr)
{
    *msw_addr = addr;
    *lsw_addr = addr ^ 1u;
}

static void lmem_note(C55xCPU *cpu, uint32_t word, uint16_t msw, uint16_t lsw)
{
    cpu->lmem_word = word;
    cpu->lmem_msw = msw;
    cpu->lmem_lsw = lsw;
    if (word & 1u) {
        cpu->lmem_even = lsw;
        cpu->lmem_odd = msw;
    } else {
        cpu->lmem_even = msw;
        cpu->lmem_odd = lsw;
    }
}

static uint64_t ac_from_lmem32(const C55xCPU *cpu, uint32_t longword)
{
    if (cpu->st1 & C55X_ST1_SXMD) {
        return (uint64_t)(int64_t)(int32_t)longword & C55X_AC_MASK;
    }
    return (uint64_t)longword;
}

static uint16_t acov_mask(unsigned ac)
{
    switch (ac & 3u) {
    case 0:
        return C55X_ST0_ACOV0;
    case 1:
        return C55X_ST0_ACOV1;
    case 2:
        return C55X_ST0_ACOV2;
    default:
        return C55X_ST0_ACOV3;
    }
}

/* SPRU374 D-unit ADD/SUB: M40 selects 32/40-bit CARRY, ACOV, SATD. */
static uint64_t alu40(C55xCPU *cpu, uint64_t a, uint64_t b, int sub,
                      unsigned dst)
{
    int m40 = (cpu->st1 & (C55X_ST1_M40 | C55X_ST1_C54CM)) != 0;
    unsigned signbit = m40 ? 39u : 31u;
    uint64_t width_mask = m40 ? C55X_AC_MASK : 0xffffffffull;
    uint64_t aa = a & C55X_AC_MASK;
    uint64_t bb = b & C55X_AC_MASK;
    uint64_t a_w = aa & width_mask;
    uint64_t b_w = bb & width_mask;
    uint64_t rhs = sub ? ((~bb + 1ull) & 0x1ffffffffffull) : bb;
    uint64_t sum = aa + rhs;
    uint64_t result = sum & C55X_AC_MASK;
    unsigned as = (unsigned)((aa >> signbit) & 1u);
    unsigned rs = (unsigned)((sum >> signbit) & 1u);
    unsigned bs = (unsigned)((rhs >> signbit) & 1u);
    int ov = (as == bs) && (rs != as);

    if (sub) {
        if (a_w >= b_w) {
            cpu->st0 |= C55X_ST0_CARRY;
        } else {
            cpu->st0 &= (uint16_t)~C55X_ST0_CARRY;
        }
    } else if (a_w + b_w > width_mask) {
        cpu->st0 |= C55X_ST0_CARRY;
    } else {
        cpu->st0 &= (uint16_t)~C55X_ST0_CARRY;
    }
    if (ov) {
        cpu->st0 |= acov_mask(dst);
        if (cpu->st1 & C55X_ST1_SATD) {
            if (!as) {
                result = (1ull << signbit) - 1ull;
            } else if (m40) {
                result = 1ull << signbit;
            } else {
                result = 0xff80000000ull;
            }
            result &= C55X_AC_MASK;
        }
    }
    return c55x_ac_store(cpu, result);
}

static uint64_t mpy16(C55xCPU *cpu, int16_t a, int16_t b, int rnd)
{
    int64_t prod = (int64_t)a * (int64_t)b;

    if (cpu->st1 & C55X_ST1_FRCT) {
        prod <<= 1;
    }
    if (rnd) {
        prod += 0x8000;
    }
    return (uint64_t)prod & C55X_AC_MASK;
}

static int16_t ac_hi(const C55xCPU *cpu, unsigned ac)
{
    return (int16_t)((pkt_read_ac(cpu, ac) >> 16) & 0xffffu);
}

static int lmem_read_words(C55xCPU *cpu, uint32_t even, uint32_t odd,
                           int is_mmr, int is_io, uint16_t *hi, uint16_t *lo)
{
    if (is_mmr) {
        *hi = c55x_mmr_read(cpu, even);
        *lo = c55x_mmr_read(cpu, odd);
        return 0;
    }
    if (is_io) {
        if (!cpu->bus.io_read ||
            cpu->bus.io_read(cpu->bus.opaque, (uint16_t)even, hi) ||
            cpu->bus.io_read(cpu->bus.opaque, (uint16_t)odd, lo)) {
            return -1;
        }
        return 0;
    }
    if (!cpu->bus.read16 ||
        cpu->bus.read16(cpu->bus.opaque, even, hi) ||
        cpu->bus.read16(cpu->bus.opaque, odd, lo)) {
        return -1;
    }
    return 0;
}

static int lmem_write_words(C55xCPU *cpu, uint32_t even, uint32_t odd,
                            int is_mmr, int is_io, uint16_t hi, uint16_t lo)
{
    if (is_mmr) {
        c55x_mmr_write(cpu, even, hi);
        c55x_mmr_write(cpu, odd, lo);
        return 0;
    }
    if (is_io) {
        if (!cpu->bus.io_write ||
            cpu->bus.io_write(cpu->bus.opaque, (uint16_t)even, hi) ||
            cpu->bus.io_write(cpu->bus.opaque, (uint16_t)odd, lo)) {
            return -1;
        }
        return 0;
    }
    if (data_write16(cpu, even, hi) || data_write16(cpu, odd, lo)) {
        return -1;
    }
    return 0;
}

/*
 * SPRU374 MOV RETA / dbl(Lmem): even word is (CFCT << 8) | RETA[23:16],
 * odd word is RETA[15:0]. mmap(@ACnL) is that MMR pair (ACnL/ACnH),
 * not the logical accumulator: _KNL_start plants KNL_glue as
 * AC0L=0x0010, AC0H=0x2db1 so RETA restores to 0x102db1.
 */
static int c55x_read_lmem32(C55xCPU *cpu, const C55xSmem *sm, int mmap,
                            int port, uint32_t *out)
{
    uint32_t word, even, odd;
    uint16_t hi = 0, lo = 0;
    int is_mmr, is_io;
    uint16_t io_port;
    int32_t post;

    if (resolve_smem(cpu, sm, mmap, port, &word, &is_mmr, &is_io, &io_port,
                     &post)) {
        return -1;
    }
    lmem_pair(word, &even, &odd);
    if (lmem_read_words(cpu, even, odd, is_mmr, is_io, &hi, &lo)) {
        return -1;
    }
    *out = ((uint32_t)hi << 16) | lo;
    apply_post(cpu, sm, post, 1);
    return 0;
}

static int c55x_write_lmem32(C55xCPU *cpu, const C55xSmem *sm, int mmap,
                             int port, uint32_t value)
{
    uint32_t word, even, odd;
    int is_mmr, is_io;
    uint16_t io_port;
    int32_t post;

    if (resolve_smem(cpu, sm, mmap, port, &word, &is_mmr, &is_io, &io_port,
                     &post)) {
        return -1;
    }
    lmem_pair(word, &even, &odd);
    if (lmem_write_words(cpu, even, odd, is_mmr, is_io,
                         (uint16_t)(value >> 16), (uint16_t)value)) {
        return -1;
    }
    apply_post(cpu, sm, post, 1);
    return 0;
}

static int lmem_read_long(C55xCPU *cpu, const C55xSmem *sm, int mmap, int port,
                          uint32_t *longword)
{
    uint32_t word, msw_a, lsw_a;
    uint16_t msw = 0, lsw = 0;
    int is_mmr, is_io;
    uint16_t io_port;
    int32_t post;

    if (resolve_smem(cpu, sm, mmap, port, &word, &is_mmr, &is_io, &io_port,
                     &post)) {
        return -1;
    }
    lmem_dbl_pair(word, &msw_a, &lsw_a);
    if (lmem_read_words(cpu, msw_a, lsw_a, is_mmr, is_io, &msw, &lsw)) {
        return -1;
    }
    *longword = ((uint32_t)msw << 16) | lsw;
    lmem_note(cpu, word, msw, lsw);
    apply_post(cpu, sm, post, 1);
    return 0;
}

static int lmem_write_long(C55xCPU *cpu, const C55xSmem *sm, int mmap, int port,
                           uint32_t value)
{
    uint32_t word, msw_a, lsw_a;
    uint16_t msw = (uint16_t)(value >> 16);
    uint16_t lsw = (uint16_t)value;
    int is_mmr, is_io;
    uint16_t io_port;
    int32_t post;

    if (resolve_smem(cpu, sm, mmap, port, &word, &is_mmr, &is_io, &io_port,
                     &post)) {
        return -1;
    }
    lmem_dbl_pair(word, &msw_a, &lsw_a);
    lmem_note(cpu, word, msw, lsw);
    if (lmem_write_words(cpu, msw_a, lsw_a, is_mmr, is_io, msw, lsw)) {
        return -1;
    }
    apply_post(cpu, sm, post, 1);
    return 0;
}

/* SPRU374: XAR = low 7 bits of MSW << 16 | LSW. */
static int lmem_read_xaddr(C55xCPU *cpu, const C55xSmem *sm, int mmap,
                           int port, uint32_t *out)
{
    uint32_t longword;

    if (lmem_read_long(cpu, sm, mmap, port, &longword)) {
        return -1;
    }
    *out = (((uint32_t)(cpu->lmem_msw & 0x7f) << 16) | cpu->lmem_lsw) &
           C55X_WORD_MASK;
    return 0;
}

static void push16(C55xCPU *cpu, uint16_t value)
{
    cpu->xsp = xar_plus(cpu->xsp, -1);
    cpu->sp_written = 1;
    data_write16(cpu, cpu->xsp & C55X_WORD_MASK, value);
}

static uint16_t pop16(C55xCPU *cpu)
{
    uint16_t value = 0;

    if (cpu->bus.read16) {
        cpu->bus.read16(cpu->bus.opaque, cpu->xsp & C55X_WORD_MASK, &value);
    }
    cpu->xsp = xar_plus(cpu->xsp, 1);
    return value;
}

static void set_reg_low16(C55xCPU *cpu, unsigned fsss, uint16_t value)
{
    fsss &= 15;
    if (fsss < 4) {
        cpu->ac[fsss] = (pkt_read_ac(cpu, fsss) & ~0xffffull) | value;
        return;
    }
    c55x_set_reg(cpu, fsss, value);
}

static void set_tcx(C55xCPU *cpu, unsigned which, int v)
{
    uint16_t mask = which ? C55X_ST0_TC2 : C55X_ST0_TC1;

    if (v) {
        cpu->st0 |= mask;
    } else {
        cpu->st0 &= (uint16_t)~mask;
    }
}

static int get_tcx(const C55xCPU *cpu, unsigned which)
{
    return !!(pkt_read_st0(cpu) & (which ? C55X_ST0_TC2 : C55X_ST0_TC1));
}

static int relop_u64(uint64_t a, uint64_t b, unsigned cc)
{
    switch (cc & 3) {
    case 0:
        return a == b;
    case 1:
        return a < b;
    case 2:
        return a >= b;
    default:
        return a != b;
    }
}

static int relop_i64(int64_t a, int64_t b, unsigned cc)
{
    switch (cc & 3) {
    case 0:
        return a == b;
    case 1:
        return a < b;
    case 2:
        return a >= b;
    default:
        return a != b;
    }
}

/* SPRU374 4.21: BCC[U] L8, src RELOP K8. U zero-extends K8; else sign-extend. */
static int cmp_src_k8(const C55xCPU *cpu, const C55xOp *op)
{
    unsigned src = op->src & 15;
    unsigned cc = op->cond;
    int uns = op->st;
    int8_t k = (int8_t)op->imm;

    if (src < 4) {
        uint64_t a = pkt_read_ac(cpu, src);
        int m40 = (cpu->st1 & (C55X_ST1_M40 | C55X_ST1_C54CM)) != 0;
        uint64_t mask = m40 ? C55X_AC_MASK : 0xffffffffull;
        unsigned sign = m40 ? 39 : 31;

        a &= mask;
        if (uns) {
            return relop_u64(a, (uint8_t)k, cc);
        }
        {
            int64_t sa = (int64_t)a;

            if (a & (1ull << sign)) {
                sa |= (int64_t)~mask;
            }
            return relop_i64(sa, (int64_t)k, cc);
        }
    }
    if (uns) {
        return relop_u64((uint16_t)c55x_get_reg(cpu, src),
                         (uint16_t)(uint8_t)k, cc);
    }
    return relop_i64((int16_t)(uint16_t)c55x_get_reg(cpu, src),
                     (int64_t)k, cc);
}

/* SPRU374: AC vs AC is 32/40-bit; mix with TAx is 16-bit. C54CM forces 40. */
static int cmp_regs(const C55xCPU *cpu, const C55xOp *op)
{
    unsigned src = op->src & 15;
    unsigned dst = op->dst & 15;
    unsigned cc = op->cond;
    int uns = op->st;

    if (src < 4 && dst < 4) {
        uint64_t a = pkt_read_ac(cpu, src);
        uint64_t b = pkt_read_ac(cpu, dst);
        int m40 = (cpu->st1 & (C55X_ST1_M40 | C55X_ST1_C54CM)) != 0;
        uint64_t mask = m40 ? C55X_AC_MASK : 0xffffffffull;
        unsigned sign = m40 ? 39 : 31;

        a &= mask;
        b &= mask;
        if (uns) {
            return relop_u64(a, b, cc);
        }
        {
            int64_t sa = (int64_t)a;
            int64_t sb = (int64_t)b;

            if (a & (1ull << sign)) {
                sa |= (int64_t)~mask;
            }
            if (b & (1ull << sign)) {
                sb |= (int64_t)~mask;
            }
            return relop_i64(sa, sb, cc);
        }
    }
    if (uns) {
        return relop_u64((uint16_t)c55x_get_reg(cpu, src),
                         (uint16_t)c55x_get_reg(cpu, dst), cc);
    }
    return relop_i64((int16_t)(uint16_t)c55x_get_reg(cpu, src),
                     (int16_t)(uint16_t)c55x_get_reg(cpu, dst), cc);
}

static void push_ssp(C55xCPU *cpu, uint16_t value)
{
    cpu->xssp = xar_plus(cpu->xssp, -1);
    cpu->ssp_written = 1;
    data_write16(cpu, cpu->xssp & C55X_WORD_MASK, value);
}

static uint16_t pop_ssp(C55xCPU *cpu)
{
    uint16_t value = 0;

    if (cpu->bus.read16) {
        cpu->bus.read16(cpu->bus.opaque, cpu->xssp & C55X_WORD_MASK, &value);
    }
    cpu->xssp = xar_plus(cpu->xssp, 1);
    return value;
}

static uint8_t current_loop_context(const C55xCPU *cpu)
{
    if (!(cpu->rpt_active || cpu->rpt_armed)) {
        return 0;
    }
    return cpu->rpt_cc ? (uint8_t)C55X_CFCT_RPTCC : (uint8_t)C55X_CFCT_RPT;
}

static void restore_loop_context(C55xCPU *cpu, uint8_t ctx)
{
    cpu->rpt_cc = !!(ctx & C55X_CFCT_RPTCC);
    if (ctx & (C55X_CFCT_RPT | C55X_CFCT_RPTCC)) {
        cpu->rpt_active = 1;
        cpu->rpt_armed = 0;
    } else {
        cpu->rpt_active = 0;
        cpu->rpt_armed = 0;
        cpu->rpt_cc = 0;
    }
}

static void suspend_loop_context(C55xCPU *cpu)
{
    cpu->rpt_active = 0;
    cpu->rpt_armed = 0;
}

static void irq_save_rpt_count(C55xCPU *cpu)
{
    unsigned slot;

    if (cpu->irq_nest == 0 || cpu->irq_nest > 32) {
        return;
    }
    slot = cpu->irq_nest - 1u;
    if (cpu->rpt_active || cpu->rpt_armed) {
        cpu->irq_rpt_left[slot] = cpu->rpt_left;
        cpu->irq_rpt_saved |= (1u << slot);
    } else {
        cpu->irq_rpt_saved &= ~(1u << slot);
    }
}

static void irq_restore_rpt_count(C55xCPU *cpu, unsigned slot)
{
    if (slot >= 32 || !(cpu->irq_rpt_saved & (1u << slot))) {
        return;
    }
    cpu->irq_rpt_saved &= ~(1u << slot);
    if (cpu->rpt_active) {
        cpu->rpt_left = cpu->irq_rpt_left[slot];
        cpu->rptc = cpu->rpt_left;
    }
}

static int pc_in_avs_text(uint32_t pc)
{
    pc &= C55X_PC_MASK;
    if (pc >= 0x100000u && pc < 0x140000u) {
        return 1;
    }
    if (pc >= 0x027f00u && pc < 0x028000u) {
        return 1;
    }
    return 0;
}

static int pc_is_wild(uint32_t pc)
{
    pc &= C55X_PC_MASK;
    if (pc >= 0x01f000u && pc < 0x020000u) {
        return 1;
    }
    if (pc >= 0x140000u && (pc < 0x027f00u || pc >= 0x028000u)) {
        return 1;
    }
    if ((pc & 0xff0000u) >= 0x580000u || (pc & 0xff0000u) == 0xa50000u) {
        return 1;
    }
    return 0;
}

static int insn_is_ctrlflow(const C55xDecodedInsn *in)
{
    unsigned i;

    for (i = 0; i < in->op_count; i++) {
        switch (in->op[i].kind) {
        case C55X_OP_RET:
        case C55X_OP_RETI:
        case C55X_OP_RETCC:
        case C55X_OP_CALL_P24:
        case C55X_OP_CALL_AC:
        case C55X_OP_CALL_L16:
        case C55X_OP_CALLCC_L16:
        case C55X_OP_CALLCC_P24:
        case C55X_OP_B_L7:
        case C55X_OP_B_L16:
        case C55X_OP_B_P24:
        case C55X_OP_B_AC:
        case C55X_OP_BCC_L8:
        case C55X_OP_BCC_L16:
        case C55X_OP_BCC_P24:
        case C55X_OP_BCC_SRC_K8:
        case C55X_OP_BCC_ARN:
        case C55X_OP_IVEC:
            return 1;
        default:
            break;
        }
    }
    return 0;
}

static int insn_is_branch(const C55xDecodedInsn *in)
{
    unsigned i;

    for (i = 0; i < in->op_count; i++) {
        switch (in->op[i].kind) {
        case C55X_OP_B_L7:
        case C55X_OP_B_L16:
        case C55X_OP_B_P24:
        case C55X_OP_B_AC:
        case C55X_OP_BCC_L8:
        case C55X_OP_BCC_L16:
        case C55X_OP_BCC_P24:
        case C55X_OP_BCC_SRC_K8:
        case C55X_OP_BCC_ARN:
            return 1;
        default:
            break;
        }
    }
    return 0;
}

static int rptb_pc_in_block(uint32_t pc, uint32_t rsa, uint32_t rea)
{
    pc &= C55X_PC_MASK;
    rsa &= C55X_PC_MASK;
    rea &= C55X_PC_MASK;
    if (rsa <= rea) {
        return pc >= rsa && pc <= rea;
    }
    return pc >= rsa || pc <= rea;
}

static void rptb_sync_braf(C55xCPU *cpu)
{
    if (!cpu->rptb0_active && !cpu->rptb1_active) {
        cpu->st1 &= (uint16_t)~C55X_ST1_BRAF;
    } else {
        cpu->st1 |= C55X_ST1_BRAF;
    }
}

static int rptb_trace_enabled(const C55xCPU *cpu)
{
    static int env = -1;

    if (cpu->flow_verbose) {
        return 1;
    }
    if (env < 0) {
        const char *e = getenv("C55X_TRACE_RPTB");

        env = (e != NULL && e[0] != '\0' && e[0] != '0') ? 1 : 0;
    }
    return env;
}

/*
 * SPRU371F: BRAF stays set across interrupts. An ISR runs with PC outside
 * [RSA,REA]; its own B/BCC must not clear the interrupted block-repeat.
 * Only a taken branch whose *source* PC is inside the active block escapes.
 */
static void rptb_escape(C55xCPU *cpu, uint32_t from, uint32_t dest)
{
    from &= C55X_PC_MASK;
    dest &= C55X_PC_MASK;
    if (cpu->rptb1_active &&
        rptb_pc_in_block(from, cpu->rsa1, cpu->rea1) &&
        !rptb_pc_in_block(dest, cpu->rsa1, cpu->rea1)) {
        cpu->rptb1_active = 0;
        if (rptb_trace_enabled(cpu)) {
            c55x_log(cpu,
                     "RPTB-ESC from=%06x dest=%06x block1 RSA1=%06x REA1=%06x\n",
                     from, dest, cpu->rsa1, cpu->rea1);
        }
    }
    if (cpu->rptb0_active &&
        rptb_pc_in_block(from, cpu->rsa0, cpu->rea0) &&
        !rptb_pc_in_block(dest, cpu->rsa0, cpu->rea0)) {
        cpu->rptb0_active = 0;
        cpu->rptb1_active = 0;
        if (rptb_trace_enabled(cpu)) {
            c55x_log(cpu,
                     "RPTB-ESC from=%06x dest=%06x block0 RSA0=%06x REA0=%06x\n",
                     from, dest, cpu->rsa0, cpu->rea0);
        }
    }
    rptb_sync_braf(cpu);
}

static uint32_t flow_push(C55xCPU *cpu, uint8_t kind, uint32_t caller,
                          uint32_t expect)
{
    uint32_t id = ++cpu->flow_seq;

    if (cpu->flow_depth < C55X_FLOW_MAX) {
        cpu->flow_id[cpu->flow_depth] = id;
        cpu->flow_kind[cpu->flow_depth] = kind;
        cpu->flow_expect[cpu->flow_depth] = expect & C55X_PC_MASK;
        cpu->flow_caller[cpu->flow_depth] = caller & C55X_PC_MASK;
        cpu->flow_depth++;
    }
    return id;
}

static void flow_pop(C55xCPU *cpu, uint32_t *id, uint32_t *expect,
                     uint32_t *caller, uint8_t *kind)
{
    if (!cpu->flow_depth) {
        if (id) {
            *id = 0;
        }
        if (expect) {
            *expect = 0xffffffffu;
        }
        if (caller) {
            *caller = 0;
        }
        if (kind) {
            *kind = 0xff;
        }
        return;
    }
    cpu->flow_depth--;
    if (id) {
        *id = cpu->flow_id[cpu->flow_depth];
    }
    if (expect) {
        *expect = cpu->flow_expect[cpu->flow_depth];
    }
    if (caller) {
        *caller = cpu->flow_caller[cpu->flow_depth];
    }
    if (kind) {
        *kind = cpu->flow_kind[cpu->flow_depth];
    }
}

static int flow_should_log(const C55xCPU *cpu, uint32_t from, uint32_t target)
{
    if (cpu->flow_verbose) {
        return 1;
    }
    if (pc_is_wild(target) || pc_is_wild(from)) {
        return 1;
    }
    if (from >= 0x102fa1u && from <= 0x103020u) {
        return 1;
    }
    return 0;
}

static void flow_log_call(C55xCPU *cpu, uint32_t id, uint32_t caller,
                          uint32_t target, uint32_t expect,
                          uint32_t old_reta, uint8_t old_cfct,
                          uint16_t saved_ds, uint16_t saved_ss)
{
    if (!flow_should_log(cpu, caller, target) && !pc_is_wild(expect)) {
        return;
    }
    c55x_log(cpu,
             "CALL #%u: caller=%06x target=%06x expected_return=%06x "
             "old_RETA=%06x old_CFCT=%02x saved_SP=%04x saved_SSP=%04x "
             "XSP=%06x XSSP=%06x fast=%u insn=%llu\n",
             id, caller & C55X_PC_MASK, target & C55X_PC_MASK,
             expect & C55X_PC_MASK, old_reta & C55X_PC_MASK, old_cfct,
             saved_ds, saved_ss, cpu->xsp & C55X_WORD_MASK,
             cpu->xssp & C55X_WORD_MASK, cpu->fast_return,
             (unsigned long long)cpu->insn_count);
}

static void flow_log_return(C55xCPU *cpu, const char *kind, uint32_t from,
                            uint32_t target, uint32_t pre_reta,
                            uint8_t pre_cfct, uint32_t pre_xsp,
                            uint32_t pre_xssp, uint16_t sp_top,
                            uint16_t ssp_top, uint32_t frame_id,
                            uint32_t expect, uint8_t frame_kind,
                            int reti)
{
    uint32_t stacked_reta = (((uint32_t)(ssp_top & 0xff) << 16) | sp_top) &
                            C55X_PC_MASK;
    uint8_t stacked_cfct = (uint8_t)(ssp_top >> 8);
    int mismatch = (frame_kind == C55X_FLOW_CALL &&
                    expect != 0xffffffffu &&
                    (target & C55X_PC_MASK) != (expect & C55X_PC_MASK));
    int log = mismatch || flow_should_log(cpu, from, target);

    if (mismatch && cpu->flow_mismatch_n < 16) {
        cpu->flow_mismatch_n++;
        log = 1;
    } else if (mismatch && cpu->flow_mismatch_n >= 16) {
        log = flow_should_log(cpu, from, target) || reti;
    }
    if (!log) {
        return;
    }
    c55x_log(cpu,
             "FLOW-RETURN kind=%s%s #%u from_pc=%06x target=%06x "
             "pre_RETA=%06x pre_CFCT=%02x pre_XSP=%06x pre_XSSP=%06x "
             "stack_data=%04x stack_system=%04x stacked_RETA=%06x "
             "stacked_CFCT=%02x post_RETA=%06x post_CFCT=%02x "
             "post_XSP=%06x post_XSSP=%06x expect=%06x rpt=%u/%u/%u "
             "fast=%u insn=%llu\n",
             kind, mismatch ? " MISMATCH" : "", frame_id,
             from & C55X_PC_MASK, target & C55X_PC_MASK,
             pre_reta & C55X_PC_MASK, pre_cfct,
             pre_xsp & C55X_WORD_MASK, pre_xssp & C55X_WORD_MASK,
             sp_top, ssp_top, stacked_reta, stacked_cfct,
             cpu->reta & C55X_PC_MASK, cpu->cfct & 0xff,
             cpu->xsp & C55X_WORD_MASK, cpu->xssp & C55X_WORD_MASK,
             expect & C55X_PC_MASK, cpu->rpt_armed, cpu->rpt_active,
             cpu->rpt_cc, cpu->fast_return,
             (unsigned long long)cpu->insn_count);
    if (from >= 0x102fa1u && from <= 0x103020u) {
        c55x_log(cpu,
                 "RET pc=%06x\n"
                 "    pre.RETA = %06x\n"
                 "    pre.CFCT = %02x\n"
                 "    XSP      = %06x\n"
                 "    XSSP     = %06x\n"
                 "    SP[top]  = %04x\n"
                 "    SSP[top] = %04x\n"
                 "    target-PC          = %06x\n"
                 "    restored.RETA      = %06x\n"
                 "    restored.CFCT      = %02x\n",
                 from & C55X_PC_MASK, pre_reta & C55X_PC_MASK, pre_cfct,
                 pre_xsp & C55X_WORD_MASK, pre_xssp & C55X_WORD_MASK,
                 sp_top, ssp_top, target & C55X_PC_MASK,
                 cpu->reta & C55X_PC_MASK, cpu->cfct & 0xff);
    }
    if (reti) {
        c55x_log(cpu,
                 "FLOW-RETURN RETI ST0=%04x ST1=%04x ST2=%04x DBSTAT=%04x\n",
                 cpu->st0, cpu->st1, cpu->st2, cpu->dbstat);
    }
}

static void call_enter(C55xCPU *cpu, uint32_t ret)
{
    uint8_t loop = current_loop_context(cpu);

    if (!cpu->fast_return) {
        push16(cpu, (uint16_t)ret);
        push_ssp(cpu, (uint16_t)(((cpu->cfct & 0xff) << 8) |
                                 ((ret >> 16) & 0xff)));
        cpu->cfct = loop;
        return;
    }

    push16(cpu, (uint16_t)cpu->reta);
    push_ssp(cpu, (uint16_t)(((cpu->cfct & 0xff) << 8) |
                             ((cpu->reta >> 16) & 0xff)));
    cpu->reta = ret & C55X_PC_MASK;
    cpu->cfct = loop;
}

static uint32_t ret_leave(C55xCPU *cpu)
{
    uint8_t loop;

    if (!cpu->fast_return) {
        uint16_t hi_cfct = pop_ssp(cpu);
        uint16_t lo = pop16(cpu);

        cpu->cfct = (uint16_t)(hi_cfct >> 8);
        restore_loop_context(cpu, (uint8_t)cpu->cfct);
        return (((uint32_t)(hi_cfct & 0xff) << 16) | lo) &
               C55X_PC_MASK;
    }

    /* SPRU371F FAST16: PC <- current RETA, loop <- current CFCT,
     * then pop the previous RETA/CFCT pair. Never pop before the
     * return PC is selected. */
    loop = (uint8_t)cpu->cfct;
    {
        uint32_t target = cpu->reta & C55X_PC_MASK;
        uint16_t hi_cfct = pop_ssp(cpu);
        uint16_t lo = pop16(cpu);

        cpu->reta = (((uint32_t)(hi_cfct & 0xff) << 16) | lo) &
                    C55X_PC_MASK;
        cpu->cfct = (uint16_t)(hi_cfct >> 8);
        restore_loop_context(cpu, loop);
        return target;
    }
}

static void irq_push_mode(C55xCPU *cpu, int c54x_stk)
{
    cpu->irq_ret_slow = (cpu->irq_ret_slow << 1) | (c54x_stk ? 1u : 0u);
    if (cpu->irq_nest < 32) {
        cpu->irq_nest++;
    }
}

static int irq_pop_mode_slow(C55xCPU *cpu)
{
    int slow = 0;

    if (cpu->irq_nest) {
        slow = (int)(cpu->irq_ret_slow & 1u);
        cpu->irq_ret_slow >>= 1;
        cpu->irq_nest--;
    }
    return slow;
}

/*
 * SPRU371F / dis55 `.ivec dest, C54X_STK` (`ea`): the interrupted PC
 * is pushed on SP/SSP and RETA is left alone. USE_RETA (`ca`) uses
 * the same save as CALL. Peek the IVT lead; anything other than `ca`
 * is C54X_STK (stock bios2420 HWI1–HWI15, and C55_plug dest dwords
 * whose high byte is 0).
 */
static int vector_c54x_stk(C55xCPU *cpu, uint32_t vec)
{
    uint8_t lead = 0;

    if (c55x_fetch(cpu, vec, &lead, 1) || lead != 0xca) {
        return 1;
    }
    return 0;
}

static void irq_push_status(C55xCPU *cpu)
{
    /* SPRU371F 4.4.2 / 4.4.4: decrement-before-write, ST2/ST0 first. */
    push16(cpu, cpu->st2);
    push_ssp(cpu, cpu->st0);
    push16(cpu, cpu->st1);
    push_ssp(cpu, cpu->dbstat);
}

static void irq_pop_status(C55xCPU *cpu)
{
    cpu->st1 = pop16(cpu);
    cpu->dbstat = pop_ssp(cpu);
    cpu->st2 = pop16(cpu);
    cpu->st0 = pop_ssp(cpu);
}

static void irq_enter(C55xCPU *cpu, uint32_t ret, int c54x_stk)
{
    uint8_t loop = current_loop_context(cpu);

    irq_push_mode(cpu, c54x_stk);
    irq_save_rpt_count(cpu);
    irq_push_status(cpu);
    if (c54x_stk) {
        /*
         * 4.4.4: PC and loop context on the stacks; RETA unchanged.
         * Stack the live RPT/RPTCC context only. Falling back to the
         * raw CFCT register re-armed a stale C55X_CFCT_RPT across RETI
         * (mumdrc main_loop @ 134f19 → T2=0xfffe after POP).
         */
        uint8_t stacked = loop;

        if (!stacked) {
            stacked = (uint8_t)(cpu->cfct & 0xffu &
                                (uint8_t)~(C55X_CFCT_RPT | C55X_CFCT_RPTCC));
        }
        push16(cpu, (uint16_t)ret);
        push_ssp(cpu, (uint16_t)(((uint16_t)stacked << 8) |
                                 ((ret >> 16) & 0xff)));
        flow_push(cpu, C55X_FLOW_IRQ, ret, ret);
        suspend_loop_context(cpu);
        return;
    }
    /* 4.4.2: old RETA/CFCT on the stacks, then RETA = interrupted PC. */
    call_enter(cpu, ret);
    flow_push(cpu, C55X_FLOW_IRQ, ret, ret);
    suspend_loop_context(cpu);
}

static uint32_t reti_leave(C55xCPU *cpu)
{
    uint32_t target;
    unsigned slot = cpu->irq_nest ? (cpu->irq_nest - 1u) : 0;

    if (!cpu->irq_nest) {
        return ret_leave(cpu);
    }
    if (irq_pop_mode_slow(cpu)) {
        uint16_t lo = pop16(cpu);
        uint16_t hi_cfct = pop_ssp(cpu);

        cpu->cfct = (uint16_t)(hi_cfct >> 8);
        target = (((uint32_t)(hi_cfct & 0xff) << 16) | lo) &
                 C55X_PC_MASK;
        restore_loop_context(cpu, (uint8_t)cpu->cfct);
        irq_restore_rpt_count(cpu, slot);
        irq_pop_status(cpu);
        return target;
    }
    target = ret_leave(cpu);
    irq_restore_rpt_count(cpu, slot);
    irq_pop_status(cpu);
    return target;
}

static void flow_log_branch(C55xCPU *cpu, const char *kind, uint32_t dest)
{
    uint32_t from = cpu->pc & C55X_PC_MASK;
    uint32_t d = dest & C55X_PC_MASK;

    /* _EAP_sortNetwork spins here (~3e6 identical BCCs). Keep the log. */
    if (from == 0x127fafu || from == 0x128041u) {
        return;
    }
    /*
     * pcm1 write-handler dispatch (avs 0x124c5c): cmd4 unmute/ready at
     * 0x125941, cmd3 sample write at 0x12536a. Always log these — the
     * startup jingle never reaches EAC unless cmd3 runs after ready.
     */
    if ((d == 0x125941u || d == 0x12536au || d == 0x125a26u ||
         d == 0x124cdcu) &&
        from >= 0x124c5cu && from <= 0x124d40u) {
        uint16_t st = peek16(cpu, cpu->xar[6] & C55X_WORD_MASK);
        uint16_t st1 = peek16(cpu, (cpu->xar[6] + 1u) & C55X_WORD_MASK);
        uint16_t line0 = peek16(cpu, cpu->xar[0] & C55X_WORD_MASK);

        c55x_log(cpu,
                 "pcm1-cmd %s from=%06x dest=%06x XAR0=%06x XAR6=%06x "
                 "*AR0=%04x *AR6=%04x *AR6+1=%04x T0=%04x T1=%04x "
                 "insn=%llu\n",
                 d == 0x125941u ? "cmd4-ready" :
                 d == 0x12536au ? "cmd3-write" :
                 d == 0x124cdcu ? "cmd8-info" : "setparams",
                 from, d,
                 cpu->xar[0] & C55X_WORD_MASK,
                 cpu->xar[6] & C55X_WORD_MASK,
                 line0, st, st1, cpu->t[0], cpu->t[1],
                 (unsigned long long)cpu->insn_count);
        eap_pcm_stat("pcm1-cmd %s from=%06x dest=%06x *AR6=%04x w1=%04x\n",
                     d == 0x125941u ? "cmd4-ready" :
                     d == 0x12536au ? "cmd3-write" :
                     d == 0x124cdcu ? "cmd8-info" : "setparams",
                     from, d, st, st1);
        if (d == 0x125941u) {
            cpu->pcm1_cmd4_ready = 1;
        }
        if (d == 0x124cdcu) {
            eap_pcm_stat(
                "pcm1-cmd8 AR6=%06x cmd=%04x w1=%04x w2=%04x w3=%04x "
                "w4=%04x w5=%04x cf34=%04x\n",
                cpu->xar[6] & C55X_WORD_MASK, st, st1,
                peek16(cpu, (cpu->xar[6] + 2u) & C55X_WORD_MASK),
                peek16(cpu, (cpu->xar[6] + 3u) & C55X_WORD_MASK),
                peek16(cpu, (cpu->xar[6] + 4u) & C55X_WORD_MASK),
                peek16(cpu, (cpu->xar[6] + 5u) & C55X_WORD_MASK),
                peek16(cpu, PCM1_WORD_MODE));
        }
        /*
         * cmd3 reads samples from fixed word 0x218000 (esd mmap target)
         * into *09cf22 then SIO_issue. Dump both so a silent EAC path
         * can be blamed on empty mmap vs stuck DMA ping-pong.
         */
        if (d == 0x12536au) {
            uint32_t src = 0x218000u;
            /* dbl(*(#09cf22h)): MSW at even word, LSW at odd (A^1). */
            uint32_t dst = ((uint32_t)peek16(cpu, 0x09cf22u) << 16) |
                           peek16(cpu, 0x09cf23u);
            uint16_t s0 = peek16(cpu, src);
            uint16_t s1 = peek16(cpu, src + 1u);
            uint16_t s2 = peek16(cpu, src + 2u);
            uint16_t s3 = peek16(cpu, src + 3u);
            int smin = 32767, smax = -32768;
            unsigned si;
            int16_t sv[4] = {
                (int16_t)s0, (int16_t)s1, (int16_t)s2, (int16_t)s3
            };

            for (si = 0; si < 4u; si++) {
                if (sv[si] < smin) {
                    smin = sv[si];
                }
                if (sv[si] > smax) {
                    smax = sv[si];
                }
            }
            uint16_t d0 = peek16(cpu, 0x0f60cu); /* CSSA 0x1ec18 word */
            uint16_t d1 = peek16(cpu, 0x0f60du);
            uint16_t d2 = peek16(cpu, 0x0f60eu);
            uint16_t d3 = peek16(cpu, 0x0f60fu);

            c55x_log(cpu,
                     "pcm1-cmd3-buf dst=%06x src218000=%04x %04x %04x %04x "
                     "src64min=%d src64max=%d "
                     "cssa1ec18=%04x %04x %04x %04x cf34=%04x cf2b=%04x "
                     "insn=%llu\n",
                     dst & C55X_WORD_MASK, s0, s1, s2, s3, smin, smax,
                     d0, d1, d2, d3,
                     peek16(cpu, 0x09cf34u), peek16(cpu, 0x09cf2bu),
                     (unsigned long long)cpu->insn_count);
            eap_cssa_src = dst & C55X_WORD_MASK;
            if (!eap_cssa_len) {
                eap_cssa_len = 0x800u;
            }
            {
                static unsigned cmd3_logs;
                int amp = abs(smin) > abs(smax) ? abs(smin) : abs(smax);

                if (cmd3_logs < 8u || amp >= 32) {
                    eap_pcm_stat(
                        "t=cmd3 dst=%06x src64min=%d src64max=%d "
                        "cssa=%04x %04x cf34=%04x cf2b=%04x\n",
                        dst & C55X_WORD_MASK, smin, smax, d0, d1,
                        peek16(cpu, 0x09cf34u), peek16(cpu, 0x09cf2bu));
                    cmd3_logs++;
                }
                if (amp >= 200) {
                    static unsigned mmap_words_logs;
                    static int mmap_best;
                    unsigned wi;
                    char buf[160];
                    int pos = 0;

                    if (amp > mmap_best && mmap_words_logs < 6u) {
                        mmap_best = amp;
                        pos = snprintf(buf, sizeof(buf), "t=mmap dst=%06x",
                                       dst & C55X_WORD_MASK);
                        for (wi = 0; wi < 8u && pos > 0 &&
                             pos < (int)sizeof(buf); wi++) {
                            int16_t w = (int16_t)peek16(cpu, src + wi);

                            pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                                            " %d", (int)w);
                        }
                        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                                        " d");
                        for (wi = 0; wi < 8u && pos > 0 &&
                             (size_t)pos < sizeof(buf); wi++) {
                            int16_t w = (int16_t)peek16(cpu, (dst & C55X_WORD_MASK) + wi);

                            pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                                            " %d", (int)w);
                        }
                        if (pos > 0) {
                            eap_pcm_stat("%s\n", buf);
                        }
                        mmap_words_logs++;
                    }
                }
            }
        }
    }
    if (!(cpu->flow_verbose || pc_is_wild(dest))) {
        return;
    }
    c55x_log(cpu,
             "FLOW-B kind=%s from=%06x dest=%06x RETA=%06x CFCT=%02x "
             "insn=%llu\n",
             kind, cpu->pc & C55X_PC_MASK, dest & C55X_PC_MASK,
             cpu->reta & C55X_PC_MASK, cpu->cfct & 0xff,
             (unsigned long long)cpu->insn_count);
}

static void call_taken(C55xCPU *cpu, uint32_t target, uint32_t ret)
{
    uint32_t old_reta = cpu->reta & C55X_PC_MASK;
    uint8_t old_cfct = (uint8_t)cpu->cfct;
    uint32_t id;
    uint32_t from = cpu->pc & C55X_PC_MASK;
    uint32_t dest = target & C55X_PC_MASK;

    call_enter(cpu, ret);
    id = flow_push(cpu, C55X_FLOW_CALL, cpu->pc, ret);
    flow_log_call(cpu, id, cpu->pc, target, ret, old_reta, old_cfct,
                  peek16(cpu, cpu->xsp), peek16(cpu, cpu->xssp));
    eapq_note_call(cpu, cpu->pc, target);
    /* Ready: CALL _bksnd || MOV #3,T1 — DSP tells ARM to fill mmap.
     * Apply the parallel mate before the callee runs. */
    if (from == 0x12597au && dest == 0x126674u) {
        uint32_t ar6 = cpu->xar[6] & C55X_WORD_MASK;

        cpu->t[1] = 3;
        eap_pcm_stat(
            "pcm1-ready-bksnd AR6=%06x *AR6=%04x w1=%04x T0=%04x T1=0003 T2=%04x\n",
            ar6, peek16(cpu, ar6),
            peek16(cpu, (ar6 + 1u) & C55X_WORD_MASK),
            cpu->t[0], cpu->t[2]);
    }
    /*
     * 0x125ca0 is CALL #0x126674 || MOV T2, T0. QEMU takes the CALL
     * before the parallel MOV, so _bksnd would see leftover T0.
     * Hardware commits the packet first. Restore T0 from T2 here.
     */
    if (from == 0x125ca0u && dest == 0x126674u) {
        uint32_t ar6 = cpu->xar[6] & C55X_WORD_MASK;
        uint32_t ar7 = cpu->xar[7] & C55X_WORD_MASK;
        uint16_t cmd = peek16(cpu, ar6);
        uint16_t w1 = peek16(cpu, (ar6 + 1u) & C55X_WORD_MASK);
        uint16_t t0_in = cpu->t[0];
        uint16_t t2 = cpu->t[2];

        cpu->t[0] = t2;
        eap_pcm_stat(
            "pcm1-bksnd AR6=%06x AR7=%06x XAR0=%06x cmd=%04x w1=%04x "
            "*AR7=%04x T0=%04x->%04x T1=%04x\n",
            ar6, ar7, cpu->xar[0] & C55X_WORD_MASK, cmd, w1,
            peek16(cpu, ar7), t0_in, t2, cpu->t[1]);
        if ((cmd == 1u || cmd == 2u || cmd == 7u || cmd == 13u) &&
            w1 != 1u && cpu->bus.write16) {
            cpu->bus.write16(cpu->bus.opaque, (ar6 + 1u) & C55X_WORD_MASK, 1);
            eap_pcm_stat("pcm1-cmd%u-status1 AR6=%06x %04x->0001 T1=%04x\n",
                         cmd, ar6, w1, cpu->t[1]);
        }
    }
}

static uint32_t return_taken(C55xCPU *cpu, const char *kind, int reti)
{
    uint32_t from = cpu->pc;
    uint32_t pre_reta = cpu->reta & C55X_PC_MASK;
    uint8_t pre_cfct = (uint8_t)cpu->cfct;
    uint32_t pre_xsp = cpu->xsp;
    uint32_t pre_xssp = cpu->xssp;
    uint16_t sp_top = peek16(cpu, cpu->xsp);
    uint16_t ssp_top = peek16(cpu, cpu->xssp);
    uint32_t target;
    uint32_t id = 0, expect = 0xffffffffu, caller = 0;
    uint8_t frame_kind = 0xff;

    if (reti) {
        target = reti_leave(cpu);
        cpu->last_reti_from = from & C55X_PC_MASK;
        cpu->last_reti_to = target & C55X_PC_MASK;
        if (cpu->in_audio_isr) {
            c55x_log(cpu,
                     "audio_isr exit n=%u from=%06x to=%06x bit=%u insn=%llu\n",
                     cpu->audio_isr_n, cpu->last_reti_from,
                     cpu->last_reti_to, cpu->last_irq_bit,
                     (unsigned long long)cpu->insn_count);
            cpu->in_audio_isr = 0;
        }
        knlq_note_reti(cpu);
    } else {
        target = ret_leave(cpu);
    }
    flow_pop(cpu, &id, &expect, &caller, &frame_kind);
    (void)caller;
    if ((from & C55X_PC_MASK) >= 0x126674u &&
        (from & C55X_PC_MASK) <= 0x1266ccu &&
        ((target & C55X_PC_MASK) == 0x125ca6u ||
         (target & C55X_PC_MASK) == 0x125980u)) {
        eap_pcm_stat("pcm1-bksnd-ret from=%06x to=%06x T0=%04x T1=%04x\n",
                     from & C55X_PC_MASK, target & C55X_PC_MASK,
                     cpu->t[0], cpu->t[1]);
    }
    flow_log_return(cpu, kind, from, target, pre_reta, pre_cfct,
                    pre_xsp, pre_xssp, sp_top, ssp_top, id, expect,
                    frame_kind, reti);
    return target;
}

int c55x_eval_cond(const C55xCPU *cpu, unsigned cond)
{
    unsigned top = (cond >> 4) & 7;
    unsigned fsss = cond & 0x0f;
    int64_t src;

    if (top <= 5) {
        src = c55x_get_reg_signed(cpu, fsss);
        switch (top) {
        case 0:
            return src == 0;
        case 1:
            return src != 0;
        case 2:
            return src < 0;
        case 3:
            return src <= 0;
        case 4:
            return src > 0;
        case 5:
            return src >= 0;
        default:
            break;
        }
    }
    switch (cond) {
    case 0x64:
        return !!(pkt_read_st0(cpu) & C55X_ST0_TC1);
    case 0x65:
        return !!(pkt_read_st0(cpu) & C55X_ST0_TC2);
    case 0x66:
        return !!(pkt_read_st0(cpu) & C55X_ST0_CARRY);
    case 0x74:
        return !(pkt_read_st0(cpu) & C55X_ST0_TC1);
    case 0x75:
        return !(pkt_read_st0(cpu) & C55X_ST0_TC2);
    case 0x76:
        return !(pkt_read_st0(cpu) & C55X_ST0_CARRY);
    default:
        return 0;
    }
}

static uint16_t *st_ptr(C55xCPU *cpu, unsigned st)
{
    switch (st) {
    case 0:
        return &cpu->st0;
    case 1:
        return &cpu->st1;
    case 2:
        return &cpu->st2;
    default:
        return &cpu->st3;
    }
}

static void mov_k16_ctl(C55xCPU *cpu, unsigned which, int32_t imm)
{
    switch (which) {
    case 0:
        cpu->xdp = (cpu->xdp & ~0xffffu) | (uint16_t)imm;
        break;
    case 1:
        cpu->xssp = (cpu->xssp & ~0xffffu) | (uint16_t)imm;
        cpu->ssp_written = 1;
        break;
    case 2:
        cpu->xcdp = (cpu->xcdp & ~0xffffu) | (uint16_t)imm;
        break;
    case 3:
        cpu->bsa01 = (uint16_t)imm;
        break;
    case 4:
        cpu->bsa23 = (uint16_t)imm;
        break;
    case 5:
        cpu->bsa45 = (uint16_t)imm;
        break;
    case 6:
        cpu->bsa67 = (uint16_t)imm;
        break;
    case 7:
        cpu->bsac = (uint16_t)imm;
        break;
    case 8:
        cpu->xsp = (cpu->xsp & ~0xffffu) | (uint16_t)imm;
        cpu->sp_written = 1;
        break;
    default:
        break;
    }
}

static int exec_op(C55xCPU *cpu, const C55xDecodedInsn *in, const C55xOp *op,
                   uint32_t *next_pc)
{
    uint16_t mem;
    uint64_t src, dst;
    int mmap = in->mmap;
    int port = in->port;

    switch (op->kind) {
    case C55X_OP_NOP:
    case C55X_OP_QUAL_MMAP:
    case C55X_OP_QUAL_PORT:
    case C55X_OP_QUAL_PORT_SMEM:
    case C55X_OP_XCC:
    case C55X_OP_XCCPART:
        return 0;
    case C55X_OP_MOV_REG_REG:
        c55x_set_reg(cpu, op->dst, c55x_get_reg(cpu, op->src));
        return 0;
    case C55X_OP_MOV_XREG:
        /*
         * ACx -> 23-bit register moves use the A-unit ALU.  When paralleled
         * with a D-unit operation producing that ACx, the A-unit sees the
         * D-unit result (the stock _MEM_init sequence uses
         * ADD AC1, AC0 || MOV AC0, XAR4 for exactly this transfer).
         * Other packet sources retain packet-entry semantics.
         */
        if (cpu->pkt_src_valid && op->src < 4 && op->dst >= 4) {
            c55x_set_xreg(cpu, op->dst,
                         (uint32_t)(cpu->ac[op->src] & C55X_WORD_MASK));
        } else {
            c55x_set_xreg(cpu, op->dst, c55x_get_xreg(cpu, op->src));
        }
        return 0;
    case C55X_OP_MOV_TAX_HI: {
        /*
         * SPRU374 4.5.3: HI(ACx) = TAx is a D-unit 16-bit move
         * (M40 / SATD / SXMD / ACOVx). Algebraic HI(ACx) = TAx is
         * TAx shifted into bits 31–16, so ACx(15–0) and the guard
         * bits are the SXMD-extended shift result, not a bitfield
         * insert. tokliBIOS _mbcmd_send (0x125f56) does
         * MOV AR1, HI(AC0) with cmd_l=0 after SFTL AC0,#1 of the
         * bid; leaving ACx(15–0) as i<<1 made BKYLD 8..15 into
         * 24/27/30/31/28.
         */
        uint16_t tax = (uint16_t)c55x_get_reg(cpu, op->src);
        int64_t val = (cpu->st1 & C55X_ST1_SXMD) ? (int64_t)(int16_t)tax
                                                 : (int64_t)(uint16_t)tax;

        cpu->ac[op->dst & 3] = ((uint64_t)val << 16) & C55X_AC_MASK;
        return 0;
    }
    case C55X_OP_MOV_TAX_CTL: {
        uint16_t tax = (uint16_t)c55x_get_reg(cpu, op->src);

        switch (op->dst) {
        case C55X_CTL_SP:
            cpu->xsp = (cpu->xsp & ~0xffffu) | tax;
            cpu->sp_written = 1;
            break;
        case C55X_CTL_SSP:
            cpu->xssp = (cpu->xssp & ~0xffffu) | tax;
            cpu->ssp_written = 1;
            break;
        case C55X_CTL_CDP:
            cpu->xcdp = (cpu->xcdp & ~0xffffu) | tax;
            break;
        case C55X_CTL_CSR:
            cpu->csr = tax;
            break;
        case C55X_CTL_BRC0:
            cpu->brc0 = tax;
            break;
        case C55X_CTL_BRC1:
            cpu->brc1 = tax;
            break;
        default:
            return -1;
        }
        return 0;
    }
    case C55X_OP_AND_AC_SHFT:
    case C55X_OP_OR_AC_SHFT:
    case C55X_OP_XOR_AC_SHFT:
    case C55X_OP_ADD_AC_SHFT:
    case C55X_OP_SUB_AC_SHFT:
    case C55X_OP_SFTS_AC:
    case C55X_OP_SFTL_AC: {
        int sh;

        if (op->kind == C55X_OP_SFTS_AC && op->bit == 2) {
            /* SFTCC: shift left 1 iff the two MSBs are equal; else TCx=0.
             * M40=0 uses bits 31:30 of the 32-bit AC image (GU clear). */
            uint64_t ac = pkt_read_ac(cpu, op->dst);
            int m40 = !!(cpu->st1 & (C55X_ST1_M40 | C55X_ST1_C54CM));
            unsigned top2;
            unsigned out;

            if (m40) {
                top2 = (unsigned)((ac >> 38) & 3ull);
                out = (unsigned)((ac >> 39) & 1ull);
            } else {
                ac &= 0xffffffffull;
                top2 = (unsigned)((ac >> 30) & 3ull);
                out = (unsigned)((ac >> 31) & 1ull);
            }
            if (top2 == 0u || top2 == 3u) {
                ac = c55x_ac_store(cpu, ac << 1);
                set_tcx(cpu, op->st, (int)out);
            } else {
                set_tcx(cpu, op->st, 0);
            }
            cpu->ac[op->dst & 3] = ac & C55X_AC_MASK;
            return 0;
        }
        sh = op->st ? (int16_t)pkt_read_t(cpu, (unsigned)op->imm)
                        : shiftw6(op->shft);
        /*
         * RX-34, M40=0, SFTS/SFTL #SHIFTW: the shift is the 32-bit
         * image. |count|==32 yields 0 (SFTS #-32 of 0x80000000 is 0,
         * not sign fill). SFTL writes CARRY with the last bit shifted
         * out. A left shift that turns a positive value negative sets
         * ACOV3; SFTS also sets ACOVx for the destination. Those two
         * bits follow this shift, they do not stick across it.
         * SFTSC and SATD left shifts stay on the path below.
         */
        if ((op->kind == C55X_OP_SFTS_AC || op->kind == C55X_OP_SFTL_AC) &&
            !op->bit && !op->st &&
            !(cpu->st1 & C55X_ST1_M40) &&
            !(op->kind == C55X_OP_SFTS_AC && sh > 0 &&
              (cpu->st1 & C55X_ST1_SATD))) {
            uint32_t src32 = (uint32_t)(pkt_read_ac(cpu, op->src) &
                                        0xffffffffu);
            uint32_t result = src32;
            int logical = (op->kind == C55X_OP_SFTL_AC);

            if (sh >= 32 || sh <= -32) {
                result = 0;
                if (logical) {
                    unsigned bit = (sh > 0) ? 0u : 31u;

                    if ((src32 >> bit) & 1u) {
                        cpu->st0 |= C55X_ST0_CARRY;
                    } else {
                        cpu->st0 &= (uint16_t)~C55X_ST0_CARRY;
                    }
                }
            } else if (sh > 0) {
                if (logical) {
                    unsigned bit = 32u - (unsigned)sh;

                    if ((src32 >> bit) & 1u) {
                        cpu->st0 |= C55X_ST0_CARRY;
                    } else {
                        cpu->st0 &= (uint16_t)~C55X_ST0_CARRY;
                    }
                }
                result = src32 << (unsigned)sh;
            } else if (sh < 0) {
                unsigned n = (unsigned)(-sh);

                if (logical) {
                    if ((src32 >> (n - 1u)) & 1u) {
                        cpu->st0 |= C55X_ST0_CARRY;
                    } else {
                        cpu->st0 &= (uint16_t)~C55X_ST0_CARRY;
                    }
                    result = src32 >> n;
                } else {
                    result = (uint32_t)((int32_t)src32 >> n);
                }
            }
            cpu->st0 &= (uint16_t)~(acov_mask(op->dst & 3) | C55X_ST0_ACOV3);
            if (sh > 0 && (result & 0x80000000u) && !(src32 & 0x80000000u)) {
                cpu->st0 |= C55X_ST0_ACOV3;
                if (!logical) {
                    cpu->st0 |= acov_mask(op->dst & 3);
                }
            }
            cpu->ac[op->dst & 3] = c55x_ac_store(cpu, result);
            return 0;
        }
        int arith = (op->kind != C55X_OP_SFTL_AC);
        uint64_t shifted = ac_shift(pkt_read_ac(cpu, op->src), sh, arith);
        uint64_t acc = pkt_read_ac(cpu, op->dst);

        if (op->kind == C55X_OP_SFTS_AC && op->bit) {
            ac_shift_carry(cpu, pkt_read_ac(cpu, op->src), sh);
        }
        if (op->kind == C55X_OP_AND_AC_SHFT) {
            acc &= shifted;
        } else if (op->kind == C55X_OP_OR_AC_SHFT) {
            acc |= shifted;
        } else if (op->kind == C55X_OP_XOR_AC_SHFT) {
            acc ^= shifted;
        } else if (op->kind == C55X_OP_ADD_AC_SHFT) {
            cpu->ac[op->dst & 3] = alu40(cpu, acc, shifted, 0, op->dst);
            return 0;
        } else if (op->kind == C55X_OP_SUB_AC_SHFT) {
            cpu->ac[op->dst & 3] = alu40(cpu, acc, shifted, 1, op->dst);
            return 0;
        } else if (op->kind == C55X_OP_SFTS_AC && sh > 0 &&
                   (cpu->st1 & C55X_ST1_SATD)) {
            /*
             * SFTS/SFTSC #SHIFTW saturates like SFTS #±1. M40=0 uses
             * bit 31. RX-34: SATD, 0x20000000 SFTS #2 → 0x7fffffff;
             * 0x40000000 SFTS #2 → 0x7fffffff. No overflow keeps ac_shift.
             */
            int m40 = (cpu->st1 & (C55X_ST1_M40 | C55X_ST1_C54CM)) != 0;
            uint64_t srcv = pkt_read_ac(cpu, op->src) & C55X_AC_MASK;
            int64_t s, maxv, minv;
            int sat = 0;
            int i;

            if (m40) {
                s = (int64_t)(srcv & C55X_AC_MASK);
                if (srcv & (1ull << 39)) {
                    s |= ~((int64_t)C55X_AC_MASK);
                }
                maxv = ((int64_t)1 << 39) - 1;
                minv = -((int64_t)1 << 39);
            } else {
                srcv &= 0xffffffffull;
                s = (int64_t)(int32_t)(uint32_t)srcv;
                maxv = 0x7fffffffLL;
                minv = (int64_t)(int32_t)0x80000000u;
            }
            for (i = 0; i < sh; i++) {
                if (s > (maxv >> 1) || s < (minv >> 1)) {
                    s = (s < 0) ? minv : maxv;
                    sat = 1;
                    break;
                }
                s <<= 1;
            }
            if (sat) {
                cpu->st0 |= acov_mask(op->dst & 3);
                cpu->ac[op->dst & 3] = c55x_ac_store(cpu,
                    m40 ? ((uint64_t)s & C55X_AC_MASK)
                        : (uint64_t)(uint32_t)s);
                return 0;
            }
            acc = shifted;
        } else {
            acc = shifted;
        }
        cpu->ac[op->dst & 3] = c55x_ac_store(cpu, acc);
        return 0;
    }
    case C55X_OP_SFTS_AC_TX: {
        int16_t tx = (int16_t)c55x_get_reg(cpu, C55X_REG_T0 + (op->imm & 3));
        int sh = tx;
        int arith = !op->st;

        if (sh > 31) {
            sh = 31;
        } else if (sh < -32) {
            sh = -32;
        }
        if (op->bit) {
            ac_shift_carry(cpu, pkt_read_ac(cpu, op->src), sh);
        }
        /*
         * SFTS/SFTSC by Tx saturates like SFTS #k when SATD is set.
         * M40=0 uses bit 31. SFTL (op->st) ignores SATD.
         * RX-34: SATD, AC0=0x20000000, T0=2, SFTS AC0,T0 → 0x7fffffff.
         * A shift that does not overflow keeps the ac_shift result.
         */
        if (arith && sh > 0 && (cpu->st1 & C55X_ST1_SATD)) {
            int m40 = (cpu->st1 & (C55X_ST1_M40 | C55X_ST1_C54CM)) != 0;
            uint64_t acc = pkt_read_ac(cpu, op->src) & C55X_AC_MASK;
            int64_t s, maxv, minv;
            int sat = 0;
            int i;

            if (m40) {
                s = (int64_t)(acc & C55X_AC_MASK);
                if (acc & (1ull << 39)) {
                    s |= ~((int64_t)C55X_AC_MASK);
                }
                maxv = ((int64_t)1 << 39) - 1;
                minv = -((int64_t)1 << 39);
            } else {
                acc &= 0xffffffffull;
                s = (int64_t)(int32_t)(uint32_t)acc;
                maxv = 0x7fffffffLL;
                minv = (int64_t)(int32_t)0x80000000u;
            }
            for (i = 0; i < sh; i++) {
                if (s > (maxv >> 1) || s < (minv >> 1)) {
                    s = (s < 0) ? minv : maxv;
                    sat = 1;
                    break;
                }
                s <<= 1;
            }
            if (sat) {
                cpu->st0 |= acov_mask(op->dst & 3);
                cpu->ac[op->dst & 3] = c55x_ac_store(cpu,
                    m40 ? ((uint64_t)s & C55X_AC_MASK)
                        : (uint64_t)(uint32_t)s);
                return 0;
            }
        }
        cpu->ac[op->dst & 3] =
            ac_shift(pkt_read_ac(cpu, op->src), sh, arith) & C55X_AC_MASK;
        return 0;
    }
    case C55X_OP_AND_K8:
        c55x_set_reg(cpu, op->dst,
                     c55x_get_reg(cpu, op->src) & (uint8_t)op->imm);
        return 0;
    case C55X_OP_OR_K8:
        c55x_set_reg(cpu, op->dst,
                     c55x_get_reg(cpu, op->src) | (uint8_t)op->imm);
        return 0;
    case C55X_OP_XOR_K8:
        c55x_set_reg(cpu, op->dst,
                     c55x_get_reg(cpu, op->src) ^ (uint8_t)op->imm);
        return 0;
    case C55X_OP_MOV_K4:
    case C55X_OP_MOV_NK4:
    case C55X_OP_MOV_K16_DST:
        c55x_set_reg(cpu, op->dst, (uint64_t)(int64_t)op->imm);
        return 0;
    case C55X_OP_MOV_HI_TAX:
        c55x_set_reg(cpu, op->dst, (pkt_read_ac(cpu, op->src) >> 16) & 0xffffull);
        return 0;
    case C55X_OP_MOV_CTL_TAX: {
        uint16_t value;

        switch (op->src) {
        case C55X_CTL_SP:
            value = (uint16_t)pkt_read_xsp(cpu);
            break;
        case C55X_CTL_SSP:
            value = (uint16_t)(cpu->pkt_src_valid ? cpu->pkt_xssp : cpu->xssp);
            break;
        case C55X_CTL_CDP:
            value = (uint16_t)pkt_read_xcdp(cpu);
            break;
        case C55X_CTL_BRC0:
            value = cpu->brc0;
            break;
        case C55X_CTL_BRC1:
            value = cpu->brc1;
            break;
        case C55X_CTL_RPTC:
            value = cpu->rptc;
            break;
        default:
            return -1;
        }
        c55x_set_reg(cpu, op->dst, value);
        return 0;
    }
    case C55X_OP_SFTS_TAX: {
        if ((op->dst & 15) < 4) {
            /*
             * M40=0 shifts the 32-bit image (sign is bit 31). SATD
             * clamps a left shift that would overflow that width.
             * RX-34: SATD, AC0=0x40000000, SFTS #1 → 0x7fffffff.
             * SXMD=0 does not make SFTS logical; -1 stays -1.
             */
            int m40 = (cpu->st1 & (C55X_ST1_M40 | C55X_ST1_C54CM)) != 0;
            int sh = (int)op->imm;
            uint64_t acc = pkt_read_ac(cpu, op->dst) & C55X_AC_MASK;
            int64_t s, maxv, minv;
            int sat = 0;

            if (m40) {
                s = (int64_t)(acc & C55X_AC_MASK);
                if (acc & (1ull << 39)) {
                    s |= ~((int64_t)C55X_AC_MASK);
                }
                maxv = ((int64_t)1 << 39) - 1;
                minv = -((int64_t)1 << 39);
            } else {
                acc &= 0xffffffffull;
                s = (int64_t)(int32_t)(uint32_t)acc;
                maxv = 0x7fffffffLL;
                minv = (int64_t)(int32_t)0x80000000u;
            }
            if (sh > 0) {
                int i;

                for (i = 0; i < sh; i++) {
                    if ((cpu->st1 & C55X_ST1_SATD) &&
                        (s > (maxv >> 1) || s < (minv >> 1))) {
                        s = (s < 0) ? minv : maxv;
                        sat = 1;
                        break;
                    }
                    s <<= 1;
                }
            } else if (sh < 0) {
                s >>= -sh;
            }
            if (sat) {
                cpu->st0 |= acov_mask(op->dst & 3);
            }
            cpu->ac[op->dst & 3] = c55x_ac_store(cpu,
                m40 ? ((uint64_t)s & C55X_AC_MASK)
                    : (uint64_t)(uint32_t)s);
            return 0;
        }
        {
            int16_t value = (int16_t)c55x_get_reg(cpu, op->dst);

            if (op->imm > 0) {
                value = (int16_t)(value << op->imm);
            } else if (op->imm < 0) {
                value = (int16_t)(value >> (-op->imm));
            }
            c55x_set_reg(cpu, op->dst, (uint16_t)value);
            return 0;
        }
    }
    case C55X_OP_SFTL_TAX: {
        unsigned tax = op->dst & 15;
        int left = op->imm > 0;

        if (tax < 4) {
            uint64_t acc = pkt_read_ac(cpu, tax) & C55X_AC_MASK;
            unsigned carry_bit = (cpu->st1 & C55X_ST1_M40) ? 39 : 31;

            if (left) {
                if (acc & (1ull << carry_bit)) {
                    cpu->st0 |= C55X_ST0_CARRY;
                } else {
                    cpu->st0 &= (uint16_t)~C55X_ST0_CARRY;
                }
                acc = c55x_ac_store(cpu, acc << 1);
            } else {
                if (acc & 1ull) {
                    cpu->st0 |= C55X_ST0_CARRY;
                } else {
                    cpu->st0 &= (uint16_t)~C55X_ST0_CARRY;
                }
                acc >>= 1;
            }
            cpu->ac[tax] = acc;
        } else {
            uint16_t value = (uint16_t)c55x_get_reg(cpu, tax);

            if (left) {
                if (value & 0x8000u) {
                    cpu->st0 |= C55X_ST0_CARRY;
                } else {
                    cpu->st0 &= (uint16_t)~C55X_ST0_CARRY;
                }
                value = (uint16_t)(value << 1);
            } else {
                if (value & 1u) {
                    cpu->st0 |= C55X_ST0_CARRY;
                } else {
                    cpu->st0 &= (uint16_t)~C55X_ST0_CARRY;
                }
                value = (uint16_t)(value >> 1);
            }
            c55x_set_reg(cpu, tax, value);
        }
        return 0;
    }
    case C55X_OP_MOV_K16_AC_SHFT:
        cpu->ac[op->dst & 3] = ((uint64_t)(uint16_t)op->imm << op->shft) &
                               C55X_AC_MASK;
        return 0;
    case C55X_OP_ADD_REG:
        /*
         * AC, AC saturates like the D-unit ALU when SATD is set.
         * RX-34: SATD, AC0=0x7fff0000+AC1=0x01000000 → 0x7fffffff.
         * Without SATD the sum is the low 32 bits and ST0 is left
         * alone: alu40's CARRY write skips pcm1 cmd 3.
         * TAx/ARx adds stay a plain sum.
         */
        if ((op->dst & 15) < 4 && (op->src & 15) < 4 &&
            (cpu->st1 & C55X_ST1_SATD)) {
            cpu->ac[op->dst & 3] = alu40(cpu, pkt_read_ac(cpu, op->dst),
                                         pkt_read_ac(cpu, op->src), 0,
                                         op->dst & 3);
            return 0;
        }
        src = c55x_get_reg(cpu, op->src);
        dst = c55x_get_reg(cpu, op->dst);
        /*
         * RX-34 par_flag: ADD AC2, AC0 || ADD AC2, AC1 keeps both
         * accumulator destinations and clears CARRY. Two D-unit ADDs
         * in one packet update the flag and do not commit either
         * destination write.
         */
        if (cpu->pkt_src_valid && in->op_count >= 2 &&
            in->op[0].kind == C55X_OP_ADD_REG &&
            in->op[1].kind == C55X_OP_ADD_REG) {
            uint64_t sum = (dst & 0xffffffffull) + (src & 0xffffffffull);

            if (sum > 0xffffffffull) {
                cpu->st0 |= C55X_ST0_CARRY;
            } else {
                cpu->st0 &= (uint16_t)~C55X_ST0_CARRY;
            }
            return 0;
        }
        c55x_set_reg(cpu, op->dst, dst + src);
        return 0;
    case C55X_OP_SUB_REG:
        src = c55x_get_reg(cpu, op->src);
        dst = c55x_get_reg(cpu, op->dst);
        c55x_set_reg(cpu, op->dst, dst - src);
        return 0;
    case C55X_OP_AND_REG:
        c55x_set_reg(cpu, op->dst,
                     c55x_get_reg(cpu, op->dst) & c55x_get_reg(cpu, op->src));
        return 0;
    case C55X_OP_OR_REG:
        c55x_set_reg(cpu, op->dst,
                     c55x_get_reg(cpu, op->dst) | c55x_get_reg(cpu, op->src));
        return 0;
    case C55X_OP_XOR_REG:
        c55x_set_reg(cpu, op->dst,
                     c55x_get_reg(cpu, op->dst) ^ c55x_get_reg(cpu, op->src));
        return 0;
    case C55X_OP_NOT_REG:
        c55x_set_reg(cpu, op->dst,
                     (~c55x_get_reg(cpu, op->src)) &
                     ((op->dst & 15) < 4 ? C55X_AC_MASK : 0xffffull));
        return 0;
    case C55X_OP_NEG_REG:
        c55x_set_reg(cpu, op->dst,
                     (uint64_t)(-(int64_t)c55x_get_reg_signed(cpu, op->src)));
        return 0;
    case C55X_OP_ABS_REG: {
        int64_t v = c55x_get_reg_signed(cpu, op->src);
        int m40 = (cpu->st1 & (C55X_ST1_M40 | C55X_ST1_C54CM)) != 0;
        int64_t minv = m40 ? -((int64_t)1 << 39)
                           : (int64_t)(int32_t)0x80000000u;

        /*
         * RX-34: SATD, ABS of the 32-bit minimum (built by SFTS #1 of
         * 0x40000000) stores 0x7fffffff. Without SATD it stays
         * 0x80000000. NEG of that value does not saturate.
         */
        if ((cpu->st1 & C55X_ST1_SATD) && v == minv) {
            if ((op->dst & 15) < 4) {
                cpu->st0 |= acov_mask(op->dst & 3);
            }
            c55x_set_reg(cpu, op->dst,
                         m40 ? (((uint64_t)1 << 39) - 1ull) : 0x7fffffffull);
            return 0;
        }
        c55x_set_reg(cpu, op->dst, (uint64_t)(v < 0 ? -v : v));
        return 0;
    }
    case C55X_OP_MAX_REG:
    case C55X_OP_MIN_REG: {
        int64_t a = c55x_get_reg_signed(cpu, op->src);
        int64_t b = c55x_get_reg_signed(cpu, op->dst);

        /*
         * RX-34: MAX of AC1=-0x2000 and AC0=0x1000 stores 0xffffe000.
         * Unsigned 32-bit order picks that value; signed order would
         * pick 0x1000. Same-sign pairs agree either way. MIN of the
         * same pair stays the signed minimum.
         */
        if (op->kind == C55X_OP_MAX_REG && (op->src & 15) < 4 &&
            (op->dst & 15) < 4) {
            uint32_t ua = (uint32_t)c55x_get_reg(cpu, op->src);
            uint32_t ub = (uint32_t)c55x_get_reg(cpu, op->dst);

            c55x_set_reg(cpu, op->dst, ua > ub ? ua : ub);
        } else if (op->kind == C55X_OP_MAX_REG) {
            c55x_set_reg(cpu, op->dst, (uint64_t)(a > b ? a : b));
        } else {
            c55x_set_reg(cpu, op->dst, (uint64_t)(a < b ? a : b));
        }
        return 0;
    }
    case C55X_OP_ADD_K4:
    case C55X_OP_ADD_K16_DST:
        c55x_set_reg(cpu, op->dst,
                     c55x_get_reg(cpu, op->kind == C55X_OP_ADD_K16_DST ?
                                  op->src : op->dst) + (uint64_t)(int64_t)op->imm);
        return 0;
    case C55X_OP_SUB_K4:
    case C55X_OP_SUB_K16_DST:
        c55x_set_reg(cpu, op->dst,
                     c55x_get_reg(cpu, op->kind == C55X_OP_SUB_K16_DST ?
                                  op->src : op->dst) - (uint64_t)(int64_t)op->imm);
        return 0;
    case C55X_OP_AND_K16_DST:
        c55x_set_reg(cpu, op->dst,
                     c55x_get_reg(cpu, op->src) & (uint16_t)op->imm);
        return 0;
    case C55X_OP_OR_K16_DST:
        c55x_set_reg(cpu, op->dst,
                     c55x_get_reg(cpu, op->src) | (uint16_t)op->imm);
        return 0;
    case C55X_OP_XOR_K16_DST:
        c55x_set_reg(cpu, op->dst,
                     c55x_get_reg(cpu, op->src) ^ (uint16_t)op->imm);
        return 0;
    case C55X_OP_OR_K16_SH16:
    case C55X_OP_AND_K16_SH16:
    case C55X_OP_XOR_K16_SH16:
    case C55X_OP_ADD_K16_SH16:
    case C55X_OP_SUB_K16_SH16:
    case C55X_OP_MOV_K16_AC_SH16: {
        uint64_t k = (uint16_t)op->imm;

        /*
         * SPRU374: ADD/SUB/MOV use signed K16 (SXMD then <<16).
         * AND/OR/XOR use unsigned k16, zero-extended, then <<< #16.
         */
        if ((op->kind == C55X_OP_ADD_K16_SH16 ||
             op->kind == C55X_OP_SUB_K16_SH16 ||
             op->kind == C55X_OP_MOV_K16_AC_SH16) &&
            (cpu->st1 & C55X_ST1_SXMD)) {
            int64_t s = (int16_t)op->imm;

            s <<= 16;
            k = (uint64_t)s & C55X_AC_MASK;
        } else {
            k = (k << 16) & C55X_AC_MASK;
        }
        src = pkt_read_ac(cpu, op->src);
        if (op->kind == C55X_OP_MOV_K16_AC_SH16) {
            cpu->ac[op->dst & 3] = c55x_ac_store(cpu, k);
        } else if (op->kind == C55X_OP_ADD_K16_SH16) {
            cpu->ac[op->dst & 3] = alu40(cpu, src, k, 0, op->dst);
        } else if (op->kind == C55X_OP_SUB_K16_SH16) {
            cpu->ac[op->dst & 3] = alu40(cpu, src, k, 1, op->dst);
        } else if (op->kind == C55X_OP_AND_K16_SH16) {
            cpu->ac[op->dst & 3] = (src & k) & 0xffffffffull;
        } else if (op->kind == C55X_OP_XOR_K16_SH16) {
            cpu->ac[op->dst & 3] = (src ^ k) & 0xffffffffull;
        } else {
            cpu->ac[op->dst & 3] = (src | k) & 0xffffffffull;
        }
        return 0;
    }
    case C55X_OP_BSET_ST:
        /*
         * RX-34 L125: BSET #4, ST1 left ST1 at the reset value. Bit 4
         * is the top of ASM and did not stick. ST0/ST3 bit 4 did.
         */
        if (!(op->st == 1 && (op->bit & 15) == 4)) {
            *st_ptr(cpu, op->st) |= (uint16_t)(1u << (op->bit & 15));
        }
        if (op->st == 3) {
            c55x_st3_write(cpu, cpu->st3);
        }
        return 0;
    case C55X_OP_BCLR_ST:
        if (!(op->st == 1 && (op->bit & 15) == 4)) {
            *st_ptr(cpu, op->st) &= (uint16_t)~(1u << (op->bit & 15));
        }
        if (op->st == 1 && (op->bit & 15) == 15) {
            cpu->rptb0_active = 0;
            cpu->rptb1_active = 0;
        }
        if (op->st == 3) {
            c55x_st3_write(cpu, cpu->st3);
        }
        return 0;
    case C55X_OP_BSET_BADDR:
    case C55X_OP_BCLR_BADDR:
    case C55X_OP_BTST_BADDR:
    case C55X_OP_BNOT_BADDR: {
        uint32_t bitaddr = 0;
        int is_mmr = 0, is_io = 0;
        uint16_t io_port = 0;
        int32_t post = 0;
        unsigned bit, maxbit, fsss = op->src & 15;
        int in_range;

        /*
         * SPRU374 Baddr: a direct Smem field is the bit number. dis55
         * writes *SP(#k) when CPL=1 for the same encoding — stock
         * _mbx_send `ec3e06` is BNOT bit 31 of AC0, not SP+0x1f.
         */
        if (op->smem.kind == C55X_AM_DIRECT) {
            bitaddr = (uint32_t)op->smem.off;
        } else if (resolve_smem(cpu, &op->smem, mmap, port, &bitaddr,
                                &is_mmr, &is_io, &io_port, &post)) {
            return -1;
        }
        if (fsss < 4) {
            bit = bitaddr & 63;
            maxbit = 39;
        } else {
            bit = bitaddr & 15;
            maxbit = 15;
        }
        in_range = bit <= maxbit;
        src = c55x_get_reg(cpu, op->src);
        if (op->kind == C55X_OP_BTST_BADDR) {
            int hit = in_range && (src & (1ull << bit));

            if (op->st) {
                unsigned bit2 = bit + 1;
                int hit2 = bit2 <= maxbit && (src & (1ull << bit2));

                cpu->st0 = hit ? (cpu->st0 | C55X_ST0_TC1) :
                           (cpu->st0 & (uint16_t)~C55X_ST0_TC1);
                cpu->st0 = hit2 ? (cpu->st0 | C55X_ST0_TC2) :
                           (cpu->st0 & (uint16_t)~C55X_ST0_TC2);
            } else if (op->bit) {
                cpu->st0 = hit ? (cpu->st0 | C55X_ST0_TC2) :
                           (cpu->st0 & (uint16_t)~C55X_ST0_TC2);
            } else {
                cpu->st0 = hit ? (cpu->st0 | C55X_ST0_TC1) :
                           (cpu->st0 & (uint16_t)~C55X_ST0_TC1);
            }
        } else if (in_range) {
            if (op->kind == C55X_OP_BSET_BADDR) {
                src |= 1ull << bit;
            } else if (op->kind == C55X_OP_BCLR_BADDR) {
                src &= ~(1ull << bit);
            } else {
                src ^= 1ull << bit;
            }
            c55x_set_reg(cpu, op->src, src);
        }
        /*
         * RX-34: 0xEC *AR2 with XAR2=0x200 turned plant 0x1234 into
         * 0x1204 for BSET, BCLR, BTSTP, BNOT, and BTST alike. Bits 5:4
         * of the addressed word clear. The AC bit op above still uses
         * the address as the bit number (0x200 -> bit 0).
         */
        if (op->smem.kind != C55X_AM_DIRECT) {
            uint16_t memw = 0;

            if (!smem_read16(cpu, &op->smem, mmap, port, &memw, 0)) {
                smem_write16(cpu, &op->smem, mmap, port,
                             (uint16_t)(memw & (uint16_t)~0x0030u), 0);
            }
        }
        apply_post(cpu, &op->smem, post, 0);
        return 0;
    }
    case C55X_OP_AMAR_XDST: {
        uint32_t word;
        int is_mmr, is_io;
        uint16_t io_port;
        int32_t post;

        if (resolve_smem(cpu, &op->smem, 0, 0, &word, &is_mmr, &is_io,
                         &io_port, &post)) {
            return -1;
        }
        c55x_set_xreg(cpu, op->dst, word);
        apply_post(cpu, &op->smem, post, 0);
        return 0;
    }
    case C55X_OP_ADD_SMEM:
    case C55X_OP_SUB_SMEM:
    case C55X_OP_AND_SMEM:
    case C55X_OP_OR_SMEM:
    case C55X_OP_XOR_SMEM: {
        uint64_t memv, srcv;
        int logic = (op->kind == C55X_OP_AND_SMEM ||
                     op->kind == C55X_OP_OR_SMEM ||
                     op->kind == C55X_OP_XOR_SMEM);
        int dst_ac = (op->dst & 15) < 4;
        int src_ac = (op->src & 15) < 4;

        if (smem_read16(cpu, &op->smem, mmap, port, &mem, 0)) {
            return -1;
        }
        if (op->cond == 2 && !logic) {
            int sh = (int)(op->shft & 0x3f);
            int64_t val;

            if (op->bit) {
                val = (uint16_t)mem;
            } else if (cpu->st1 & C55X_ST1_SXMD) {
                val = (int16_t)mem;
            } else {
                val = (uint16_t)mem;
            }
            if (sh & 32) {
                sh -= 64;
            }
            if (sh >= 0) {
                val <<= sh;
            } else {
                val >>= -sh;
            }
            srcv = pkt_read_ac(cpu, op->src);
            cpu->ac[op->dst & 3] = alu40(cpu, srcv,
                                         (uint64_t)val & C55X_AC_MASK,
                                         op->kind == C55X_OP_SUB_SMEM,
                                         op->dst);
            return 0;
        }
        if (op->cond == 3 && !logic) {
            int sh = (int16_t)pkt_read_t(cpu, (unsigned)op->imm);
            int64_t val = (cpu->st1 & C55X_ST1_SXMD) ? (int16_t)mem
                                                     : (int32_t)(uint16_t)mem;

            if (sh >= 0) {
                val <<= sh;
            } else {
                val >>= -sh;
            }
            srcv = pkt_read_ac(cpu, op->src);
            cpu->ac[op->dst & 3] = alu40(cpu, srcv,
                                         (uint64_t)val & C55X_AC_MASK,
                                         op->kind == C55X_OP_SUB_SMEM,
                                         op->dst);
            return 0;
        }
        if (op->cond == 1 && !logic) {
            int carry = !!(cpu->st0 & C55X_ST0_CARRY);

            memv = (uint16_t)mem;
            srcv = pkt_read_ac(cpu, op->src);
            if (op->kind == C55X_OP_SUB_SMEM) {
                cpu->ac[op->dst & 3] = alu40(cpu, srcv, memv + !carry, 1,
                                             op->dst);
            } else {
                cpu->ac[op->dst & 3] = alu40(cpu, srcv, memv + carry, 0,
                                             op->dst);
            }
            return 0;
        }
        if (logic) {
            memv = (uint16_t)mem;
            srcv = (src_ac && dst_ac) ? c55x_get_reg(cpu, op->src) :
                   (uint16_t)c55x_get_reg(cpu, op->src);
            if (op->kind == C55X_OP_AND_SMEM) {
                srcv &= memv;
            } else if (op->kind == C55X_OP_OR_SMEM) {
                srcv |= memv;
            } else {
                srcv ^= memv;
            }
        } else {
            if (op->st || !(cpu->st1 & C55X_ST1_SXMD)) {
                memv = (uint16_t)mem;
            } else {
                memv = (uint64_t)(int64_t)(int16_t)mem & C55X_AC_MASK;
            }
            if (dst_ac) {
                if (src_ac) {
                    srcv = c55x_get_reg(cpu, op->src);
                } else if (!op->st && (cpu->st1 & C55X_ST1_SXMD)) {
                    srcv = (uint64_t)(int64_t)(int16_t)c55x_get_reg(cpu, op->src) &
                           C55X_AC_MASK;
                } else {
                    srcv = (uint16_t)c55x_get_reg(cpu, op->src);
                }
            } else {
                srcv = (uint16_t)c55x_get_reg(cpu, op->src);
                memv = (uint16_t)mem;
            }
            if (op->kind == C55X_OP_SUB_SMEM) {
                if (op->st) {
                    srcv -= memv;
                } else {
                    srcv = op->bit ? (memv - srcv) : (srcv - memv);
                }
            } else {
                srcv += memv;
            }
        }
        if (dst_ac) {
            cpu->ac[op->dst & 3] = srcv & C55X_AC_MASK;
        } else {
            c55x_set_reg(cpu, op->dst, (uint16_t)srcv);
        }
        return 0;
    }
    case C55X_OP_MOV_K8_SMEM:
    case C55X_OP_MOV_K16_SMEM:
        return smem_write16(cpu, &op->smem, mmap, port, (uint16_t)op->imm, 0);
    case C55X_OP_MOV_SRC_SMEM:
        if (op->cond == 1 || op->cond == 2) {
            uint16_t cur = 0;
            uint16_t byte = (uint16_t)c55x_get_reg(cpu, op->src);

            if (smem_read16(cpu, &op->smem, mmap, port, &cur, 0)) {
                return -1;
            }
            if (op->cond == 2) {
                cur = (uint16_t)((cur & 0x00ff) | ((byte & 0xff) << 8));
            } else {
                cur = (uint16_t)((cur & 0xff00) | (byte & 0xff));
            }
            return smem_write16(cpu, &op->smem, mmap, port, cur, 0);
        }
        return smem_write16(cpu, &op->smem, mmap, port,
                            (uint16_t)c55x_get_reg(cpu, op->src), 0);
    case C55X_OP_MOV_SMEM_DST:
        if (smem_read16(cpu, &op->smem, mmap, port, &mem, 0)) {
            return -1;
        }
        if (op->cond == 1 || op->cond == 2) {
            uint16_t b8 = (op->cond == 2) ? (uint16_t)(mem >> 8) :
                          (uint16_t)(mem & 0xff);

            if (op->bit || !(cpu->st1 & C55X_ST1_SXMD)) {
                c55x_set_reg(cpu, op->dst, b8);
            } else {
                c55x_set_reg(cpu, op->dst,
                             (uint16_t)(int16_t)(int8_t)b8);
            }
            return 0;
        }
        /*
         * SPRU371: MOV Smem, ACx sign-extends the 16-bit load when
         * SXMD is set. c55x_ac_store only extends from bit 31, so a
         * raw 0xffff stays 65535 and the soft-clip cubic turns the
         * tune's −1 into 26701.
         */
        if ((op->dst & 15) < 4) {
            uint64_t acv = (uint16_t)mem;

            if (cpu->st1 & C55X_ST1_SXMD) {
                acv = (uint64_t)(int64_t)(int16_t)mem & C55X_AC_MASK;
            }
            c55x_set_reg(cpu, op->dst, acv);
            return 0;
        }
        c55x_set_reg(cpu, op->dst, mem);
        return 0;
    case C55X_OP_MOV_SMEM_AC:
        if (smem_read16(cpu, &op->smem, mmap, port, &mem, 0)) {
            return -1;
        }
        if (op->bit) {
            cpu->ac[op->dst & 3] = (uint16_t)mem;
        } else if (cpu->st1 & C55X_ST1_SXMD) {
            cpu->ac[op->dst & 3] = (uint64_t)(int64_t)(int16_t)mem &
                                   C55X_AC_MASK;
        } else {
            cpu->ac[op->dst & 3] = (uint16_t)mem;
        }
        return 0;
    case C55X_OP_MOV_SMEM_SHFT: {
        int sh = (int)(op->shft & 0x3f);
        int64_t val;

        if (smem_read16(cpu, &op->smem, mmap, port, &mem, 0)) {
            return -1;
        }
        if (op->bit) {
            val = (uint16_t)mem;
        } else if (cpu->st1 & C55X_ST1_SXMD) {
            val = (int16_t)mem;
        } else {
            val = (uint16_t)mem;
        }
        if (sh & 32) {
            sh -= 64;
        }
        if (sh >= 0) {
            val <<= sh;
        } else {
            val >>= -sh;
        }
        cpu->ac[op->dst & 3] = (uint64_t)val & C55X_AC_MASK;
        return 0;
    }
    case C55X_OP_MOV_AC_DBL: {
        uint32_t value = (uint32_t)pkt_read_ac(cpu, op->src);

        return lmem_write_long(cpu, &op->smem, mmap, port, value);
    }
    case C55X_OP_MOV_XREG_DBL: {
        /*
         * 0x8e MOV XARn, dbl(Smem) || AADD #k, ARn writes the A-unit
         * result. Packet-entry snapshot would store the pre-add XARn
         * and tokliBIOS `_register_mbq` (0x12983a) would enqueue TCFG
         * at the object base instead of the MBQ slot at +18.
         */
        unsigned xsss = op->src & 15;
        uint32_t value = (xsss >= 8)
                         ? (cpu->xar[xsss - 8] & C55X_WORD_MASK)
                         : c55x_get_xreg(cpu, op->src);

        return lmem_write_long(cpu, &op->smem, mmap, port, value);
    }
    case C55X_OP_MOV_PAIR_DBL: {
        unsigned base = op->src & 14;
        /*
         * SPRU374 pair(T2) is T2 at the even/MSW word and T3 at the
         * odd/LSW word. _KNL_switch saves with `eb106c_98` and restores
         * with `ed106e_98`. Packing T2 in the LSW swaps them, so the
         * nested mailbox switch returns T3=0 into mumdrc main_loop
         * (`MOV T3,T0` → BRC0=0xffff, missing POLL tids).
         */
        uint32_t value = ((uint32_t)(uint16_t)c55x_get_reg(cpu, base) << 16) |
                         (uint16_t)c55x_get_reg(cpu, base + 1);

        return lmem_write_long(cpu, &op->smem, mmap, port, value);
    }
    case C55X_OP_MOV_DBL_XDST: {
        uint32_t value;

        if (lmem_read_xaddr(cpu, &op->smem, mmap, port, &value)) {
            return -1;
        }
        c55x_set_xreg(cpu, op->dst, value);
        /*
         * The convert call's XAR1 dword says 0x20d000 / 0x20d800.
         * Those words stay zero. The tune is in the esd mmap at
         * 0x218000, with the other channel 0x800 words later.
         */
        if ((cpu->pc & C55X_PC_MASK) == 0x132ff0u ||
            (cpu->pc & C55X_PC_MASK) == 0x132fffu) {
            unsigned xdst = op->dst & 15;
            uint32_t ptr;

            if (xdst >= 8) {
                ptr = cpu->xar[xdst - 8] & C55X_WORD_MASK;
                /* 0x20d000 + 0xB000 = 0x218000. Later calls advance
                 * the same window (0x20d0dc, 0x20d800, ...). */
                if ((ptr & 0xfff000u) == 0x20d000u) {
                    static unsigned page_logs;
                    int peak = 0;
                    unsigned wi;

                    c55x_set_xreg(cpu, op->dst, ptr + 0xb000u);
                    for (wi = 0; wi < 8u; wi++) {
                        int v = abs((int16_t)peek16(cpu, ptr + 0xb000u + wi));

                        if (v > peak) {
                            peak = v;
                        }
                    }
                    if (page_logs < 12u || peak > 0) {
                        if (page_logs < 24u) {
                            eap_pcm_stat(
                                "t=page pc=%06x xdst=%u ptr=%06x peak=%d\n",
                                cpu->pc & C55X_PC_MASK, xdst, ptr, peak);
                            page_logs++;
                        }
                    }
                }
            }
        }
        if ((op->dst & 15) == 4 || (op->dst & 15) == 5) {
            c55x_log(cpu,
                     "XREG-load pc=%06x dst=%u value=%06x XSP=%06x XSSP=%06x\n",
                     cpu->pc, op->dst & 15, value,
                     cpu->xsp & C55X_WORD_MASK, cpu->xssp & C55X_WORD_MASK);
        }
        return 0;
    }
    case C55X_OP_MOV_DBL_PAIR: {
        uint32_t value;
        unsigned pair = op->dst & 3;
        uint16_t hi, lo;

        if (lmem_read_long(cpu, &op->smem, mmap, port, &value)) {
            return -1;
        }
        hi = (uint16_t)(value >> 16);
        lo = (uint16_t)value;
        if (op->cond == 2) {
            unsigned n = op->dst & 2;

            /* Even/MSW → even Tx (pair(T2): T2=MSW, T3=LSW). */
            cpu->t[n] = hi;
            cpu->t[n + 1] = lo;
        } else if (op->cond == 1) {
            cpu->ac[pair] = hi;
            cpu->ac[(pair + 1) & 3] = lo;
        } else {
            cpu->ac[pair] = (uint64_t)hi << 16;
            cpu->ac[(pair + 1) & 3] = (uint64_t)lo << 16;
        }
        return 0;
    }
    case C55X_OP_MOV_DBL_RETA: {
        uint32_t value;

        if (c55x_read_lmem32(cpu, &op->smem, mmap, port, &value)) {
            return -1;
        }
        cpu->cfct = (uint16_t)(value >> 24);
        cpu->reta = value & C55X_PC_MASK;
        restore_loop_context(cpu, (uint8_t)cpu->cfct);
        if (cpu->flow_verbose || pc_is_wild(cpu->reta)) {
            c55x_log(cpu,
                     "FLOW-RETA-LOAD pc=%06x RETA=%06x CFCT=%02x "
                     "rpt=%u/%u/%u\n",
                     cpu->pc, cpu->reta & C55X_PC_MASK, cpu->cfct & 0xff,
                     cpu->rpt_armed, cpu->rpt_active, cpu->rpt_cc);
        }
        return 0;
    }
    case C55X_OP_MOV_RETA_DBL: {
        uint32_t value = ((uint32_t)(cpu->cfct & 0xff) << 24) |
                         (cpu->reta & C55X_PC_MASK);

        return c55x_write_lmem32(cpu, &op->smem, mmap, port, value);
    }
    case C55X_OP_MOV_DBL_AC: {
        uint32_t longword;

        if (lmem_read_long(cpu, &op->smem, mmap, port, &longword)) {
            return -1;
        }
        cpu->ac[op->dst & 3] = ac_from_lmem32(cpu, longword);
        return 0;
    }
    case C55X_OP_ADD_DBL_AC:
    case C55X_OP_SUB_DBL_AC:
    case C55X_OP_RSUB_DBL_AC: {
        uint32_t longword;
        uint64_t lmem;
        uint64_t src_ac = pkt_read_ac(cpu, op->src);
        uint64_t result;

        if (lmem_read_long(cpu, &op->smem, mmap, port, &longword)) {
            return -1;
        }
        lmem = ac_from_lmem32(cpu, longword);
        if (op->kind == C55X_OP_ADD_DBL_AC) {
            result = alu40(cpu, src_ac, lmem, 0, op->dst);
        } else if (op->kind == C55X_OP_SUB_DBL_AC) {
            result = alu40(cpu, src_ac, lmem, 1, op->dst);
        } else {
            result = alu40(cpu, lmem, src_ac, 1, op->dst);
        }
        cpu->ac[op->dst & 3] = result;
        return 0;
    }
    case C55X_OP_AND_K16_SMEM:
    case C55X_OP_OR_K16_SMEM:
    case C55X_OP_XOR_K16_SMEM:
    case C55X_OP_ADD_K16_SMEM:
        if (smem_read16(cpu, &op->smem, mmap, port, &mem, 0)) {
            return -1;
        }
        if (op->kind == C55X_OP_AND_K16_SMEM) {
            mem &= (uint16_t)op->imm;
        } else if (op->kind == C55X_OP_OR_K16_SMEM) {
            mem |= (uint16_t)op->imm;
        } else if (op->kind == C55X_OP_XOR_K16_SMEM) {
            mem ^= (uint16_t)op->imm;
        } else {
            mem = (uint16_t)(mem + (uint16_t)op->imm);
        }
        return smem_write16(cpu, &op->smem, mmap, port, mem, 0);
    case C55X_OP_MOV_K16_CTL:
        mov_k16_ctl(cpu, op->dst, op->imm);
        return 0;
    case C55X_OP_B_L7:
    case C55X_OP_B_L16:
        *next_pc = (cpu->pc + in->length + op->imm) & C55X_PC_MASK;
        if (op->kind == C55X_OP_B_L16 &&
            (cpu->pc & C55X_PC_MASK) == PCM1_PC_CMD1_B &&
            pcm1_cmd_at_ar6(cpu) == 1) {
            *next_pc = PCM1_PC_CMD1_SEND10;
            eap_pcm_stat("pcm1-cmd1-send10 from=%06x dest=%06x T1=%04x\n",
                         cpu->pc & C55X_PC_MASK, *next_pc, cpu->t[1]);
        }
        if (op->kind == C55X_OP_B_L16 &&
            (cpu->pc & C55X_PC_MASK) == 0x124d3du) {
            uint32_t ar6 = cpu->xar[6] & C55X_WORD_MASK;

            eap_pcm_stat(
                "pcm1-cmd8-send AR6=%06x cmd=%04x w1=%04x w4=%04x w5=%04x "
                "cf34=%04x T1=%04x\n",
                ar6, peek16(cpu, ar6),
                peek16(cpu, (ar6 + 1u) & C55X_WORD_MASK),
                peek16(cpu, (ar6 + 4u) & C55X_WORD_MASK),
                peek16(cpu, (ar6 + 5u) & C55X_WORD_MASK),
                peek16(cpu, PCM1_WORD_MODE), cpu->t[1]);
        }
        flow_log_branch(cpu, "B", *next_pc);
        return 0;
    case C55X_OP_B_P24:
        *next_pc = op->target;
        flow_log_branch(cpu, "B", *next_pc);
        return 0;
    case C55X_OP_IVEC:
        /*
         * dis55 .ivec is a delayed B P24: the rest of the 8-byte slot
         * (MOV #n, mmap(@BIOS) or NOP_16) runs, then the branch.
         * accept_irq already saved the interrupted PC using this
         * slot's C54X_STK (`ea`) vs USE_RETA (`ca`) lead.
         */
        cpu->br_delay_target = op->target & C55X_PC_MASK;
        cpu->br_delay_pending = 1;
        c55x_log(cpu, "IVEC pc=%06x dest=%06x %s\n",
                 cpu->pc, cpu->br_delay_target,
                 op->bit ? "C54X_STK" : "USE_RETA");
        return 0;
    case C55X_OP_B_AC:
        *next_pc = (uint32_t)pkt_read_ac(cpu, op->src) & C55X_PC_MASK;
        flow_log_branch(cpu, "B", *next_pc);
        return 0;
    case C55X_OP_CALL_P24:
        cpu->ret_pc = (cpu->pc + in->length) & C55X_PC_MASK;
        *next_pc = op->target;
        call_taken(cpu, *next_pc, cpu->ret_pc);
        return 0;
    case C55X_OP_CALL_AC:
        cpu->ret_pc = (cpu->pc + in->length) & C55X_PC_MASK;
        *next_pc = (uint32_t)pkt_read_ac(cpu, op->src) & C55X_PC_MASK;
        call_taken(cpu, *next_pc, cpu->ret_pc);
        if ((*next_pc & 0xff0000u) >= 0x200000u || *next_pc == 0) {
            c55x_log(cpu,
                     "CALL-AC pc=%06x target=%06x RETA=%06x AC0=%010llx "
                     "AR5=%06x nest=%u\n",
                     cpu->pc, *next_pc, cpu->reta & C55X_PC_MASK,
                     (unsigned long long)cpu->ac[0],
                     cpu->xar[5] & C55X_WORD_MASK, cpu->irq_nest);
            if (*next_pc == 0 && (cpu->pc & C55X_PC_MASK) == 0x1012fbu) {
                knlq_note_call0(cpu);
            }
        }
        return 0;
    case C55X_OP_CALL_L16:
        cpu->ret_pc = (cpu->pc + in->length) & C55X_PC_MASK;
        *next_pc = (cpu->pc + in->length + op->imm) & C55X_PC_MASK;
        call_taken(cpu, *next_pc, cpu->ret_pc);
        return 0;
    case C55X_OP_CALLCC_L16:
        if (c55x_eval_cond(cpu, op->cond)) {
            cpu->ret_pc = (cpu->pc + in->length) & C55X_PC_MASK;
            *next_pc = (cpu->pc + in->length + op->imm) & C55X_PC_MASK;
            call_taken(cpu, *next_pc, cpu->ret_pc);
        }
        return 0;
    case C55X_OP_BCC_L8:
    case C55X_OP_BCC_L16:
        if (c55x_eval_cond(cpu, op->cond)) {
            *next_pc = (cpu->pc + in->length + op->imm) & C55X_PC_MASK;
            flow_log_branch(cpu, "BCC", *next_pc);
        }
        return 0;
    case C55X_OP_BCC_P24:
        if (c55x_eval_cond(cpu, op->cond)) {
            *next_pc = op->target;
            flow_log_branch(cpu, "BCC", *next_pc);
        }
        return 0;
    case C55X_OP_BCC_SRC_K8:
        if (cmp_src_k8(cpu, op)) {
            *next_pc = (cpu->pc + in->length + (int32_t)op->target) &
                       C55X_PC_MASK;
            flow_log_branch(cpu, "BCC", *next_pc);
        }
        return 0;
    case C55X_OP_RET:
    case C55X_OP_RETI:
        if (op->kind == C55X_OP_RETI) {
            *next_pc = return_taken(cpu, "RETI", 1);
            cpu->st1 &= (uint16_t)~C55X_ST1_INTM;
        } else {
            *next_pc = return_taken(cpu, "RET", 0);
        }
        if (pc_is_wild(*next_pc)) {
            c55x_log(cpu,
                     "RET-WILD pc=%06x target=%06x RETA=%06x CFCT=%02x "
                     "XSP=%06x XSSP=%06x IVPD=%04x\n",
                     cpu->pc, *next_pc, cpu->reta & C55X_PC_MASK,
                     cpu->cfct & 0xff, cpu->xsp & C55X_WORD_MASK,
                     cpu->xssp & C55X_WORD_MASK, cpu->ivpd);
        }
        return 0;
    case C55X_OP_PSH_SRC:
        push16(cpu, (uint16_t)c55x_get_reg(cpu, op->src));
        return 0;
    case C55X_OP_POP_DST:
        c55x_set_reg(cpu, op->dst, pop16(cpu));
        return 0;
    case C55X_OP_PSH_PAIR:
        /* SPRU374: SP -= 2; [SP]=src1; [SP+1]=src2 */
        push16(cpu, (uint16_t)c55x_get_reg(cpu, op->dst));
        push16(cpu, (uint16_t)c55x_get_reg(cpu, op->src));
        return 0;
    case C55X_OP_POP_PAIR:
        set_reg_low16(cpu, op->dst, pop16(cpu));
        set_reg_low16(cpu, op->src, pop16(cpu));
        return 0;
    case C55X_OP_AMAR_SMEM: {
        uint32_t word;
        int is_mmr, is_io;
        uint16_t io_port;
        int32_t post;

        if (resolve_smem(cpu, &op->smem, mmap, port, &word, &is_mmr, &is_io,
                         &io_port, &post)) {
            return -1;
        }
        apply_post(cpu, &op->smem, post, 0);
        return 0;
    }
    case C55X_OP_PSH_SMEM:
        if (smem_read16(cpu, &op->smem, mmap, port, &mem, 0)) {
            return -1;
        }
        push16(cpu, mem);
        return 0;
    case C55X_OP_POP_SMEM:
        return smem_write16(cpu, &op->smem, mmap, port, pop16(cpu), 0);
    case C55X_OP_PSH_DBL_LMEM: {
        uint32_t val;

        if (lmem_read_long(cpu, &op->smem, mmap, port, &val)) {
            return -1;
        }
        /* SPRU374: [SP]=Lmem MSW, [SP+1]=LSW; SP -= 2 */
        push16(cpu, (uint16_t)val);
        push16(cpu, (uint16_t)(val >> 16));
        return 0;
    }
    case C55X_OP_POP_DBL_LMEM: {
        uint16_t hi = pop16(cpu);
        uint16_t lo = pop16(cpu);

        return lmem_write_long(cpu, &op->smem, mmap, port,
                               ((uint32_t)hi << 16) | lo);
    }
    case C55X_OP_MOV_HI_SMEM:
        return smem_write16(cpu, &op->smem, mmap, port,
                            (uint16_t)(pkt_read_ac(cpu, op->src) >> 16), 0);
    case C55X_OP_MOV_AC_SHFT_SMEM:
    case C55X_OP_MOV_HI_AC_SHFT_SMEM: {
        int sh = (op->cond == 2 &&
                  (op->kind == C55X_OP_MOV_HI_AC_SHFT_SMEM ||
                   op->kind == C55X_OP_MOV_AC_SHFT_SMEM)) ?
                 (int16_t)pkt_read_t(cpu, op->shft) : shiftw6(op->shft);
        int arith = !!(cpu->st1 & C55X_ST1_SXMD);
        uint64_t val;

        if (op->kind == C55X_OP_MOV_HI_AC_SHFT_SMEM && op->bit) {
            arith = 0;
        }

        if (op->kind == C55X_OP_MOV_AC_SHFT_SMEM && op->cond == 1) {
            /* MOV low/high_byte(Smem) << #SHIFTW, ACx. bit=1 selects the high byte. */
            if (smem_read16(cpu, &op->smem, mmap, port, &mem, 0)) {
                return -1;
            }
            val = op->bit ? ((uint16_t)mem >> 8) : ((uint16_t)mem & 0xff);
            cpu->ac[op->src & 3] = ac_shift(val, sh, 0);
            return 0;
        }
        val = ac_shift(pkt_read_ac(cpu, op->src), sh, arith);

        if (op->kind == C55X_OP_MOV_HI_AC_SHFT_SMEM) {
            if (op->st >= 2) {
                int64_t s = (int64_t)(val << 24) >> 24;

                if (s > 0x7fffffffLL) {
                    s = 0x7fffffffLL;
                } else if (s < -0x80000000LL) {
                    s = -0x80000000LL;
                }
                val = (uint64_t)s & C55X_AC_MASK;
            }
            if (op->st == 1 || op->st == 3) {
                val = (val + 0x8000ull) & C55X_AC_MASK;
            }
            val >>= 16;
        } else if (op->cond == 1) {
            val &= 0xffull;
        }
        return smem_write16(cpu, &op->smem, mmap, port, (uint16_t)val, 0);
    }
    case C55X_OP_CMP:
    case C55X_OP_CMPAND:
    case C55X_OP_CMPOR: {
        int cmp = cmp_regs(cpu, op);
        int other = get_tcx(cpu, op->shft);

        if (op->imm) {
            other = !other;
        }
        if (op->kind == C55X_OP_CMPAND) {
            cmp = cmp && other;
        } else if (op->kind == C55X_OP_CMPOR) {
            cmp = cmp || other;
        }
        set_tcx(cpu, op->bit, cmp);
        return 0;
    }
    case C55X_OP_MOV_K12_CTL: {
        unsigned k = (unsigned)op->imm & 0xfff;

        switch (op->dst) {
        case 0x00:
            cpu->xdp = (cpu->xdp & 0xffffu) | ((uint32_t)(k & 0x7f) << 16);
            cpu->xdp &= C55X_WORD_MASK;
            return 0;
        case 0x03:
            cpu->pdp = (uint16_t)(k & 0x1ff);
            return 0;
        case 0x04:
            cpu->bk03 = (uint16_t)k;
            return 0;
        case 0x05:
            cpu->bk47 = (uint16_t)k;
            return 0;
        case 0x06:
            cpu->bkc = (uint16_t)k;
            return 0;
        case 0x08:
            cpu->csr = (uint16_t)k;
            return 0;
        case 0x09:
            cpu->brc0 = (uint16_t)k;
            return 0;
        case 0x0a:
            cpu->brc1 = (uint16_t)k;
            return 0;
        default:
            return -1;
        }
    }
    case C55X_OP_CMP_SMEM_K16:
        if (smem_read16(cpu, &op->smem, mmap, port, &mem, 0)) {
            return -1;
        }
        set_tcx(cpu, op->bit, mem == (uint16_t)op->imm);
        return 0;
    case C55X_OP_BAND:
        if (smem_read16(cpu, &op->smem, mmap, port, &mem, 0)) {
            return -1;
        }
        set_tcx(cpu, op->bit, (mem & (uint16_t)op->imm) != 0);
        return 0;
    case C55X_OP_BTST_SRC_SMEM: {
        unsigned k = (unsigned)c55x_get_reg(cpu, op->src) & 15;
        uint16_t mask = (uint16_t)(1u << k);

        if (smem_read16(cpu, &op->smem, mmap, port, &mem, 0)) {
            return -1;
        }
        set_tcx(cpu, op->bit, !!(mem & mask));
        return 0;
    }
    case C55X_OP_PSH_SRC_SMEM:
        if (smem_read16(cpu, &op->smem, mmap, port, &mem, 0)) {
            return -1;
        }
        push16(cpu, mem);
        push16(cpu, (uint16_t)c55x_get_reg(cpu, op->src));
        return 0;
    case C55X_OP_POP_DST_SMEM: {
        uint16_t dstv = pop16(cpu);
        uint16_t memv = pop16(cpu);

        set_reg_low16(cpu, op->dst, dstv);
        return smem_write16(cpu, &op->smem, mmap, port, memv, 0);
    }
    case C55X_OP_BCC_ARN: {
        uint32_t word;
        int is_mmr, is_io;
        uint16_t io_port;
        int32_t post;

        if (op->smem.kind != C55X_AM_AR) {
            return 0;
        }
        if (resolve_smem(cpu, &op->smem, mmap, port, &word, &is_mmr, &is_io,
                         &io_port, &post)) {
            return -1;
        }
        apply_post(cpu, &op->smem, post, 0);
        if (cpu->xar[op->smem.ar & 7] & C55X_WORD_MASK) {
            *next_pc = (cpu->pc + in->length + op->imm) & C55X_PC_MASK;
        }
        return 0;
    }
    case C55X_OP_BTST_K4_SMEM: {
        unsigned k = (unsigned)op->imm & 15;
        uint16_t mask = (uint16_t)(1u << k);

        if (smem_read16(cpu, &op->smem, mmap, port, &mem, 0)) {
            return -1;
        }
        set_tcx(cpu, op->bit, !!(mem & mask));
        if (op->st == 1) {
            mem |= mask;
        } else if (op->st == 2) {
            mem &= (uint16_t)~mask;
        } else if (op->st == 3) {
            mem ^= mask;
        } else {
            return 0;
        }
        return smem_write16(cpu, &op->smem, mmap, port, mem, 0);
    }
    case C55X_OP_BSET_SMEM:
    case C55X_OP_BCLR_SMEM:
    case C55X_OP_BNOT_SMEM: {
        unsigned k = (unsigned)c55x_get_reg(cpu, op->src) & 15;
        uint16_t mask = (uint16_t)(1u << k);

        if (smem_read16(cpu, &op->smem, mmap, port, &mem, 0)) {
            return -1;
        }
        if (op->kind == C55X_OP_BSET_SMEM) {
            mem |= mask;
        } else if (op->kind == C55X_OP_BCLR_SMEM) {
            mem &= (uint16_t)~mask;
        } else {
            mem ^= mask;
        }
        return smem_write16(cpu, &op->smem, mmap, port, mem, 0);
    }
    case C55X_OP_AADD_K8_SP:
        cpu->xsp = xar_plus(cpu->xsp, op->imm);
        cpu->sp_written = 1;
        return 0;
    case C55X_OP_AADD_K8_TAX:
        tax_add_imm(cpu, op->dst, op->imm);
        return 0;
    case C55X_OP_AMOV_K8_TAX:
    case C55X_OP_AMOV_D16:
        c55x_set_reg(cpu, op->dst, (uint16_t)op->imm);
        return 0;
    case C55X_OP_ASUB_K8_TAX:
        tax_add_imm(cpu, op->dst, -op->imm);
        return 0;
    case C55X_OP_AADD_TAX:
        if (op->bit) {
            c55x_set_xreg(cpu, op->dst,
                          c55x_get_xreg(cpu, op->dst) +
                          c55x_get_xreg(cpu, op->src));
            return 0;
        }
        tax_add_imm(cpu, op->dst, (int16_t)c55x_get_reg(cpu, op->src));
        return 0;
    case C55X_OP_AMOV_TAX:
        if (op->bit) {
            c55x_set_xreg(cpu, op->dst, c55x_get_xreg(cpu, op->src));
            return 0;
        }
        c55x_set_reg(cpu, op->dst, c55x_get_reg(cpu, op->src));
        return 0;
    case C55X_OP_ASUB_TAX:
        if (op->bit) {
            c55x_set_xreg(cpu, op->dst,
                          c55x_get_xreg(cpu, op->dst) -
                          c55x_get_xreg(cpu, op->src));
            return 0;
        }
        tax_add_imm(cpu, op->dst, -(int16_t)c55x_get_reg(cpu, op->src));
        return 0;
    case C55X_OP_RPT_K8:
    case C55X_OP_RPT_K16:
        cpu->rpt_left = (uint16_t)op->imm;
        cpu->rpt_armed = 1;
        cpu->rpt_active = 0;
        cpu->rpt_cc = 0;
        cpu->rptc = cpu->rpt_left;
        return 0;
    case C55X_OP_PSHBOTH: {
        uint32_t value = c55x_get_xreg(cpu, op->src);

        if (op->src < 4) {
            value = (uint32_t)pkt_read_ac(cpu, op->src);
        }
        push16(cpu, (uint16_t)value);
        push_ssp(cpu, (uint16_t)(value >> 16));
        return 0;
    }
    case C55X_OP_PSH_DBL_AC: {
        uint64_t ac = pkt_read_ac(cpu, op->src);

        /* SPRU374: [SP]=ACx(31–16), [SP+1]=ACx(15–0); SP -= 2 */
        push16(cpu, (uint16_t)ac);
        push16(cpu, (uint16_t)(ac >> 16));
        return 0;
    }
    case C55X_OP_POP_DBL_AC: {
        uint16_t hi = pop16(cpu);
        uint16_t lo = pop16(cpu);
        unsigned ac = op->dst & 3;

        cpu->ac[ac] = (cpu->ac[ac] & 0xff00000000ull) |
                      ((uint64_t)hi << 16) | lo;
        return 0;
    }
    case C55X_OP_POPBOTH: {
        uint16_t hi = pop_ssp(cpu);
        uint16_t lo = pop16(cpu);
        uint32_t value = ((uint32_t)hi << 16) | lo;

        if (op->dst < 4) {
            cpu->ac[op->dst & 3] = (pkt_read_ac(cpu, op->dst) &
                                   ~0xffffffffull) | value;
        } else {
            c55x_set_xreg(cpu, op->dst, value);
        }
        return 0;
    }
    case C55X_OP_RPT_CSR:
        cpu->rpt_left = cpu->pkt_src_valid ? cpu->pkt_csr : cpu->csr;
        cpu->rpt_armed = 1;
        cpu->rpt_active = 0;
        cpu->rpt_cc = 0;
        cpu->rptc = cpu->rpt_left;
        return 0;
    case C55X_OP_MPYMK:
    case C55X_OP_MACMK: {
        int32_t k = (int8_t)op->imm;
        int64_t prod;

        mem = 0;
        if (smem_read16(cpu, &op->smem, mmap, port, &mem, 0)) {
            return -1;
        }
        if (op->bit) {
            cpu->t[3] = mem;
        }
        prod = (int64_t)(int16_t)mem * (int64_t)k;
        if (cpu->st1 & C55X_ST1_FRCT) {
            prod <<= 1;
        }
        if (op->kind == C55X_OP_MACMK) {
            cpu->ac[op->dst & 3] = alu40(cpu, pkt_read_ac(cpu, op->src),
                                         (uint64_t)prod & C55X_AC_MASK,
                                         0, op->dst);
        } else {
            cpu->ac[op->dst & 3] = (uint64_t)prod & C55X_AC_MASK;
        }
        return 0;
    }
    case C55X_OP_MPYK_K16: {
        int32_t hi = (int16_t)((pkt_read_ac(cpu, op->src) >> 16) & 0xffffu);
        int32_t k = (int16_t)op->imm;
        int64_t prod = (int64_t)hi * (int64_t)k;

        /* SPRU374: multiply ACx(32–16) × K16; FRCT shifts the product. */
        if (cpu->st1 & C55X_ST1_FRCT) {
            prod <<= 1;
        }
        (void)op->bit;
        cpu->ac[op->dst & 3] = (uint64_t)prod & C55X_AC_MASK;
        return 0;
    }
    case C55X_OP_RPTB:
    case C55X_OP_RPTBLOCAL: {
        uint32_t rsa = (cpu->pc + in->length) & C55X_PC_MASK;
        /*
         * SPRU374: REA is the first byte of the last instruction.
         * Encoded l16 is pmad - RSA (dis55 `RPTB #0x1033d4 || MOV #0,T1`
         * is `0e 00 6b 3d 05`: RSA=0x103369, l16=0x006b, REA=0x1033d4).
         * The earlier RSA+l16-1 rule assumed a 3-byte singleton RPTB.
         */
        uint32_t rea = (rsa + (op->target & 0xffffu)) & C55X_PC_MASK;

        /*
         * Nested RPTB is only for a second block whose setup sits inside
         * the live outer [RSA0, REA0]. Stock `_DEV_match` and
         * `_EAP_CC_RequestStream` BCC out of a block and later issue a
         * new RPTB at a different address; that is a new outer loop
         * (BRC0), not BRC1=BRS1. Leaving the abandoned block active made
         * `/eap`+0008 compare only `'/'` and SELECT `/audio`.
         */
        if (!cpu->rptb0_active ||
            !rptb_pc_in_block(cpu->pc, cpu->rsa0, cpu->rea0)) {
            if (cpu->rptb0_active && rptb_trace_enabled(cpu)) {
                c55x_log(cpu,
                         "RPTB pc=%06x replace abandoned "
                         "RSA0=%06x REA0=%06x\n",
                         cpu->pc, cpu->rsa0, cpu->rea0);
            }
            cpu->rsa0 = rsa;
            cpu->rea0 = rea;
            cpu->rptb0_active = 1;
            cpu->rptb1_active = 0;
            cpu->st1 |= C55X_ST1_BRAF;
            c55x_log(cpu, "RPTB pc=%06x BRC0=%04x RSA0=%06x REA0=%06x\n",
                     cpu->pc, cpu->brc0, rsa, rea);
        } else {
            /*
             * The inner count is the BRC1 the block just loaded.
             * avs_kernel's double-stage convert does
             * `MOV #4095, BRC1` and then this RPTB; the only BRS1
             * accesses in that image are push/pop. Copying BRS1
             * here replaced 4095 with 0, so the filter stage ran
             * once and the resampler repeated a handful of samples.
             */
            cpu->rsa1 = rsa;
            cpu->rea1 = rea;
            cpu->rptb1_active = 1;
            cpu->st1 |= C55X_ST1_BRAF;
            c55x_log(cpu, "RPTB pc=%06x BRC1=%04x BRS1=%04x RSA1=%06x REA1=%06x\n",
                     cpu->pc, cpu->brc1, cpu->brs1, rsa, rea);
        }
        return 0;
    }
    case C55X_OP_MOV_XMEM_YMEM: {
        uint32_t xaddr;
        uint32_t yaddr;
        uint16_t value = 0;
        int x_mmr = 0, y_mmr = 0;

        xaddr = dual_ar_addr(cpu, &op->smem);
        yaddr = dual_ar_addr(cpu, &op->ymem);

        smem_alias_mmr(xaddr, 0, &x_mmr);
        smem_alias_mmr(yaddr, 0, &y_mmr);
        if (x_mmr) {
            value = c55x_mmr_read(cpu, xaddr);
        } else if (!cpu->bus.read16 ||
                   cpu->bus.read16(cpu->bus.opaque, xaddr, &value)) {
            return -1;
        }
        if (y_mmr) {
            c55x_mmr_write(cpu, yaddr, value);
        } else if (data_write16(cpu, yaddr, value)) {
            return -1;
        }
        dual_ar_commit(cpu, &op->smem, 1);
        dual_ar_commit(cpu, &op->ymem, 1);
        return 0;
    }
    case C55X_OP_MOV_DBL_XY: {
        uint32_t xw, yw, x_msw_a, x_lsw_a, y_msw_a, y_lsw_a;
        int x_mmr, y_mmr, x_io, y_io;
        uint16_t x_port, y_port, msw = 0, lsw = 0;
        int32_t xpost, ypost;

        if (resolve_smem(cpu, &op->smem, 0, 0, &xw, &x_mmr, &x_io,
                         &x_port, &xpost) ||
            resolve_smem(cpu, &op->ymem, 0, 0, &yw, &y_mmr, &y_io,
                         &y_port, &ypost)) {
            return -1;
        }
        lmem_dbl_pair(xw, &x_msw_a, &x_lsw_a);
        lmem_dbl_pair(yw, &y_msw_a, &y_lsw_a);
        /*
         * SPRU371F: data addresses in 0x00..0x5f are the CPU MMR overlay
         * (SP at 0x18). Stock mumdrc RPTB `MOV dbl(*ARx+),dbl(*ARy+)` must
         * update XSP when the Y pointer page-wraps into that range — raw
         * bus writes only touch the DARAM shadow and leave SP stale, which
         * later yields BRC0=0xfffe QMF stomps and null-handle _QUE_get.
         */
        if (lmem_read_words(cpu, x_msw_a, x_lsw_a, x_mmr, x_io, &msw, &lsw) ||
            lmem_write_words(cpu, y_msw_a, y_lsw_a, y_mmr, y_io, msw, lsw)) {
            return -1;
        }
        lmem_note(cpu, xw, msw, lsw);
        apply_post(cpu, &op->smem, xpost, 1);
        apply_post(cpu, &op->ymem, ypost, 1);
        return 0;
    }
    case C55X_OP_IDLE:
        /*
         * RX-34 one-step L245 (IER=0) retires IDLE and runs the
         * mailbox save that follows. Firmware _issue_idle sets IER
         * first and still waits for IFR & IER.
         */
        if ((cpu->ier0 | cpu->ier1 | cpu->dbier0 | cpu->dbier1) == 0) {
            return 0;
        }
        cpu->halt = C55X_HALT_IDLE;
        c55x_log(cpu,
                 "IDLE pc=%06x IER0=%04x IFR0=%04x IER1=%04x IFR1=%04x "
                 "INTM=%u irq_pend=%u insn=%llu\n",
                 cpu->pc & C55X_PC_MASK, cpu->ier0, cpu->ifr0,
                 cpu->ier1, cpu->ifr1, !!(cpu->st1 & C55X_ST1_INTM),
                 ((cpu->ifr0 & cpu->ier0) != 0) ||
                 ((cpu->ifr1 & cpu->ier1) != 0),
                 (unsigned long long)cpu->insn_count);
        return 0;
    case C55X_OP_RESET:
        c55x_reset(cpu);
        return 0;
    case C55X_OP_INTR:
    case C55X_OP_TRAP:
        cpu->ifr0 |= (uint16_t)(1u << (op->imm & 15));
        return 0;
    case C55X_OP_EXP: {
        int m40 = !!(cpu->st1 & C55X_ST1_M40);
        int width = m40 ? 40 : 32;
        uint64_t mask = m40 ? C55X_AC_MASK : 0xffffffffull;
        uint64_t ac = pkt_read_ac(cpu, op->src) & mask;
        int expv;

        if (ac == 0) {
            /* RX-34: EXP of AC0=0 stores 0 in T0. */
            expv = 0;
        } else {
            int sign = (int)((ac >> (width - 1)) & 1);
            int i;

            expv = 0;
            for (i = width - 2; i >= 0; i--) {
                if ((int)((ac >> i) & 1) != sign) {
                    break;
                }
                expv++;
            }
        }
        cpu->t[op->dst & 3] = (uint16_t)expv;
        return 0;
    }
    case C55X_OP_MPY_TX:
    case C55X_OP_MAC_TX:
    case C55X_OP_MAS_TX:
    case C55X_OP_MPY_AC:
    case C55X_OP_SQA:
    case C55X_OP_SQS:
    case C55X_OP_SQR: {
        int16_t xa, xb;
        uint64_t prod;

        if (op->kind == C55X_OP_MPY_TX || op->kind == C55X_OP_MAC_TX ||
            op->kind == C55X_OP_MAS_TX) {
            xa = (int16_t)pkt_read_t(cpu, (unsigned)op->imm);
            xb = ac_hi(cpu, op->src);
        } else if (op->kind == C55X_OP_MPY_AC) {
            xa = ac_hi(cpu, op->src);
            xb = ac_hi(cpu, op->dst);
        } else {
            xa = ac_hi(cpu, op->src);
            xb = xa;
        }
        prod = mpy16(cpu, xa, xb, op->bit);
        if (op->kind == C55X_OP_MAC_TX && op->st) {
            /* SPRU374: ACy = (ACy * Tx) + ACx */
            prod = mpy16(cpu, ac_hi(cpu, op->dst),
                         (int16_t)pkt_read_t(cpu, (unsigned)op->imm),
                         op->bit);
            cpu->ac[op->dst & 3] = alu40(cpu, pkt_read_ac(cpu, op->src),
                                         prod, 0, op->dst);
        } else if (op->kind == C55X_OP_MAC_TX || op->kind == C55X_OP_SQA) {
            cpu->ac[op->dst & 3] = alu40(cpu, pkt_read_ac(cpu, op->dst),
                                         prod, 0, op->dst);
        } else if (op->kind == C55X_OP_MAS_TX || op->kind == C55X_OP_SQS) {
            cpu->ac[op->dst & 3] = alu40(cpu, pkt_read_ac(cpu, op->dst),
                                         prod, 1, op->dst);
        } else {
            cpu->ac[op->dst & 3] = prod;
        }
        return 0;
    }
    case C55X_OP_ADDV:
        /*
         * SPRU374 ADD[R]V: ACy += HI(ACx) (bits 31:16), not full ACx.
         * Silicon L168: AC1=0x50000, AC0=0x30000 → AC1=0x50003.
         */
        cpu->ac[op->dst & 3] = alu40(cpu, pkt_read_ac(cpu, op->dst),
                                     (pkt_read_ac(cpu, op->src) >> 16) &
                                     0xffffull, 0, op->dst);
        return 0;
    case C55X_OP_ROUND: {
        uint64_t acx = pkt_read_ac(cpu, op->src);

        /*
         * RX-34 L173: % = 0 copies ACx. 0x54 0x0b (% = 1) adds 2^15
         * (SPRU371 RND).
         */
        if (op->bit) {
            cpu->ac[op->dst & 3] = alu40(cpu, acx, 0x8000ull, 0, op->dst);
        } else {
            cpu->ac[op->dst & 3] = c55x_ac_store(cpu, acx);
        }
        return 0;
    }
    case C55X_OP_MPYM:
    case C55X_OP_SQRM:
    case C55X_OP_MACM:
    case C55X_OP_MASM:
    case C55X_OP_SQAM:
    case C55X_OP_SQSM: {
        int16_t xa, xb;
        uint64_t prod;
        uint64_t acc;
        int uns = 0;
        int sub;

        if (smem_read16(cpu, &op->smem, mmap, port, &mem, 0)) {
            return -1;
        }
        if (op->st) {
            cpu->t[3] = mem;
        }
        if (op->kind == C55X_OP_SQRM || op->kind == C55X_OP_SQAM ||
            op->kind == C55X_OP_SQSM) {
            xa = (int16_t)mem;
            xb = xa;
        } else if (op->imm != 0xff) {
            uns = op->shft & 1;
            xa = uns ? (int16_t)(uint16_t)mem : (int16_t)mem;
            xb = (int16_t)pkt_read_t(cpu, (unsigned)op->imm);
        } else {
            xa = (int16_t)mem;
            xb = ac_hi(cpu, op->src);
        }
        if (uns) {
            prod = (uint64_t)(uint16_t)mem *
                   (uint64_t)(uint16_t)pkt_read_t(cpu, (unsigned)op->imm);
            if (cpu->st1 & C55X_ST1_FRCT) {
                prod <<= 1;
            }
            if (op->bit) {
                prod += 0x8000;
            }
            prod &= C55X_AC_MASK;
        } else {
            prod = mpy16(cpu, xa, xb, op->bit);
        }
        if (op->kind == C55X_OP_MPYM || op->kind == C55X_OP_SQRM) {
            cpu->ac[op->dst & 3] = prod;
            return 0;
        }
        if ((op->kind == C55X_OP_MACM || op->kind == C55X_OP_MASM) &&
            op->imm == 0xff) {
            acc = pkt_read_ac(cpu, op->dst);
        } else {
            acc = pkt_read_ac(cpu, op->src);
        }
        sub = (op->kind == C55X_OP_MASM || op->kind == C55X_OP_SQSM);
        cpu->ac[op->dst & 3] = alu40(cpu, acc, prod, sub, op->dst);
        return 0;
    }
    case C55X_OP_MPYM_XY:
    case C55X_OP_MACM_XY:
    case C55X_OP_MASM_XY: {
        uint32_t xaddr = dual_ar_addr(cpu, &op->smem);
        uint32_t yaddr = dual_ar_addr(cpu, &op->ymem);
        uint16_t xv = 0, yv = 0;
        uint64_t prod, acc;

        if (!cpu->bus.read16 ||
            cpu->bus.read16(cpu->bus.opaque, xaddr, &xv) ||
            cpu->bus.read16(cpu->bus.opaque, yaddr, &yv)) {
            return -1;
        }
        dual_ar_commit(cpu, &op->smem, 1);
        dual_ar_commit(cpu, &op->ymem, 1);
        /*
         * 0x86 Xmem/Ymem MMM=100 is dis55 *(ARn+T1): the address is
         * ARn+T1 and ARn then advances by T1. Indexed-only addressing
         * reuses one coefficient for the whole repeat. Smem *ARn+
         * (read ARn, then +1) is a different field and collapsed the
         * SRC to one clipped channel. MOV dbl keeps MMM=100 indexed;
         * this post-step is only the 0x86 XY multiply.
         */
        if (op->smem.mod == C55X_MOD_INDEX_T1) {
            ar_modify(cpu, op->smem.ar, (int16_t)pkt_read_t(cpu, 1));
        }
        if (op->ymem.mod == C55X_MOD_INDEX_T1) {
            ar_modify(cpu, op->ymem.ar, (int16_t)pkt_read_t(cpu, 1));
        }
        if (op->st) {
            cpu->t[3] = xv;
        }
        if (op->cond == 3) {
            /* MASM/MACM Xmem, Tx, ACx :: MOV Ymem << #16, ACy.
             * The MOV is last so ACx==ACy keeps Ymem << #16. */
            int16_t tx = (int16_t)pkt_read_t(cpu, op->imm & 3);
            uint64_t ysh = ((uint64_t)(int64_t)(int16_t)yv << 16) &
                           C55X_AC_MASK;

            prod = mpy16(cpu, (int16_t)xv, tx, op->bit);
            cpu->ac[op->dst & 3] = alu40(cpu, pkt_read_ac(cpu, op->dst),
                                         prod, op->kind == C55X_OP_MASM_XY,
                                         op->dst);
            cpu->ac[op->src & 3] = ysh;
            return 0;
        }
        if ((op->shft & 3) == 3) {
            prod = (uint64_t)xv * (uint64_t)yv;
            if (cpu->st1 & C55X_ST1_FRCT) {
                prod <<= 1;
            }
            if (op->bit) {
                prod += 0x8000;
            }
            prod &= C55X_AC_MASK;
        } else {
            prod = mpy16(cpu, (int16_t)xv, (int16_t)yv, op->bit);
        }
        if (op->kind == C55X_OP_MPYM_XY) {
            cpu->ac[op->dst & 3] = prod;
            return 0;
        }
        if (op->cond == 2) {
            cpu->ac[op->src & 3] = alu40(cpu, pkt_read_ac(cpu, op->src),
                                         prod, 0, op->src);
            cpu->ac[op->dst & 3] = ((uint64_t)yv << 16) & C55X_AC_MASK;
            return 0;
        }
        acc = pkt_read_ac(cpu, op->src);
        if (op->cond == 1) {
            acc = (acc >> 16) & C55X_AC_MASK;
        }
        cpu->ac[op->dst & 3] = alu40(cpu, acc, prod,
                                     op->kind == C55X_OP_MASM_XY, op->dst);
        return 0;
    }
    case C55X_OP_ADD_XY_AC:
    case C55X_OP_SUB_XY_AC:
    case C55X_OP_MOV_XY_AC: {
        uint32_t xaddr = dual_ar_addr(cpu, &op->smem);
        uint32_t yaddr = dual_ar_addr(cpu, &op->ymem);
        uint16_t xv = 0, yv = 0;
        uint64_t xsh, ysh;

        if (!cpu->bus.read16 ||
            cpu->bus.read16(cpu->bus.opaque, xaddr, &xv) ||
            cpu->bus.read16(cpu->bus.opaque, yaddr, &yv)) {
            return -1;
        }
        dual_ar_commit(cpu, &op->smem, 1);
        dual_ar_commit(cpu, &op->ymem, 1);
        if (op->kind == C55X_OP_MOV_XY_AC) {
            cpu->ac[op->dst & 3] = ((uint64_t)yv << 16) | xv;
            return 0;
        }
        xsh = (uint64_t)(int64_t)(int16_t)xv << 16;
        ysh = (uint64_t)(int64_t)(int16_t)yv << 16;
        cpu->ac[op->dst & 3] = alu40(cpu, xsh & C55X_AC_MASK,
                                     ysh & C55X_AC_MASK,
                                     op->kind == C55X_OP_SUB_XY_AC,
                                     op->dst);
        return 0;
    }
    case C55X_OP_SAT: {
        int m40 = !!(cpu->st1 & C55X_ST1_M40);
        uint64_t ac = pkt_read_ac(cpu, op->src);
        unsigned signbit = m40 ? 39u : 31u;
        uint64_t signext = ((ac >> signbit) & 1ull) ?
                           (C55X_AC_MASK ^ ((1ull << signbit) - 1ull)) : 0;
        uint64_t high = ac & (C55X_AC_MASK ^ ((1ull << signbit) - 1ull));

        if (high != signext) {
            if ((ac >> signbit) & 1ull) {
                ac = m40 ? (1ull << 39) : 0xff80000000ull;
            } else {
                ac = (1ull << signbit) - 1ull;
            }
        }
        cpu->ac[op->dst & 3] = ac & C55X_AC_MASK;
        return 0;
    }
    case C55X_OP_MACK: {
        int16_t tx = (int16_t)pkt_read_t(cpu, op->st);
        int64_t prod = (int64_t)tx * (int64_t)(int16_t)op->imm;

        if (cpu->st1 & C55X_ST1_FRCT) {
            prod <<= 1;
        }
        if (op->bit) {
            prod += 0x8000;
        }
        cpu->ac[op->dst & 3] = alu40(cpu, pkt_read_ac(cpu, op->src),
                                     (uint64_t)prod & C55X_AC_MASK, 0,
                                     op->dst);
        return 0;
    }
    case C55X_OP_BFXTR: {
        uint16_t mask = (uint16_t)op->imm;
        uint16_t bits = (uint16_t)c55x_get_reg(cpu, op->src);
        uint16_t out = 0;
        unsigned i, bit = 0;

        for (i = 0; i < 16; i++) {
            if (mask & (1u << i)) {
                if (bits & (1u << i)) {
                    out |= (uint16_t)(1u << bit);
                }
                bit++;
            }
        }
        c55x_set_reg(cpu, op->dst, out);
        return 0;
    }
    case C55X_OP_BFXPA: {
        /*
         * Expand low bits of ACx into mask-selected positions.
         * RX-34 L214_bfxpa_i1: non-selected bits are cleared
         * (AC1 0x22 mask 0x0505 → 0x4), not left unchanged.
         */
        uint16_t mask = (uint16_t)op->imm;
        uint16_t bits = (uint16_t)c55x_get_reg(cpu, op->src);
        uint16_t packed = 0;
        unsigned i, bit = 0;

        for (i = 0; i < 16; i++) {
            if (mask & (1u << i)) {
                if (bits & (1u << bit)) {
                    packed |= (uint16_t)(1u << i);
                }
                bit++;
            }
        }
        c55x_set_reg(cpu, op->dst, packed);
        return 0;
    }
    case C55X_OP_ADD_K16_SHFT: {
        int sh = shiftw6(op->shft);
        unsigned acn = op->dst & 3;
        uint64_t acc = pkt_read_ac(cpu, op->src & 3);
        uint64_t k;

        if (op->st <= 1) {
            k = ac_shift((uint64_t)(int64_t)(int16_t)op->imm, sh, 1);
            cpu->ac[acn] = alu40(cpu, acc, k, op->st == 1, acn);
        } else {
            k = ac_shift((uint16_t)op->imm, sh, 0);
            if (op->st == 2) {
                cpu->ac[acn] = c55x_ac_store(cpu, acc & k);
            } else if (op->st == 3) {
                cpu->ac[acn] = c55x_ac_store(cpu, acc | k);
            } else {
                cpu->ac[acn] = c55x_ac_store(cpu, acc ^ k);
            }
        }
        return 0;
    }
    case C55X_OP_MOV_SMEM_CTL:
    case C55X_OP_MOV_CTL_SMEM: {
        uint16_t value = 0;
        unsigned ctl = (op->kind == C55X_OP_MOV_SMEM_CTL) ? op->dst : op->src;

        if (op->kind == C55X_OP_MOV_SMEM_CTL) {
            if (smem_read16(cpu, &op->smem, mmap, port, &value, 0)) {
                return -1;
            }
        }
        switch (ctl) {
        case C55X_CTL_SP:
            if (op->kind == C55X_OP_MOV_SMEM_CTL) {
                cpu->xsp = (cpu->xsp & ~0xffffu) | value;
            } else {
                value = (uint16_t)pkt_read_xsp(cpu);
            }
            break;
        case C55X_CTL_SSP:
            if (op->kind == C55X_OP_MOV_SMEM_CTL) {
                cpu->xssp = (cpu->xssp & ~0xffffu) | value;
            } else {
                value = (uint16_t)cpu->xssp;
            }
            break;
        case C55X_CTL_CDP:
            if (op->kind == C55X_OP_MOV_SMEM_CTL) {
                cpu->xcdp = (cpu->xcdp & ~0xffffu) | value;
            } else {
                value = (uint16_t)pkt_read_xcdp(cpu);
            }
            break;
        case C55X_CTL_CSR:
            if (op->kind == C55X_OP_MOV_SMEM_CTL) {
                cpu->csr = value;
            } else {
                value = cpu->csr;
            }
            break;
        case C55X_CTL_BRC0:
            if (op->kind == C55X_OP_MOV_SMEM_CTL) {
                cpu->brc0 = value;
            } else {
                value = cpu->brc0;
            }
            break;
        case C55X_CTL_BRC1:
            if (op->kind == C55X_OP_MOV_SMEM_CTL) {
                cpu->brc1 = value;
            } else {
                value = cpu->brc1;
            }
            break;
        case C55X_CTL_RPTC:
            if (op->kind == C55X_OP_MOV_SMEM_CTL) {
                cpu->rptc = value;
            } else {
                value = cpu->rptc;
            }
            break;
        case C55X_CTL_DP:
            if (op->kind == C55X_OP_MOV_SMEM_CTL) {
                cpu->xdp = (cpu->xdp & ~0xffffu) | value;
            } else {
                value = (uint16_t)pkt_read_xdp(cpu);
            }
            break;
        case C55X_CTL_BSA01:
            if (op->kind == C55X_OP_MOV_SMEM_CTL) {
                cpu->bsa01 = value;
            } else {
                value = cpu->bsa01;
            }
            break;
        case C55X_CTL_BSA23:
            if (op->kind == C55X_OP_MOV_SMEM_CTL) {
                cpu->bsa23 = value;
            } else {
                value = cpu->bsa23;
            }
            break;
        case C55X_CTL_BSA45:
            if (op->kind == C55X_OP_MOV_SMEM_CTL) {
                cpu->bsa45 = value;
            } else {
                value = cpu->bsa45;
            }
            break;
        case C55X_CTL_BSA67:
            if (op->kind == C55X_OP_MOV_SMEM_CTL) {
                cpu->bsa67 = value;
            } else {
                value = cpu->bsa67;
            }
            break;
        case C55X_CTL_BSAC:
            if (op->kind == C55X_OP_MOV_SMEM_CTL) {
                cpu->bsac = value;
            } else {
                value = cpu->bsac;
            }
            break;
        case C55X_CTL_TRN0:
            if (op->kind == C55X_OP_MOV_SMEM_CTL) {
                cpu->trn0 = value;
            } else {
                value = cpu->trn0;
            }
            break;
        case C55X_CTL_TRN1:
            if (op->kind == C55X_OP_MOV_SMEM_CTL) {
                cpu->trn1 = value;
            } else {
                value = cpu->trn1;
            }
            break;
        case C55X_CTL_BK03:
            if (op->kind == C55X_OP_MOV_SMEM_CTL) {
                cpu->bk03 = value;
            } else {
                value = cpu->bk03;
            }
            break;
        case C55X_CTL_BK47:
            if (op->kind == C55X_OP_MOV_SMEM_CTL) {
                cpu->bk47 = value;
            } else {
                value = cpu->bk47;
            }
            break;
        case C55X_CTL_BKC:
            if (op->kind == C55X_OP_MOV_SMEM_CTL) {
                cpu->bkc = value;
            } else {
                value = cpu->bkc;
            }
            break;
        case C55X_CTL_DPH:
            if (op->kind == C55X_OP_MOV_SMEM_CTL) {
                cpu->xdp = (cpu->xdp & 0xffffu) |
                           (((uint32_t)value & 0x7f) << 16);
            } else {
                value = (uint16_t)((cpu->xdp >> 16) & 0x7f);
            }
            break;
        case C55X_CTL_PDP:
            /*
             * k9 writes 9 bits. The Smem round trip of 0x1234 came back
             * as 0x34, so this path keeps a byte (bit 8 did not survive).
             */
            if (op->kind == C55X_OP_MOV_SMEM_CTL) {
                cpu->pdp = value & 0xff;
            } else {
                value = (uint16_t)(cpu->pdp & 0xff);
            }
            break;
        default:
            return -1;
        }
        if (op->kind == C55X_OP_MOV_CTL_SMEM) {
            return smem_write16(cpu, &op->smem, mmap, port, value, 0);
        }
        return 0;
    }
    case C55X_OP_MACMZ:
    case C55X_OP_MPYM_CMEM:
    case C55X_OP_MACM_CMEM:
    case C55X_OP_MASM_CMEM: {
        C55xSmem cmem;
        uint16_t sv = 0, cv = 0;
        uint64_t prod;

        cmem_from_mm(&cmem, op->shft);
        if (op->kind == C55X_OP_MACMZ) {
            uint32_t word;
            int is_mmr, is_io;
            uint16_t io_port;
            int32_t post;

            /*
             * RX-34 L375: MACMZ copies Smem into the next word and
             * leaves Smem itself. The product replaces ACx.
             */
            if (resolve_smem(cpu, &op->smem, mmap, port, &word, &is_mmr,
                             &is_io, &io_port, &post) ||
                is_mmr || is_io || !cpu->bus.read16 ||
                cpu->bus.read16(cpu->bus.opaque, word, &sv) ||
                smem_read16(cpu, &cmem, 0, 0, &cv, 0)) {
                return -1;
            }
            if (op->st) {
                cpu->t[3] = sv;
            }
            prod = mpy16(cpu, (int16_t)sv, (int16_t)cv, op->bit);
            cpu->ac[op->dst & 3] = prod;
            if (!cpu->bus.write16 ||
                cpu->bus.write16(cpu->bus.opaque,
                                 (word + 1u) & C55X_WORD_MASK, sv)) {
                return -1;
            }
            apply_post(cpu, &op->smem, post, 0);
            return 0;
        }
        if (smem_read16(cpu, &op->smem, mmap, port, &sv, 0) ||
            smem_read16(cpu, &cmem, 0, 0, &cv, 0)) {
            return -1;
        }
        if (op->st) {
            cpu->t[3] = sv;
        }
        prod = mpy16(cpu, (int16_t)sv, (int16_t)cv, op->bit);
        if (op->kind == C55X_OP_MPYM_CMEM) {
            cpu->ac[op->dst & 3] = prod;
        } else {
            cpu->ac[op->dst & 3] = alu40(cpu, pkt_read_ac(cpu, op->dst),
                                         prod, op->kind == C55X_OP_MASM_CMEM,
                                         op->dst);
        }
        return 0;
    }
    case C55X_OP_DUAL_MAC:
    case C55X_OP_AMAR_XYC:
    case C55X_OP_FIRSADD:
    case C55X_OP_FIRSSUB: {
        C55xSmem cmem;
        uint32_t xaddr = dual_ar_addr(cpu, &op->smem);
        uint32_t yaddr = dual_ar_addr(cpu, &op->ymem);
        uint16_t xv = 0, yv = 0, cv = 0;
        uint64_t px, py;

        cmem_from_mm(&cmem, op->shft);
        if (!cpu->bus.read16 ||
            cpu->bus.read16(cpu->bus.opaque, xaddr, &xv) ||
            cpu->bus.read16(cpu->bus.opaque, yaddr, &yv) ||
            smem_read16(cpu, &cmem, 0, 0, &cv, 0)) {
            static unsigned dual_faults;

            if (dual_faults < 4u) {
                eap_pcm_stat(
                    "t=dualfault pc=%06x x=%06x y=%06x cdp=%06x "
                    "ar1=%06x ar3=%06x\n",
                    cpu->pc & C55X_PC_MASK, xaddr, yaddr,
                    cpu->xcdp & C55X_WORD_MASK,
                    cpu->xar[1] & C55X_WORD_MASK,
                    cpu->xar[3] & C55X_WORD_MASK);
                dual_faults++;
            }
            return -1;
        }
        dual_ar_commit(cpu, &op->smem, 1);
        dual_ar_commit(cpu, &op->ymem, 1);
        if (op->kind == C55X_OP_AMAR_XYC) {
            return 0;
        }
        px = mpy16(cpu, (int16_t)xv, (int16_t)cv, op->bit);
        py = mpy16(cpu, (int16_t)yv, (int16_t)cv, op->bit);
        if (op->kind == C55X_OP_FIRSADD || op->kind == C55X_OP_FIRSSUB) {
            uint64_t acy = pkt_read_ac(cpu, op->dst);
            uint64_t hi = mpy16(cpu, ac_hi(cpu, op->src), (int16_t)cv, 0);
            uint64_t acx_new = alu40(cpu, ((uint64_t)xv << 16) & C55X_AC_MASK,
                                     py, 0, op->src);
            uint64_t acy_new = alu40(cpu, acy, hi,
                                     op->kind == C55X_OP_FIRSSUB, op->dst);

            /* ACy last: RX-34 aliases ACx onto ACy and that update wins. */
            cpu->ac[op->src & 3] = acx_new;
            cpu->ac[op->dst & 3] = acy_new;
            return 0;
        }
        /*
         * 82ab20c4 at 0x134f19 is MPY (replace), not MAC. The form
         * bit that sets cond=1 is the uns modifier. Adding a stale
         * AC0 saturates this polyphase stage.
         */
        if (op->cond == 0 || (cpu->pc & C55X_PC_MASK) == 0x134f19u) {
            cpu->ac[op->src & 3] = px;
        } else if (op->cond == 2) {
            cpu->ac[op->src & 3] = alu40(cpu, pkt_read_ac(cpu, op->src),
                                         px, 1, op->src);
        } else {
            cpu->ac[op->src & 3] = alu40(cpu, pkt_read_ac(cpu, op->src),
                                         px, 0, op->src);
        }
        if (op->st == 0) {
            /*
             * dspfin mac_same: MPY into the same AC keeps px
             * (0x1234*0x1234 = 0x014b5a90). Writing py second
             * left 0x5678*0x1234. cond!=0 still replaces with py
             * (limiter 82259004, both destinations AC0).
             */
            if (!(op->cond == 0 && (op->src & 3) == (op->dst & 3))) {
                cpu->ac[op->dst & 3] = py;
            }
        } else if (op->st == 2) {
            cpu->ac[op->dst & 3] = alu40(cpu, pkt_read_ac(cpu, op->dst),
                                         py, 1, op->dst);
        } else {
            uint64_t acc = pkt_read_ac(cpu, op->dst);

            if (op->imm) {
                acc = (acc >> 16) & C55X_AC_MASK;
            }
            cpu->ac[op->dst & 3] = alu40(cpu, acc, py, 0, op->dst);
        }
        return 0;
    }
    case C55X_OP_LMS:
    case C55X_OP_SQDST:
    case C55X_OP_ABDST: {
        uint32_t xaddr = dual_ar_addr(cpu, &op->smem);
        uint32_t yaddr = dual_ar_addr(cpu, &op->ymem);
        uint16_t xv = 0, yv = 0;
        int32_t diff;

        if (!cpu->bus.read16 ||
            cpu->bus.read16(cpu->bus.opaque, xaddr, &xv) ||
            cpu->bus.read16(cpu->bus.opaque, yaddr, &yv)) {
            return -1;
        }
        dual_ar_commit(cpu, &op->smem, 1);
        dual_ar_commit(cpu, &op->ymem, 1);
        if (op->kind == C55X_OP_LMS) {
            uint64_t acx = pkt_read_ac(cpu, op->dst);
            uint64_t acy = pkt_read_ac(cpu, op->src);
            uint64_t px = mpy16(cpu, ac_hi(cpu, op->src), (int16_t)xv, op->bit);
            uint64_t py = mpy16(cpu, (int16_t)xv, (int16_t)yv, op->bit);

            /* Both sides use the original ACy. ACy is last so an alias keeps the product term. */
            cpu->ac[op->dst & 3] = alu40(cpu, acx, px, 1, op->dst);
            cpu->ac[op->src & 3] = alu40(cpu, acy, py, 0, op->src);
            return 0;
        }
        diff = (int32_t)(int16_t)xv - (int32_t)(int16_t)yv;
        if (op->kind == C55X_OP_SQDST) {
            uint64_t sq = mpy16(cpu, (int16_t)diff, (int16_t)diff, 0);
            uint64_t acx = pkt_read_ac(cpu, op->dst);
            uint64_t acy = pkt_read_ac(cpu, op->src);

            /* ACx += (X-Y); ACy += (X-Y)^2. */
            cpu->ac[op->dst & 3] = alu40(cpu, acx,
                                         (uint64_t)(int64_t)diff & C55X_AC_MASK,
                                         0, op->dst);
            cpu->ac[op->src & 3] = alu40(cpu, acy, sq, 0, op->src);
        } else {
            int32_t ad = diff < 0 ? -diff : diff;
            uint64_t acx = pkt_read_ac(cpu, op->dst);
            uint64_t acy = pkt_read_ac(cpu, op->src);

            /* ACy += (X-Y); ACx += |X-Y|. */
            cpu->ac[op->src & 3] = alu40(cpu, acy,
                                         (uint64_t)(int64_t)diff & C55X_AC_MASK,
                                         0, op->src);
            cpu->ac[op->dst & 3] = alu40(cpu, acx, (uint64_t)ad, 0, op->dst);
        }
        return 0;
    }
    case C55X_OP_MAC_HI_Y: {
        uint32_t xaddr = dual_ar_addr(cpu, &op->smem);
        uint32_t yaddr = dual_ar_addr(cpu, &op->ymem);
        uint16_t xv = 0, yv = 0;
        unsigned form = op->cond & 7;
        unsigned acx_n = op->src & 3;
        unsigned acy_n = op->dst & 3;
        uint64_t acx, xsh, store_ac;
        int sh = (int16_t)pkt_read_t(cpu, 2);

        if (!cpu->bus.read16 ||
            cpu->bus.read16(cpu->bus.opaque, xaddr, &xv) ||
            cpu->bus.read16(cpu->bus.opaque, yaddr, &yv)) {
            return -1;
        }
        if (op->st) {
            cpu->t[3] = xv;
        }
        acx = pkt_read_ac(cpu, acx_n);
        xsh = ((uint64_t)(int64_t)(int16_t)xv << 16) & C55X_AC_MASK;
        if (form <= 2) {
            int16_t tx = (int16_t)pkt_read_t(cpu, op->imm & 3);
            uint64_t prod = mpy16(cpu, (int16_t)xv, tx, op->bit);
            uint64_t acc = (form == 0) ? 0 : pkt_read_ac(cpu, acy_n);

            cpu->ac[acy_n] = alu40(cpu, acc, prod, form == 2, acy_n);
            store_ac = acx;
        } else if (form == 4) {
            /* MOV HI(ACy << T2) reads ACy from before the ADD. */
            store_ac = pkt_read_ac(cpu, acy_n);
            cpu->ac[acy_n] = alu40(cpu, acx, xsh, 0, acy_n);
        } else if (form == 5) {
            /* RX-34: ACy = (Xmem << #16) - ACx, not ACx - (Xmem << #16).
             * The parallel store still sees the old ACy. */
            store_ac = pkt_read_ac(cpu, acy_n);
            cpu->ac[acy_n] = alu40(cpu, xsh, acx, 1, acy_n);
        } else {
            cpu->ac[acy_n] = xsh;
            store_ac = acx;
        }
        store_ac = ac_shift(store_ac, sh, 1);
        if (!cpu->bus.write16 ||
            cpu->bus.write16(cpu->bus.opaque, yaddr,
                             (uint16_t)(store_ac >> 16))) {
            return -1;
        }
        dual_ar_commit(cpu, &op->smem, 1);
        dual_ar_commit(cpu, &op->ymem, 1);
        (void)yv;
        return 0;
    }
    case C55X_OP_MOV_AC_XY: {
        uint32_t xaddr = dual_ar_addr(cpu, &op->smem);
        uint32_t yaddr = dual_ar_addr(cpu, &op->ymem);
        uint64_t ac = pkt_read_ac(cpu, op->src);

        if (!cpu->bus.write16 ||
            cpu->bus.write16(cpu->bus.opaque, xaddr, (uint16_t)(ac >> 16)) ||
            cpu->bus.write16(cpu->bus.opaque, yaddr, (uint16_t)ac)) {
            return -1;
        }
        dual_ar_commit(cpu, &op->smem, 1);
        dual_ar_commit(cpu, &op->ymem, 1);
        return 0;
    }
    case C55X_OP_SUBC: {
        uint64_t ac = pkt_read_ac(cpu, op->dst);
        uint64_t sub;

        mem = 0;
        if (smem_read16(cpu, &op->smem, mmap, port, &mem, 0)) {
            return -1;
        }
        sub = (uint64_t)mem << 15;
        if (ac >= sub) {
            cpu->ac[op->dst & 3] = ((ac - sub) << 1) | 1ull;
        } else {
            cpu->ac[op->dst & 3] = (ac << 1) & C55X_AC_MASK;
        }
        cpu->ac[op->dst & 3] &= C55X_AC_MASK;
        return 0;
    }
    case C55X_OP_ADD_SMEM16: {
        uint64_t src_ac;

        mem = 0;
        if (smem_read16(cpu, &op->smem, mmap, port, &mem, 0)) {
            return -1;
        }
        src_ac = pkt_read_ac(cpu, op->src);
        if (op->cond == 1) {
            cpu->ac[op->dst & 3] = alu40(cpu,
                                         (uint64_t)(int64_t)(int16_t)mem << 16,
                                         src_ac, 1, op->dst);
        } else {
            cpu->ac[op->dst & 3] = alu40(cpu, src_ac,
                                         (uint64_t)(int64_t)(int16_t)mem << 16,
                                         op->st, op->dst);
        }
        return 0;
    }
    case C55X_OP_ADDSUBCC:
    case C55X_OP_ADDSUB:
    case C55X_OP_SUBADD: {
        int16_t tx = (int16_t)pkt_read_t(cpu, (unsigned)op->imm);
        int32_t a, b;

        mem = 0;
        if (smem_read16(cpu, &op->smem, mmap, port, &mem, 0)) {
            return -1;
        }
        a = (int16_t)mem;
        b = tx;
        if (op->kind == C55X_OP_ADDSUBCC) {
            int tc1 = !!(cpu->st0 & C55X_ST0_TC1);
            int tc2 = !!(cpu->st0 & C55X_ST0_TC2);
            uint64_t acx = pkt_read_ac(cpu, op->src);
            uint64_t sm;
            int sub = 0;

            if (op->cond == 2) {
                /* ADDSUB2CC: TC2 selects Tx vs #16; TC1 selects subtract. */
                int sh = tc2 ? (int)tx : 16;
                int64_t val = a;

                if (sh >= 0) {
                    val <<= sh;
                } else {
                    val >>= -sh;
                }
                sm = (uint64_t)val & C55X_AC_MASK;
                sub = tc1;
            } else if (op->cond == 3 && !tc1 && !tc2) {
                /* Both flags clear: ACy stays ACx. RX-34 L432. */
                cpu->ac[op->dst & 3] = acx;
                return 0;
            } else {
                int tc = (op->cond == 1) ? tc2 : tc1;

                sm = ((uint64_t)(int64_t)a << 16) & C55X_AC_MASK;
                sub = (op->cond == 3) ? (tc2 && !tc1) : tc;
            }
            cpu->ac[op->dst & 3] = alu40(cpu, acx, sm, sub, op->dst);
            return 0;
        }
        if (op->cond == 1) {
            uint32_t longword = 0;
            int16_t hi, lo;

            if (lmem_read_long(cpu, &op->smem, mmap, port, &longword)) {
                return -1;
            }
            hi = (int16_t)(longword >> 16);
            lo = (int16_t)longword;
            if (op->bit == 0) {
                hi = (int16_t)(b - hi);
                lo = (int16_t)(b - lo);
            } else if (op->bit == 1) {
                hi = (int16_t)(hi + b);
                lo = (int16_t)(lo + b);
            } else if (op->bit == 2) {
                hi = (int16_t)(hi - b);
                lo = (int16_t)(lo - b);
            } else if (op->bit == 3) {
                hi = (int16_t)(hi + b);
                lo = (int16_t)(lo - b);
            } else {
                hi = (int16_t)(hi - b);
                lo = (int16_t)(lo + b);
            }
            cpu->ac[op->dst & 3] = ((uint32_t)(uint16_t)hi << 16) |
                                   (uint16_t)lo;
            return 0;
        }
        {
            uint16_t sum = (uint16_t)(a + b);
            uint16_t dif = (uint16_t)(a - b);

            if (op->kind == C55X_OP_SUBADD) {
                cpu->ac[op->dst & 3] = ((uint32_t)dif << 16) | sum;
            } else {
                cpu->ac[op->dst & 3] = ((uint32_t)sum << 16) | dif;
            }
        }
        return 0;
    }
    case C55X_OP_MOV_SMEM_TX: {
        int sh = (int16_t)pkt_read_t(cpu, (unsigned)op->imm);
        uint64_t val;

        mem = 0;
        if (smem_read16(cpu, &op->smem, mmap, port, &mem, 0)) {
            return -1;
        }
        val = (uint64_t)(int64_t)(int16_t)mem;
        cpu->ac[op->dst & 3] = ac_shift(val, sh, 1);
        return 0;
    }
    case C55X_OP_RETCC:
        if (c55x_eval_cond(cpu, op->cond)) {
            *next_pc = return_taken(cpu, "RETCC", 0);
        }
        return 0;
    case C55X_OP_CALLCC_P24:
        if (c55x_eval_cond(cpu, op->cond)) {
            cpu->ret_pc = (cpu->pc + in->length) & C55X_PC_MASK;
            *next_pc = op->target;
            call_taken(cpu, *next_pc, cpu->ret_pc);
        }
        return 0;
    case C55X_OP_RPTCC:
        if (c55x_eval_cond(cpu, op->cond)) {
            cpu->rpt_left = (uint16_t)op->imm;
            cpu->rpt_armed = 1;
            cpu->rpt_active = 0;
            cpu->rpt_cc = 1;
            cpu->rptc = cpu->rpt_left;
            if (cpu->flow_verbose) {
                c55x_log(cpu, "RPTCC-ON pc=%06x count=%u cond=%u\n",
                         cpu->pc, cpu->rpt_left, op->cond);
            }
        }
        return 0;
    case C55X_OP_RPTADD:
        cpu->csr = (uint16_t)(cpu->csr + c55x_get_reg(cpu, op->src));
        cpu->rpt_left = cpu->csr;
        cpu->rpt_armed = 1;
        cpu->rpt_active = 0;
        cpu->rpt_cc = 0;
        cpu->rptc = cpu->rpt_left;
        return 0;
    case C55X_OP_RPTSUB:
        cpu->csr = (uint16_t)(cpu->csr - c55x_get_reg(cpu, op->src));
        cpu->rpt_left = cpu->csr;
        cpu->rpt_armed = 1;
        cpu->rpt_active = 0;
        cpu->rpt_cc = 0;
        cpu->rptc = cpu->rpt_left;
        return 0;
    case C55X_OP_SWAP: {
        /*
         * Silicon L196: AC3 <- AC1 (full), AC1 <- AC3[15:0].
         * Base/i1 look like a full swap only because AC3 fit in 16 bits.
         * L196_swap_i2 (AC3=0x0def0000) leaves AC1=0, AC3=old AC1.
         */
        uint64_t a = c55x_get_reg(cpu, op->src);
        uint64_t b = c55x_get_reg(cpu, op->dst);

        c55x_set_reg(cpu, op->src, b & 0xffffull);
        c55x_set_reg(cpu, op->dst, a);
        return 0;
    }
    case C55X_OP_MOV_SMEM_CMEM: {
        C55xSmem cmem;
        uint16_t sv = 0;
        uint16_t sv2 = 0;
        uint32_t cword = 0;
        int is_mmr, is_io;
        uint16_t io_port;
        int32_t post;

        cmem_from_mm(&cmem, op->shft);
        if (op->cond == 0) {
            if (smem_read16(cpu, &cmem, 0, 0, &sv, 0)) {
                return -1;
            }
            return smem_write16(cpu, &op->smem, mmap, port, sv, 0);
        }
        if (op->cond == 2) {
            if (resolve_smem(cpu, &cmem, 0, 0, &cword, &is_mmr, &is_io,
                             &io_port, &post) ||
                !cpu->bus.read16 ||
                cpu->bus.read16(cpu->bus.opaque, cword, &sv) ||
                cpu->bus.read16(cpu->bus.opaque,
                                (cword + 1) & C55X_WORD_MASK, &sv2)) {
                return -1;
            }
            apply_post(cpu, &cmem, post, 1);
            return lmem_write_long(cpu, &op->smem, mmap, port,
                                   ((uint32_t)sv << 16) | sv2);
        }
        if (op->cond == 3) {
            uint32_t longword;

            if (lmem_read_long(cpu, &op->smem, mmap, port, &longword) ||
                resolve_smem(cpu, &cmem, 0, 0, &cword, &is_mmr, &is_io,
                             &io_port, &post) ||
                !cpu->bus.write16 ||
                cpu->bus.write16(cpu->bus.opaque, cword,
                                 (uint16_t)(longword >> 16)) ||
                cpu->bus.write16(cpu->bus.opaque,
                                 (cword + 1) & C55X_WORD_MASK,
                                 (uint16_t)longword)) {
                return -1;
            }
            apply_post(cpu, &cmem, post, 1);
            return 0;
        }
        if (smem_read16(cpu, &op->smem, mmap, port, &sv, 0)) {
            return -1;
        }
        return smem_write16(cpu, &cmem, 0, 0, sv, 0);
    }
    case C55X_OP_DELAY: {
        uint32_t word;
        int is_mmr, is_io;
        uint16_t io_port;
        int32_t post;

        if (resolve_smem(cpu, &op->smem, mmap, port, &word, &is_mmr, &is_io,
                         &io_port, &post)) {
            return -1;
        }
        if (!cpu->bus.read16 ||
            cpu->bus.read16(cpu->bus.opaque, word, &mem) ||
            !cpu->bus.write16 ||
            cpu->bus.write16(cpu->bus.opaque, (word + 1) & C55X_WORD_MASK,
                             mem)) {
            return -1;
        }
        apply_post(cpu, &op->smem, post, 0);
        return 0;
    }
    case C55X_OP_MANT:
    case C55X_OP_NEXP: {
        uint64_t ac = pkt_read_ac(cpu, op->src);
        int expv = 0;
        int width = (cpu->st1 & C55X_ST1_M40) ? 40 : 32;
        uint64_t mask = (cpu->st1 & C55X_ST1_M40) ? C55X_AC_MASK : 0xffffffffull;

        ac &= mask;
        if (ac != 0) {
            int sign = (int)((ac >> (width - 1)) & 1);
            int i;

            for (i = width - 2; i >= 0; i--) {
                if ((int)((ac >> i) & 1) != sign) {
                    break;
                }
                expv++;
            }
        }
        if (op->kind == C55X_OP_NEXP) {
            cpu->t[op->dst & 3] = (uint16_t)(-expv);
        } else {
            cpu->ac[op->dst & 3] = ac_shift(ac, expv, 1);
        }
        return 0;
    }
    case C55X_OP_BCNT: {
        uint64_t ac = pkt_read_ac(cpu, op->src);
        unsigned n = 0;

        while (ac) {
            n += (unsigned)(ac & 1ull);
            ac >>= 1;
        }
        cpu->t[op->dst & 3] = (uint16_t)n;
        return 0;
    }
    case C55X_OP_MAXDIFF: {
        int want_min = !!(op->st & 2);
        int dual = !!(op->st & 1);

        if (dual) {
            int32_t a = (int32_t)pkt_read_ac(cpu, op->src);
            int32_t b = (int32_t)pkt_read_ac(cpu, op->dst);

            cpu->trn0 = (uint16_t)((uint32_t)((int64_t)a - (int64_t)b));
            if (want_min ? (a > b) : (a < b)) {
                cpu->ac[op->dst & 3] = pkt_read_ac(cpu, op->src);
            }
        } else {
            /* RX-34: the high half of ACy becomes ACy_hi - ACx_hi.
             * MAXDIFF and MINDIFF both did this for 0x0001 vs 0x0002;
             * the low half stayed. The select is not visible in the AC. */
            int16_t dy = ac_hi(cpu, op->dst);
            int16_t sx = ac_hi(cpu, op->src);
            int16_t diff = (int16_t)(dy - sx);
            uint64_t ac = pkt_read_ac(cpu, op->dst);

            cpu->trn0 = (uint16_t)diff;
            ac = (ac & 0xffffull) | ((uint64_t)(uint16_t)diff << 16);
            cpu->ac[op->dst & 3] = ac & C55X_AC_MASK;
            (void)want_min;
        }
        return 0;
    }
    case C55X_OP_ROL:
    case C55X_OP_ROR: {
        uint64_t ac = pkt_read_ac(cpu, op->src);
        unsigned carry = !!(cpu->st0 & C55X_ST0_CARRY);
        uint64_t bit;

        if (op->kind == C55X_OP_ROL) {
            bit = (ac >> 31) & 1ull;
            ac = ((ac << 1) | carry) & 0xffffffffull;
        } else {
            bit = ac & 1ull;
            ac = ((ac >> 1) | ((uint64_t)carry << 31)) & 0xffffffffull;
        }
        if (bit) {
            cpu->st0 |= C55X_ST0_CARRY;
        } else {
            cpu->st0 &= (uint16_t)~C55X_ST0_CARRY;
        }
        cpu->ac[op->dst & 3] = ac;
        return 0;
    }
    default:
        return -1;
    }
}

static int op_uses_smem(C55xOpKind kind)
{
    switch (kind) {
    case C55X_OP_MOV_K8_SMEM:
    case C55X_OP_MOV_K16_SMEM:
    case C55X_OP_MOV_SMEM_DST:
    case C55X_OP_MOV_SMEM_SHFT:
    case C55X_OP_MOV_SMEM_AC:
    case C55X_OP_MOV_SRC_SMEM:
    case C55X_OP_MOV_AC_DBL:
    case C55X_OP_MOV_XREG_DBL:
    case C55X_OP_MOV_DBL_AC:
    case C55X_OP_AND_K16_SMEM:
    case C55X_OP_OR_K16_SMEM:
    case C55X_OP_XOR_K16_SMEM:
    case C55X_OP_ADD_K16_SMEM:
    case C55X_OP_ADD_SMEM:
    case C55X_OP_SUB_SMEM:
    case C55X_OP_AND_SMEM:
    case C55X_OP_OR_SMEM:
    case C55X_OP_XOR_SMEM:
    case C55X_OP_AMAR_SMEM:
    case C55X_OP_PSH_SMEM:
    case C55X_OP_POP_SMEM:
    case C55X_OP_PSH_DBL_LMEM:
    case C55X_OP_POP_DBL_LMEM:
    case C55X_OP_MOV_HI_SMEM:
    case C55X_OP_MOV_AC_SHFT_SMEM:
    case C55X_OP_CMP_SMEM_K16:
    case C55X_OP_BTST_K4_SMEM:
    case C55X_OP_BTST_SRC_SMEM:
    case C55X_OP_PSH_SRC_SMEM:
    case C55X_OP_POP_DST_SMEM:
    case C55X_OP_BCC_ARN:
    case C55X_OP_BSET_SMEM:
    case C55X_OP_BCLR_SMEM:
    case C55X_OP_BNOT_SMEM:
    case C55X_OP_BSET_BADDR:
    case C55X_OP_BCLR_BADDR:
    case C55X_OP_BNOT_BADDR:
    case C55X_OP_BTST_BADDR:
    case C55X_OP_AMAR_XDST:
    case C55X_OP_MOV_PAIR_DBL:
    case C55X_OP_MOV_DBL_PAIR:
    case C55X_OP_MPYMK:
    case C55X_OP_MACMK:
    case C55X_OP_MPYM:
    case C55X_OP_SQRM:
    case C55X_OP_MACM:
    case C55X_OP_MASM:
    case C55X_OP_SQAM:
    case C55X_OP_SQSM:
    case C55X_OP_BAND:
    case C55X_OP_MOV_DBL_XDST:
    case C55X_OP_MOV_DBL_RETA:
    case C55X_OP_MOV_RETA_DBL:
    case C55X_OP_ADD_DBL_AC:
    case C55X_OP_SUB_DBL_AC:
    case C55X_OP_RSUB_DBL_AC:
    case C55X_OP_MOV_SMEM_CTL:
    case C55X_OP_MOV_CTL_SMEM:
    case C55X_OP_MACMZ:
    case C55X_OP_MPYM_CMEM:
    case C55X_OP_MACM_CMEM:
    case C55X_OP_MASM_CMEM:
    case C55X_OP_SUBC:
    case C55X_OP_ADDSUBCC:
    case C55X_OP_ADDSUB:
    case C55X_OP_SUBADD:
    case C55X_OP_ADD_SMEM16:
    case C55X_OP_MOV_SMEM_TX:
    case C55X_OP_DELAY:
    case C55X_OP_MOV_SMEM_CMEM:
        return 1;
    default:
        return 0;
    }
}

static int op_dbl_mem(C55xOpKind kind)
{
    switch (kind) {
    case C55X_OP_MOV_AC_DBL:
    case C55X_OP_MOV_XREG_DBL:
    case C55X_OP_MOV_DBL_AC:
    case C55X_OP_MOV_PAIR_DBL:
    case C55X_OP_MOV_DBL_PAIR:
    case C55X_OP_MOV_DBL_XDST:
    case C55X_OP_MOV_DBL_RETA:
    case C55X_OP_MOV_RETA_DBL:
    case C55X_OP_MOV_DBL_XY:
    case C55X_OP_ADD_DBL_AC:
    case C55X_OP_SUB_DBL_AC:
    case C55X_OP_RSUB_DBL_AC:
    case C55X_OP_PSH_DBL_LMEM:
    case C55X_OP_POP_DBL_LMEM:
        return 1;
    default:
        return 0;
    }
}

/*
 * XCCPART false: address-phase effects remain (AR pre/post, EA, SP).
 * Execute-phase load/store, ALU, dest writes, and flags do not.
 */
static int exec_address_only(C55xCPU *cpu, const C55xDecodedInsn *in,
                             const C55xOp *op)
{
    uint32_t word;
    int is_mmr, is_io;
    uint16_t io_port;
    int32_t post;
    uint32_t dummy_pc = cpu->pc;

    switch (op->kind) {
    case C55X_OP_AADD_K8_SP:
    case C55X_OP_AADD_K8_TAX:
    case C55X_OP_AMOV_K8_TAX:
    case C55X_OP_ASUB_K8_TAX:
    case C55X_OP_AADD_TAX:
    case C55X_OP_AMOV_TAX:
    case C55X_OP_ASUB_TAX:
    case C55X_OP_AMOV_D16:
        return exec_op(cpu, in, op, &dummy_pc);
    case C55X_OP_PSH_SRC:
        cpu->xsp = xar_plus(cpu->xsp, -1);
        cpu->sp_written = 1;
        return 0;
    case C55X_OP_POP_DST:
        cpu->xsp = xar_plus(cpu->xsp, 1);
        cpu->sp_written = 1;
        return 0;
    case C55X_OP_PSH_PAIR:
    case C55X_OP_PSH_DBL_AC:
        cpu->xsp = xar_plus(cpu->xsp, -2);
        cpu->sp_written = 1;
        return 0;
    case C55X_OP_POP_PAIR:
    case C55X_OP_POP_DBL_AC:
        cpu->xsp = xar_plus(cpu->xsp, 2);
        cpu->sp_written = 1;
        return 0;
    case C55X_OP_PSH_DBL_LMEM:
        if (resolve_smem(cpu, &op->smem, in->mmap, in->port, &word, &is_mmr,
                         &is_io, &io_port, &post)) {
            return -1;
        }
        apply_post(cpu, &op->smem, post, 1);
        cpu->xsp = xar_plus(cpu->xsp, -2);
        cpu->sp_written = 1;
        return 0;
    case C55X_OP_POP_DBL_LMEM:
        if (resolve_smem(cpu, &op->smem, in->mmap, in->port, &word, &is_mmr,
                         &is_io, &io_port, &post)) {
            return -1;
        }
        apply_post(cpu, &op->smem, post, 1);
        cpu->xsp = xar_plus(cpu->xsp, 2);
        cpu->sp_written = 1;
        return 0;
    case C55X_OP_PSH_SMEM:
        if (resolve_smem(cpu, &op->smem, in->mmap, in->port, &word, &is_mmr,
                         &is_io, &io_port, &post)) {
            return -1;
        }
        apply_post(cpu, &op->smem, post, 0);
        cpu->xsp = xar_plus(cpu->xsp, -1);
        cpu->sp_written = 1;
        return 0;
    case C55X_OP_POP_SMEM:
        if (resolve_smem(cpu, &op->smem, in->mmap, in->port, &word, &is_mmr,
                         &is_io, &io_port, &post)) {
            return -1;
        }
        apply_post(cpu, &op->smem, post, 0);
        cpu->xsp = xar_plus(cpu->xsp, 1);
        cpu->sp_written = 1;
        return 0;
    case C55X_OP_PSHBOTH:
        cpu->xsp = xar_plus(cpu->xsp, -1);
        cpu->xssp = xar_plus(cpu->xssp, -1);
        cpu->sp_written = 1;
        cpu->ssp_written = 1;
        return 0;
    case C55X_OP_POPBOTH:
        cpu->xsp = xar_plus(cpu->xsp, 1);
        cpu->xssp = xar_plus(cpu->xssp, 1);
        cpu->sp_written = 1;
        cpu->ssp_written = 1;
        return 0;
    case C55X_OP_MOV_XMEM_YMEM:
        dual_ar_commit(cpu, &op->smem, 1);
        dual_ar_commit(cpu, &op->ymem, 1);
        return 0;
    case C55X_OP_MOV_DBL_XY: {
        uint32_t yw;
        int y_mmr, y_io;
        uint16_t y_port;
        int32_t ypost;

        if (resolve_smem(cpu, &op->smem, 0, 0, &word, &is_mmr, &is_io,
                         &io_port, &post) ||
            resolve_smem(cpu, &op->ymem, 0, 0, &yw, &y_mmr, &y_io,
                         &y_port, &ypost)) {
            return -1;
        }
        apply_post(cpu, &op->smem, post, 1);
        apply_post(cpu, &op->ymem, ypost, 1);
        return 0;
    }
    default:
        if (!op_uses_smem(op->kind)) {
            return 0;
        }
        if (resolve_smem(cpu, &op->smem, in->mmap, in->port, &word, &is_mmr,
                         &is_io, &io_port, &post)) {
            return -1;
        }
        apply_post(cpu, &op->smem, post, op_dbl_mem(op->kind));
        return 0;
    }
}

static int irq_pending(const C55xCPU *cpu)
{
    return ((cpu->ifr0 & cpu->ier0) != 0) || ((cpu->ifr1 & cpu->ier1) != 0);
}

static int accept_irq(C55xCPU *cpu)
{
    unsigned bit;
    uint32_t vec;

    knlq_note_accept(cpu);
    if (cpu->st1 & C55X_ST1_INTM) {
        return 0;
    }
    if (!cpu->sp_written || !cpu->ssp_written) {
        return 0;
    }
    for (bit = 0; bit < 16; bit++) {
        uint16_t mask = (uint16_t)(1u << bit);
        if ((cpu->ifr0 & cpu->ier0 & mask) == 0) {
            continue;
        }
        if (knlq_hold_int5(cpu, bit, cpu->pc)) {
            continue;
        }
        if (knlq_hold_nest(cpu, bit, cpu->pc)) {
            continue;
        }
        if (knlq_arm_snap(cpu, bit, cpu->pc) && cpu->bus.snapshot) {
            cpu->bus.snapshot(cpu->bus.opaque, "c55x_1012fb_call0_replay");
        }
        cpu->ifr0 &= (uint16_t)~mask;
        vec = ((uint32_t)cpu->ivpd << 8) + (uint32_t)bit * 8;
        {
            int c54x = vector_c54x_stk(cpu, vec);
            uint32_t from = cpu->pc;
            uint16_t ifr0 = cpu->ifr0 | mask;

            irq_enter(cpu, from, c54x);
            cpu->st1 |= C55X_ST1_INTM;
            cpu->pc = vec & C55X_PC_MASK;
            cpu->last_irq_from = from & C55X_PC_MASK;
            cpu->last_irq_vec = cpu->pc;
            cpu->last_irq_bit = (uint8_t)bit;
            {
                uint8_t vb[8];

                if (c55x_fetch(cpu, cpu->pc, vb, 8) == 0) {
                    c55x_log(cpu,
                             "IRQ-vec bytes=%02x %02x %02x %02x "
                             "%02x %02x %02x %02x\n",
                             vb[0], vb[1], vb[2], vb[3],
                             vb[4], vb[5], vb[6], vb[7]);
                }
            }
            c55x_log(cpu,
                     "IRQ bit=%u vec=%06x from=%06x %s RETA=%06x CFCT=%02x "
                     "IVPD=%04x IER0=%04x IFR0=%04x IER1=%04x IFR1=%04x "
                     "ST0=%04x ST1=%04x ST2=%04x ST3=%04x "
                     "XSP=%06x XSSP=%06x nest=%u rpt=%u/%u/%u insn=%llu\n",
                     bit, cpu->pc, from,
                     c54x ? "C54X_STK" : "USE_RETA",
                     cpu->reta & C55X_PC_MASK, cpu->cfct & 0xff,
                     cpu->ivpd, cpu->ier0, ifr0,
                     cpu->ier1, cpu->ifr1, cpu->st0, cpu->st1, cpu->st2,
                     cpu->st3, cpu->xsp & C55X_WORD_MASK,
                     cpu->xssp & C55X_WORD_MASK, cpu->irq_nest,
                     cpu->rpt_armed, cpu->rpt_active, cpu->rpt_cc,
                     (unsigned long long)cpu->insn_count);
            if (bit == 5) {
                bios_watch_arm();
            }
            eapq_note_irq(cpu, bit);
            knlq_note_irq(cpu, bit, from);
        }
        return 1;
    }
    return 0;
}

typedef struct {
    uint8_t end0;
    uint8_t end1;
    uint8_t repeat0;
    uint8_t repeat1;
} C55xRptbLast;

static C55xRptbLast rptb_begin_last(C55xCPU *cpu, uint32_t insn_pc)
{
    C55xRptbLast st = { 0, 0, 0, 0 };

    if (cpu->rptb1_active && insn_pc == cpu->rea1) {
        st.end1 = 1;
        if (cpu->brc1 != 0) {
            uint16_t was = cpu->brc1;

            cpu->brc1--;
            st.repeat1 = 1;
            c55x_log(cpu, "RPTB-DEC pc=%06x BRC1 %04x -> %04x\n",
                     insn_pc, was, cpu->brc1);
        }
    }
    if (!st.repeat1 && cpu->rptb0_active && insn_pc == cpu->rea0) {
        st.end0 = 1;
        if (cpu->brc0 != 0) {
            uint16_t was = cpu->brc0;

            cpu->brc0--;
            st.repeat0 = 1;
            c55x_log(cpu, "RPTB-DEC pc=%06x BRC0 %04x -> %04x\n",
                     insn_pc, was, cpu->brc0);
        }
    }
    return st;
}

static void rptb_finish_last(C55xCPU *cpu, uint32_t insn_pc, C55xRptbLast st)
{
    if (st.end1) {
        if (st.repeat1) {
            cpu->pc = cpu->rsa1;
            c55x_log(cpu, "RPTB-END pc=%06x BRC1=%04x jump=%06x\n",
                     insn_pc, cpu->brc1, cpu->rsa1);
        } else {
            cpu->rptb1_active = 0;
            c55x_log(cpu, "RPTB-END pc=%06x BRC1=0 done\n", insn_pc);
        }
    }
    if (st.end0) {
        if (st.repeat0) {
            cpu->pc = cpu->rsa0;
            c55x_log(cpu, "RPTB-END pc=%06x BRC0=%04x jump=%06x\n",
                     insn_pc, cpu->brc0, cpu->rsa0);
        } else {
            cpu->rptb0_active = 0;
            c55x_log(cpu, "RPTB-END pc=%06x BRC0=0 done\n", insn_pc);
        }
    }
    rptb_sync_braf(cpu);
}

static const char *xar3_write_kind(const C55xDecodedInsn *in)
{
    unsigned i;

    if (!in) {
        return "none";
    }
    for (i = 0; i < in->op_count; i++) {
        const C55xOp *op = &in->op[i];

        switch (op->kind) {
        case C55X_OP_MOV_XREG:
            if ((op->dst & 15) == 11) {
                return "full-xar-assign";
            }
            break;
        case C55X_OP_AMAR_XDST:
            if ((op->dst & 15) == 11) {
                return "full-xar-effective-addr";
            }
            break;
        case C55X_OP_MOV_DBL_XDST:
            if ((op->dst & 15) == 11) {
                return "full-xar-from-dbl";
            }
            break;
        case C55X_OP_POPBOTH:
            if ((op->dst & 15) == 11) {
                return "full-xar-popboth";
            }
            break;
        case C55X_OP_AADD_K8_TAX:
        case C55X_OP_AADD_TAX:
        case C55X_OP_ASUB_K8_TAX:
        case C55X_OP_ASUB_TAX:
            if ((op->dst & 15) == 11) {
                return "low-ar-arith";
            }
            break;
        case C55X_OP_AMOV_K8_TAX:
        case C55X_OP_AMOV_TAX:
        case C55X_OP_AMOV_D16:
        case C55X_OP_MOV_REG_REG:
        case C55X_OP_MOV_K4:
        case C55X_OP_MOV_NK4:
        case C55X_OP_MOV_K16_DST:
            if ((op->dst & 15) == 11) {
                return "low-ar-assign";
            }
            break;
        default:
            break;
        }
        if (op->smem.kind == C55X_AM_AR && op->smem.ar == 3 &&
            op->smem.mod != C55X_MOD_NONE) {
            return "low-ar-postmod";
        }
    }
    return "other";
}

static void xar3_note(C55xCPU *cpu, uint32_t insn_pc,
                      const C55xDecodedInsn *in)
{
    uint32_t now = cpu->xar[3] & C55X_WORD_MASK;
    uint32_t old = cpu->xar3_prev & C55X_WORD_MASK;
    int in_window = (insn_pc >= 0x103300u && insn_pc <= 0x103400u);
    char dis[96];
    char extra[160];
    const char *kind;
    const C55xOp *op;
    unsigned i;

    if (now == old) {
        return;
    }
    if (!in_window && !cpu->xar3_watch) {
        cpu->xar3_prev = now;
        return;
    }
    if (!in_window && cpu->xar3_nlogged >= 64) {
        cpu->xar3_prev = now;
        return;
    }
    kind = xar3_write_kind(in);
    if (!in_window && strcmp(kind, "low-ar-postmod") == 0) {
        cpu->xar3_prev = now;
        return;
    }
    cpu->xar3_nlogged++;
    c55x_disasm(in, dis, sizeof(dis));
    extra[0] = '\0';
    op = NULL;
    for (i = 0; in && i < in->op_count; i++) {
        if ((in->op[i].dst & 15) == 11 ||
            in->op[i].kind == C55X_OP_MOV_DBL_XDST) {
            op = &in->op[i];
            if (in->op[i].kind == C55X_OP_MOV_DBL_XDST &&
                (in->op[i].dst & 15) == 11) {
                break;
            }
        }
    }
    if (op && op->kind == C55X_OP_MOV_DBL_XDST && (op->dst & 15) == 11) {
        uint32_t rebuilt = (((uint32_t)(cpu->lmem_msw & 0x7f) << 16) |
                            cpu->lmem_lsw) & C55X_WORD_MASK;

        snprintf(extra, sizeof(extra),
                 " src=dbl word=%06x first=%06x pair=%06x MSW=%04x LSW=%04x"
                 " rebuilt=%06x AC1=%010llx",
                 cpu->lmem_word, cpu->lmem_word, cpu->lmem_word ^ 1u,
                 cpu->lmem_msw, cpu->lmem_lsw, rebuilt,
                 (unsigned long long)cpu->ac[1]);
    } else if (op && op->kind == C55X_OP_MOV_XREG && (op->dst & 15) == 11) {
        snprintf(extra, sizeof(extra), " src=%s=%06x",
                 c55x_xreg_name(op->src), c55x_get_xreg(cpu, op->src));
    } else if (op && op->kind == C55X_OP_AMAR_XDST && (op->dst & 15) == 11) {
        snprintf(extra, sizeof(extra), " src=effective-word=%06x", now);
    } else if (op && (op->kind == C55X_OP_AADD_TAX ||
                      op->kind == C55X_OP_AADD_K8_TAX ||
                      op->kind == C55X_OP_ASUB_TAX ||
                      op->kind == C55X_OP_ASUB_K8_TAX) &&
               (op->dst & 15) == 11) {
        snprintf(extra, sizeof(extra), " src=%s imm=%d T1=%04x",
                 c55x_reg_name(op->src), op->imm, cpu->t[1]);
    }
    c55x_log(cpu,
             "XAR3 pc=%06x %s old=%06x new=%06x kind=%s "
             "page %02x->%02x wrap=%s%s\n",
             insn_pc, dis, old, now, kind,
             (old >> 16) & 0x7f, (now >> 16) & 0x7f,
             ((old >> 16) == (now >> 16)) ? "low16-only" : "page-changed",
             extra);
    cpu->xar3_prev = now;
}

static int insn_uses_dbl_lmem(const C55xDecodedInsn *in)
{
    unsigned i;

    for (i = 0; in && i < in->op_count; i++) {
        switch (in->op[i].kind) {
        case C55X_OP_MOV_AC_DBL:
        case C55X_OP_MOV_XREG_DBL:
        case C55X_OP_MOV_DBL_AC:
        case C55X_OP_MOV_PAIR_DBL:
        case C55X_OP_MOV_DBL_PAIR:
        case C55X_OP_MOV_DBL_XDST:
        case C55X_OP_MOV_DBL_XY:
            return 1;
        default:
            break;
        }
    }
    return 0;
}

static void ac0_note(C55xCPU *cpu, uint32_t insn_pc, const C55xDecodedInsn *in)
{
    uint64_t now = cpu->ac[0] & C55X_AC_MASK;
    uint64_t old = cpu->ac0_prev & C55X_AC_MASK;
    int in_window = (insn_pc >= 0x103367u && insn_pc <= 0x1033acu);
    char dis[96];
    char raw[40];
    unsigned i;
    int n = 0;

    if (now == old) {
        return;
    }
    if (!in_window && !cpu->ac0_watch) {
        cpu->ac0_prev = now;
        return;
    }
    if (!in_window && cpu->ac0_nlogged >= 128) {
        cpu->ac0_prev = now;
        return;
    }
    cpu->ac0_nlogged++;
    c55x_disasm(in, dis, sizeof(dis));
    raw[0] = '\0';
    if (in) {
        for (i = 0; i < in->length && i < C55X_FETCH_MAX; i++) {
            n += snprintf(raw + n, sizeof(raw) - (size_t)n, "%s%02x",
                          i ? " " : "", in->bytes[i]);
            if (n < 0 || (size_t)n >= sizeof(raw)) {
                break;
            }
        }
    }
    if (insn_uses_dbl_lmem(in)) {
        c55x_log(cpu,
                 "AC0 pc=%06x bytes=%s %s old=%010llx new=%010llx "
                 "Lmem word=%06x first=%06x pair=%06x MSW=%04x LSW=%04x "
                 "M40=%u SXMD=%u SATD=%u\n",
                 insn_pc, raw, dis,
                 (unsigned long long)old, (unsigned long long)now,
                 cpu->lmem_word, cpu->lmem_word, cpu->lmem_word ^ 1u,
                 cpu->lmem_msw, cpu->lmem_lsw,
                 !!(cpu->st1 & C55X_ST1_M40),
                 !!(cpu->st1 & C55X_ST1_SXMD),
                 !!(cpu->st1 & C55X_ST1_SATD));
    } else {
        c55x_log(cpu,
                 "AC0 pc=%06x bytes=%s %s old=%010llx new=%010llx "
                 "M40=%u SXMD=%u SATD=%u\n",
                 insn_pc, raw, dis,
                 (unsigned long long)old, (unsigned long long)now,
                 !!(cpu->st1 & C55X_ST1_M40),
                 !!(cpu->st1 & C55X_ST1_SXMD),
                 !!(cpu->st1 & C55X_ST1_SATD));
    }
    cpu->ac0_prev = now;
}

static uint16_t peek16(C55xCPU *cpu, uint32_t word)
{
    uint16_t value = 0;

    /*
     * Logging reads must not latch FAULT_AD. The unmapped EXMAP
     * probe samples that register after MOV *AR0 misses.
     */
    cpu->diag_read = 1;
    if (cpu->bus.read16) {
        cpu->bus.read16(cpu->bus.opaque, word, &value);
    }
    cpu->diag_read = 0;
    return value;
}

/* Diagnostic reads only. A stack-derived pointer of 0x660000 at
 * `_init_tasks` walked the DSP MMU and the next RPT body at
 * 0x10063e fetched 0x00. */
static int peek_word_safe(uint32_t word)
{
    word &= C55X_WORD_MASK;
    if (!data_word_is_ram(word) || word < 0x100u) {
        return 0;
    }
    /* On-chip + tokliBIOS BSS/data (09xxxx). Deny the 0x660000-class
     * EXMAP walk that used to set the DSP MMU fault latch. */
    if (word < 0x20000u) {
        return 1;
    }
    return word >= 0x090000u && word < 0x0b0000u;
}

static uint16_t peek16_ram(C55xCPU *cpu, uint32_t word)
{
    word &= C55X_WORD_MASK;
    if (!peek_word_safe(word)) {
        return 0;
    }
    return peek16(cpu, word);
}

/*
 * avs_kernel.out DSP/BIOS 5 / tokliBIOS PCs (byte) and data words.
 * SWI_D_* words are COFF byte addresses / 2. Do not infer SWI object
 * fields; only name the three handles mailbox.c posts.
 */
#define BIOS_PC_SWI_ENABLE      0x1024dau
#define BIOS_PC_SWI_POST        0x10250du
#define BIOS_PC_SWI_EXEC_SYNC   0x102598u
#define BIOS_PC_SWI_EXEC        0x10262du
#define BIOS_PC_SWI_RUN         0x102719u
#define BIOS_PC_HWI_DISPATCH    0x1028c4u
#define BIOS_PC_HWI_ISR_CALL    0x102a29u
#define BIOS_PC_HWI_LOCK_DEC    0x102a6du
#define BIOS_PC_HWI_NEST_BCC    0x102a7bu
#define BIOS_PC_HWI_READY_BCC   0x102a8au
#define BIOS_PC_HWI_SWI_CALL    0x102a9cu
#define BIOS_PC_HWI_RETI        0x102be3u
#define BIOS_PC_KNL_RUN         0x1012a4u
#define BIOS_PC_KNL_CALL0      0x1012fbu
#define BIOS_PC_KNL_RUN_END    0x101340u
#define BIOS_PC_KNL_IPOST      0x1022a4u
#define BIOS_PC_KNL_IPOST_BCC  0x1022b9u
#define BIOS_PC_KNL_IPOST_WORK 0x1022dfu
#define BIOS_PC_KNL_IPOST_RET  0x1022e5u
#define BIOS_PC_KNL_CLEAR_WORK 0x1012c7u
#define BIOS_PC_ATM_INCU      0x102ec5u
#define BIOS_PC_ATM_INCU_RET  0x102eddu
#define BIOS_PC_QUE_PUT_RET   0x103237u
#define BIOS_PC_SRC_RPTB0      0x134900u
#define BIOS_PC_SRC_RPTB1      0x134980u
#define BIOS_PC_KNL_READY       0x1019dcu
#define BIOS_PC_KNL_SWITCH      0x102d63u
#define BIOS_PC_SWI_OR          0x103239u
#define BIOS_PC_SWI_ORHOOK      0x103258u
#define BIOS_PC_HWI_DISABLE     0x1032fau
#define BIOS_PC_HWI_ENABLE      0x103306u
#define BIOS_PC_HWI_RESTORE     0x10330au
#define BIOS_PC_SWI_DISABLE     0x103322u
#define BIOS_PC_BALANCE         0x12607cu
#define BIOS_PC_TCFG_UNPACK     0x126938u
#define BIOS_PC_TCFG_DISP       0x126a80u
#define BIOS_PC_MBCMD_SEND      0x125f3cu
#define BIOS_PC_CMD_DISP        0x129600u
#define BIOS_PC_GET_MBQ         0x129720u
#define BIOS_PC_TASK_LOOP       0x129780u
#define BIOS_PC_TCFG_REPLY      0x1294b0u
#define BIOS_PC_REG_MBQ         0x1297c8u
#define BIOS_PC_SEM_PEND        0x1031a9u
#define BIOS_PC_MBQ_TIDGE       0x1297dbu
#define BIOS_PC_MBQ_NULLB       0x1297f3u
#define BIOS_PC_MBQ_ERR16       0x1297f5u
#define BIOS_PC_MBQ_STAT        0x129815u
#define BIOS_PC_MBQ_FULL        0x129821u
#define BIOS_PC_MBQ_WRAP        0x12986fu
#define BIOS_PC_MBQ_OVF         0x12987bu
#define BIOS_PC_MBQ_OK          0x12989bu
#define BIOS_PC_MBQ_RET         0x12989fu
#define BIOS_PC_INIT_TASKS      0x1298a4u
#define BIOS_PC_SEM_POST        0x102fa1u
#define BIOS_PC_MBX_NEWMSG      0x131eecu
#define BIOS_PC_MBX_SEQ_BCC     0x131f2eu
#define BIOS_PC_MBX_SEQ_ERR     0x131f43u
#define BIOS_PC_MBX_SFTL        0x131f56u
#define BIOS_PC_MBX_NULL_BCC    0x131f6fu
#define BIOS_PC_MBX_CALL        0x131f79u
#define BIOS_PC_MBX_NOTFULL     0x131f84u
#define BIOS_PC_MAILBOX_ISR     0x131fb0u
#define BIOS_PC_MBX_POST_NEW    0x131fc0u
#define BIOS_PC_POLL_SEND       0x131c7cu
#define BIOS_PC_POLL_BCAST      0x131b44u
#define BIOS_PC_POLL_FAN        0x131bafu
#define BIOS_PC_POLL_CLEAR      0x131c04u
#define BIOS_PC_POLL_BTST0      0x131c23u
#define BIOS_PC_POLL_BTST1      0x131c55u
#define BIOS_PC_POLL_LAST       0x131c79u
#define BIOS_PC_MBQ_GOT         0x1297b2u
#define BIOS_PC_ISSUE_IDLE      0x13082fu
#define BIOS_PC_SLEEP_DSP       0x130844u
#define BIOS_PC_IER_DIS         0x10309bu
#define BIOS_PC_CMD54           0x126170u
#define BIOS_PC_SIO_CREATE      0x100998u
#define BIOS_PC_SIO_FXNS_COPY   0x100a73u
#define BIOS_PC_SIO_FXNS_OPEN   0x100af3u
#define BIOS_PC_SIO_DELETE      0x1013ecu
#define BIOS_PC_SIO_RECLAIM     0x101f14u
#define BIOS_PC_SIO_ISSUE       0x101fe0u
#define BIOS_PC_QUE_GET         0x1031f7u
#define BIOS_PC_QUE_PUT         0x103216u
#define BIOS_PC_EAP_POSTSTREAM  0x12a24cu
#define BIOS_PC_EAP_COPYCH      0x12c540u
#define BIOS_PC_EAP_COPYCH_ZERO 0x12c624u
#define BIOS_PC_MUMDRC_COPY_AR  0x1327efu
#define BIOS_PC_MUMDRC_COPY_ST  0x1327f8u
#define BIOS_PC_MUMDRC_QMF_SIZE 0x13488bu
#define BIOS_PC_MUMDRC_ANALYZE_ST 0x134759u
#define BIOS_PC_MUMDRC_ENTRY    0x132708u
#define BIOS_PC_MUMDRC_MAIN_T2  0x134b03u /* after MOV T0,T2 */
#define BIOS_PC_MUMDRC_T2_STOMP 0x134d8cu /* MOV AC0,dbl(*(AR2+T0)) */
#define BIOS_PC_MUMDRC_CALLSP6  0x134d28u /* MOV AC2,dbl(*(AR2-T0)) T0=6 */
#define BIOS_PC_MUMDRC_PROLOGUE 0x134af3u /* PSH ST2 entry */
#define BIOS_PC_MUMDRC_MAIN_POP 0x134fcdu /* POP T2,T3 */
#define BIOS_PC_EAP_CTRL        0x128510u
#define BIOS_PC_EAP_SORT        0x127f2cu /* _EAP_sortNetwork */
#define BIOS_PC_EAP_SORT_LOOP   0x127fa8u /* CMPU outer head */
#define BIOS_PC_EAP_PROCESS     0x12a398u
#define BIOS_PC_EAP_CHREADY     0x12c920u
#define BIOS_PC_EAP_RECLAIM     0x12cac0u
#define BIOS_PC_EAP_READY       0x12caf8u
#define BIOS_PC_EAP_ISSUE       0x12cc44u
#define BIOS_PC_EAP_ISSUE_RET   0x12cc93u
#define BIOS_PC_EAP_ISSUE_BCC   0x12cc5bu
#define BIOS_PC_EAP_ISSUE_ST2   0x12cc65u
#define BIOS_PC_EAP_ISSUE_ST3   0x12cc6cu
#define BIOS_PC_EAP_ISSUE_DIR   0x12cc7fu
#define BIOS_PC_DMAENABLE       0x12a4e8u
#define BIOS_PC_DMAEN_RET       0x12a578u
#define BIOS_PC_DMAEN_BCC       0x12a516u
#define BIOS_PC_DMAEN_SKIP      0x12a565u
#define BIOS_PC_EAP_CLOCK       0x12870cu
#define BIOS_PC_AUDIO_ISR       0x01f460u
#define BIOS_PC_C55_ENINT       0x101b48u
#define BIOS_PC_SWI_EAP         0x0200a0u
#define BIOS_PC_SWI_EAP_RET     0x0200c8u
#define BIOS_WORD_SWI_EAP       0x010050u
#define BIOS_WORD_SWI_EAP_RET   0x010064u
#define BIOS_WORD_EAP_SEM       0x00f136u
#define BIOS_WORD_DMA_SEM       0x081c3eu
#define BIOS_WORD_EAP_GLOBAL    0x00ef7au
#define BIOS_WORD_DMA_DISCNT    0x09d0a4u
#define BIOS_WORD_AUDIO_ON      0x09d0a5u
#define BIOS_WORD_MCBSP_ONCE    0x09d068u
#define BIOS_WORD_DMA_MODE      0x09d069u
#define BIOS_PC_ENABLE_DMA      0x130b44u
#define BIOS_PC_CFG_DMA         0x130d38u
#define BIOS_PC_ENABLE_MCBSP    0x133390u
#define BIOS_PC_CFG_MCBSP       0x1333b8u
#define BIOS_PC_SRC_CONVERT     0x132f5cu
#define BIOS_PC_SRC_DBL         0x135fcfu
#define BIOS_PC_SRC_RPTCSR      0x1360ceu
#define BIOS_PC_EAP_PENTRY      0x12a048u
#define BIOS_PC_REMOVE_STREAM   0x12797cu
#define BIOS_PC_REQ_STREAM      0x1277e8u
#define BIOS_PC_REQ_T2          0x127855u
#define BIOS_PC_REQ_SCAN        0x12788au
#define BIOS_PC_REQ_FAIL        0x12791cu
#define BIOS_PC_REQ_OK          0x12796eu
#define BIOS_PC_REQ_RET         0x12797au
#define BIOS_PC_NAME4_A         0x1239beu
#define BIOS_PC_NAME4_B         0x122686u
#define BIOS_PC_NAME4_C         0x124c16u
#define BIOS_PC_NAME5_A         0x1239d5u
#define BIOS_PC_NAME5_B         0x12269du
#define BIOS_PC_NAME5_C         0x124c2du
#define BIOS_PC_DEV_MATCH       0x101e18u
#define BIOS_PC_DEVM_CAND       0x101e35u
#define BIOS_PC_DEVM_STRLEN     0x101e4cu
#define BIOS_PC_DEVM_SUB        0x101e66u
#define BIOS_PC_DEVM_MIS        0x101e6bu
#define BIOS_PC_DEVM_HIT        0x101e78u
#define BIOS_PC_DEVM_NEXT       0x101e80u
#define BIOS_PC_DEV_MATCH_RET   0x101e99u
#define BIOS_WORD_DEVQ          0x09cf8au
#define BIOS_PC_EAP_OPEN        0x1300c8u
#define BIOS_PC_EAP_OPEN_PARSE  0x13011du
#define BIOS_PC_EAP_OPEN_FAIL   0x13017bu
#define BIOS_WORD_SIO_EAP       0x09cf62u
#define BIOS_WORD_EAP_NAME_A    0x09cf4eu
#define BIOS_WORD_EAP_NAME_B    0x09cecau
#define BIOS_WORD_EAP_NAME_C    0x09cf24u
#define BIOS_WORD_EAP_ID_A      0x09cf58u
#define BIOS_WORD_EAP_ID_B      0x09ced4u
#define BIOS_WORD_EAP_ID_C      0x09cf2eu
#define BIOS_DEV_FXNS           0x0eu
#define BIOS_DEV_IDLE           0x12u
#define BIOS_DEV_FXNS_END       0x1bu
#define BIOS_IDLE_STALE         0x01ef7au
#define BIOS_WORD_MSGSTAT1      0x7f1062u
#define BIOS_WORD_FIFOSTAT1     0x7f1042u
#define BIOS_WORD_RUNADDR       0x8023eu
#define BIOS_WORD_CURMASK       0x80242u
#define BIOS_WORD_CURSET        0x80243u
#define BIOS_WORD_LOCK          0x80244u
#define BIOS_WORD_MSGSTAT       0x7f1060u
#define BIOS_WORD_IRQSTAT       0x7f1084u
#define BIOS_WORD_CMDTAB        0x9c9ceu
#define BIOS_WORD_SEQ           0x9caceu
#define BIOS_WORD_SWI_KNL       0x10000u
#define BIOS_WORD_SWI_NEWMSG    0x10014u
#define BIOS_WORD_SWI_NOTFULL   0x10028u
#define BIOS_WORD_TIDTAB        0x9ccfau
#define BIOS_TIDTAB_WORDS       10u
#define BIOS_WORD_POLLMASK      0x09cf9au
#define BIOS_WORD_POLLCNT0      0x09cfbau
#define BIOS_WORD_POLLCNT1      0x09cfbbu
#define BIOS_WORD_KNL_WORK      0x09cba8u
#define BIOS_WORD_KNL_SET       0x09cba9u
#define BIOS_WORD_KNL_QUEUES    0x09cbaau
#define BIOS_WORD_KNL_WORKQ     0x09cbfau
#define BIOS_WORD_KNL_DUMMY     0x09cc04u
#define BIOS_WORD_KNL_CURTASK   0x09cc1cu
#define BIOS_WORD_EAP_F140      0x00f140u

static uint32_t peek_dbl(C55xCPU *cpu, uint32_t word)
{
    uint32_t even = word & ~1u;

    return ((uint32_t)peek16(cpu, even) << 16) | peek16(cpu, even + 1u);
}

static uint32_t peek_dbl_ram(C55xCPU *cpu, uint32_t word)
{
    uint32_t even = word & ~1u;

    if (!peek_word_safe(even) || !peek_word_safe(even + 1u)) {
        return 0;
    }
    return ((uint32_t)peek16_ram(cpu, even) << 16) | peek16_ram(cpu, even + 1u);
}

#include "c55x_knlq.inc"
#if 0
#define KNLQ_EV 16
#define KNLQ_KIND_PUT 1
#define KNLQ_KIND_GET 2
#define KNLQ_KIND_SENT 3
#define KNLQ_KIND_INT5 4
#define KNLQ_KIND_RETI 5
#define KNLQ_KIND_WORK 6
#define KNLQ_KIND_CALL 7
#define KNLQ_KIND_RUN 8
#define KNLQ_KIND_HOLD 9
#define KNLQ_KIND_TC 10
#define KNLQ_KIND_CLNK 11
#define KNLQ_KIND_ISR 12

static uint8_t knlq_inited;
static uint8_t knlq_delay_int5;
static uint8_t knlq_trace_que;
static uint8_t knlq_suppress_put;
static uint8_t knlq_hold_logged;
static uint8_t knlq_skip_put;
static uint8_t knlq_in_get;
static uint8_t knlq_in_put;
static uint8_t knlq_ev_n;
static uint8_t knlq_cb_n;
static uint8_t knlq_cb_good;
static uint32_t knlq_arg_handle;
static uint32_t knlq_arg_elem;
static uint32_t knlq_pre_next;
static uint32_t knlq_pre_prev;
static struct {
    uint8_t kind;
    uint32_t pc;
    uint32_t a;
    uint32_t b;
    uint64_t insn;
} knlq_ev[KNLQ_EV];

static int knlq_env_on(const char *name)
{
    const char *e = getenv(name);

    return e && e[0] && e[0] != '0';
}

static void knlq_init(void)
{
    if (knlq_inited) {
        return;
    }
    knlq_inited = 1;
    knlq_delay_int5 = knlq_env_on("C55X_DELAY_INT5");
    knlq_trace_que = knlq_env_on("C55X_TRACE_BIOS_QUE");
    knlq_suppress_put = knlq_env_on("C55X_SUPPRESS_KNLQ_PUT");
}

static void knlq_reset_ring(void)
{
    knlq_ev_n = 0;
    knlq_cb_n = 0;
    knlq_cb_good = 0;
    knlq_in_get = 0;
    knlq_in_put = 0;
    knlq_skip_put = 0;
    knlq_hold_logged = 0;
    memset(knlq_ev, 0, sizeof(knlq_ev));
}

static void knlq_ev_push(uint8_t kind, uint32_t pc, uint32_t a, uint32_t b,
                          uint64_t insn)
{
    memmove(&knlq_ev[1], &knlq_ev[0], sizeof(knlq_ev) - sizeof(knlq_ev[0]));
    knlq_ev[0].kind = kind;
    knlq_ev[0].pc = pc & C55X_PC_MASK;
    knlq_ev[0].a = a;
    knlq_ev[0].b = b;
    knlq_ev[0].insn = insn;
    if (knlq_ev_n < KNLQ_EV) {
        knlq_ev_n++;
    }
}

static uint32_t knlq_handle(C55xCPU *cpu)
{
    return peek_dbl_ram(cpu, BIOS_WORD_KNL_WORKQ) & C55X_WORD_MASK;
}

static uint32_t knlq_next(C55xCPU *cpu, uint32_t q)
{
    return peek_dbl_ram(cpu, q) & C55X_WORD_MASK;
}

static uint32_t knlq_prev(C55xCPU *cpu, uint32_t q)
{
    return peek_dbl_ram(cpu, (q + 2u) & C55X_WORD_MASK) & C55X_WORD_MASK;
}

static uint32_t knlq_fxn(C55xCPU *cpu, uint32_t e)
{
    return peek_dbl(cpu, (e + 6u) & C55X_WORD_MASK) & C55X_WORD_MASK;
}

static int knlq_in_rptb(uint32_t pc)
{
    pc &= C55X_PC_MASK;
    return pc >= BIOS_PC_SRC_RPTB0 && pc < BIOS_PC_SRC_RPTB1;
}

static int knlq_in_run(uint32_t pc)
{
    pc &= C55X_PC_MASK;
    return pc >= BIOS_PC_KNL_RUN && pc < BIOS_PC_KNL_RUN_END;
}

static const char *knlq_kind_name(uint8_t kind)
{
    switch (kind) {
    case KNLQ_KIND_PUT:
        return "PUT";
    case KNLQ_KIND_GET:
        return "GET";
    case KNLQ_KIND_SENT:
        return "EMPTY-SENTINEL";
    case KNLQ_KIND_INT5:
        return "INT5";
    case KNLQ_KIND_RETI:
        return "INT5-EXIT";
    case KNLQ_KIND_WORK:
        return "WORK";
    case KNLQ_KIND_CALL:
        return "CALL";
    case KNLQ_KIND_RUN:
        return "KNL_run";
    case KNLQ_KIND_HOLD:
        return "INT5-HOLD";
    case KNLQ_KIND_TC:
        return "TC";
    case KNLQ_KIND_CLNK:
        return "CLNK";
    case KNLQ_KIND_ISR:
        return "audio_isr";
    default:
        return "?";
    }
}

static void knlq_dump_ev(C55xCPU *cpu)
{
    unsigned i;

    c55x_log(cpu, "KNLQ-LAST\n");
    for (i = 0; i < knlq_ev_n; i++) {
        c55x_log(cpu, "  t%u %s pc=%06x a=%06x b=%06x insn=%llu\n",
                 i, knlq_kind_name(knlq_ev[i].kind), knlq_ev[i].pc,
                 knlq_ev[i].a, knlq_ev[i].b,
                 (unsigned long long)knlq_ev[i].insn);
    }
}

static void knlq_check_obj(C55xCPU *cpu, uint32_t q, const char *tag)
{
    uint32_t next;
    uint32_t prev;
    uint32_t nn;
    uint32_t pp;

    if (!q) {
        return;
    }
    next = knlq_next(cpu, q);
    prev = knlq_prev(cpu, q);
    if (!next || !prev) {
        return;
    }
    nn = knlq_next(cpu, prev);
    pp = knlq_prev(cpu, next);
    if (nn != q || pp != q) {
        c55x_log(cpu,
                 "QUE-INVARIANT %s q=%06x next=%06x prev=%06x "
                 "prev.next=%06x next.prev=%06x pc=%06x insn=%llu\n",
                 tag, q, next, prev, nn, pp, cpu->pc & C55X_PC_MASK,
                 (unsigned long long)cpu->insn_count);
    }
}

static void knlq_walk(C55xCPU *cpu, uint32_t q, const char *tag)
{
    uint32_t p;
    unsigned n = 0;

    if (!knlq_trace_que || !q) {
        return;
    }
    knlq_check_obj(cpu, q, tag);
    p = knlq_next(cpu, q);
    while (p && p != q && n < 32) {
        knlq_check_obj(cpu, p, tag);
        p = knlq_next(cpu, p);
        n++;
    }
}

static void knlq_log_state(C55xCPU *cpu, const char *tag)
{
    uint32_t q = knlq_handle(cpu);
    uint16_t work = peek16(cpu, BIOS_WORD_KNL_WORK);
    uint32_t next = knlq_next(cpu, q);
    uint32_t prev = knlq_prev(cpu, q);
    int empty = q && next == q;

    c55x_log(cpu,
             "%s q=%06x next=%06x prev=%06x work=%u empty=%u "
             "set=%04x nest=%u INTM=%u IER0=%04x IFR0=%04x "
             "RETA=%06x CFCT=%02x XSP=%06x XSSP=%06x "
             "last_irq=%u from=%06x audio=%u tc=%u clnk=%u insn=%llu\n",
             tag, q, next, prev, work, empty,
             peek16(cpu, BIOS_WORD_KNL_SET), cpu->irq_nest,
             !!(cpu->st1 & C55X_ST1_INTM), cpu->ier0, cpu->ifr0,
             cpu->reta & C55X_PC_MASK, cpu->cfct & 0xffu,
             cpu->xsp & C55X_WORD_MASK, cpu->xssp & C55X_WORD_MASK,
             cpu->last_irq_bit, cpu->last_irq_from & C55X_PC_MASK,
             cpu->audio_isr_n, cpu->host_tc_n, cpu->host_clnk_n,
             (unsigned long long)cpu->insn_count);
    if (work && empty) {
        c55x_log(cpu,
                 "QUE-READY-EMPTY q=%06x work=%u pc=%06x nest=%u insn=%llu\n",
                 q, work, cpu->pc & C55X_PC_MASK,
                 cpu->irq_nest, (unsigned long long)cpu->insn_count);
    }
}

static int knlq_hold_int5(C55xCPU *cpu, unsigned bit, uint32_t from)
{
    knlq_init();
    if (!knlq_delay_int5 || bit != 5 || !knlq_in_rptb(from)) {
        knlq_hold_logged = 0;
        return 0;
    }
    if (!knlq_hold_logged) {
        knlq_hold_logged = 1;
        knlq_ev_push(KNLQ_KIND_HOLD, from, knlq_handle(cpu),
                     peek16(cpu, BIOS_WORD_KNL_WORK), cpu->insn_count);
        c55x_log(cpu, "INT5-HOLD from=%06x nest=%u insn=%llu\n",
                 from & C55X_PC_MASK, cpu->irq_nest,
                 (unsigned long long)cpu->insn_count);
    }
    return 1;
}

static int knlq_arm_snap(C55xCPU *cpu, unsigned bit, uint32_t from)
{
    knlq_init();
    if (bit != 5 || !knlq_in_rptb(from) || cpu->snap_1012fb) {
        return 0;
    }
    cpu->snap_1012fb = 1;
    c55x_log(cpu, "C55X-1012FB-SNAP from=%06x nest=%u insn=%llu\n",
             from & C55X_PC_MASK, cpu->irq_nest,
             (unsigned long long)cpu->insn_count);
    return 1;
}

static void knlq_note_irq(C55xCPU *cpu, unsigned bit, uint32_t from)
{
    knlq_init();
    if (bit != 5) {
        return;
    }
    knlq_ev_push(KNLQ_KIND_INT5, from, knlq_handle(cpu),
                 peek16(cpu, BIOS_WORD_KNL_WORK), cpu->insn_count);
    knlq_log_state(cpu, "INT5-ENTRY");
    knlq_walk(cpu, knlq_handle(cpu), "INT5-ENTRY");
}

static void knlq_note_reti(C55xCPU *cpu)
{
    if (cpu->last_irq_bit != 5) {
        return;
    }
    knlq_ev_push(KNLQ_KIND_RETI, cpu->pc, knlq_handle(cpu),
                 peek16(cpu, BIOS_WORD_KNL_WORK), cpu->insn_count);
    knlq_log_state(cpu, "INT5-EXIT");
}

static void knlq_note_work_store(C55xCPU *cpu, uint16_t old, uint16_t value)
{
    knlq_init();
    knlq_ev_push(KNLQ_KIND_WORK, cpu->pc, old, value, cpu->insn_count);
    c55x_log(cpu,
             "KNL-WORK pc=%06x %u->%u q=%06x next=%06x nest=%u insn=%llu\n",
             cpu->pc & C55X_PC_MASK, old, value, knlq_handle(cpu),
             knlq_next(cpu, knlq_handle(cpu)), cpu->irq_nest,
             (unsigned long long)cpu->insn_count);
}

static void knlq_log_get_after(C55xCPU *cpu, uint32_t from_pc)
{
    uint32_t ar0 = cpu->xar[0] & C55X_WORD_MASK;
    uint32_t after_next = knlq_next(cpu, knlq_arg_handle);
    uint32_t after_prev = knlq_prev(cpu, knlq_arg_handle);
    uint32_t fxn = knlq_fxn(cpu, ar0);
    uint32_t q = knlq_handle(cpu);
    int sentinel = knlq_arg_handle && ar0 == knlq_arg_handle;

    knlq_ev_push(sentinel ? KNLQ_KIND_SENT : KNLQ_KIND_GET, from_pc, ar0,
                 fxn, cpu->insn_count);
    c55x_log(cpu,
             "QUEUE %06x GET pc=%06x elem=%06x fxn=%06x "
             "empty_sentinel=%u next %06x->%06x prev %06x->%06x "
             "work=%u nest=%u knl=%u insn=%llu\n",
             knlq_arg_handle, from_pc, ar0, fxn, sentinel,
             knlq_pre_next, after_next, knlq_pre_prev, after_prev,
             peek16(cpu, BIOS_WORD_KNL_WORK), cpu->irq_nest,
             knlq_arg_handle == q, (unsigned long long)cpu->insn_count);
    knlq_walk(cpu, knlq_arg_handle, "GET");
}

static void knlq_log_put_after(C55xCPU *cpu, uint32_t from_pc)
{
    uint32_t after_next = knlq_next(cpu, knlq_arg_handle);
    uint32_t after_prev = knlq_prev(cpu, knlq_arg_handle);
    uint32_t fxn = knlq_fxn(cpu, knlq_arg_elem);
    uint32_t q = knlq_handle(cpu);

    knlq_ev_push(KNLQ_KIND_PUT, from_pc, knlq_arg_elem, fxn, cpu->insn_count);
    c55x_log(cpu,
             "QUEUE %06x PUT pc=%06x elem=%06x fxn=%06x "
             "next %06x->%06x prev %06x->%06x work=%u nest=%u knl=%u "
             "insn=%llu\n",
             knlq_arg_handle, from_pc, knlq_arg_elem, fxn,
             knlq_pre_next, after_next, knlq_pre_prev, after_prev,
             peek16(cpu, BIOS_WORD_KNL_WORK), cpu->irq_nest,
             knlq_arg_handle == q, (unsigned long long)cpu->insn_count);
    knlq_walk(cpu, knlq_arg_handle, "PUT");
}

static void knlq_note_before(C55xCPU *cpu)
{
    uint32_t pc = cpu->pc & C55X_PC_MASK;
    uint32_t q;
    uint32_t ar0;
    uint32_t ar1;
    uint32_t ar5;
    uint32_t fxn;
    uint16_t work;
    int sentinel;

    knlq_init();
    if (cpu->insn_count == 0) {
        knlq_reset_ring();
    }
    if (pc != BIOS_PC_AUDIO_ISR && pc != BIOS_PC_KNL_RUN &&
        pc != BIOS_PC_KNL_IPOST && pc != BIOS_PC_KNL_CALL0 &&
        pc != BIOS_PC_QUE_GET && pc != BIOS_PC_QUE_PUT) {
        return;
    }
    q = knlq_handle(cpu);
    ar0 = cpu->xar[0] & C55X_WORD_MASK;
    ar1 = cpu->xar[1] & C55X_WORD_MASK;
    ar5 = cpu->xar[5] & C55X_WORD_MASK;

    if (pc == BIOS_PC_AUDIO_ISR) {
        knlq_ev_push(KNLQ_KIND_ISR, pc, cpu->audio_isr_n + 1u,
                     cpu->host_tc_n, cpu->insn_count);
        return;
    }
    if (pc == BIOS_PC_KNL_RUN || pc == BIOS_PC_KNL_IPOST) {
        knlq_ev_push(KNLQ_KIND_RUN, pc, q, peek16(cpu, BIOS_WORD_KNL_WORK),
                     cpu->insn_count);
        knlq_log_state(cpu, pc == BIOS_PC_KNL_IPOST ? "KNL-IPOST" : "KNL-RUN");
        knlq_walk(cpu, q, "KNL-RUN");
        return;
    }
    if (pc == BIOS_PC_KNL_CALL0) {
        work = peek16(cpu, BIOS_WORD_KNL_WORK);
        sentinel = q && ar5 == q;
        fxn = knlq_fxn(cpu, ar5);
        knlq_cb_n++;
        if (!sentinel && (cpu->ac[0] & 0xffffffu) != 0) {
            knlq_cb_good++;
        }
        knlq_ev_push(sentinel ? KNLQ_KIND_SENT : KNLQ_KIND_CALL, pc, ar5,
                     (uint32_t)(cpu->ac[0] & 0xffffffu), cpu->insn_count);
        c55x_log(cpu,
                 "CALLBACK-GET caller=%06x queue_handle=%06x "
                 "before next=%06x prev=%06x QUE_get return=%06x "
                 "empty_sentinel=%u +0=%04x +1=%04x +2=%04x +3=%04x "
                 "+4=%04x +5=%04x +6=%06x AC0=%010llx work=%u "
                 "work_set=%04x nest=%u INTM=%u IER0=%04x IFR0=%04x "
                 "last_irq=%u from=%06x audio=%u tc=%u clnk=%u "
                 "good=%u/%u insn=%llu\n",
                 cpu->reta & C55X_PC_MASK, q, knlq_next(cpu, q),
                 knlq_prev(cpu, q), ar5, sentinel,
                 peek16(cpu, ar5), peek16(cpu, ar5 + 1u),
                 peek16(cpu, ar5 + 2u), peek16(cpu, ar5 + 3u),
                 peek16(cpu, ar5 + 4u), peek16(cpu, ar5 + 5u),
                 fxn, (unsigned long long)cpu->ac[0], work,
                 peek16(cpu, BIOS_WORD_KNL_SET), cpu->irq_nest,
                 !!(cpu->st1 & C55X_ST1_INTM), cpu->ier0, cpu->ifr0,
                 cpu->last_irq_bit, cpu->last_irq_from & C55X_PC_MASK,
                 cpu->audio_isr_n, cpu->host_tc_n, cpu->host_clnk_n,
                 knlq_cb_good, knlq_cb_n,
                 (unsigned long long)cpu->insn_count);
        if (sentinel) {
            c55x_log(cpu,
                     "CALLBACK-GET-SENTINEL queue=%06x AR5=%06x "
                     "AC0=%010llx work=%u nest=%u last_irq=%u from=%06x "
                     "insn=%llu\n",
                     q, ar5, (unsigned long long)cpu->ac[0], work,
                     cpu->irq_nest, cpu->last_irq_bit,
                     cpu->last_irq_from & C55X_PC_MASK,
                     (unsigned long long)cpu->insn_count);
            knlq_dump_ev(cpu);
        }
        if (work && sentinel) {
            c55x_log(cpu,
                     "QUE-READY-EMPTY q=%06x work=%u pc=%06x nest=%u "
                     "insn=%llu\n",
                     q, work, pc, cpu->irq_nest,
                     (unsigned long long)cpu->insn_count);
        }
        knlq_walk(cpu, q, "CALLBACK-GET");
        return;
    }
    if (pc == BIOS_PC_QUE_GET) {
        knlq_arg_handle = ar0;
        knlq_pre_next = knlq_next(cpu, ar0);
        knlq_pre_prev = knlq_prev(cpu, ar0);
        knlq_in_get = 1;
        if (ar0 == q || knlq_in_run(cpu->reta)) {
            c55x_log(cpu,
                     "KNL-QUEGET-BEFORE handle=%06x arg=%06x next=%06x "
                     "prev=%06x work=%u nest=%u insn=%llu\n",
                     q, ar0, knlq_pre_next, knlq_pre_prev,
                     peek16(cpu, BIOS_WORD_KNL_WORK), cpu->irq_nest,
                     (unsigned long long)cpu->insn_count);
        }
        return;
    }
    if (pc == BIOS_PC_QUE_PUT) {
        knlq_arg_handle = ar0;
        knlq_arg_elem = ar1;
        knlq_pre_next = knlq_next(cpu, ar0);
        knlq_pre_prev = knlq_prev(cpu, ar0);
        knlq_in_put = 1;
        if (knlq_suppress_put && q && ar0 == q && cpu->irq_nest >= 2) {
            knlq_skip_put = 1;
            c55x_log(cpu,
                     "KNLQ-PUT-SUPPRESS handle=%06x elem=%06x fxn=%06x "
                     "nest=%u insn=%llu\n",
                     ar0, ar1, knlq_fxn(cpu, ar1), cpu->irq_nest,
                     (unsigned long long)cpu->insn_count);
        }
        return;
    }
}

static void knlq_note_after(C55xCPU *cpu, uint32_t from, uint32_t next)
{
    uint32_t from_pc = from & C55X_PC_MASK;
    uint32_t next_pc = next & C55X_PC_MASK;

    knlq_init();
    if (knlq_in_get && from_pc >= BIOS_PC_QUE_GET &&
        from_pc < BIOS_PC_QUE_PUT &&
        (next_pc < BIOS_PC_QUE_GET || next_pc >= BIOS_PC_QUE_PUT)) {
        knlq_in_get = 0;
        knlq_log_get_after(cpu, from_pc);
        return;
    }
    if (knlq_in_put && from_pc >= BIOS_PC_QUE_PUT &&
        from_pc < BIOS_PC_SWI_OR &&
        (next_pc < BIOS_PC_QUE_PUT || next_pc >= BIOS_PC_SWI_OR)) {
        knlq_in_put = 0;
        knlq_log_put_after(cpu, from_pc);
    }
}

static int knlq_take_skip(C55xCPU *cpu)
{
    if (!knlq_skip_put) {
        return 0;
    }
    knlq_skip_put = 0;
    knlq_in_put = 0;
    (void)cpu;
    return 1;
}

static void knlq_note_call0(C55xCPU *cpu)
{
    knlq_init();
    c55x_log(cpu,
             "CALL-0 queue_handle=%06x AR5=%06x AC0=%010llx "
             "empty_sentinel=%u nest=%u insn=%llu\n",
             knlq_handle(cpu), cpu->xar[5] & C55X_WORD_MASK,
             (unsigned long long)cpu->ac[0],
             knlq_handle(cpu) &&
                 ((cpu->xar[5] & C55X_WORD_MASK) == knlq_handle(cpu)),
             cpu->irq_nest, (unsigned long long)cpu->insn_count);
    knlq_dump_ev(cpu);
}

void c55x_knlq_note_iodma(C55xCPU *cpu, int clnk, unsigned n, unsigned ch)
{
    knlq_init();
    if (clnk) {
        cpu->host_clnk_n = n;
        knlq_ev_push(KNLQ_KIND_CLNK, cpu->pc, ch, n, cpu->insn_count);
    } else {
        cpu->host_tc_n = n;
        knlq_ev_push(KNLQ_KIND_TC, cpu->pc, ch, n, cpu->insn_count);
    }
}

#endif /* old knlq */

static uint32_t mbq_task_of(C55xCPU *cpu, uint16_t tid)
{
    if (tid >= 32u) {
        return 0;
    }
    return peek_dbl(cpu, BIOS_WORD_TIDTAB + (uint32_t)tid * 2u);
}

static void log_mbq_task(C55xCPU *cpu, uint16_t tid, uint32_t task,
                         uint32_t cmd, const char *tag)
{
    uint32_t sem;
    unsigned i;
    char q[80];
    int n = 0;

    q[0] = '\0';
    cmd &= C55X_WORD_MASK;
    task &= C55X_WORD_MASK;
    if (!peek_word_safe(task)) {
        c55x_log(cpu,
                 "MBQ %s tid=%u task=%06x cmd=%04x %04x %04x T0=%04x "
                 "TC1=%u insn=%llu\n",
                 tag, tid, task,
                 peek_word_safe(cmd) ? peek16_ram(cpu, cmd) : 0,
                 peek_word_safe(cmd + 1u) ? peek16_ram(cpu, cmd + 1u) : 0,
                 peek_word_safe(cmd + 2u) ? peek16_ram(cpu, cmd + 2u) : 0,
                 cpu->t[0], !!(cpu->st0 & C55X_ST0_TC1),
                 (unsigned long long)cpu->insn_count);
        return;
    }
    for (i = 0; i < 8u; i++) {
        n += snprintf(q + n, sizeof(q) - (size_t)n, "%s%04x",
                      i ? " " : "", peek16_ram(cpu, task + 18u + i));
        if (n < 0 || (size_t)n >= sizeof(q)) {
            break;
        }
    }
    sem = peek_word_safe(task + 14u) ?
          (((uint32_t)peek16_ram(cpu, task + 14u) << 16) |
           peek16_ram(cpu, task + 15u)) : 0;
    c55x_log(cpu,
             "MBQ %s tid=%u task=%06x +0c=%04x wr=%04x rd=%04x +22=%04x "
             "q=%s sem=%06x scnt=%04x cmd=%04x %04x %04x T0=%04x TC1=%u "
             "insn=%llu\n",
             tag, tid, task, peek16_ram(cpu, task + 12u),
             peek16_ram(cpu, task + 16u), peek16_ram(cpu, task + 17u),
             peek16_ram(cpu, task + 0x22u), q, sem,
             peek_word_safe(sem + 4u) ? peek16_ram(cpu, sem + 4u) : 0,
             peek_word_safe(cmd) ? peek16_ram(cpu, cmd) : 0,
             peek_word_safe(cmd + 1u) ? peek16_ram(cpu, cmd + 1u) : 0,
             peek_word_safe(cmd + 2u) ? peek16_ram(cpu, cmd + 2u) : 0,
             cpu->t[0], !!(cpu->st0 & C55X_ST0_TC1),
             (unsigned long long)cpu->insn_count);
}

#define POLL_TID_MAX 32u

static struct {
    unsigned gen;
    uint16_t type;
    uint32_t participants;
    uint32_t queued;
    uint32_t posted;
    uint32_t scheduled;
    uint32_t dequeued;
    uint32_t cleared;
    uint32_t task[POLL_TID_MAX];
    uint32_t tsk[POLL_TID_MAX];
    uint32_t sem[POLL_TID_MAX];
    uint16_t wr0[POLL_TID_MAX];
    uint16_t rd0[POLL_TID_MAX];
    uint16_t last_cmd_h[POLL_TID_MAX];
    uint16_t last_cmd_d[POLL_TID_MAX];
    uint64_t last_post[POLL_TID_MAX];
    uint64_t last_pend[POLL_TID_MAX];
    uint64_t last_disp[POLL_TID_MAX];
    uint32_t last_xsp[POLL_TID_MAX];
    uint16_t cnt_enter;
    uint8_t live;
    uint8_t summarized;
    uint8_t ckpt;
} poll_tr;

static uint16_t task_last_cmd_h[POLL_TID_MAX];
static uint16_t task_last_cmd_d[POLL_TID_MAX];
static uint64_t task_last_disp[POLL_TID_MAX];
static uint64_t task_last_deq[POLL_TID_MAX];
static uint64_t task_last_sched[POLL_TID_MAX];
static void poll_checkpoint(C55xCPU *cpu, const char *why);

static void poll_fmt_set(uint32_t bits, char *buf, size_t n)
{
    unsigned i;
    int used = 0;

    buf[0] = '\0';
    for (i = 0; i < POLL_TID_MAX; i++) {
        if (!(bits & (1u << i))) {
            continue;
        }
        used += snprintf(buf + used, n - (size_t)used, "%s%u",
                         used ? "," : "", i);
        if (used < 0 || (size_t)used >= n) {
            break;
        }
    }
    if (!used && n) {
        buf[0] = '-';
        buf[1] = '\0';
    }
}

static void poll_bind_tid(C55xCPU *cpu, unsigned tid, uint32_t task)
{
    if (tid >= POLL_TID_MAX) {
        return;
    }
    if (!peek_word_safe(task)) {
        task = mbq_task_of(cpu, (uint16_t)tid);
    }
    poll_tr.task[tid] = task;
    poll_tr.tsk[tid] = peek_dbl_ram(cpu, task + 0x0au);
    poll_tr.sem[tid] = peek_dbl_ram(cpu, task + 14u);
}

static int poll_tid_of_sem(uint32_t sem)
{
    unsigned tid;

    sem &= C55X_WORD_MASK;
    if (!sem) {
        return -1;
    }
    for (tid = 0; tid < POLL_TID_MAX; tid++) {
        if (poll_tr.sem[tid] && (poll_tr.sem[tid] & C55X_WORD_MASK) == sem) {
            return (int)tid;
        }
    }
    return -1;
}

static int poll_tid_of_tsk(uint32_t tsk)
{
    unsigned tid;

    tsk &= C55X_WORD_MASK;
    if (!tsk) {
        return -1;
    }
    for (tid = 0; tid < POLL_TID_MAX; tid++) {
        uint32_t handle = poll_tr.tsk[tid] & C55X_WORD_MASK;

        if (handle && (tsk == handle || tsk == ((handle + 0x10u) & C55X_WORD_MASK))) {
            return (int)tid;
        }
    }
    return -1;
}

static void poll_dump_words(C55xCPU *cpu, uint32_t word, unsigned n,
                            const char *tag);
static void poll_log_task(C55xCPU *cpu, unsigned tid, const char *tag);

#define EAPQ_WORD      0xf140u
#define EAPQ_WORDS     8u
#define EAPQ_CALL_RING 8u
#define EAPQ_EV_CAP    400u

static struct {
    uint8_t flow_000e;
    uint8_t flow_000f;
    uint8_t parked4;
    uint8_t snap_000e;
    unsigned ev_n;
    uint32_t cmd20_open;
    uint32_t cmd20_wait;
    uint32_t cmd20_ret;
    uint16_t cmd20_data[POLL_TID_MAX];
    uint32_t cmd20_wait_obj[POLL_TID_MAX];
    uint32_t cmd20_wait_pc[POLL_TID_MAX];
    uint32_t tsk[POLL_TID_MAX];
    uint32_t call_from[EAPQ_CALL_RING];
    uint32_t call_to[EAPQ_CALL_RING];
    unsigned call_n;
    uint8_t blocked[POLL_TID_MAX];
    uint32_t blk_obj[POLL_TID_MAX];
    uint32_t blk_pc[POLL_TID_MAX];
    uint64_t blk_insn[POLL_TID_MAX];
    uint32_t last_wake_pc[POLL_TID_MAX];
    uint64_t last_wake_insn[POLL_TID_MAX];
    uint32_t last_wake_irq;
    uint32_t f140_put_pc;
    uint32_t f140_get_pc;
    unsigned f140_put_n;
    unsigned f140_get_n;
} eapq;

static const char *eapq_near(uint32_t pc)
{
    static const struct {
        uint32_t pc;
        const char *name;
    } tab[] = {
        { 0x01f460u, "audio_isr" },
        { 0x0200a0u, "_swiEAP" },
        { 0x0200c8u, "_swiEAPReturn" },
        { 0x101b48u, "_C55_enableInt" },
        { 0x100b48u, "_SEM_pendEnterKnl" },
        { 0x102f8cu, "_KNL_max" },
        { 0x101f14u, "_SIO_reclaim" },
        { 0x101fe0u, "_SIO_issue" },
        { 0x102214u, "_SEM_postEnterKnl" },
        { 0x1031f7u, "_QUE_get" },
        { 0x103216u, "_QUE_put" },
        { 0x1032fau, "_HWI_disable" },
        { 0x103306u, "_HWI_enable" },
        { 0x10330au, "_HWI_restore" },
        { 0x126e5cu, "_SetDMA" },
        { 0x1271f8u, "_EAP_NOKIA_tn_eventDone" },
        { 0x128068u, "_EAP_removeStream" },
        { 0x1280e4u, "_EAP_processEvent" },
        { 0x128510u, "_EAP_ctrl" },
        { 0x12870cu, "_EAP_clock" },
        { 0x12a048u, "_EAP_processEntry" },
        { 0x12a164u, "_EAP_processEntries" },
        { 0x12a1c0u, "_EAP_getBufsFromADD" },
        { 0x12a24cu, "_EAP_postStream" },
        { 0x12a398u, "_EAP_process" },
        { 0x12a4e8u, "_DMAEnableReq" },
        { 0x12c920u, "_EAP_channelReady" },
        { 0x12ca2cu, "_EAP_processNetwork" },
        { 0x12cac0u, "_EAP_reclaim" },
        { 0x12caf8u, "_EAP_ready" },
        { 0x12cb18u, "_EAP_open" },
        { 0x12cc44u, "_EAP_issue" },
        { 0x12cc98u, "_EAP_idle" },
        { 0x12cea0u, "_EAP_close" },
        { 0x130b44u, "_Enable_DMA" },
        { 0x130ba8u, "_Disable_DMA" },
        { 0x130ca8u, "_DMA_lch_ctrl" },
        { 0x130d38u, "_Configure_DMA" },
        { 0x13337cu, "_Reset_McBSP_I2S" },
        { 0x133390u, "_Enable_McBSP_I2S" },
        { 0x1333a4u, "_Disable_McBSP_I2S" },
        { 0x1333b8u, "_Configure_McBSP_I2S" },
        { 0x1334b8u, "TSK_SWITCHFXN" },
        { 0x1334bcu, "TSK_READYFXN" },
    };
    const char *exact = bios_pc_name(pc);
    unsigned i;
    const char *best = NULL;
    uint32_t best_pc = 0;

    if (exact) {
        return exact;
    }
    for (i = 0; i < sizeof(tab) / sizeof(tab[0]); i++) {
        if (tab[i].pc <= pc && tab[i].pc >= best_pc) {
            best_pc = tab[i].pc;
            best = tab[i].name;
        }
    }
    if (best && pc - best_pc < 0x200u) {
        return best;
    }
    return "?";
}

static unsigned eapq_cur_tid(C55xCPU *cpu)
{
    int tid = poll_tid_of_tsk(peek_dbl_ram(cpu, BIOS_WORD_KNL_CURTASK));

    if (tid >= 0) {
        return (unsigned)tid;
    }
    if (cpu->t[0] < POLL_TID_MAX) {
        return cpu->t[0];
    }
    return 99u;
}

static void eapq_bind(C55xCPU *cpu, unsigned tid)
{
    uint32_t task;

    if (tid >= POLL_TID_MAX) {
        return;
    }
    poll_bind_tid(cpu, tid, mbq_task_of(cpu, (uint16_t)tid));
    task = poll_tr.task[tid];
    eapq.tsk[tid] = poll_tr.tsk[tid] & C55X_WORD_MASK;
    if (!eapq.tsk[tid] && peek_word_safe(task + 0x0au)) {
        eapq.tsk[tid] = peek_dbl_ram(cpu, task + 0x0au) & C55X_WORD_MASK;
    }
}

static int eapq_tid_of_tsk(uint32_t tsk)
{
    unsigned tid;

    tsk &= C55X_WORD_MASK;
    if (!tsk) {
        return -1;
    }
    for (tid = 0; tid < POLL_TID_MAX; tid++) {
        if (eapq.tsk[tid] && eapq.tsk[tid] == tsk) {
            return (int)tid;
        }
    }
    return poll_tid_of_tsk(tsk);
}

static void eapq_dump_cpu(C55xCPU *cpu, const char *why)
{
    c55x_log(cpu,
             "EAPQ-CPU %s pc=%06x %s RETA=%06x "
             "AC0=%010llx AC1=%010llx AC2=%010llx AC3=%010llx "
             "T0=%04x T1=%04x T2=%04x T3=%04x "
             "XAR0=%06x XAR1=%06x XAR2=%06x XAR3=%06x "
             "XAR4=%06x XAR5=%06x XAR6=%06x XAR7=%06x "
             "XSP=%06x INTM=%u IER0=%04x IFR0=%04x IER1=%04x IFR1=%04x "
             "insn=%llu\n",
             why, cpu->pc & C55X_PC_MASK, eapq_near(cpu->pc),
             cpu->reta & C55X_PC_MASK,
             (unsigned long long)(cpu->ac[0] & C55X_AC_MASK),
             (unsigned long long)(cpu->ac[1] & C55X_AC_MASK),
             (unsigned long long)(cpu->ac[2] & C55X_AC_MASK),
             (unsigned long long)(cpu->ac[3] & C55X_AC_MASK),
             cpu->t[0], cpu->t[1], cpu->t[2], cpu->t[3],
             cpu->xar[0] & C55X_WORD_MASK, cpu->xar[1] & C55X_WORD_MASK,
             cpu->xar[2] & C55X_WORD_MASK, cpu->xar[3] & C55X_WORD_MASK,
             cpu->xar[4] & C55X_WORD_MASK, cpu->xar[5] & C55X_WORD_MASK,
             cpu->xar[6] & C55X_WORD_MASK, cpu->xar[7] & C55X_WORD_MASK,
             cpu->xsp & C55X_WORD_MASK, !!(cpu->st1 & C55X_ST1_INTM),
             cpu->ier0, cpu->ifr0, cpu->ier1, cpu->ifr1,
             (unsigned long long)cpu->insn_count);
}

static void eapq_dump_qelem(C55xCPU *cpu, uint32_t obj, const char *tag)
{
    obj &= C55X_WORD_MASK;
    c55x_log(cpu,
             "EAPQ-QELEM %s obj=%06x %04x %04x %04x %04x insn=%llu\n",
             tag, obj,
             peek_word_safe(obj) ? peek16_ram(cpu, obj) : 0,
             peek_word_safe(obj + 1u) ? peek16_ram(cpu, obj + 1u) : 0,
             peek_word_safe(obj + 2u) ? peek16_ram(cpu, obj + 2u) : 0,
             peek_word_safe(obj + 3u) ? peek16_ram(cpu, obj + 3u) : 0,
             (unsigned long long)cpu->insn_count);
}

static void eapq_dump_calls(C55xCPU *cpu)
{
    unsigned n = eapq.call_n;
    unsigned i;
    unsigned start = n > EAPQ_CALL_RING ? n - EAPQ_CALL_RING : 0;

    for (i = start; i < n; i++) {
        unsigned slot = i % EAPQ_CALL_RING;

        c55x_log(cpu, "EAPQ-CALL-RING [%u] %06x -> %06x %s\n",
                 i, eapq.call_from[slot], eapq.call_to[slot],
                 eapq_near(eapq.call_to[slot]));
    }
}

static void eapq_refresh_flow(void)
{
    eapq_flow = (uint8_t)(eapq.flow_000e || eapq.flow_000f);
    eapq_parked4 = eapq.parked4;
}

static void eapq_wait_enter(C55xCPU *cpu, unsigned tid, uint32_t tsk)
{
    tsk &= C55X_WORD_MASK;
    if (tid >= POLL_TID_MAX) {
        return;
    }
    if (eapq.blocked[tid] && eapq.blk_obj[tid] == EAPQ_WORD) {
        return;
    }
    eapq.blocked[tid] = 1;
    eapq.blk_obj[tid] = EAPQ_WORD;
    eapq.blk_pc[tid] = cpu->pc & C55X_PC_MASK;
    eapq.blk_insn[tid] = cpu->insn_count;
    eapq.cmd20_wait |= 1u << tid;
    eapq.cmd20_wait_obj[tid] = EAPQ_WORD;
    eapq.cmd20_wait_pc[tid] = cpu->pc & C55X_PC_MASK;
    c55x_log(cpu,
             "WAIT-ENTER tid=%u pc=%06x %s queue=%06x tsk=%06x "
             "INTM=%u IER0=%04x IFR0=%04x IER1=%04x IFR1=%04x insn=%llu\n",
             tid, cpu->pc & C55X_PC_MASK, eapq_near(cpu->pc),
             EAPQ_WORD, tsk, !!(cpu->st1 & C55X_ST1_INTM),
             cpu->ier0, cpu->ifr0, cpu->ier1, cpu->ifr1,
             (unsigned long long)cpu->insn_count);
    eapq_dump_calls(cpu);
    eapq_dump_cpu(cpu, "wait-enter");
    eapq_dump_qelem(cpu, EAPQ_WORD, "queue-after");
    eapq_dump_qelem(cpu, tsk, "tsk-after");
    c55x_log(cpu,
             "TASK-BLOCK tid=%u tsk=%06x pc=%06x %s reason=QUEUE "
             "object=%06x symbol=EAP_DATA insn=%llu\n",
             tid, tsk, cpu->pc & C55X_PC_MASK, eapq_near(cpu->pc),
             EAPQ_WORD, (unsigned long long)cpu->insn_count);
    if (tid == 4u) {
        eapq.parked4 = 1;
        eapq.flow_000e = 0;
        eapq_refresh_flow();
        c55x_l2intc_log_state(cpu, "wait-enter-tid4");
    }
}

static void eapq_wait_leave(C55xCPU *cpu, unsigned tid, uint32_t tsk)
{
    tsk &= C55X_WORD_MASK;
    if (tid >= POLL_TID_MAX || !eapq.blocked[tid]) {
        return;
    }
    eapq.blocked[tid] = 0;
    eapq.last_wake_pc[tid] = cpu->pc & C55X_PC_MASK;
    eapq.last_wake_insn[tid] = cpu->insn_count;
    c55x_log(cpu,
             "TASK-WAKE tid=%u tsk=%06x source_pc=%06x %s source_irq=%u "
             "object=%06x insn=%llu\n",
             tid, tsk, cpu->pc & C55X_PC_MASK, eapq_near(cpu->pc),
             eapq.last_wake_irq, EAPQ_WORD,
             (unsigned long long)cpu->insn_count);
    eapq_dump_qelem(cpu, EAPQ_WORD, "wake-queue");
    eapq_dump_qelem(cpu, tsk, "wake-tsk");
    if (tid == 4u) {
        eapq.parked4 = 0;
        eapq_refresh_flow();
    }
}

static int eapq_qelem_links(C55xCPU *cpu, uint32_t tsk)
{
    uint16_t w0;
    uint16_t w1;
    uint16_t w2;
    uint16_t w3;

    tsk &= C55X_WORD_MASK;
    if (!peek_word_safe(tsk)) {
        return 0;
    }
    w0 = peek16_ram(cpu, tsk);
    w1 = peek16_ram(cpu, tsk + 1u);
    w2 = peek16_ram(cpu, tsk + 2u);
    w3 = peek16_ram(cpu, tsk + 3u);
    return w0 == (uint16_t)EAPQ_WORD || w1 == (uint16_t)EAPQ_WORD ||
           w2 == (uint16_t)EAPQ_WORD || w3 == (uint16_t)EAPQ_WORD;
}

static void eapq_note_store(C55xCPU *cpu, uint32_t word, uint16_t old,
                           uint16_t value)
{
    unsigned tid;
    uint32_t tsk;
    int qhit;

    word &= C55X_WORD_MASK;
    if (old == value) {
        return;
    }
    qhit = (word >= EAPQ_WORD && word < EAPQ_WORD + EAPQ_WORDS);
    if (qhit) {
        const char *kind = "STATE";
        int tid_val = eapq_tid_of_tsk(value);
        int old_tid = eapq_tid_of_tsk(old);

        if (tid_val >= 0 && old_tid < 0) {
            kind = "PUT";
            eapq.f140_put_n++;
            eapq.f140_put_pc = cpu->pc & C55X_PC_MASK;
        } else if (old_tid >= 0 && tid_val < 0) {
            kind = "GET";
            eapq.f140_get_n++;
            eapq.f140_get_pc = cpu->pc & C55X_PC_MASK;
        }
        c55x_log(cpu,
                 "EAP_DATA %s word=%06x %04x->%04x pc=%06x %s "
                 "curtsk=%06x tid=%u insn=%llu\n",
                 kind, word, old, value, cpu->pc & C55X_PC_MASK,
                 eapq_near(cpu->pc),
                 peek_dbl_ram(cpu, BIOS_WORD_KNL_CURTASK) & C55X_WORD_MASK,
                 eapq_cur_tid(cpu), (unsigned long long)cpu->insn_count);
        eapq_dump_qelem(cpu, EAPQ_WORD, kind);
        if (tid_val >= 0) {
            eapq_wait_enter(cpu, (unsigned)tid_val,
                            eapq.tsk[tid_val] ? eapq.tsk[tid_val] : value);
        } else if (old_tid >= 0) {
            eapq_wait_leave(cpu, (unsigned)old_tid, eapq.tsk[old_tid]);
        }
    }
    for (tid = 0; tid < POLL_TID_MAX; tid++) {
        tsk = eapq.tsk[tid];
        if (!tsk || word < tsk || word > tsk + 3u) {
            continue;
        }
        eapq_dump_qelem(cpu, tsk, "tsk-store");
        if (eapq_qelem_links(cpu, tsk)) {
            eapq_wait_enter(cpu, tid, tsk);
        } else if (eapq.blocked[tid] && eapq.blk_obj[tid] == EAPQ_WORD) {
            eapq_wait_leave(cpu, tid, tsk);
        }
    }
}

static void eapq_note_mmio(C55xCPU *cpu, uint32_t word, uint16_t value)
{
    if (!eapq_flow) {
        return;
    }
    word &= C55X_WORD_MASK;
    if (eapq.ev_n >= EAPQ_EV_CAP) {
        return;
    }
    eapq.ev_n++;
    c55x_log(cpu,
             "EAPQ-MMIO-W tid=%u word=%06x val=%04x pc=%06x %s insn=%llu\n",
             eapq_cur_tid(cpu), word, value, cpu->pc & C55X_PC_MASK,
             eapq_near(cpu->pc), (unsigned long long)cpu->insn_count);
}

static void eapq_note_call(C55xCPU *cpu, uint32_t from, uint32_t dest)
{
    unsigned slot;

    if (!eapq_flow) {
        return;
    }
    from &= C55X_PC_MASK;
    dest &= C55X_PC_MASK;
    slot = eapq.call_n % EAPQ_CALL_RING;
    eapq.call_from[slot] = from;
    eapq.call_to[slot] = dest;
    eapq.call_n++;
    if (eapq.ev_n < EAPQ_EV_CAP) {
        eapq.ev_n++;
        c55x_log(cpu, "EAPQ-CALL tid=%u %06x -> %06x %s insn=%llu\n",
                 eapq_cur_tid(cpu), from, dest, eapq_near(dest),
                 (unsigned long long)cpu->insn_count);
    }
}

static void eapq_note_bcc(C55xCPU *cpu, uint32_t from, uint32_t dest, int taken)
{
    if (!eapq_flow || !taken || eapq.ev_n >= EAPQ_EV_CAP) {
        return;
    }
    eapq.ev_n++;
    c55x_log(cpu, "EAPQ-BCC tid=%u %06x -> %06x taken=%u insn=%llu\n",
             eapq_cur_tid(cpu), from & C55X_PC_MASK, dest & C55X_PC_MASK,
             taken, (unsigned long long)cpu->insn_count);
}

static void eapq_note_irq(C55xCPU *cpu, unsigned bit)
{
    eapq.last_wake_irq = bit;
    if (!eapq_flow && !eapq.parked4) {
        return;
    }
    c55x_log(cpu,
             "EAPQ-IRQ bit=%u pc=%06x parked4=%u INTM=%u IFR0=%04x "
             "insn=%llu\n",
             bit, cpu->pc & C55X_PC_MASK, eapq.parked4,
             !!(cpu->st1 & C55X_ST1_INTM), cpu->ifr0,
             (unsigned long long)cpu->insn_count);
}

static void eapq_note_api(C55xCPU *cpu, uint32_t pc)
{
    uint32_t a0 = cpu->xar[0] & C55X_WORD_MASK;
    uint32_t a1 = cpu->xar[1] & C55X_WORD_MASK;
    int hit = (a0 == EAPQ_WORD || a1 == EAPQ_WORD ||
               cpu->t[0] == (uint16_t)EAPQ_WORD);

    if (pc != BIOS_PC_QUE_PUT && pc != BIOS_PC_QUE_GET &&
        pc != BIOS_PC_SIO_RECLAIM && pc != BIOS_PC_SIO_ISSUE &&
        pc != BIOS_PC_EAP_RECLAIM && pc != BIOS_PC_EAP_ISSUE &&
        pc != BIOS_PC_EAP_READY && pc != BIOS_PC_EAP_CTRL &&
        pc != BIOS_PC_EAP_PROCESS && pc != BIOS_PC_EAP_CHREADY &&
        pc != BIOS_PC_SWI_EAP && pc != BIOS_PC_SWI_EAP_RET &&
        pc != BIOS_PC_ENABLE_DMA && pc != BIOS_PC_CFG_DMA &&
        pc != BIOS_PC_ENABLE_MCBSP && pc != BIOS_PC_CFG_MCBSP &&
        pc != BIOS_PC_DMAENABLE && pc != BIOS_PC_EAP_CLOCK &&
        pc != BIOS_PC_SEM_POST && pc != BIOS_PC_SEM_PEND &&
        pc != BIOS_PC_SWI_POST && pc != BIOS_PC_SWI_OR) {
        return;
    }
    if (pc == BIOS_PC_SEM_POST || pc == BIOS_PC_SEM_PEND) {
        if (a0 != EAPQ_WORD && a0 != BIOS_WORD_EAP_SEM &&
            a0 != BIOS_WORD_DMA_SEM && !hit) {
            return;
        }
    } else if (pc == BIOS_PC_SWI_POST || pc == BIOS_PC_SWI_OR) {
        if (a0 != BIOS_WORD_SWI_EAP && a0 != BIOS_WORD_SWI_EAP_RET) {
            return;
        }
    } else if (pc != BIOS_PC_CFG_DMA && pc != BIOS_PC_ENABLE_DMA &&
               pc != BIOS_PC_CFG_MCBSP && pc != BIOS_PC_ENABLE_MCBSP &&
               !eapq_flow && !hit && !eapq.parked4) {
        return;
    }
    c55x_log(cpu,
             "EAPQ-API %s pc=%06x tid=%u XAR0=%06x XAR1=%06x "
             "T0=%04x T1=%04x RETA=%06x hit_f140=%u insn=%llu\n",
             eapq_near(pc), pc, eapq_cur_tid(cpu), a0, a1,
             cpu->t[0], cpu->t[1], cpu->reta & C55X_PC_MASK, hit,
             (unsigned long long)cpu->insn_count);
    if (pc == BIOS_PC_QUE_PUT && hit) {
        eapq.f140_put_n++;
        eapq.f140_put_pc = pc;
        eapq_dump_qelem(cpu, EAPQ_WORD, "que-put-before");
        if (a1) {
            eapq_dump_qelem(cpu, a1, "que-put-elem-before");
        }
    }
    if (pc == BIOS_PC_QUE_GET && hit) {
        eapq.f140_get_n++;
        eapq.f140_get_pc = pc;
        eapq_dump_qelem(cpu, EAPQ_WORD, "que-get-before");
    }
}

static void eapq_note_disp(C55xCPU *cpu, unsigned tid, uint16_t cmd_h,
                          uint16_t cmd_d)
{
    unsigned i;

    if (tid >= POLL_TID_MAX || cmd_h != 0x20u) {
        return;
    }
    for (i = 0; i < 5u; i++) {
        eapq_bind(cpu, i);
    }
    eapq_bind(cpu, tid);
    eapq.cmd20_open |= 1u << tid;
    eapq.cmd20_data[tid] = cmd_d;
    c55x_log(cpu,
             "CMD20 tid=%u data=%04x tsk=%06x task=%06x handler=? "
             "insn=%llu\n",
             tid, cmd_d, eapq.tsk[tid], poll_tr.task[tid],
             (unsigned long long)cpu->insn_count);
    if (tid == 4u && cmd_d == 0x000eu) {
        eapq.flow_000e = 1;
        if (!eapq.flow_000f) {
            eapq.ev_n = 0;
            eapq.call_n = 0;
        }
        eapq_refresh_flow();
        c55x_log(cpu, "DISPATCH tid=4 cmd=20 data=000e\n");
        eapq_dump_cpu(cpu, "dispatch-000e");
        eapq_dump_qelem(cpu, EAPQ_WORD, "dispatch-000e-q");
        if (eapq.tsk[4]) {
            eapq_dump_qelem(cpu, eapq.tsk[4], "dispatch-000e-tsk");
        }
        for (i = 0; i < 5u; i++) {
            eapq_bind(cpu, i);
            poll_log_task(cpu, i, "pre-000e");
        }
        poll_dump_words(cpu, BIOS_WORD_EAP_F140, 8u, "pre-000e");
        poll_dump_words(cpu, BIOS_WORD_KNL_QUEUES, 8u, "pre-000e");
        c55x_l2intc_log_state(cpu, "pre-000e");
        eapq.snap_000e = 1;
    }
    if (tid == 2u && cmd_d == 0x000fu) {
        eapq.flow_000f = 1;
        if (!eapq.flow_000e) {
            eapq.ev_n = 0;
            eapq.call_n = 0;
        }
        eapq_refresh_flow();
        c55x_log(cpu, "DISPATCH tid=2 cmd=20 data=000f\n");
        eapq_dump_cpu(cpu, "dispatch-000f");
        eapq_dump_qelem(cpu, EAPQ_WORD, "dispatch-000f-q");
        if (eapq.tsk[2]) {
            eapq_dump_qelem(cpu, eapq.tsk[2], "dispatch-000f-tsk");
        }
    }
}

static void eapq_note_get_mbq(C55xCPU *cpu, unsigned tid)
{
    if (tid >= POLL_TID_MAX || !(eapq.cmd20_open & (1u << tid))) {
        return;
    }
    eapq.cmd20_open &= ~(1u << tid);
    eapq.cmd20_ret |= 1u << tid;
    c55x_log(cpu,
             "CMD20-RET tid=%u data=%04x wait=%u obj=%06x wait_pc=%06x "
             "insn=%llu\n",
             tid, eapq.cmd20_data[tid],
             !!(eapq.cmd20_wait & (1u << tid)),
             eapq.cmd20_wait_obj[tid], eapq.cmd20_wait_pc[tid],
             (unsigned long long)cpu->insn_count);
    if (tid == 2u) {
        eapq.flow_000f = 0;
        eapq_refresh_flow();
    }
    if (tid == 4u) {
        eapq.flow_000e = 0;
        eapq_refresh_flow();
    }
}

static void eapq_log_blocked(C55xCPU *cpu, unsigned tid)
{
    if (tid >= POLL_TID_MAX || !eapq.blocked[tid]) {
        return;
    }
    c55x_log(cpu,
             "tid%u blocked since insn=%llu pc=%06x %s reason=EAP_DATA "
             "object=%06x last_wake_pc=%06x last_wake_irq=%u "
             "put_n=%u get_n=%u put_pc=%06x get_pc=%06x\n",
             tid, (unsigned long long)eapq.blk_insn[tid],
             eapq.blk_pc[tid], eapq_near(eapq.blk_pc[tid]),
             eapq.blk_obj[tid], eapq.last_wake_pc[tid],
             eapq.last_wake_irq, eapq.f140_put_n, eapq.f140_get_n,
             eapq.f140_put_pc, eapq.f140_get_pc);
}

static void poll_dump_words(C55xCPU *cpu, uint32_t word, unsigned n,
                            const char *tag)
{
    char buf[160];
    unsigned i;
    int used = 0;

    buf[0] = '\0';
    word &= C55X_WORD_MASK;
    for (i = 0; i < n; i++) {
        used += snprintf(buf + used, sizeof(buf) - (size_t)used, "%s%04x",
                         i ? " " : "",
                         peek_word_safe(word + i) ? peek16_ram(cpu, word + i) : 0);
        if (used < 0 || (size_t)used >= sizeof(buf)) {
            break;
        }
    }
    c55x_log(cpu, "POLL %s word=%06x %s\n", tag, word, buf);
}

static struct {
    uint8_t issue_on;
    uint8_t dmaen_on;
    uint8_t forced;
    uint8_t saw_swi_or;
    uint8_t saw_swi_post;
    uint8_t saw_swi_ret;
    uint8_t saw_swi_exec;
    uint8_t saw_cfg_dma;
    uint8_t saw_en_dma;
    uint8_t saw_cfg_mcbsp;
    uint8_t saw_en_mcbsp;
    uint8_t dmaen_posted;
    uint32_t sio;
    uint32_t buf;
    uint32_t device;
    uint16_t nbytes;
    uint16_t dir;
    uint16_t stream;
    uint16_t dma_sem_cnt_in;
    uint16_t dma_sem_cnt_out;
    uint16_t last_ier0;
} eapiss;

/*
 * _EAP_processEntry attaches extra+0x4a / +0x4e (SIO/mmap block).
 * _SRC_TII_asmDoubleStageConvert stores HI(ACx) into that output
 * (8b534c1270 MOV HI(AC0),*AR2(short(#1)) || ASUB T3,T0). Log the
 * on-chip CSSA ping-pong the EAC IODMA actually copies.
 */
static int eap_block_peak(C55xCPU *cpu, uint32_t src, unsigned n)
{
    unsigned i;
    int peak = 0;

    if (!src || !peek_word_safe(src) || !n) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        int v = abs((int16_t)peek16_ram(cpu, src + i));

        if (v > peak) {
            peak = v;
        }
    }
    return peak;
}

static int eap_bus_peak(C55xCPU *cpu, uint32_t src, unsigned n)
{
    unsigned i;
    int peak = 0;

    if (!cpu->bus.read16 || !n) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        uint16_t v = 0;

        if (cpu->bus.read16(cpu->bus.opaque,
                            (src + i) & C55X_WORD_MASK, &v)) {
            break;
        }
        if (abs((int16_t)v) > peak) {
            peak = abs((int16_t)v);
        }
    }
    return peak;
}

static void eap_pcm_stat(const char *fmt, ...)
{
    const char *stat = getenv("N8X0_PCM_STAT");
    FILE *f;
    va_list ap;

    if (!stat || !stat[0]) {
        stat = "/tmp/n8x0-pcm-stat.log";
    }
    f = fopen(stat, "a");
    if (!f) {
        return;
    }
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fclose(f);
}

static void eap_note_cssa(C55xCPU *cpu)
{
    uint32_t dst = (cpu->audio_isr_n & 1u) ? 0x0f7ecu : 0x0f60cu;
    int peak = eap_block_peak(cpu, dst, 32u);
    static unsigned silent;

    if (peak >= 32) {
        eap_pcm_stat("t=isr cssa peak=%d dst=%06x isr=%u\n",
                     peak, dst, cpu->audio_isr_n);
        return;
    }
    if (silent < 8u) {
        eap_pcm_stat("t=isr cssa-silent dst=%06x isr=%u src=%06x len=%u\n",
                     dst, cpu->audio_isr_n, eap_cssa_src, eap_cssa_len);
        silent++;
    }
}

/* 20260916T220747Z-direct already ran the one-shot `_SWI_or`. */
static const int eapiss_do_force;

static uint32_t eapiss_dbl(C55xCPU *cpu, uint32_t word)
{
    word &= C55X_WORD_MASK;
    if (!peek_word_safe(word) || !peek_word_safe(word + 1u)) {
        return 0;
    }
    return ((uint32_t)peek16_ram(cpu, word) << 16) | peek16_ram(cpu, word + 1u);
}

static void eapiss_refresh(C55xCPU *cpu)
{
    if (eapiss.sio && peek_word_safe(eapiss.sio + 7u)) {
        eapiss.dir = peek16_ram(cpu, eapiss.sio + 7u);
        eapiss.device = eapiss_dbl(cpu, eapiss.sio + 0x0cu);
    }
    if (eapiss.device && peek_word_safe(eapiss.device + 26u)) {
        eapiss.stream = peek16_ram(cpu, eapiss.device + 26u);
    }
}

static void eapiss_state(C55xCPU *cpu, const char *why)
{
    uint16_t semc = peek_word_safe(BIOS_WORD_EAP_SEM + 4u) ?
                    peek16_ram(cpu, BIOS_WORD_EAP_SEM + 4u) : 0;
    uint16_t dmac = peek_word_safe(BIOS_WORD_DMA_SEM + 4u) ?
                    peek16_ram(cpu, BIOS_WORD_DMA_SEM + 4u) : 0;
    uint16_t discnt = peek16_ram(cpu, BIOS_WORD_DMA_DISCNT);
    uint16_t audio = peek16_ram(cpu, BIOS_WORD_AUDIO_ON);

    eapiss_refresh(cpu);
    c55x_log(cpu,
             "EAP-STATE %s sio=%06x device=%06x buf=%06x bytes=%04x "
             "dir=%04x stream=%04x SEM=%06x semc=%04x dmasem=%06x dmac=%04x "
             "swiEAP=%06x swiRet=%06x curset=%04x curmask=%04x lock=%04x "
             "IER0=%04x IFR0=%04x DMADisableCnt=%04x audio_on=%04x "
             "mcbsp_once=%04x dma_mode=%04x "
             "dma_req=%u dma_cfg=%u dma_en=%u mcbsp_cfg=%u mcbsp_en=%u "
             "swi_or=%u swi_post=%u swi_ret=%u swi_exec=%u pendQ=%06x "
             "insn=%llu\n",
             why, eapiss.sio, eapiss.device, eapiss.buf, eapiss.nbytes,
             eapiss.dir, eapiss.stream, BIOS_WORD_EAP_SEM, semc,
             BIOS_WORD_DMA_SEM, dmac, BIOS_WORD_SWI_EAP, BIOS_WORD_SWI_EAP_RET,
             peek16(cpu, BIOS_WORD_CURSET), peek16(cpu, BIOS_WORD_CURMASK),
             peek16(cpu, BIOS_WORD_LOCK), cpu->ier0, cpu->ifr0, discnt, audio,
             peek16_ram(cpu, BIOS_WORD_MCBSP_ONCE),
             peek16_ram(cpu, BIOS_WORD_DMA_MODE),
             eapiss.dmaen_posted, eapiss.saw_cfg_dma, eapiss.saw_en_dma,
             eapiss.saw_cfg_mcbsp, eapiss.saw_en_mcbsp,
             eapiss.saw_swi_or, eapiss.saw_swi_post, eapiss.saw_swi_ret,
             eapiss.saw_swi_exec, EAPQ_WORD,
             (unsigned long long)cpu->insn_count);
    if (eapiss.sio) {
        poll_dump_words(cpu, eapiss.sio, 16u, why);
    }
    if (eapiss.device) {
        poll_dump_words(cpu, eapiss.device, 34u, why);
    }
    if (eapiss.buf) {
        poll_dump_words(cpu, eapiss.buf, 8u, why);
    }
    poll_dump_words(cpu, BIOS_WORD_EAP_GLOBAL, 16u, why);
    poll_dump_words(cpu, BIOS_WORD_EAP_SEM, 8u, why);
    poll_dump_words(cpu, BIOS_WORD_SWI_EAP, 20u, why);
    poll_dump_words(cpu, BIOS_WORD_SWI_EAP_RET, 20u, why);
    poll_dump_words(cpu, BIOS_WORD_DMA_SEM, 8u, why);
    poll_dump_words(cpu, BIOS_WORD_DMA_DISCNT, 4u, why);
    poll_dump_words(cpu, EAPQ_WORD, 8u, why);
}

static void eapiss_force_swi(C55xCPU *cpu, uint32_t cont)
{
    if (eapiss.forced) {
        return;
    }
    eapiss.forced = 1;
    c55x_log(cpu,
             "EAP-FORCE-SWI _SWI_or swiEAP=%06x T0=0010 continue=%06x "
             "insn=%llu\n",
             BIOS_WORD_SWI_EAP, cont & C55X_PC_MASK,
             (unsigned long long)cpu->insn_count);
    eapiss_state(cpu, "force-before");
    cpu->xar[0] = BIOS_WORD_SWI_EAP;
    cpu->t[0] = 0x0010u;
    call_taken(cpu, BIOS_PC_SWI_OR, cont & C55X_PC_MASK);
    cpu->pc = BIOS_PC_SWI_OR;
}

static void eapiss_reset_issue_flags(void)
{
    eapiss.saw_swi_or = 0;
    eapiss.saw_swi_post = 0;
    eapiss.saw_swi_ret = 0;
    eapiss.saw_swi_exec = 0;
    eapiss.saw_cfg_dma = 0;
    eapiss.saw_en_dma = 0;
    eapiss.saw_cfg_mcbsp = 0;
    eapiss.saw_en_mcbsp = 0;
    eapiss.dmaen_posted = 0;
}

static void eapiss_note_pc(C55xCPU *cpu, uint32_t pc)
{
    uint32_t a0 = cpu->xar[0] & C55X_WORD_MASK;

    if (pc == BIOS_PC_EAP_ISSUE && eapq.flow_000e) {
        eapiss_reset_issue_flags();
        eapiss.issue_on = 1;
        eapiss.sio = a0;
        eapiss.buf = cpu->xar[1] & C55X_WORD_MASK;
        eapiss.nbytes = cpu->t[0];
        eapiss.last_ier0 = cpu->ier0;
        eapiss_refresh(cpu);
        c55x_log(cpu,
                 "EAP-ISSUE enter sio=%06x device=%06x buf=%06x T0=%04x "
                 "dir=%04x stream=%04x RETA=%06x insn=%llu\n",
                 eapiss.sio, eapiss.device, eapiss.buf, eapiss.nbytes,
                 eapiss.dir, eapiss.stream, cpu->reta & C55X_PC_MASK,
                 (unsigned long long)cpu->insn_count);
        eapiss_state(cpu, "issue-enter");
        return;
    }
    if (pc == BIOS_PC_DMAENABLE && (eapiss.issue_on || eapq.flow_000e)) {
        eapiss.dmaen_on = 1;
        eapiss.dma_sem_cnt_in = peek_word_safe(BIOS_WORD_DMA_SEM + 4u) ?
                                peek16_ram(cpu, BIOS_WORD_DMA_SEM + 4u) : 0;
        c55x_log(cpu,
                 "EAP-DMAEN enter XAR0=%06x T0=%04x RETA=%06x dmac=%04x "
                 "DMADisableCnt=%04x insn=%llu\n",
                 a0, cpu->t[0], cpu->reta & C55X_PC_MASK,
                 eapiss.dma_sem_cnt_in, peek16_ram(cpu, BIOS_WORD_DMA_DISCNT),
                 (unsigned long long)cpu->insn_count);
        eapiss_state(cpu, "dmaen-enter");
        return;
    }
    if (pc == BIOS_PC_SWI_OR && a0 == BIOS_WORD_SWI_EAP) {
        eapiss.saw_swi_or = 1;
        if (eapiss.dmaen_on) {
            eapiss.dmaen_posted = 1;
        }
        c55x_log(cpu, "EAP-SWI-OR swiEAP T0=%04x RETA=%06x insn=%llu\n",
                 cpu->t[0], cpu->reta & C55X_PC_MASK,
                 (unsigned long long)cpu->insn_count);
        return;
    }
    if (pc == BIOS_PC_SWI_POST && a0 == BIOS_WORD_SWI_EAP) {
        eapiss.saw_swi_post = 1;
        c55x_log(cpu, "EAP-SWI-POST swiEAP T0=%04x RETA=%06x insn=%llu\n",
                 cpu->t[0], cpu->reta & C55X_PC_MASK,
                 (unsigned long long)cpu->insn_count);
        return;
    }
    if (pc == BIOS_PC_SWI_POST && a0 == BIOS_WORD_SWI_EAP_RET) {
        eapiss.saw_swi_ret = 1;
        c55x_log(cpu,
                 "EAP-SWI-POST swiEAPReturn T0=%04x RETA=%06x insn=%llu\n",
                 cpu->t[0], cpu->reta & C55X_PC_MASK,
                 (unsigned long long)cpu->insn_count);
        return;
    }
    if ((pc == BIOS_PC_SWI_EXEC_SYNC || pc == BIOS_PC_SWI_EXEC ||
         pc == BIOS_PC_SWI_RUN) &&
        (a0 == BIOS_WORD_SWI_EAP || a0 == (BIOS_WORD_SWI_EAP + 6u) ||
         a0 == BIOS_WORD_SWI_EAP_RET || eapiss.saw_swi_post ||
         eapiss.saw_swi_ret || eapiss.forced)) {
        if (pc == BIOS_PC_SWI_EXEC || pc == BIOS_PC_SWI_EXEC_SYNC) {
            eapiss.saw_swi_exec = 1;
        }
        c55x_log(cpu, "EAP-SWI-RUN %s XAR0=%06x curset=%04x insn=%llu\n",
                 eapq_near(pc), a0, peek16(cpu, BIOS_WORD_CURSET),
                 (unsigned long long)cpu->insn_count);
        return;
    }
    if (pc == BIOS_PC_CFG_DMA) {
        if (eapiss.issue_on || eapiss.forced) {
            eapiss.saw_cfg_dma = 1;
        }
        c55x_log(cpu, "EAP-CFG-DMA XAR0=%06x T0=%04x insn=%llu\n",
                 a0, cpu->t[0], (unsigned long long)cpu->insn_count);
        return;
    }
    if (pc == BIOS_PC_ENABLE_DMA) {
        if (eapiss.issue_on || eapiss.forced) {
            eapiss.saw_en_dma = 1;
        }
        c55x_log(cpu, "EAP-EN-DMA XAR0=%06x T0=%04x insn=%llu\n",
                 a0, cpu->t[0], (unsigned long long)cpu->insn_count);
        return;
    }
    if (pc == BIOS_PC_CFG_MCBSP) {
        if (eapiss.issue_on || eapiss.forced) {
            eapiss.saw_cfg_mcbsp = 1;
        }
        c55x_log(cpu, "EAP-CFG-MCBSP XAR0=%06x T0=%04x insn=%llu\n",
                 a0, cpu->t[0], (unsigned long long)cpu->insn_count);
        return;
    }
    if (pc == BIOS_PC_ENABLE_MCBSP) {
        if (eapiss.issue_on || eapiss.forced) {
            eapiss.saw_en_mcbsp = 1;
        }
        c55x_log(cpu, "EAP-EN-MCBSP XAR0=%06x T0=%04x insn=%llu\n",
                 a0, cpu->t[0], (unsigned long long)cpu->insn_count);
        return;
    }
    if (pc == BIOS_PC_EAP_PROCESS || pc == BIOS_PC_EAP_CLOCK) {
        if (eapiss.issue_on || eapiss.forced || eapiss.saw_swi_exec) {
            c55x_log(cpu, "EAP-SWI-BODY %s XAR0=%06x insn=%llu\n",
                     eapq_near(pc), a0, (unsigned long long)cpu->insn_count);
        }
        return;
    }
    if (pc == BIOS_PC_AUDIO_ISR) {
        cpu->audio_isr_n++;
        cpu->in_audio_isr = 1;
        eap_note_cssa(cpu);
        c55x_log(cpu,
                 "audio_isr entry n=%u XAR0=%06x T0=%04x last_irq=%u "
                 "insn=%llu\n",
                 cpu->audio_isr_n, a0, cpu->t[0], cpu->last_irq_bit,
                 (unsigned long long)cpu->insn_count);
        return;
    }
    /*
     * _SRC_TII_convert picks the output count at these three PCs.
     * 0x132f89 is the input count and the first ratio. 0x132f9f is
     * the second-stage quotient in AR1 against *AR6. 0x132fc9 is
     * the smaller of those two, about to become T0.
     */
    /*
     * Sum destination versus the soft-clip source. Both channels
     * show samples, then one decode still reads a zero slot.
     */
    if (pc == 0x12a450u) {
        static unsigned mask_logs;
        uint16_t ena = peek16(cpu, 0xf2a1u);

        if (mask_logs < 4u) {
            eap_pcm_stat("t=mask t0=%04x f2a1=%04x slot=%04x\n",
                         cpu->t[0], ena, peek16(cpu, 0x9d0a6u));
            mask_logs++;
        }
    }
    if (pc == 0x12a17eu) {
        static unsigned tab_logs;

        if (tab_logs < 14u) {
            uint32_t ent = ((uint32_t)peek16(cpu, (cpu->xar[0] & C55X_WORD_MASK) +
                                                   0x18u)
                            << 16) |
                           peek16(cpu, (cpu->xar[0] & C55X_WORD_MASK) + 0x19u);

            eap_pcm_stat("t=tab base=%06x ent=%06x fl=%04x\n",
                         cpu->xar[0] & C55X_WORD_MASK, ent,
                         peek16(cpu, (cpu->xar[0] & C55X_WORD_MASK) + 0x20u));
            tab_logs++;
        }
    }
    if (pc == 0x129c97u) {
        static unsigned put_logs;

        if (put_logs < 4u) {
            eap_pcm_stat("t=put a=%06x b=%06x\n",
                         ((uint32_t)peek16(cpu, 0xf03au) << 16) |
                             peek16(cpu, 0xf03bu),
                         ((uint32_t)peek16(cpu, 0xf0a0u) << 16) |
                             peek16(cpu, 0xf0a1u));
            put_logs++;
        }
    }
    if (pc == 0x12a070u && swap_seen) {
        static unsigned pe_logs;

        if (pe_logs < 8u) {
            eap_pcm_stat(
                "t=pe ent=%06x p4a=%06x ac0=%08x ac1=%08x\n",
                cpu->xar[7] & C55X_WORD_MASK,
                ((uint32_t)peek16(cpu, (cpu->xar[7] & C55X_WORD_MASK) + 0x4au)
                 << 16) |
                    peek16(cpu, (cpu->xar[7] & C55X_WORD_MASK) + 0x4bu),
                (unsigned)cpu->ac[0], (unsigned)cpu->ac[1]);
            pe_logs++;
        }
    }
    if (pc == 0x12a090u || pc == 0x12a0ccu) {
        static unsigned inst_logs;

        if (inst_logs < 8u) {
            eap_pcm_stat("t=inst pc=%06x ent=%06x buf=%06x\n", pc,
                         cpu->xar[7] & C55X_WORD_MASK,
                         cpu->xar[2] & C55X_WORD_MASK);
            inst_logs++;
        }
    }
    if (pc == 0x12a2d0u) {
        static unsigned swap_logs;

        swap_seen = 1;
        if (swap_logs < 6u) {
            eap_pcm_stat(
                "t=swap ent=%06x new=%06x pos=%04x thr=%04x\n",
                cpu->xar[5] & C55X_WORD_MASK,
                cpu->xar[3] & C55X_WORD_MASK,
                peek16(cpu, (cpu->xar[5] & C55X_WORD_MASK) + 0x50u),
                peek16(cpu, (cpu->xar[5] & C55X_WORD_MASK) + 0x4eu));
            swap_logs++;
        }
    }
    if (pc == 0x12c291u) {
        static unsigned sum_logs;
        uint64_t ac = cpu->ac[0] & C55X_AC_MASK;
        int32_t sample = (int32_t)(int16_t)(ac & 0xffffu);
        /* A zero-extended 0xfff4 is 65524, not signed −12. Catch that
         * magnitude as well as a genuinely loud low half. */
        int loud = sample > 1000 || sample < -1000 ||
                   (ac > 1000u && ac < (C55X_AC_MASK - 1000u));

        if (sum_logs < 4u && loud) {
            eap_pcm_stat(
                "t=sum ac0=%010llx sample=%d ar3=%06x ar5=%06x st1=%04x\n",
                (unsigned long long)ac, sample,
                cpu->xar[3] & C55X_WORD_MASK, cpu->xar[5] & C55X_WORD_MASK,
                cpu->st1);
            sum_logs++;
        }
    }
    if (pc == 0x12c4dfu) {
        static unsigned mix8_logs;

        if (mix8_logs < 2u && cpu->bus.read16) {
            uint32_t sum = cpu->xar[0] & C55X_WORD_MASK;
            uint16_t mmap_w[8];
            uint16_t sum_w[8];
            unsigned i;

            for (i = 0; i < 8u; i++) {
                mmap_w[i] = 0;
                sum_w[i] = 0;
                cpu->bus.read16(cpu->bus.opaque,
                                (0x218000u + i) & C55X_WORD_MASK, &mmap_w[i]);
                cpu->bus.read16(cpu->bus.opaque,
                                (sum + i) & C55X_WORD_MASK, &sum_w[i]);
            }
            eap_pcm_stat(
                "t=mix8 sum=%06x out=%06x st1=%04x "
                "mmap=%04x %04x %04x %04x %04x %04x %04x %04x "
                "slot=%04x %04x %04x %04x %04x %04x %04x %04x\n",
                sum, cpu->xar[1] & C55X_WORD_MASK, cpu->st1,
                mmap_w[0], mmap_w[1], mmap_w[2], mmap_w[3],
                mmap_w[4], mmap_w[5], mmap_w[6], mmap_w[7],
                sum_w[0], sum_w[1], sum_w[2], sum_w[3],
                sum_w[4], sum_w[5], sum_w[6], sum_w[7]);
            mix8_logs++;
        }
    }
    if (pc == 0x1330d6u) {
        static unsigned clip_logs;
        int32_t ac0 = (int32_t)(cpu->ac[0] & 0xffffffffu);

        if (clip_logs < 4u && (ac0 > 1000 || ac0 < -1000)) {
            eap_pcm_stat(
                "t=clip ac0=%010llx st1=%04x ar0=%06x\n",
                (unsigned long long)(cpu->ac[0] & C55X_AC_MASK), cpu->st1,
                cpu->xar[0] & C55X_WORD_MASK);
            clip_logs++;
        }
    }
    if (pc == 0x125825u) {
        static unsigned split_logs;

        if (split_logs < 4u) {
            uint32_t src = cpu->xar[5] & C55X_WORD_MASK;
            uint16_t w[8];
            unsigned i;
            int even = 0, odd = 0;

            for (i = 0; i < 8; i++) {
                w[i] = 0;
                if (cpu->bus.read16) {
                    cpu->bus.read16(cpu->bus.opaque,
                                    (src + i) & C55X_WORD_MASK, &w[i]);
                }
            }
            for (i = 0; i < 32; i++) {
                uint16_t v = 0;
                int a;

                if (!cpu->bus.read16 ||
                    cpu->bus.read16(cpu->bus.opaque,
                                    (src + i) & C55X_WORD_MASK, &v)) {
                    break;
                }
                a = abs((int16_t)v);
                if (i & 1) {
                    if (a > odd) {
                        odd = a;
                    }
                } else if (a > even) {
                    even = a;
                }
            }
            eap_pcm_stat(
                "t=split src=%06x n=%04x even=%d odd=%d "
                "%04x %04x %04x %04x %04x %04x %04x %04x\n",
                src, cpu->xar[1] & 0xffffu, even, odd,
                w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]);
            split_logs++;
        }
    }
    if (pc == 0x12586eu) {
        static unsigned half_logs;
        static unsigned half_seen;
        uint32_t buf = ((uint32_t)peek16(cpu, 0x09cf22u) << 16) |
                       peek16(cpu, 0x09cf23u);

        if (half_seen < 40u && half_logs < 4u) {
            int all;

            half_seen++;
            all = eap_bus_peak(cpu, buf, 0x800u);
            if (all) {
                uint16_t s0 = 0, s1 = 0;

                cpu->bus.read16(cpu->bus.opaque, buf, &s0);
                cpu->bus.read16(cpu->bus.opaque,
                                (buf + 0x400u) & C55X_WORD_MASK, &s1);
                eap_pcm_stat(
                    "t=half buf=%06x lo=%d hi=%d s0=%04x s400=%04x\n",
                    buf, eap_bus_peak(cpu, buf, 0x400u),
                    eap_bus_peak(cpu, buf + 0x400u, 0x400u), s0, s1);
                half_logs++;
            }
        }
    }
    if (pc == 0x101fe0u) {
        static unsigned issue_logs;

        uint32_t buf = cpu->xar[1] & C55X_WORD_MASK;

        if (issue_logs < 8u && buf >= 0x200000u) {
            eap_pcm_stat(
                "t=issue reta=%06x stream=%06x buf=%06x n=%04x\n",
                cpu->ret_pc & C55X_PC_MASK,
                cpu->xar[0] & C55X_WORD_MASK, buf, cpu->t[0]);
            issue_logs++;
        }
    }
    if (pc == 0x103216u) {
        static unsigned qput_logs;
        uint32_t node = cpu->xar[1] & C55X_WORD_MASK;
        uint32_t buf = ((uint32_t)peek16(cpu, node + 4u) << 16) |
                       peek16(cpu, node + 5u);

        if (qput_logs < 12u && buf >= 0x200000u && buf < 0x230000u) {
            eap_pcm_stat("t=qput reta=%06x list=%06x node=%06x buf=%06x\n",
                         cpu->ret_pc & C55X_PC_MASK,
                         cpu->xar[0] & C55X_WORD_MASK, node, buf);
            qput_logs++;
        }
    }
    if (pc == 0x12c260u) {
        uint32_t p = cpu->xar[3] & C55X_WORD_MASK;

        /* Same window the SRC convert load translates at 0x132ff0. */
        if ((p & 0xfff000u) == 0x20d000u) {
            cpu->xar[3] = p + 0xb000u;
        }
    }
    if (pc == 0x12c25bu && mix_slot_hot) {
        static unsigned strm_logs;
        uint32_t ent = cpu->xar[4] & C55X_WORD_MASK;

        if (strm_logs < 6u) {
            eap_pcm_stat(
                "t=strm ar4=%06x p=%06x pos=%04x thr=%04x\n",
                ent,
                ((uint32_t)peek16(cpu, ent + 0x4au) << 16) |
                    peek16(cpu, ent + 0x4bu),
                peek16(cpu, ent + 0x50u), peek16(cpu, ent + 0x4eu));
            strm_logs++;
        }
    }
    if (pc == 0x12c284u && mix_slot_hot) {
        static unsigned add_logs;

        if (add_logs < 6u) {
            uint32_t src = cpu->xar[3] & C55X_WORD_MASK;
            uint32_t off = cpu->xar[1] & 0xffffu;

            eap_pcm_stat(
                "t=add n=%04x off=%04x src=%06x peak=%d\n",
                (unsigned)(cpu->ac[0] & 0xffffu), off, src,
                eap_block_peak(cpu, (src + off) & C55X_WORD_MASK, 16u));
            add_logs++;
        }
    }
    if (pc == 0x12c240u && mix_slot_hot) {
        static unsigned sump_logs;

        if (sump_logs < 6u) {
            eap_pcm_stat(
                "t=off ac0=%08x t0=%04x st2=%04x ar3=%06x\n",
                (unsigned)(cpu->ac[0] & 0xffffffffu), cpu->t[0],
                cpu->st2, cpu->xar[3] & C55X_WORD_MASK);
            sump_logs++;
        }
    }
    if (mix_slot_hot && (pc == 0x12c4bbu || pc == 0x12c4dfu ||
                         pc == 0x12c4f8u)) {
        static unsigned mix_logs;

        if (mix_logs < 8u) {
            {
                uint32_t dst = cpu->xar[1] & C55X_WORD_MASK;

                eap_pcm_stat(
                    "t=mix pc=%06x xar0=%06x xar1=%06x m0=%04x m1=%04x "
                    "t0=%04x peak=%d\n",
                    pc, cpu->xar[0] & C55X_WORD_MASK, dst,
                    peek16(cpu, dst), peek16(cpu, dst + 1u), cpu->t[0],
                    eap_block_peak(cpu, dst, 32u));
            }
            mix_logs++;
        }
    }
    /*
     * _EAP_decode input. XAR0 is the entry, XAR1 is the sample
     * buffer. One entry's buffer still holds the tune when the
     * other entry's converter runs.
     */
    if (pc == 0x12c2c8u && mix_slot_hot) {
        static unsigned dec_logs;

        if (dec_logs < 8u) {
            uint32_t ent = cpu->xar[0] & C55X_WORD_MASK;
            uint32_t in = cpu->xar[1] & C55X_WORD_MASK;
            uint32_t slot = ((uint32_t)peek16(cpu, ent + 0x4au) << 16) |
                            peek16(cpu, ent + 0x4bu);

            eap_pcm_stat(
                "t=dec xar0=%06x xar1=%06x w=%04x slot=%06x nest=%u "
                "reta=%06x\n",
                ent, in, peek16(cpu, in), slot & 0xffffffu,
                cpu->irq_nest, cpu->reta & C55X_PC_MASK);
            dec_logs++;
        }
    }
    /*
     * Submix channel loop: AC0 is the channel's +0x18 pointer.
     * A null pointer skips that channel's samples.
     */
    if (pc == 0x12c4b6u) {
        static unsigned sum_logs;

        if (mix_slot_hot && sum_logs < 8u) {
            uint32_t buf = (uint32_t)cpu->ac[0] & C55X_WORD_MASK;
            int peak = buf ? eap_block_peak(cpu, buf, 4u) : 0;

            eap_pcm_stat(
                "t=sum t3=%04x t2=%04x ac0=%08x bufpeak=%d\n",
                cpu->t[3], cpu->t[2],
                (unsigned)(cpu->ac[0] & 0xffffffffu), peak);
            sum_logs++;
        }
    }
    /*
     * _EAP_copyChToCh either copies a channel or fills the dest with
     * zeros when the source pointer is null. One planar half of the
     * speaker buffer stays silent; this says which path ran.
     */
    if (pc == 0x12c5c5u || pc == 0x12c64du || pc == 0x12c67au) {
        static unsigned ch_z, ch_nz, ch_dec, ch_copy;
        unsigned ac0 = (unsigned)(cpu->ac[0] & 0xffffffffu);
        int take = 0;

        if (pc == 0x12c5c5u) {
            if (ac0 == 0 && ch_z < 6u) {
                ch_z++;
                take = 1;
            } else if (ac0 != 0 && ch_nz < 6u) {
                ch_nz++;
                take = 1;
            }
        } else if (pc == 0x12c64du && ch_copy < 6u) {
            ch_copy++;
            take = 1;
        } else if (pc == 0x12c67au && ch_dec < 6u) {
            ch_dec++;
            take = 1;
        }
        if (take) {
            eap_pcm_stat(
                "t=ch pc=%06x ac0=%08x xar1=%06x xar5=%06x t0=%04x t1=%04x\n",
                pc, ac0,
                cpu->xar[1] & C55X_WORD_MASK,
                cpu->xar[5] & C55X_WORD_MASK,
                cpu->t[0], cpu->t[1]);
        }
    }
    if (pc == 0x132f89u || pc == 0x132f9fu || pc == 0x132fc9u) {
        static unsigned fout_logs;
        uint32_t ar6 = cpu->xar[6] & C55X_WORD_MASK;

        src_budget_word = ar6;
        if (fout_logs < 24u) {
            eap_pcm_stat(
                "t=fout pc=%06x t0=%04x t1=%04x ar0=%04x ar1=%04x "
                "ar6=%06x star6=%04x\n",
                pc, cpu->t[0], cpu->t[1],
                (unsigned)(cpu->xar[0] & 0xffffu),
                (unsigned)(cpu->xar[1] & 0xffffu),
                ar6, peek16(cpu, ar6));
            fout_logs++;
        }
    }
    /*
     * MOV HI(AC0),*AR2 is the sample the SRC just computed.
     * The entry outpeak above is the previous buffer, so a loud
     * HI here is the stage that turns a ±12 mix word into the
     * thousands the IODMA later copies.
     */
    if (pc == 0x136192u) {
        static unsigned hi_logs;
        uint64_t ac = cpu->ac[0] & C55X_AC_MASK;
        int hi = (int16_t)((ac >> 16) & 0xffffu);

        if (hi_logs < 8u && (hi >= 200 || hi <= -200)) {
            eap_pcm_stat(
                "t=histore hi=%d ac0=%010llx t2=%04x ar2=%06x\n",
                hi, (unsigned long long)ac, cpu->t[2],
                cpu->xar[2] & C55X_WORD_MASK);
            hi_logs++;
        }
    }
    /*
     * 0x136113 writes the first stage into the CDP delay. A loud
     * HI here means the spike is already present before the
     * second-stage FIR. BK47 is the AR4/AR5 circular size.
     */
    if (pc == 0x136113u) {
        static unsigned dstore_logs;
        uint64_t ac = cpu->ac[0] & C55X_AC_MASK;
        int hi = (int16_t)((ac >> 16) & 0xffffu);

        if (dstore_logs < 6u && (hi >= 80 || hi <= -80)) {
            eap_pcm_stat(
                "t=dstore hi=%d bk47=%04x bkc=%04x cdp=%06x t0=%04x\n",
                hi, cpu->bk47, cpu->bkc,
                cpu->xcdp & C55X_WORD_MASK, cpu->t[0]);
            dstore_logs++;
        }
    }
    /* Second-stage tap. A repeated sample with a full-scale coeff
     * is the burst that dies after one delay length. */
    if (pc == 0x13614cu) {
        static unsigned tap_logs;
        uint32_t cdp = cdp_ea(cpu, cpu->xcdp, 0);
        uint32_t ar6 = cpu->xar[6] & C55X_WORD_MASK;
        int sample = (int16_t)peek16(cpu, cdp);
        int coeff = (int16_t)peek16(cpu, ar6);

        if (tap_logs < 6u && (sample >= 40 || sample <= -40)) {
            eap_pcm_stat(
                "t=tap2 smp=%d coef=%d cdp=%06x ar6=%06x bkc=%04x "
                "csr=%04x\n",
                sample, coeff, cdp, ar6, cpu->bkc, cpu->csr);
            tap_logs++;
        }
    }
    /*
     * T1 at the coefficient MAC is the stride the scoped post-modify
     * adds to AR6. T2 at 0x136171 is the shift applied to that sum
     * before MOV HI. The value at the store itself is a later T2.
     */
    if (pc == 0x1360d3u || pc == 0x1360e6u) {
        static unsigned mac_logs;
        unsigned sar = (pc == 0x1360d3u) ? 4u : 5u;
        int32_t t1 = (int16_t)cpu->t[1];
        uint32_t saddr = ar_ea(cpu, sar, cpu->xar[sar], 0);
        uint32_t caddr = ar_ea(cpu, 6, cpu->xar[6], t1);
        uint16_t sample = peek16(cpu, saddr);
        uint16_t coeff = peek16(cpu, caddr);

        if (abs((int)(int16_t)sample) >= 8 && mac_logs < 8u) {
            eap_pcm_stat(
                "t=mac pc=%06x t1=%04x csr=%04x left=%u bk03=%04x "
                "smp=%04x coef=%04x saddr=%06x caddr=%06x\n",
                pc, cpu->t[1], cpu->csr, cpu->rpt_left, cpu->bk03,
                sample, coeff, saddr, caddr);
            mac_logs++;
        }
    }
    /* Second-stage repeat. A CSR of hundreds turns one quiet
     * sample into the burst on the loud channel. */
    if (pc == 0x13616au) {
        static unsigned rpt_logs;

        if (rpt_logs < 8u) {
            eap_pcm_stat("t=rpt2 csr=%04x t0=%04x t2=%04x bkc=%04x\n",
                         cpu->csr, cpu->t[0], cpu->t[2], cpu->bkc);
            rpt_logs++;
        }
    }
    /* First-stage shift. A positive T2 turns a quiet tap sum into
     * the 2335 that the delay line then rereads. */
    if (pc == 0x1360eau) {
        static unsigned s1_logs;
        uint64_t ac = cpu->ac[0] & C55X_AC_MASK;
        int hi = (int16_t)((ac >> 16) & 0xffffu);

        if (s1_logs < 6u && (hi >= 80 || hi <= -80)) {
            eap_pcm_stat(
                "t=sfts1 t2=%04x hi=%d csr=%04x bk47=%04x ar4=%06x "
                "smp=%04x\n",
                cpu->t[2], hi, cpu->csr, cpu->bk47,
                cpu->xar[4] & C55X_WORD_MASK,
                peek16(cpu, ar_ea(cpu, 4, cpu->xar[4], 0)));
            s1_logs++;
        }
    }
    if (pc == 0x136171u) {
        static unsigned sfts_logs;
        uint64_t ac = cpu->ac[0] & C55X_AC_MASK;
        int hi = (int16_t)((ac >> 16) & 0xffffu);

        if (sfts_logs < 8u && (hi >= 50 || hi <= -50)) {
            eap_pcm_stat("t=sfts t2=%04x hi=%d ac0=%010llx\n",
                         cpu->t[2], hi,
                         (unsigned long long)ac);
            sfts_logs++;
        }
    }
    if (pc == BIOS_PC_SRC_CONVERT || pc == BIOS_PC_SRC_DBL) {
        uint32_t obj = a0;
        /*
         * The audible convert is entered with XAR1 in the on-chip
         * mix slot (0x5d2, then +0xdc). That slot is not the esd
         * mmap. The same stride belongs on 0x218000 / 0x218800,
         * which is where cmd3 already sees the tune. Do this before
         * the t=src sample so the fixture sees that page.
         */
        {
            uint32_t x1 = cpu->xar[1] & C55X_WORD_MASK;

            if (x1 < 0x1000u) {
                uint32_t base = (obj == 0x6c1au) ? 0x218800u : 0x218000u;
                uint32_t off = (x1 >= 0x5d2u && x1 - 0x5d2u <= 0x200u)
                               ? (x1 - 0x5d2u) : 0;
                int peak = 0;
                unsigned wi;

                for (wi = 0; wi < 8u; wi++) {
                    int v = abs((int16_t)peek16(cpu, base + wi));

                    if (v > peak) {
                        peak = v;
                    }
                }
                if (peak > 0) {
                    cpu->xar[1] = (base + off) & C55X_WORD_MASK;
                }
            }
        }
        c55x_log(cpu,
                 "EAP-SRC %s XAR0=%06x XAR1=%06x XAR2=%06x XAR3=%06x "
                 "T0=%04x T1=%04x nch=%04x f6=%04x phase=%04x f2e=%04x "
                 "slot18=%06x ST2=%04x BSA23=%04x BSA45=%04x BK03=%04x "
                 "insn=%llu\n",
                 pc == BIOS_PC_SRC_DBL ? "dbl" : "convert",
                 obj, cpu->xar[1] & C55X_WORD_MASK,
                 cpu->xar[2] & C55X_WORD_MASK,
                 cpu->xar[3] & C55X_WORD_MASK,
                 cpu->t[0], cpu->t[1],
                 obj ? peek16_ram(cpu, obj + 5u) : 0,
                 obj ? peek16_ram(cpu, obj + 6u) : 0,
                 obj ? peek16_ram(cpu, obj + 0x26u) : 0,
                 obj ? peek16_ram(cpu, obj + 0x2eu) : 0,
                 eapiss.device ? peek_dbl_ram(cpu, eapiss.device + 0x18u) : 0,
                 cpu->st2, cpu->bsa23, cpu->bsa45, cpu->bk03,
                 (unsigned long long)cpu->insn_count);
        if (obj && pc == BIOS_PC_SRC_DBL) {
            poll_dump_words(cpu, obj, 50u, "src-obj");
            src_out_base = cpu->xar[2] & C55X_WORD_MASK;
            src_out_n = cpu->t[0];
            src_out_armed = 1;
        }
        {
            static unsigned src_logs;
            static unsigned src_quiet;
            static int src_best;
            uint32_t inb = cpu->xar[1] & C55X_WORD_MASK;
            uint32_t outb = cpu->xar[2] & C55X_WORD_MASK;
            int inpeak = 0;
            int outpeak = eap_block_peak(cpu, outb, 8u);
            unsigned wi;
            int record;

            for (wi = 0; wi < 8u; wi++) {
                int v = abs((int16_t)peek16(cpu, inb + wi));

                if (v > inpeak) {
                    inpeak = v;
                }
            }

            /*
             * The first calls scan an empty page, before cmd3 fills
             * it. A one-LSB prefix used to fill the log and hide the
             * later block. Always keep a new high-water peak.
             */
            {
                uint32_t page = inb & 0xfff000u;

                record = src_logs < 12u || inpeak > src_best ||
                         (obj == 0x69f4u && src_quiet < 8u) ||
                         ((page == 0x20d000u || page == 0x218000u) &&
                          inpeak > 0 && src_logs < 48u);
            }
            if (record) {
                if (inpeak > src_best) {
                    src_best = inpeak;
                }
                if (obj == 0x69f4u && src_logs >= 12u) {
                    src_quiet++;
                }
                eap_pcm_stat(
                    "t=src xar0=%06x xar1=%06x xar2=%06x t0=%04x t1=%04x "
                    "inpeak=%d outpeak=%d st2=%04x nch=%04x "
                    "f6=%04x f7=%04x f8=%04x f9=%04x f38=%04x "
                    "o=%04x %04x %04x %04x reta=%06x\n",
                    obj, inb, outb, cpu->t[0], cpu->t[1], inpeak, outpeak,
                    cpu->st2, obj ? peek16_ram(cpu, obj + 5u) : 0,
                    obj ? peek16_ram(cpu, obj + 6u) : 0,
                    obj ? peek16_ram(cpu, obj + 7u) : 0,
                    obj ? peek16_ram(cpu, obj + 8u) : 0,
                    obj ? peek16_ram(cpu, obj + 9u) : 0,
                    obj ? peek16_ram(cpu, obj + 38u) : 0,
                    peek16(cpu, outb), peek16(cpu, outb + 1u),
                    peek16(cpu, outb + 2u), peek16(cpu, outb + 3u),
                    cpu->reta & C55X_PC_MASK);
                src_logs++;
            }
        }
        return;
    }
    if (pc == 0x1365cdu && src_out_armed) {
        static unsigned src_done_logs;
        unsigned n = src_out_n;
        int peak;
        unsigned i;
        int at = -1;

        src_out_armed = 0;
        if (n > 512u) {
            n = 512u;
        }
        if (!n) {
            n = 8u;
        }
        peak = 0;
        for (i = 0; i < n; i++) {
            int v = abs((int16_t)peek16(cpu, src_out_base + i));

            if (v > peak) {
                peak = v;
                at = (int)i;
            }
        }
        if (src_done_logs < 8u) {
            eap_pcm_stat(
                "t=srcdone n=%u peak=%d at=%d base=%06x "
                "w0=%04x w1=%04x\n",
                n, peak, at, src_out_base,
                peek16(cpu, src_out_base),
                peek16(cpu, src_out_base + 1u));
            src_done_logs++;
        }
    }
    if (pc == BIOS_PC_SRC_RPTCSR) {
        static unsigned src_rpt_logs;

        if (src_rpt_logs < 8u) {
            uint32_t ar3 = cpu->xar[3] & C55X_WORD_MASK;
            uint32_t ea = ar_ea(cpu, 3u, ar3, 0);

            c55x_log(cpu,
                     "EAP-SRC rptcsr AR3=%06x EA=%06x *EA=%04x CSR=%04x "
                     "T0=%04x BRC0=%04x BRC1=%04x ST2=%04x BSA23=%04x "
                     "BK03=%04x insn=%llu\n",
                     ar3, ea, peek16_ram(cpu, ea), cpu->csr, cpu->t[0],
                     cpu->brc0, cpu->brc1, cpu->st2, cpu->bsa23, cpu->bk03,
                     (unsigned long long)cpu->insn_count);
            src_rpt_logs++;
        }
        return;
    }
    if (pc == BIOS_PC_EAP_PENTRY) {
        uint32_t extra = a0;
        uint32_t slot = extra ? peek_dbl_ram(cpu, extra) : 0;
        uint32_t sio = slot ? peek_dbl_ram(cpu, slot + 0x16u) : 0;
        uint32_t tod = sio ? peek_dbl_ram(cpu, sio) : 0;
        uint32_t from = sio ? peek_dbl_ram(cpu, sio + 2u) : 0;

        c55x_log(cpu,
                 "EAP-PENTRY extra=%06x slot=%06x buf4a=%06x "
                 "len4e=%04x acc50=%04x sio=%06x tod=%06x from=%06x "
                 "insn=%llu\n",
                 extra, slot,
                 extra ? peek_dbl_ram(cpu, extra + 0x4au) : 0,
                 extra ? peek16_ram(cpu, extra + 0x4eu) : 0,
                 extra ? peek16_ram(cpu, extra + 0x50u) : 0,
                 sio, tod, from,
                 (unsigned long long)cpu->insn_count);
        eap_cssa_src = extra ? peek_dbl_ram(cpu, extra + 0x4au) : 0;
        eap_cssa_len = extra ? peek16_ram(cpu, extra + 0x4eu) : 0;
        {
            static unsigned pentry_logs;

            if (pentry_logs < 16u) {
                eap_pcm_stat("t=pentry extra=%06x buf4a=%06x len4e=%04x\n",
                             extra, eap_cssa_src, eap_cssa_len);
                pentry_logs++;
            }
        }
        if (slot) {
            poll_dump_words(cpu, slot, 34u, "pentry-slot");
        }
        if (extra) {
            poll_dump_words(cpu, extra, 16u, "pentry-extra");
            poll_dump_words(cpu, extra + 0x4au, 8u, "pentry-extra4a");
        }
        if (sio) {
            poll_dump_words(cpu, sio, 16u, "pentry-sio");
        }
        if (tod) {
            poll_dump_words(cpu, tod, 8u, "pentry-tod");
            poll_dump_words(cpu, peek_dbl_ram(cpu, tod), 8u, "pentry-tod0");
        }
        if (from) {
            poll_dump_words(cpu, from, 8u, "pentry-from");
        }
        if (eapiss.buf) {
            poll_dump_words(cpu, eapiss.buf, 8u, "pentry-issued");
        }
        return;
    }
    if ((eapiss.issue_on || eapiss.dmaen_on) &&
        (pc == BIOS_PC_HWI_DISABLE || pc == BIOS_PC_HWI_ENABLE ||
         pc == BIOS_PC_HWI_RESTORE || pc == BIOS_PC_C55_ENINT ||
         pc == BIOS_PC_SEM_PEND || pc == BIOS_PC_SEM_POST)) {
        if ((pc == BIOS_PC_SEM_PEND || pc == BIOS_PC_SEM_POST) &&
            a0 != BIOS_WORD_DMA_SEM && a0 != BIOS_WORD_EAP_SEM) {
            return;
        }
        c55x_log(cpu,
                 "EAP-EVT %s XAR0=%06x T0=%04x IER0=%04x IFR0=%04x "
                 "insn=%llu\n",
                 eapq_near(pc), a0, cpu->t[0], cpu->ier0, cpu->ifr0,
                 (unsigned long long)cpu->insn_count);
    }
}

static void eapiss_note_after(C55xCPU *cpu, uint32_t pc, uint32_t next)
{
    if ((eapiss.issue_on || eapiss.dmaen_on) && cpu->ier0 != eapiss.last_ier0) {
        c55x_log(cpu,
                 "EAP-IER0 %04x->%04x pc=%06x %s insn=%llu\n",
                 eapiss.last_ier0, cpu->ier0, pc & C55X_PC_MASK,
                 eapq_near(pc), (unsigned long long)cpu->insn_count);
        eapiss.last_ier0 = cpu->ier0;
    }
    if (eapiss.dmaen_on && pc == BIOS_PC_DMAEN_BCC) {
        int skip = (next == BIOS_PC_DMAEN_SKIP);

        c55x_log(cpu,
                 "EAP-DMAEN-BCC pc=%06x next=%06x skip_swi=%u "
                 "DMADisableCnt=%04x (1=no _SWI_or) insn=%llu\n",
                 pc, next, skip, peek16_ram(cpu, BIOS_WORD_DMA_DISCNT),
                 (unsigned long long)cpu->insn_count);
        return;
    }
    if (eapiss.issue_on &&
        (pc == BIOS_PC_EAP_ISSUE_BCC || pc == BIOS_PC_EAP_ISSUE_ST2 ||
         pc == BIOS_PC_EAP_ISSUE_ST3 || pc == BIOS_PC_EAP_ISSUE_DIR)) {
        c55x_log(cpu,
                 "EAP-ISSUE-BCC pc=%06x next=%06x T0=%04x dir=%04x "
                 "stream=%04x insn=%llu\n",
                 pc, next, cpu->t[0], eapiss.dir, eapiss.stream,
                 (unsigned long long)cpu->insn_count);
        return;
    }
    if (eapiss.dmaen_on && pc == BIOS_PC_DMAEN_RET) {
        eapiss.dmaen_on = 0;
        eapiss.dma_sem_cnt_out = peek_word_safe(BIOS_WORD_DMA_SEM + 4u) ?
                                 peek16_ram(cpu, BIOS_WORD_DMA_SEM + 4u) : 0;
        c55x_log(cpu,
                 "EAP-DMAEN leave next=%06x T0=%04x dmac %04x->%04x "
                 "posted=%u DMADisableCnt=%04x insn=%llu\n",
                 next, cpu->t[0], eapiss.dma_sem_cnt_in,
                 eapiss.dma_sem_cnt_out, eapiss.dmaen_posted,
                 peek16_ram(cpu, BIOS_WORD_DMA_DISCNT),
                 (unsigned long long)cpu->insn_count);
        eapiss_state(cpu, "dmaen-leave");
        return;
    }
    if (eapiss.issue_on && pc == BIOS_PC_EAP_ISSUE_RET) {
        eapiss.issue_on = 0;
        c55x_log(cpu,
                 "EAP-ISSUE leave next=%06x T0=%04x posted_swiEAP=%u "
                 "posted_swiRet=%u swi_exec=%u cfg_dma=%u class=%c "
                 "insn=%llu\n",
                 next, cpu->t[0], eapiss.saw_swi_or || eapiss.saw_swi_post,
                 eapiss.saw_swi_ret, eapiss.saw_swi_exec, eapiss.saw_cfg_dma,
                 !eapiss.dmaen_posted ? 'A' :
                 (!eapiss.saw_swi_exec ? 'B' :
                  (!eapiss.saw_cfg_dma ? 'C' : 'D')),
                 (unsigned long long)cpu->insn_count);
        eapiss_state(cpu, "issue-leave");
        if (eapiss_do_force && eapq.flow_000e && !eapiss.forced) {
            eapiss_force_swi(cpu, next);
        }
    }
}

static void eapiss_note_store(C55xCPU *cpu, uint32_t word, uint16_t old,
                             uint16_t value)
{
    if (!eapiss.issue_on && !eapiss.dmaen_on && !eapiss.forced) {
        return;
    }
    if (old == value) {
        return;
    }
    word &= C55X_WORD_MASK;
    if ((word >= BIOS_WORD_EAP_GLOBAL && word < BIOS_WORD_EAP_GLOBAL + 0x330u) ||
        (word >= BIOS_WORD_SWI_EAP && word < BIOS_WORD_SWI_EAP + 40u) ||
        (word >= BIOS_WORD_DMA_SEM && word < BIOS_WORD_DMA_SEM + 8u) ||
        (word >= BIOS_WORD_EAP_SEM && word < BIOS_WORD_EAP_SEM + 8u) ||
        (word >= BIOS_WORD_DMA_DISCNT && word < BIOS_WORD_DMA_DISCNT + 12u) ||
        word == BIOS_WORD_MCBSP_ONCE || word == BIOS_WORD_DMA_MODE) {
        c55x_log(cpu,
                 "EAP-GLOB-W word=%06x %04x->%04x pc=%06x %s insn=%llu\n",
                 word, old, value, cpu->pc & C55X_PC_MASK,
                 eapq_near(cpu->pc), (unsigned long long)cpu->insn_count);
    }
}

static void poll_log_task(C55xCPU *cpu, unsigned tid, const char *tag)
{
    uint32_t task = (tid < POLL_TID_MAX) ? poll_tr.task[tid] : 0;
    uint32_t tsk;
    uint32_t sem;
    uint32_t run;
    uint32_t pendq;
    uint32_t cur;

    if (tid >= POLL_TID_MAX) {
        return;
    }
    if (!peek_word_safe(task)) {
        task = mbq_task_of(cpu, (uint16_t)tid);
    }
    tsk = peek_word_safe(task) ? peek_dbl_ram(cpu, task + 0x0au) : 0;
    sem = peek_word_safe(task) ? peek_dbl_ram(cpu, task + 14u) : 0;
    poll_tr.task[tid] = task;
    poll_tr.tsk[tid] = tsk;
    poll_tr.sem[tid] = sem;
    run = peek_dbl(cpu, BIOS_WORD_RUNADDR);
    pendq = peek_dbl_ram(cpu, sem);
    cur = peek_dbl_ram(cpu, BIOS_WORD_KNL_CURTASK);
    c55x_log(cpu,
             "POLL %s gen=%u tid=%u task=%06x tsk=%06x run=%06x cur=%06x "
             "+0c=%04x wr=%04x rd=%04x +22=%04x sem=%06x scnt=%04x "
             "pendq=%06x tsk0=%04x %04x %04x %04x "
             "lastcmd=%04x %04x lastpost=%llu lastpend=%llu lastdisp=%llu "
             "lastxsp=%06x pc=%06x insn=%llu\n",
             tag, poll_tr.gen, tid, task, tsk & C55X_WORD_MASK,
             run & C55X_PC_MASK, cur & C55X_WORD_MASK,
             peek_word_safe(task) ? peek16_ram(cpu, task + 12u) : 0,
             peek_word_safe(task) ? peek16_ram(cpu, task + 16u) : 0,
             peek_word_safe(task) ? peek16_ram(cpu, task + 17u) : 0,
             peek_word_safe(task) ? peek16_ram(cpu, task + 0x22u) : 0,
             sem, peek_word_safe(sem + 4u) ? peek16_ram(cpu, sem + 4u) : 0,
             pendq & C55X_WORD_MASK,
             peek_word_safe(tsk) ? peek16_ram(cpu, tsk) : 0,
             peek_word_safe(tsk + 1u) ? peek16_ram(cpu, tsk + 1u) : 0,
             peek_word_safe(tsk + 2u) ? peek16_ram(cpu, tsk + 2u) : 0,
             peek_word_safe(tsk + 3u) ? peek16_ram(cpu, tsk + 3u) : 0,
             poll_tr.last_cmd_h[tid] ? poll_tr.last_cmd_h[tid] :
             task_last_cmd_h[tid],
             poll_tr.last_cmd_d[tid] ? poll_tr.last_cmd_d[tid] :
             task_last_cmd_d[tid],
             (unsigned long long)poll_tr.last_post[tid],
             (unsigned long long)poll_tr.last_pend[tid],
             (unsigned long long)(poll_tr.last_disp[tid] ?
                                  poll_tr.last_disp[tid] : task_last_disp[tid]),
             poll_tr.last_xsp[tid],
             cpu->pc & C55X_PC_MASK,
             (unsigned long long)cpu->insn_count);
}

static void poll_summary(C55xCPU *cpu, const char *why)
{
    char part[96], queued[96], posted[96], sched[96], deq[96], clr[96], miss[96];
    uint32_t missing;
    unsigned tid;

    if (!poll_tr.live || poll_tr.summarized) {
        return;
    }
    missing = poll_tr.participants & ~poll_tr.cleared;
    poll_fmt_set(poll_tr.participants, part, sizeof(part));
    poll_fmt_set(poll_tr.queued, queued, sizeof(queued));
    poll_fmt_set(poll_tr.posted, posted, sizeof(posted));
    poll_fmt_set(poll_tr.scheduled, sched, sizeof(sched));
    poll_fmt_set(poll_tr.dequeued, deq, sizeof(deq));
    poll_fmt_set(poll_tr.cleared, clr, sizeof(clr));
    poll_fmt_set(missing, miss, sizeof(miss));
    c55x_log(cpu,
             "POLL gen=%u type=%u %s participants={%s} queued={%s} "
             "posted={%s} scheduled={%s} dequeued={%s} cleared={%s} "
             "missing={%s} cnt1=%04x insn=%llu\n",
             poll_tr.gen, poll_tr.type, why, part, queued, posted, sched,
             deq, clr, miss, peek16_ram(cpu, BIOS_WORD_POLLCNT1),
             (unsigned long long)cpu->insn_count);
    for (tid = 0; tid < 5u; tid++) {
        c55x_log(cpu,
                 "CMD20-SURVEY tid=%u data=%04x wait=%u ret=%u open=%u "
                 "obj=%06x wait_pc=%06x tsk=%06x\n",
                 tid, eapq.cmd20_data[tid],
                 !!(eapq.cmd20_wait & (1u << tid)),
                 !!(eapq.cmd20_ret & (1u << tid)),
                 !!(eapq.cmd20_open & (1u << tid)),
                 eapq.cmd20_wait_obj[tid], eapq.cmd20_wait_pc[tid],
                 eapq.tsk[tid]);
    }
    for (tid = 0; tid < POLL_TID_MAX; tid++) {
        if (missing & (1u << tid)) {
            poll_log_task(cpu, tid, "missing");
            poll_dump_words(cpu, poll_tr.tsk[tid], 16u, "missing-tsk");
            poll_dump_words(cpu, poll_tr.sem[tid], 8u, "missing-sem");
            poll_dump_words(cpu, BIOS_WORD_KNL_QUEUES, 8u, "missing-knlq");
            poll_dump_words(cpu, BIOS_WORD_EAP_F140, 8u, "missing-f140");
            eapq_log_blocked(cpu, tid);
        }
    }
    poll_tr.summarized = 1;
}

void c55x_poll_trace_reset(C55xCPU *cpu)
{
    poll_summary(cpu, "rst");
    poll_tr.live = 0;
    memset(&eapq, 0, sizeof(eapq));
    memset(&eapiss, 0, sizeof(eapiss));
    eapq_flow = 0;
    eapq_parked4 = 0;
}

static void poll_begin(C55xCPU *cpu)
{
    if (poll_tr.live && !poll_tr.summarized &&
        (poll_tr.participants & ~poll_tr.cleared)) {
        poll_summary(cpu, "replaced");
    }
    poll_tr.gen++;
    poll_tr.type = cpu->t[0];
    poll_tr.participants = 0;
    poll_tr.queued = 0;
    poll_tr.posted = 0;
    poll_tr.scheduled = 0;
    poll_tr.dequeued = 0;
    poll_tr.cleared = 0;
    memset(poll_tr.task, 0, sizeof(poll_tr.task));
    memset(poll_tr.tsk, 0, sizeof(poll_tr.tsk));
    memset(poll_tr.sem, 0, sizeof(poll_tr.sem));
    memset(poll_tr.wr0, 0, sizeof(poll_tr.wr0));
    memset(poll_tr.rd0, 0, sizeof(poll_tr.rd0));
    memset(poll_tr.last_cmd_h, 0, sizeof(poll_tr.last_cmd_h));
    memset(poll_tr.last_cmd_d, 0, sizeof(poll_tr.last_cmd_d));
    memset(poll_tr.last_post, 0, sizeof(poll_tr.last_post));
    memset(poll_tr.last_pend, 0, sizeof(poll_tr.last_pend));
    memset(poll_tr.last_disp, 0, sizeof(poll_tr.last_disp));
    memset(poll_tr.last_xsp, 0, sizeof(poll_tr.last_xsp));
    poll_tr.live = 1;
    poll_tr.summarized = 0;
    poll_tr.ckpt = 0;
    c55x_log(cpu, "POLL gen=%u type=%u begin pc=%06x insn=%llu\n",
             poll_tr.gen, poll_tr.type, cpu->pc & C55X_PC_MASK,
             (unsigned long long)cpu->insn_count);
    poll_checkpoint(cpu, "pre");
}

static void poll_checkpoint(C55xCPU *cpu, const char *why)
{
    unsigned tid;

    c55x_log(cpu,
             "POLL-CKPT %s gen=%u pc=%06x RETA=%06x XSP=%06x XSSP=%06x "
             "ST0=%04x ST1=%04x ST2=%04x INTM=%u IER0=%04x IFR0=%04x "
             "run=%06x cur=%06x curset=%04x curmask=%04x knlset=%04x "
             "cnt1=%04x insn=%llu\n",
             why, poll_tr.gen, cpu->pc & C55X_PC_MASK,
             cpu->reta & C55X_PC_MASK, cpu->xsp & C55X_WORD_MASK,
             cpu->xssp & C55X_WORD_MASK, cpu->st0, cpu->st1, cpu->st2,
             !!(cpu->st1 & C55X_ST1_INTM), cpu->ier0, cpu->ifr0,
             peek_dbl(cpu, BIOS_WORD_RUNADDR) & C55X_PC_MASK,
             peek_dbl_ram(cpu, BIOS_WORD_KNL_CURTASK) & C55X_WORD_MASK,
             peek16(cpu, BIOS_WORD_CURSET), peek16(cpu, BIOS_WORD_CURMASK),
             peek16_ram(cpu, BIOS_WORD_KNL_SET),
             peek16_ram(cpu, BIOS_WORD_POLLCNT1),
             (unsigned long long)cpu->insn_count);
    for (tid = 0; tid < 5u; tid++) {
        poll_bind_tid(cpu, tid, mbq_task_of(cpu, (uint16_t)tid));
        poll_log_task(cpu, tid, why);
        poll_dump_words(cpu, poll_tr.tsk[tid], 16u, why);
        poll_dump_words(cpu, poll_tr.sem[tid], 8u, why);
    }
    poll_dump_words(cpu, BIOS_WORD_KNL_QUEUES, 8u, why);
    poll_dump_words(cpu, BIOS_WORD_KNL_DUMMY, 8u, why);
    poll_dump_words(cpu, BIOS_WORD_EAP_F140, 8u, why);
}

void c55x_task_census(C55xCPU *cpu, const char *why)
{
    static const char *const names[5] = {
        "pcm3", "pcm_rec1", "pcm1", "audiopp", "pcm0"
    };
    char part[96], queued[96], posted[96], sched[96], deq[96], clr[96], miss[96];
    unsigned tid;

    poll_checkpoint(cpu, why);
    poll_fmt_set(poll_tr.participants, part, sizeof(part));
    poll_fmt_set(poll_tr.queued, queued, sizeof(queued));
    poll_fmt_set(poll_tr.posted, posted, sizeof(posted));
    poll_fmt_set(poll_tr.scheduled, sched, sizeof(sched));
    poll_fmt_set(poll_tr.dequeued, deq, sizeof(deq));
    poll_fmt_set(poll_tr.cleared, clr, sizeof(clr));
    poll_fmt_set(poll_tr.participants & ~poll_tr.cleared, miss, sizeof(miss));
    c55x_log(cpu,
             "POLL generation\n"
             "  trigger=%s live=%u gen=%u type=%u\n"
             "  _mbx_newmsg pc=%s\n"
             "  dispatch=%s\n"
             "  _poll_broadcast=%s\n"
             "  participants={%s}\n"
             "  queued={%s}\n"
             "  posted={%s}\n"
             "  scheduled={%s}\n"
             "  dequeued={%s}\n"
             "  cleared={%s}\n"
             "  missing={%s}\n",
             why, poll_tr.live, poll_tr.gen, poll_tr.type,
             (cpu->pc & C55X_PC_MASK) == BIOS_PC_MBX_NEWMSG ? "131eec" :
             "not-entered",
             poll_tr.live ? "see MBOX DISPATCH" : "not-entered",
             poll_tr.live ? "entered" : "not-entered",
             part, queued, posted, sched, deq, clr, miss);
    for (tid = 0; tid < 5u; tid++) {
        uint32_t task = mbq_task_of(cpu, (uint16_t)tid);
        uint32_t tsk = peek_word_safe(task) ? peek_dbl_ram(cpu, task + 0x0au) : 0;
        uint32_t sem = peek_word_safe(task) ? peek_dbl_ram(cpu, task + 14u) : 0;
        uint16_t wr = peek_word_safe(task) ? peek16_ram(cpu, task + 16u) : 0;
        uint16_t rd = peek_word_safe(task) ? peek16_ram(cpu, task + 17u) : 0;
        uint16_t mode = peek_word_safe(task) ? peek16_ram(cpu, task + 12u) : 0;
        uint32_t saved = peek_word_safe(tsk) ? peek_dbl_ram(cpu, tsk + 4u) : 0;
        uint32_t cur = peek_dbl_ram(cpu, BIOS_WORD_KNL_CURTASK);

        c55x_log(cpu,
                 "TASK CENSUS %s tid=%u name=%s tsk=%06x state=%04x "
                 "cur=%06x saved_pc=%06x blk=%u blk_pc=%06x blk_obj=%06x "
                 "lastcmd=%04x:%04x lastdisp=%llu last_deq=%llu "
                 "last_sched=%llu mbq wr=%04x rd=%04x full=%u sem=%06x "
                 "scnt=%04x cmd20_wait=%u wait_pc=%06x\n",
                 why, tid, names[tid], tsk & C55X_WORD_MASK, mode,
                 cur & C55X_WORD_MASK, saved & C55X_PC_MASK,
                 eapq.blocked[tid], eapq.blk_pc[tid], eapq.blk_obj[tid],
                 task_last_cmd_h[tid], task_last_cmd_d[tid],
                 (unsigned long long)task_last_disp[tid],
                 (unsigned long long)task_last_deq[tid],
                 (unsigned long long)task_last_sched[tid],
                 wr, rd, mode == 2u, sem,
                 peek_word_safe(sem + 4u) ? peek16_ram(cpu, sem + 4u) : 0,
                 !!(eapq.cmd20_wait & (1u << tid)),
                 eapq.cmd20_wait_pc[tid]);
        eapq_log_blocked(cpu, tid);
    }
}

static void poll_note_cmd(unsigned tid, uint16_t cmd_h, uint16_t cmd_d)
{
    if (tid >= POLL_TID_MAX) {
        return;
    }
    task_last_cmd_h[tid] = cmd_h;
    task_last_cmd_d[tid] = cmd_d;
    if (poll_tr.live) {
        poll_tr.last_cmd_h[tid] = cmd_h;
        poll_tr.last_cmd_d[tid] = cmd_d;
    }
}

static void poll_chain(C55xCPU *cpu, uint32_t pc)
{
    int tid;
    uint32_t handle;
    uint16_t scnt;
    uint32_t pendq;

    if (pc == BIOS_PC_CMD_DISP) {
        tid = (int)cpu->t[0];
        if (tid >= 0 && tid < (int)POLL_TID_MAX) {
            uint32_t cmd = cpu->xar[0] & C55X_WORD_MASK;

            poll_note_cmd((unsigned)tid, peek16_ram(cpu, cmd),
                          peek16_ram(cpu, cmd + 1u));
            task_last_disp[tid] = cpu->insn_count;
            eapq_note_disp(cpu, (unsigned)tid, task_last_cmd_h[tid],
                           task_last_cmd_d[tid]);
            if (poll_tr.live) {
                poll_tr.last_disp[tid] = cpu->insn_count;
                c55x_log(cpu,
                         "POLL-DISPATCH gen=%u tid=%u cmd=%04x %04x "
                         "insn=%llu\n",
                         poll_tr.gen, tid, task_last_cmd_h[tid],
                         task_last_cmd_d[tid],
                         (unsigned long long)cpu->insn_count);
            }
        }
        return;
    }
    if (pc == BIOS_PC_GET_MBQ) {
        tid = (int)cpu->t[0];
        if (tid >= 0 && tid < (int)POLL_TID_MAX) {
            task_last_deq[tid] = cpu->insn_count;
        }
        eapq_note_get_mbq(cpu, cpu->t[0]);
    }
    if (pc == BIOS_PC_KNL_SWITCH || pc == BIOS_PC_KNL_READY) {
        handle = cpu->xar[0] & C55X_WORD_MASK;
        tid = poll_tid_of_tsk(handle);
        if (tid >= 0) {
            task_last_sched[tid] = cpu->insn_count;
        }
    }
    if (!poll_tr.live) {
        return;
    }
    if (pc == BIOS_PC_SEM_POST || pc == BIOS_PC_SEM_PEND) {
        handle = cpu->xar[0] & C55X_WORD_MASK;
        tid = poll_tid_of_sem(handle);
        scnt = peek_word_safe(handle + 4u) ? peek16_ram(cpu, handle + 4u) : 0;
        pendq = peek_dbl_ram(cpu, handle);
        if (tid >= 0) {
            if (pc == BIOS_PC_SEM_POST) {
                poll_tr.posted |= 1u << tid;
                poll_tr.last_post[tid] = cpu->insn_count;
            } else {
                poll_tr.last_pend[tid] = cpu->insn_count;
            }
            c55x_log(cpu,
                     "POLL-%s gen=%u tid=%u sem=%06x scnt=%04x pendq=%06x "
                     "caller=%06x insn=%llu\n",
                     pc == BIOS_PC_SEM_POST ? "SEM-POST" : "SEM-PEND",
                     poll_tr.gen, tid, handle, scnt,
                     pendq & C55X_WORD_MASK, cpu->reta & C55X_PC_MASK,
                     (unsigned long long)cpu->insn_count);
            poll_log_task(cpu, (unsigned)tid,
                          pc == BIOS_PC_SEM_POST ? "sem-post" : "sem-pend");
        }
        return;
    }
    if (pc == BIOS_PC_KNL_SWITCH || pc == BIOS_PC_KNL_READY) {
        handle = cpu->xar[0] & C55X_WORD_MASK;
        tid = poll_tid_of_tsk(handle);
        if (tid >= 0) {
            poll_tr.scheduled |= 1u << tid;
            poll_tr.last_xsp[tid] = cpu->xsp & C55X_WORD_MASK;
            c55x_log(cpu,
                     "POLL-%s gen=%u tid=%u tsk=%06x xar0=%06x "
                     "curmask=%04x curset=%04x xsp=%06x insn=%llu\n",
                     pc == BIOS_PC_KNL_SWITCH ? "SWITCH" : "READY",
                     poll_tr.gen, tid, poll_tr.tsk[tid] & C55X_WORD_MASK,
                     handle, peek16(cpu, BIOS_WORD_CURMASK),
                     peek16(cpu, BIOS_WORD_CURSET),
                     cpu->xsp & C55X_WORD_MASK,
                     (unsigned long long)cpu->insn_count);
            poll_log_task(cpu, (unsigned)tid,
                          pc == BIOS_PC_KNL_SWITCH ? "switch" : "ready");
        }
        return;
    }
    if (pc == BIOS_PC_TASK_LOOP || pc == BIOS_PC_GET_MBQ) {
        tid = (int)cpu->t[0];
        if (tid >= 0 && tid < (int)POLL_TID_MAX &&
            (poll_tr.participants & (1u << tid))) {
            poll_tr.scheduled |= 1u << tid;
            c55x_log(cpu, "POLL-%s gen=%u tid=%u insn=%llu\n",
                     pc == BIOS_PC_TASK_LOOP ? "TASK-LOOP" : "GET-MBQ",
                     poll_tr.gen, tid, (unsigned long long)cpu->insn_count);
        }
    }
}

static int poll_from_bcast(const C55xCPU *cpu)
{
    uint32_t ret = cpu->reta & C55X_PC_MASK;

    return ret == 0x131bb3u || ret == 0x131bafu;
}

static void poll_note_before(C55xCPU *cpu, uint32_t pc)
{
    if (pc == BIOS_PC_POLL_BCAST) {
        poll_begin(cpu);
        return;
    }
    if (pc == BIOS_PC_POLL_FAN && poll_tr.live) {
        uint32_t sp = cpu->xsp & C55X_WORD_MASK;
        unsigned tid = peek16_ram(cpu, sp + 1u);
        uint32_t task = peek_dbl(cpu, sp + 2u);
        uint32_t cmd = (sp + 6u) & C55X_WORD_MASK;

        if (tid < POLL_TID_MAX) {
            poll_tr.participants |= 1u << tid;
            poll_bind_tid(cpu, tid, task);
            poll_tr.wr0[tid] = peek_word_safe(task) ?
                               peek16_ram(cpu, task + 16u) : 0;
            poll_tr.rd0[tid] = peek_word_safe(task) ?
                               peek16_ram(cpu, task + 17u) : 0;
            c55x_log(cpu,
                     "POLL-QUEUE gen=%u tid=%u before wr=%04x rd=%04x "
                     "task=%06x cmd=%04x %04x %04x insn=%llu\n",
                     poll_tr.gen, tid, poll_tr.wr0[tid], poll_tr.rd0[tid],
                     task, peek16_ram(cpu, cmd), peek16_ram(cpu, cmd + 1u),
                     peek16_ram(cpu, cmd + 2u),
                     (unsigned long long)cpu->insn_count);
            poll_log_task(cpu, tid, "participant");
        }
        return;
    }
    if (pc == BIOS_PC_POLL_CLEAR) {
        poll_tr.cnt_enter = peek16_ram(cpu, BIOS_WORD_POLLCNT1);
        return;
    }
    if (pc == BIOS_PC_POLL_SEND) {
        poll_summary(cpu, "send");
    }
}

static void poll_note_after(C55xCPU *cpu, uint32_t pc, uint32_t next_pc)
{
    if (pc == BIOS_PC_MBQ_OK && poll_tr.live && poll_from_bcast(cpu)) {
        uint32_t sp = cpu->xsp & C55X_WORD_MASK;
        unsigned tid = peek16_ram(cpu, sp + 8u);
        uint32_t task = peek_dbl(cpu, sp + 2u);

        if (tid < POLL_TID_MAX) {
            poll_tr.queued |= 1u << tid;
            poll_bind_tid(cpu, tid, task);
            c55x_log(cpu,
                     "POLL-QUEUE gen=%u tid=%u after wr=%04x rd=%04x "
                     "T0=%04x insn=%llu\n",
                     poll_tr.gen, tid,
                     peek_word_safe(task) ? peek16_ram(cpu, task + 16u) : 0,
                     peek_word_safe(task) ? peek16_ram(cpu, task + 17u) : 0,
                     cpu->t[0], (unsigned long long)cpu->insn_count);
            if (!poll_tr.ckpt &&
                (poll_tr.queued & poll_tr.participants) == poll_tr.participants &&
                poll_tr.participants) {
                poll_checkpoint(cpu, "queued");
                poll_tr.ckpt = 1;
            }
        }
        return;
    }
    if (pc == BIOS_PC_MBQ_GOT && poll_tr.live) {
        uint32_t sp = cpu->xsp & C55X_WORD_MASK;
        unsigned tid = cpu->t[0];
        uint32_t cmd = (sp + 6u) & C55X_WORD_MASK;
        uint16_t cmd_h = peek16_ram(cpu, cmd);

        if (tid < POLL_TID_MAX && cmd_h == 0x32) {
            poll_tr.dequeued |= 1u << tid;
            c55x_log(cpu,
                     "POLL-DEQUEUE gen=%u tid=%u cmd=%04x %04x caller=%06x "
                     "insn=%llu\n",
                     poll_tr.gen, tid, cmd_h, peek16_ram(cpu, cmd + 1u),
                     cpu->reta & C55X_PC_MASK,
                     (unsigned long long)cpu->insn_count);
            poll_log_task(cpu, tid, "dequeued");
        }
        return;
    }
    if (pc == BIOS_PC_POLL_LAST && poll_tr.live) {
        unsigned tid = peek16_ram(cpu, (cpu->xsp & C55X_WORD_MASK));
        uint16_t now = peek16_ram(cpu, BIOS_WORD_POLLCNT1);
        int sent = (next_pc == 0x131c7cu);

        if (tid < POLL_TID_MAX) {
            poll_tr.cleared |= 1u << tid;
        }
        c55x_log(cpu,
                 "POLL-CLEAR gen=%u tid=%u caller=%06x cnt %u -> %u "
                 "send=%u insn=%llu\n",
                 poll_tr.gen, tid, cpu->reta & C55X_PC_MASK,
                 poll_tr.cnt_enter, now, sent,
                 (unsigned long long)cpu->insn_count);
        poll_log_task(cpu, tid, "cleared");
        if (!sent && (poll_tr.participants & ~poll_tr.cleared) == 0) {
            poll_summary(cpu, "cleared-all");
        }
        return;
    }
}

static void log_poll_state(C55xCPU *cpu, const char *tag)
{
    unsigned i;
    char m[48];
    int n = 0;

    m[0] = '\0';
    for (i = 0; i < 5u; i++) {
        n += snprintf(m + n, sizeof(m) - (size_t)n, "%s%04x",
                      i ? " " : "", peek16(cpu, BIOS_WORD_POLLMASK + i));
        if (n < 0 || (size_t)n >= sizeof(m)) {
            break;
        }
    }
    c55x_log(cpu,
             "POLL %s T0=%04x T1=%04x AR1=%04x mask=%s cnt0=%04x cnt1=%04x "
             "TC1=%u insn=%llu\n",
             tag, cpu->t[0], cpu->t[1], cpu->xar[1] & 0xffffu, m,
             peek16(cpu, BIOS_WORD_POLLCNT0),
             peek16(cpu, BIOS_WORD_POLLCNT1),
             !!(cpu->st0 & C55X_ST0_TC1),
             (unsigned long long)cpu->insn_count);
}

static const char *dev_fxn_name(uint32_t off)
{
    switch (off & ~1u) {
    case 0x0eu:
        return "close";
    case 0x10u:
        return "ctrl";
    case 0x12u:
        return "idle";
    case 0x14u:
        return "issue";
    case 0x16u:
        return "open";
    case 0x18u:
        return "ready";
    case 0x1au:
        return "reclaim";
    default:
        return "?";
    }
}

static const char *dev_near_name(uint32_t pc)
{
    const char *name = bios_pc_name(pc);

    if (name) {
        return name;
    }
    if (pc >= 0x100998u && pc < 0x100b40u) {
        return "_SIO_create";
    }
    if (pc >= 0x1013ecu && pc < 0x101500u) {
        return "_SIO_delete";
    }
    if (pc >= 0x101f14u && pc < 0x101f7cu) {
        return "_SIO_reclaim";
    }
    if (pc >= 0x101fe0u && pc < 0x1020a8u) {
        return "_SIO_issue";
    }
    if (pc >= 0x1031f7u && pc < 0x103216u) {
        return "_QUE_get";
    }
    if (pc >= 0x103216u && pc < 0x103239u) {
        return "_QUE_put";
    }
    if (pc >= 0x12cac0u && pc < 0x12caf8u) {
        return "_EAP_reclaim";
    }
    if (pc >= 0x12caf8u && pc < 0x12cb18u) {
        return "_EAP_ready";
    }
    if (pc >= 0x12cc44u && pc < 0x12cc98u) {
        return "_EAP_issue";
    }
    if (pc >= 0x128510u && pc < 0x12870cu) {
        return "_EAP_ctrl";
    }
    if (pc >= 0x12797cu && pc < 0x127a2cu) {
        return "_EAP_CC_RemoveStream";
    }
    if (pc >= 0x1239e0u && pc < 0x123a10u) {
        return "EAP_SIO_open";
    }
    return "?";
}

static void dev_watch_add(C55xCPU *cpu, uint32_t handle)
{
    unsigned i;

    handle &= C55X_WORD_MASK;
    if (!handle) {
        return;
    }
    for (i = 0; i < cpu->dev_watch_n; i++) {
        if (cpu->dev_watch[i] == handle) {
            return;
        }
    }
    if (cpu->dev_watch_n >= C55X_DEV_WATCH_MAX) {
        return;
    }
    cpu->dev_watch[cpu->dev_watch_n++] = handle;
}

static int dev_watch_hit(const C55xCPU *cpu, uint32_t word, uint32_t *base)
{
    unsigned i;

    word &= C55X_WORD_MASK;
    for (i = 0; i < cpu->dev_watch_n; i++) {
        uint32_t h = cpu->dev_watch[i];

        if (word >= h + BIOS_DEV_FXNS && word <= h + BIOS_DEV_FXNS_END) {
            if (base) {
                *base = h;
            }
            return 1;
        }
    }
    return 0;
}

static void log_idle_code(C55xCPU *cpu, uint32_t idle, const char *why)
{
    uint8_t b[8];
    unsigned i;
    int nz = 0;
    int rc;

    idle &= C55X_PC_MASK;
    memset(b, 0, sizeof(b));
    rc = c55x_fetch(cpu, idle, b, 8);
    for (i = 0; i < 8; i++) {
        nz |= b[i];
    }
    c55x_log(cpu,
             "DEV-IDLE-CODE why=%s addr=%06x fetch=%d nonzero=%u "
             "bytes=%02x %02x %02x %02x %02x %02x %02x %02x insn=%llu\n",
             why, idle, rc, nz != 0, b[0], b[1], b[2], b[3], b[4], b[5],
             b[6], b[7], (unsigned long long)cpu->insn_count);
}

static void log_dev_fxns(C55xCPU *cpu, uint32_t handle, const char *why)
{
    static const uint32_t offs[] = {
        0x0eu, 0x10u, 0x12u, 0x14u, 0x16u, 0x18u, 0x1au
    };
    unsigned i;
    uint32_t idle;

    handle &= C55X_WORD_MASK;
    if (!handle) {
        c55x_log(cpu, "DEV-FXNS why=%s handle=000000\n", why);
        return;
    }
    idle = peek_dbl(cpu, handle + BIOS_DEV_IDLE) & C55X_PC_MASK;
    c55x_log(cpu,
             "DEV-FXNS why=%s handle=%06x "
             "todevice=%06x fromdevice=%06x bufsize=%04x nbufs=%04x "
             "segid=%04x mode=%04x devid=%06x params=%06x object=%06x "
             "close=%06x ctrl=%06x idle=%06x issue=%06x open=%06x "
             "ready=%06x reclaim=%06x insn=%llu\n",
             why, handle,
             peek_dbl(cpu, handle + 0x00u) & C55X_WORD_MASK,
             peek_dbl(cpu, handle + 0x02u) & C55X_WORD_MASK,
             peek16(cpu, handle + 0x04u), peek16(cpu, handle + 0x05u),
             peek16(cpu, handle + 0x06u), peek16(cpu, handle + 0x07u),
             peek_dbl(cpu, handle + 0x08u) & C55X_WORD_MASK,
             peek_dbl(cpu, handle + 0x0au) & C55X_WORD_MASK,
             peek_dbl(cpu, handle + 0x0cu) & C55X_WORD_MASK,
             peek_dbl(cpu, handle + 0x0eu) & C55X_PC_MASK,
             peek_dbl(cpu, handle + 0x10u) & C55X_PC_MASK,
             idle,
             peek_dbl(cpu, handle + 0x14u) & C55X_PC_MASK,
             peek_dbl(cpu, handle + 0x16u) & C55X_PC_MASK,
             peek_dbl(cpu, handle + 0x18u) & C55X_PC_MASK,
             peek_dbl(cpu, handle + 0x1au) & C55X_PC_MASK,
             (unsigned long long)cpu->insn_count);
    for (i = 0; i < 7; i++) {
        uint32_t fn = peek_dbl(cpu, handle + offs[i]) & C55X_PC_MASK;

        c55x_log(cpu, "  DEV %s = %06x %s\n",
                 dev_fxn_name(offs[i]), fn, dev_near_name(fn));
    }
    log_idle_code(cpu, idle, why);
}

static uint32_t sio_eap_handle(C55xCPU *cpu)
{
    return peek_dbl(cpu, BIOS_WORD_SIO_EAP) & C55X_WORD_MASK;
}

static char eap_ascii(uint16_t w)
{
    w &= 0xff;
    if (w >= 0x20u && w <= 0x7eu) {
        return (char)w;
    }
    return '.';
}

static void log_eap_id(C55xCPU *cpu, const char *tag, uint16_t value)
{
    char ch = eap_ascii(value);

    c55x_log(cpu,
             "EAP-ID %s value=0x%04x unsigned=%u ASCII='%c'%s "
             "pc=%06x T0=%04x T1=%04x T2=%04x T3=%04x "
             "XAR0=%06x XAR1=%06x XAR2=%06x RETA=%06x insn=%llu\n",
             tag, value, value, ch,
             (value >= 0x20u && value <= 0x7eu) ? "" : " (non-ascii)",
             cpu->pc & C55X_PC_MASK, cpu->t[0], cpu->t[1], cpu->t[2],
             cpu->t[3], cpu->xar[0] & C55X_WORD_MASK,
             cpu->xar[1] & C55X_WORD_MASK, cpu->xar[2] & C55X_WORD_MASK,
             cpu->reta & C55X_PC_MASK,
             (unsigned long long)cpu->insn_count);
}

static void log_eap_name(C55xCPU *cpu, uint32_t base, const char *why)
{
    uint16_t w[8];
    unsigned i;
    char a[9];

    base &= C55X_WORD_MASK;
    for (i = 0; i < 8; i++) {
        w[i] = peek16(cpu, base + i);
        a[i] = eap_ascii(w[i]);
    }
    a[8] = 0;
    c55x_log(cpu,
             "EAP-NAME %s base=%06x "
             "words=%04x %04x %04x %04x %04x %04x %04x %04x "
             "ascii=\"%s\" insn=%llu\n",
             why, base, w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7],
             a, (unsigned long long)cpu->insn_count);
}

static uint32_t devm_in;
static unsigned devm_cand;
static unsigned devm_step;
static int devm_on;

static int devm_watch_input(uint32_t word)
{
    word &= C55X_WORD_MASK;
    return word == BIOS_WORD_EAP_NAME_A || word == 0x09ce32u ||
           word == BIOS_WORD_EAP_NAME_C || word == 0x010e22u ||
           word == 0x010d3au;
}

static void log_dev_device(C55xCPU *cpu, uint32_t dev, unsigned idx,
                           const char *why)
{
    uint32_t name, fxns, params, next;
    uint16_t w[12];
    char a[13];
    unsigned i;

    dev &= C55X_WORD_MASK;
    if (!dev) {
        c55x_log(cpu, "DEV-MATCH %s #%u device=000000\n", why, idx);
        return;
    }
    next = peek_dbl(cpu, dev) & C55X_WORD_MASK;
    name = peek_dbl(cpu, dev + 6u) & C55X_WORD_MASK;
    fxns = peek_dbl(cpu, dev + 8u) & C55X_WORD_MASK;
    params = peek_dbl(cpu, dev + 0xcu) & C55X_WORD_MASK;
    for (i = 0; i < 12; i++) {
        w[i] = peek16(cpu, name + i);
        a[i] = eap_ascii(w[i]);
        if (w[i] == 0) {
            a[i] = 0;
            break;
        }
    }
    a[12] = 0;
    c55x_log(cpu,
             "DEV-MATCH %s #%u device=%06x next=%06x name_ptr=%06x "
             "name=\"%s\" words=%04x %04x %04x %04x %04x %04x "
             "fxns=%06x devid=%06x params=%06x type=%04x "
             "T1=%04x insn=%llu\n",
             why, idx, dev, next, name, a, w[0], w[1], w[2], w[3],
             w[4], w[5], fxns & C55X_PC_MASK,
             peek_dbl(cpu, dev + 0xau) & C55X_WORD_MASK, params,
             peek16(cpu, dev + 0xeu), cpu->t[1],
             (unsigned long long)cpu->insn_count);
}

static void log_dev_list(C55xCPU *cpu)
{
    uint32_t head = BIOS_WORD_DEVQ;
    uint32_t p = peek_dbl(cpu, head) & C55X_WORD_MASK;
    unsigned n = 0;

    c55x_log(cpu, "DEV-MATCH list head=%06x first=%06x\n", head, p);
    while (p && p != head && n < 24) {
        log_dev_device(cpu, p, n, "list");
        p = peek_dbl(cpu, p) & C55X_WORD_MASK;
        n++;
    }
}

static void note_dev_store(C55xCPU *cpu, uint32_t word, uint16_t old,
                           uint16_t value)
{
    uint32_t base = 0;
    uint32_t even;
    uint32_t dword;
    uint32_t old_dword;
    int watched;

    word &= C55X_WORD_MASK;
    if (old == value) {
        return;
    }
    if (word == PCM1_WORD_MODE) {
        eap_pcm_stat("pcm1-cf34 pc=%06x %04x->%04x\n",
                     cpu->pc & C55X_PC_MASK, old, value);
    }
    if (word == BIOS_WORD_KNL_WORK) {
        knlq_note_work_store(cpu, old, value);
    }
    {
        uint32_t q = BIOS_WORD_KNL_QUEUES;
        uint32_t h = knlq_arg_handle;

        if ((word >= q && word < q + 4u) ||
            (knlq_elem && word >= knlq_elem && word < knlq_elem + 4u) ||
            (h && (knlq_in_get || knlq_in_put) &&
             word >= h && word < h + 4u)) {
            knlq_note_link(cpu, word, old, value);
        }
    }
    /* EAP GenAudioPlay / initADDStreams queue-handle slots at 0xf220/0xf240. */
    if ((word == 0xf220u || word == 0xf221u || word == 0xf222u ||
         word == 0xf223u || word == 0xf240u || word == 0xf241u ||
         word == 0xf242u || word == 0xf243u) &&
        (old != 0 || value != 0)) {
        c55x_log(cpu,
                 "EAP-QHANDLE-WRITE pc=%06x word=%06x %04x->%04x "
                 "dbl=%06x RETA=%06x insn=%llu\n",
                 cpu->pc & C55X_PC_MASK, word, old, value,
                 peek_dbl_ram(cpu, word & ~1u) & C55X_WORD_MASK,
                 cpu->reta & C55X_PC_MASK,
                 (unsigned long long)cpu->insn_count);
    }
    /*
     * SIO objects store QUE_Handles at +0/+2. Zeroing them (e.g. copyChToCh
     * treating the SIO as a PCM plane) is the null-handle _QUE_get source.
     */
    if ((word == 0x636eu || word == 0x636fu || word == 0x6370u ||
         word == 0x6371u || word == 0x63cau || word == 0x63cbu ||
         word == 0x63ccu || word == 0x63cdu) &&
        (old != 0 || value != 0)) {
        c55x_log(cpu,
                 "EAP-SIO-QHANDLE pc=%06x word=%06x %04x->%04x "
                 "dbl=%06x AR5=%06x RETA=%06x insn=%llu\n",
                 cpu->pc & C55X_PC_MASK, word, old, value,
                 peek_dbl_ram(cpu, word & ~1u) & C55X_WORD_MASK,
                 cpu->xar[5] & C55X_WORD_MASK,
                 cpu->reta & C55X_PC_MASK,
                 (unsigned long long)cpu->insn_count);
    }
    /* Stream object +0x18 PCM cursor (f044+18 = f05c). */
    if ((word == 0xf05cu || word == 0xf05du) && (old != 0 || value != 0)) {
        c55x_log(cpu,
                 "EAP-FIELD18-WRITE pc=%06x word=%06x %04x->%04x "
                 "dbl=%06x RETA=%06x insn=%llu\n",
                 cpu->pc & C55X_PC_MASK, word, old, value,
                 peek_dbl_ram(cpu, 0xf05cu) & C55X_WORD_MASK,
                 cpu->reta & C55X_PC_MASK,
                 (unsigned long long)cpu->insn_count);
    }
    /* mumdrc channel object+2 inner pointer (harvest 00634a). */
    if ((word == 0x634au || word == 0x634bu) && (old != 0 || value != 0)) {
        c55x_log(cpu,
                 "MUMDRC-INNER-WRITE pc=%06x word=%06x %04x->%04x "
                 "dbl=%06x RETA=%06x XSP=%06x insn=%llu\n",
                 cpu->pc & C55X_PC_MASK, word, old, value,
                 peek_dbl_ram(cpu, 0x634au) & C55X_WORD_MASK,
                 cpu->reta & C55X_PC_MASK,
                 cpu->xsp & C55X_WORD_MASK,
                 (unsigned long long)cpu->insn_count);
    }
    if (word >= BIOS_WORD_TIDTAB &&
        word < BIOS_WORD_TIDTAB + BIOS_TIDTAB_WORDS && !(word & 1u) &&
        old && value == 0) {
        c55x_log(cpu,
                 "TASK UNREGISTER tidtab word=%06x tid=%u old=%04x "
                 "pc=%06x insn=%llu\n",
                 word, (unsigned)((word - BIOS_WORD_TIDTAB) / 2u), old,
                 cpu->pc & C55X_PC_MASK, (unsigned long long)cpu->insn_count);
    }
    if (word == BIOS_WORD_DEVQ || word == BIOS_WORD_DEVQ + 1u) {
        c55x_log(cpu,
                 "DEV-LIST-WRITE pc=%06x %s word=%06x %04x->%04x "
                 "head=%06x insn=%llu\n",
                 cpu->pc & C55X_PC_MASK, dev_near_name(cpu->pc),
                 word, old, value,
                 peek_dbl(cpu, BIOS_WORD_DEVQ) & C55X_WORD_MASK,
                 (unsigned long long)cpu->insn_count);
        log_dev_list(cpu);
    }
    if (word == BIOS_WORD_SIO_EAP || word == BIOS_WORD_SIO_EAP + 1u) {
        uint32_t handle = sio_eap_handle(cpu);

        dev_watch_add(cpu, handle);
        c55x_log(cpu,
                 "DEV-SIO-HANDLE pc=%06x %s word=%06x %04x->%04x "
                 "handle=%06x AC0=%010llx XAR0=%06x XAR3=%06x insn=%llu\n",
                 cpu->pc & C55X_PC_MASK, dev_near_name(cpu->pc),
                 word, old, value, handle,
                 (unsigned long long)(cpu->ac[0] & C55X_AC_MASK),
                 cpu->xar[0] & C55X_WORD_MASK,
                 cpu->xar[3] & C55X_WORD_MASK,
                 (unsigned long long)cpu->insn_count);
        if (handle) {
            log_dev_fxns(cpu, handle, "SIO_handle_store");
        }
    }
    watched = dev_watch_hit(cpu, word, &base);
    even = word & ~1u;
    dword = peek_dbl(cpu, even);
    if (word == even) {
        old_dword = ((uint32_t)old << 16) | peek16(cpu, even + 1u);
    } else {
        old_dword = ((uint32_t)peek16(cpu, even) << 16) | old;
    }
    if (watched && old_dword != dword) {
        c55x_log(cpu,
                 "DEV-FXNS-WRITE pc=%06x %s handle=%06x +%02x %s "
                 "old=%06x new=%06x word=%06x %04x->%04x "
                 "AC0=%010llx XAR2=%06x XAR3=%06x T0=%04x insn=%llu\n",
                 cpu->pc & C55X_PC_MASK, dev_near_name(cpu->pc),
                 base, (unsigned)(even - base), dev_fxn_name(even - base),
                 old_dword & C55X_PC_MASK, dword & C55X_PC_MASK,
                 word, old, value,
                 (unsigned long long)(cpu->ac[0] & C55X_AC_MASK),
                 cpu->xar[2] & C55X_WORD_MASK,
                 cpu->xar[3] & C55X_WORD_MASK, cpu->t[0],
                 (unsigned long long)cpu->insn_count);
        if ((dword & C55X_PC_MASK) == BIOS_IDLE_STALE) {
            log_idle_code(cpu, BIOS_IDLE_STALE, "first_idle_01ef7a");
        }
    } else if (!watched && (dword & C55X_PC_MASK) == BIOS_IDLE_STALE &&
               (old_dword & C55X_PC_MASK) != BIOS_IDLE_STALE) {
        c55x_log(cpu,
                 "DEV-IDLE-STALE-WRITE pc=%06x %s word=%06x "
                 "old=%06x new=%06x AC0=%010llx XAR2=%06x XAR3=%06x "
                 "insn=%llu\n",
                 cpu->pc & C55X_PC_MASK, dev_near_name(cpu->pc),
                 word, old_dword & C55X_PC_MASK, dword & C55X_PC_MASK,
                 (unsigned long long)(cpu->ac[0] & C55X_AC_MASK),
                 cpu->xar[2] & C55X_WORD_MASK,
                 cpu->xar[3] & C55X_WORD_MASK,
                 (unsigned long long)cpu->insn_count);
        log_idle_code(cpu, BIOS_IDLE_STALE, "stale_write");
    }
    eapq_note_store(cpu, word, old, value);
    eapiss_note_store(cpu, word, old, value);
}

static uint32_t bios_watch;

static void bios_watch_arm(void)
{
    bios_watch = 48;
}

static const char *bios_pc_name(uint32_t pc)
{
    switch (pc) {
    case BIOS_PC_SWI_ENABLE:
        return "_SWI_enable";
    case BIOS_PC_SWI_POST:
        return "_SWI_post";
    case BIOS_PC_SWI_EXEC_SYNC:
        return "SWI_F_exec_sync";
    case BIOS_PC_SWI_EXEC:
        return "SWI_F_exec";
    case BIOS_PC_SWI_RUN:
        return "SWI_F_run";
    case BIOS_PC_HWI_DISPATCH:
        return "_HWI_F_dispatch";
    case BIOS_PC_HWI_ISR_CALL:
        return "HWI_ISR_CALL";
    case BIOS_PC_HWI_LOCK_DEC:
        return "HWI_lock_dec";
    case BIOS_PC_HWI_NEST_BCC:
        return "HWI_nest_bcc";
    case BIOS_PC_HWI_READY_BCC:
        return "HWI_ready_bcc";
    case BIOS_PC_HWI_SWI_CALL:
        return "HWI_SWI_CALL";
    case BIOS_PC_HWI_RETI:
        return "HWI_RETI";
    case BIOS_PC_KNL_RUN:
        return "_KNL_run";
    case BIOS_PC_KNL_CALL0:
        return "_KNL_run+CALL";
    case BIOS_PC_KNL_IPOST:
        return "_KNL_ipost";
    case BIOS_PC_KNL_SWITCH:
        return "_KNL_switch";
    case BIOS_PC_KNL_READY:
        return "_KNL_ready";
    case BIOS_PC_SWI_OR:
        return "_SWI_or";
    case BIOS_PC_SWI_ORHOOK:
        return "_SWI_orHook";
    case BIOS_PC_SWI_DISABLE:
        return "_SWI_disable";
    case BIOS_PC_BALANCE:
        return "_balance_ipbuf";
    case BIOS_PC_TCFG_UNPACK:
        return "TCFG_unpack";
    case BIOS_PC_TCFG_DISP:
        return "TCFG_dispatch";
    case BIOS_PC_TCFG_REPLY:
        return "TCFG_reply";
    case BIOS_PC_MBCMD_SEND:
        return "_mbcmd_send";
    case BIOS_PC_CMD_DISP:
        return "mbq_dispatch";
    case BIOS_PC_GET_MBQ:
        return "get_mbq";
    case BIOS_PC_TASK_LOOP:
        return "task_loop";
    case BIOS_PC_SEM_PEND:
        return "_SEM_pend";
    case BIOS_PC_REG_MBQ:
        return "_register_mbq";
    case BIOS_PC_MBQ_TIDGE:
        return "mbq_tid_ge32";
    case BIOS_PC_MBQ_NULLB:
        return "mbq_task_null";
    case BIOS_PC_MBQ_ERR16:
        return "mbq_err16";
    case BIOS_PC_MBQ_STAT:
        return "mbq_stat";
    case BIOS_PC_MBQ_FULL:
        return "mbq_full225";
    case BIOS_PC_MBQ_WRAP:
        return "mbq_wrap";
    case BIOS_PC_MBQ_OVF:
        return "mbq_ovf225";
    case BIOS_PC_MBQ_OK:
        return "mbq_ok";
    case BIOS_PC_MBQ_RET:
        return "mbq_ret";
    case BIOS_PC_INIT_TASKS:
        return "_init_tasks";
    case BIOS_PC_SEM_POST:
        return "_SEM_post";
    case BIOS_PC_MBX_NEWMSG:
        return "_mbx_newmsg";
    case BIOS_PC_MBX_SEQ_BCC:
        return "mbx_seq_bcc";
    case BIOS_PC_MBX_SEQ_ERR:
        return "mbx_seq_err";
    case BIOS_PC_MBX_SFTL:
        return "mbx_cmd_sftl";
    case BIOS_PC_MBX_NULL_BCC:
        return "mbx_null_bcc";
    case BIOS_PC_MBX_CALL:
        return "mbx_handler_call";
    case BIOS_PC_MBX_NOTFULL:
        return "_mbx_notfull";
    case BIOS_PC_MAILBOX_ISR:
        return "_mailbox_interrupt";
    case BIOS_PC_MBX_POST_NEW:
        return "SWI_newmsg_post";
    case BIOS_PC_POLL_SEND:
        return "POLL_send";
    case BIOS_PC_POLL_BCAST:
        return "_poll_broadcast";
    case BIOS_PC_POLL_CLEAR:
        return "_poll_clear";
    case BIOS_PC_ISSUE_IDLE:
        return "_issue_idle";
    case BIOS_PC_SLEEP_DSP:
        return "_sleep_dsp";
    case BIOS_PC_IER_DIS:
        return "IER0_disable";
    case BIOS_PC_CMD54:
        return "cmd54_send";
    case BIOS_PC_SIO_CREATE:
        return "_SIO_create";
    case BIOS_PC_SIO_FXNS_COPY:
        return "SIO_fxns_copy";
    case BIOS_PC_SIO_FXNS_OPEN:
        return "SIO_fxns_open";
    case BIOS_PC_SIO_DELETE:
        return "_SIO_delete";
    case BIOS_PC_SIO_RECLAIM:
        return "_SIO_reclaim";
    case BIOS_PC_SIO_ISSUE:
        return "_SIO_issue";
    case BIOS_PC_QUE_GET:
        return "_QUE_get";
    case BIOS_PC_QUE_PUT:
        return "_QUE_put";
    case BIOS_PC_EAP_CTRL:
        return "_EAP_ctrl";
    case BIOS_PC_EAP_PROCESS:
        return "_EAP_process";
    case BIOS_PC_EAP_CHREADY:
        return "_EAP_channelReady";
    case BIOS_PC_EAP_RECLAIM:
        return "_EAP_reclaim";
    case BIOS_PC_EAP_READY:
        return "_EAP_ready";
    case BIOS_PC_EAP_ISSUE:
        return "_EAP_issue";
    case BIOS_PC_DMAENABLE:
        return "_DMAEnableReq";
    case BIOS_PC_EAP_CLOCK:
        return "_EAP_clock";
    case BIOS_PC_AUDIO_ISR:
        return "audio_isr";
    case BIOS_PC_C55_ENINT:
        return "_C55_enableInt";
    case BIOS_PC_HWI_DISABLE:
        return "_HWI_disable";
    case BIOS_PC_HWI_ENABLE:
        return "_HWI_enable";
    case BIOS_PC_HWI_RESTORE:
        return "_HWI_restore";
    case BIOS_PC_SWI_EAP:
        return "_swiEAP";
    case BIOS_PC_SWI_EAP_RET:
        return "_swiEAPReturn";
    case BIOS_PC_ENABLE_DMA:
        return "_Enable_DMA";
    case BIOS_PC_CFG_DMA:
        return "_Configure_DMA";
    case BIOS_PC_ENABLE_MCBSP:
        return "_Enable_McBSP_I2S";
    case BIOS_PC_CFG_MCBSP:
        return "_Configure_McBSP_I2S";
    case BIOS_PC_REMOVE_STREAM:
        return "_EAP_CC_RemoveStream";
    default:
        return NULL;
    }
}

static const char *bios_swi_handle(uint32_t word)
{
    word &= C55X_WORD_MASK;
    if (word == BIOS_WORD_SWI_NEWMSG) {
        return "SWI_newmsg";
    }
    if (word == BIOS_WORD_SWI_NOTFULL) {
        return "SWI_notfull";
    }
    if (word == BIOS_WORD_SWI_KNL) {
        return "KNL_swi";
    }
    if (word == BIOS_WORD_SWI_EAP) {
        return "swiEAP";
    }
    if (word == BIOS_WORD_SWI_EAP_RET) {
        return "swiEAPReturn";
    }
    return "?";
}

static int bios_pc_always(uint32_t pc)
{
    return pc == BIOS_PC_SWI_POST || pc == BIOS_PC_SWI_OR ||
           pc == BIOS_PC_SWI_ORHOOK || pc == BIOS_PC_SWI_ENABLE ||
           pc == BIOS_PC_SWI_DISABLE || pc == BIOS_PC_SWI_EXEC ||
           pc == BIOS_PC_SWI_RUN || pc == BIOS_PC_SWI_EXEC_SYNC ||
           pc == BIOS_PC_MAILBOX_ISR || pc == BIOS_PC_MBX_NEWMSG ||
           pc == BIOS_PC_MBX_SEQ_BCC || pc == BIOS_PC_MBX_SEQ_ERR ||
           pc == BIOS_PC_MBX_SFTL || pc == BIOS_PC_MBX_NULL_BCC ||
           pc == BIOS_PC_MBX_CALL ||            pc == BIOS_PC_TCFG_DISP ||
           pc == BIOS_PC_TCFG_UNPACK || pc == BIOS_PC_TCFG_REPLY ||
           pc == BIOS_PC_MBCMD_SEND || pc == BIOS_PC_CMD_DISP ||
           pc == BIOS_PC_GET_MBQ || pc == BIOS_PC_TASK_LOOP ||
           pc == BIOS_PC_REG_MBQ || pc == BIOS_PC_MBQ_TIDGE ||
           pc == BIOS_PC_MBQ_NULLB || pc == BIOS_PC_MBQ_ERR16 ||
           pc == BIOS_PC_MBQ_STAT || pc == BIOS_PC_MBQ_FULL ||
           pc == BIOS_PC_MBQ_WRAP || pc == BIOS_PC_MBQ_OVF ||
           pc == BIOS_PC_MBQ_OK || pc == BIOS_PC_MBQ_RET ||
           pc == BIOS_PC_INIT_TASKS ||
           pc == BIOS_PC_MBX_NOTFULL || pc == BIOS_PC_MBX_POST_NEW ||
           pc == BIOS_PC_HWI_ISR_CALL || pc == BIOS_PC_HWI_LOCK_DEC ||
           pc == BIOS_PC_HWI_NEST_BCC || pc == BIOS_PC_HWI_READY_BCC ||
           pc == BIOS_PC_HWI_SWI_CALL || pc == BIOS_PC_HWI_RETI ||
           pc == BIOS_PC_HWI_DISPATCH || pc == BIOS_PC_POLL_SEND ||
           pc == BIOS_PC_POLL_BCAST || pc == BIOS_PC_POLL_CLEAR ||
           pc == BIOS_PC_ISSUE_IDLE || pc == BIOS_PC_SLEEP_DSP ||
           pc == BIOS_PC_IER_DIS || pc == BIOS_PC_CMD54 ||
           pc == BIOS_PC_SIO_CREATE || pc == BIOS_PC_SIO_FXNS_COPY ||
           pc == BIOS_PC_SIO_FXNS_OPEN || pc == BIOS_PC_SIO_DELETE ||
           pc == BIOS_PC_REMOVE_STREAM;
}

static void bios_log(C55xCPU *cpu, uint32_t pc, const char *when,
                     uint32_t next_pc)
{
    const char *name = bios_pc_name(pc);
    uint32_t xar0 = cpu->xar[0] & C55X_WORD_MASK;
    uint32_t run = ((uint32_t)peek16(cpu, BIOS_WORD_RUNADDR) << 16) |
                   peek16(cpu, BIOS_WORD_RUNADDR + 1u);

    if (!name) {
        return;
    }
    if (pc == BIOS_PC_SWI_POST || pc == BIOS_PC_SWI_OR ||
        pc == BIOS_PC_MAILBOX_ISR || pc == BIOS_PC_MBX_POST_NEW ||
        pc == BIOS_PC_REG_MBQ || pc == BIOS_PC_TASK_LOOP ||
        pc == BIOS_PC_GET_MBQ || pc == BIOS_PC_POLL_SEND) {
        bios_watch_arm();
    }
    c55x_log(cpu,
             "BIOS %s %s pc=%06x next=%06x handle=%s XAR0=%06x T0=%04x T1=%04x "
             "AC0=%010llx AC1=%010llx lock=%04x curset=%04x curmask=%04x "
             "run=%06x obj=%04x %04x irqstat=%04x %04x msgstat=%04x %04x "
             "seq=%04x %04x h60=%04x %04x h70=%04x %04x "
             "nest=%u INTM=%u TC1=%u IER0=%04x IFR0=%04x "
             "XSP=%06x RETA=%06x insn=%llu\n",
             when, name, pc, next_pc, bios_swi_handle(xar0), xar0,
             cpu->t[0], cpu->t[1],
             (unsigned long long)(cpu->ac[0] & C55X_AC_MASK),
             (unsigned long long)(cpu->ac[1] & C55X_AC_MASK),
             peek16(cpu, BIOS_WORD_LOCK), peek16(cpu, BIOS_WORD_CURSET),
             peek16(cpu, BIOS_WORD_CURMASK), run & C55X_PC_MASK,
             peek16(cpu, xar0), peek16(cpu, xar0 + 1u),
             peek16(cpu, BIOS_WORD_IRQSTAT),
             peek16(cpu, BIOS_WORD_IRQSTAT + 1u),
             peek16(cpu, BIOS_WORD_MSGSTAT),
             peek16(cpu, BIOS_WORD_MSGSTAT + 1u),
             peek16(cpu, BIOS_WORD_SEQ), peek16(cpu, BIOS_WORD_SEQ + 1u),
             peek16(cpu, BIOS_WORD_CMDTAB + 0xc0u),
             peek16(cpu, BIOS_WORD_CMDTAB + 0xc1u),
             peek16(cpu, BIOS_WORD_CMDTAB + 0xe0u),
             peek16(cpu, BIOS_WORD_CMDTAB + 0xe1u),
             cpu->irq_nest, !!(cpu->st1 & C55X_ST1_INTM),
             !!(cpu->st0 & C55X_ST0_TC1), cpu->ier0, cpu->ifr0,
             cpu->xsp & C55X_WORD_MASK, cpu->reta & C55X_PC_MASK,
             (unsigned long long)cpu->insn_count);
    if (pc == BIOS_PC_REG_MBQ) {
        c55x_log(cpu,
                 "TASK REGISTER tid=%u task=%06x T0=%04x insn=%llu\n",
                 cpu->t[0], xar0, cpu->t[0],
                 (unsigned long long)cpu->insn_count);
    }
    if (pc == BIOS_PC_INIT_TASKS) {
        c55x_log(cpu, "TASK CREATE _init_tasks insn=%llu\n",
                 (unsigned long long)cpu->insn_count);
    }
    if (pc == BIOS_PC_REMOVE_STREAM) {
        c55x_log(cpu,
                 "TASK UNREGISTER _EAP_CC_RemoveStream XAR0=%06x "
                 "T0=%04x insn=%llu\n",
                 xar0, cpu->t[0], (unsigned long long)cpu->insn_count);
    }
    {
        uint32_t raw = (uint32_t)(cpu->ac[0] & 0xffffffffull);
        uint16_t cmd_h = peek16(cpu, xar0);

        if (pc == BIOS_PC_POLL_SEND || cmd_h == 0x32 ||
            ((raw >> 24) & 0x7f) == 0x32) {
            c55x_log(cpu,
                     "BIOS POLL %s pc=%06x cmd=%04x %04x h32=%04x %04x "
                     "fifo0=%04x fifo1=%04x full1=%04x insn=%llu\n",
                     name, pc, cmd_h, peek16(cpu, xar0 + 1u),
                     peek16(cpu, BIOS_WORD_CMDTAB + 0x64u),
                     peek16(cpu, BIOS_WORD_CMDTAB + 0x65u),
                     peek16(cpu, BIOS_WORD_MSGSTAT),
                     peek16(cpu, BIOS_WORD_MSGSTAT1),
                     peek16(cpu, BIOS_WORD_FIFOSTAT1),
                     (unsigned long long)cpu->insn_count);
        }
        if (pc == BIOS_PC_MBX_CALL) {
            unsigned dcmd = (raw >> 24) & 0x7f;
            uint32_t entry = BIOS_WORD_CMDTAB + dcmd * 2u;
            uint32_t target = (uint32_t)(cpu->ac[1] & C55X_PC_MASK);
            const char *tname = bios_pc_name(target);

            c55x_log(cpu,
                     "MBOX DISPATCH: cmd=%02x:%02x seq=%u data=%04x "
                     "table=%06x entry=%06x slot=%04x %04x "
                     "target=%06x %s ST1=%04x ST2=%04x INTM=%u DBGM=%u "
                     "lock=%04x curset=%04x curmask=%04x nest=%u "
                     "XSP=%06x XSSP=%06x insn=%llu\n",
                     dcmd, (raw >> 16) & 0xffu, (raw >> 31) & 1u,
                     raw & 0xffffu, BIOS_WORD_CMDTAB, entry,
                     peek16(cpu, entry), peek16(cpu, entry + 1u),
                     target, tname ? tname : "?",
                     cpu->st1, cpu->st2, !!(cpu->st1 & C55X_ST1_INTM),
                     !!(cpu->st2 & C55X_ST2_DBGM),
                     peek16(cpu, BIOS_WORD_LOCK),
                     peek16(cpu, BIOS_WORD_CURSET),
                     peek16(cpu, BIOS_WORD_CURMASK), cpu->irq_nest,
                     cpu->xsp & C55X_WORD_MASK, cpu->xssp & C55X_WORD_MASK,
                     (unsigned long long)cpu->insn_count);
        }
    }
    if (pc == BIOS_PC_REG_MBQ || pc == BIOS_PC_MBQ_TIDGE ||
        pc == BIOS_PC_MBQ_NULLB || pc == BIOS_PC_MBQ_ERR16 ||
        pc == BIOS_PC_MBQ_STAT || pc == BIOS_PC_MBQ_FULL ||
        pc == BIOS_PC_MBQ_WRAP || pc == BIOS_PC_MBQ_OVF ||
        pc == BIOS_PC_MBQ_OK || pc == BIOS_PC_MBQ_RET ||
        pc == BIOS_PC_INIT_TASKS || pc == BIOS_PC_TASK_LOOP ||
        pc == BIOS_PC_GET_MBQ || pc == BIOS_PC_CMD_DISP) {
        char tab[160];
        uint16_t tid;
        uint32_t cmd;
        uint32_t task;
        unsigned i;
        int n = 0;

        if (poll_tr.live) {
            /* POLL-CHAIN / POLL-QUEUE already records the barrier. */
        } else {
        tab[0] = '\0';
        for (i = 0; i < BIOS_TIDTAB_WORDS; i++) {
            n += snprintf(tab + n, sizeof(tab) - (size_t)n, "%s%04x",
                          i ? " " : "", peek16(cpu, BIOS_WORD_TIDTAB + i));
            if (n < 0 || (size_t)n >= sizeof(tab)) {
                break;
            }
        }
        c55x_log(cpu, "BIOS tidtab %s\n", tab);
        if (pc == BIOS_PC_REG_MBQ) {
            cmd = xar0;
            tid = peek16_ram(cpu, cmd + 1u);
            task = mbq_task_of(cpu, tid);
        } else if (pc == BIOS_PC_GET_MBQ || pc == BIOS_PC_TASK_LOOP ||
                   pc == BIOS_PC_CMD_DISP || pc == BIOS_PC_INIT_TASKS) {
            tid = cpu->t[0];
            cmd = xar0;
            task = mbq_task_of(cpu, tid);
        } else {
            uint32_t sp = cpu->xsp & C55X_WORD_MASK;

            tid = peek16_ram(cpu, sp + 8u);
            cmd = (((uint32_t)peek16_ram(cpu, sp) << 16) |
                   peek16_ram(cpu, sp + 1u));
            task = (((uint32_t)peek16_ram(cpu, sp + 2u) << 16) |
                    peek16_ram(cpu, sp + 3u));
            if (!peek_word_safe(task)) {
                task = mbq_task_of(cpu, tid);
            }
        }
        log_mbq_task(cpu, tid, task, cmd, name);
        }
    }
    if (pc == BIOS_PC_POLL_BCAST || pc == BIOS_PC_POLL_CLEAR ||
        pc == BIOS_PC_POLL_SEND) {
        log_poll_state(cpu, name);
    }
}

static uint32_t eap_name_pc(uint32_t pc)
{
    if (pc == BIOS_PC_NAME4_A || pc == BIOS_PC_NAME5_A) {
        return BIOS_WORD_EAP_NAME_A;
    }
    if (pc == BIOS_PC_NAME4_B || pc == BIOS_PC_NAME5_B) {
        return BIOS_WORD_EAP_NAME_B;
    }
    if (pc == BIOS_PC_NAME4_C || pc == BIOS_PC_NAME5_C) {
        return BIOS_WORD_EAP_NAME_C;
    }
    return 0;
}

static void eap_note_before(C55xCPU *cpu, uint32_t pc)
{
    uint32_t name;

    if (pc == BIOS_PC_EAP_POSTSTREAM) {
        uint32_t stream = cpu->xar[0] & C55X_WORD_MASK;
        uint32_t slot = stream ?
            (peek_dbl_ram(cpu, (stream + 0x16u) & C55X_WORD_MASK) &
             C55X_WORD_MASK) : 0;
        uint32_t handle = slot ?
            (peek_dbl_ram(cpu, slot) & C55X_WORD_MASK) : 0;

        c55x_log(cpu,
                 "EAP-POSTSTREAM stream=%06x +16=%06x handle=%06x "
                 "+18=%06x mode=%04x RETA=%06x insn=%llu\n",
                 stream, slot, handle,
                 stream ?
                 (peek_dbl_ram(cpu, (stream + 0x18u) & C55X_WORD_MASK) &
                  C55X_WORD_MASK) : 0,
                 stream ? peek16(cpu, (stream + 0x1au) & C55X_WORD_MASK) : 0,
                 cpu->reta & C55X_PC_MASK,
                 (unsigned long long)cpu->insn_count);
        return;
    }
    if (pc == BIOS_PC_MUMDRC_ENTRY) {
        c55x_log(cpu,
                 "MUMDRC-ENTER XAR0=%06x XAR1=%06x XAR2=%06x XAR3=%06x "
                 "XAR4=%06x T0=%04x T2=%04x XSP=%06x RETA=%06x insn=%llu\n",
                 cpu->xar[0] & C55X_WORD_MASK, cpu->xar[1] & C55X_WORD_MASK,
                 cpu->xar[2] & C55X_WORD_MASK, cpu->xar[3] & C55X_WORD_MASK,
                 cpu->xar[4] & C55X_WORD_MASK, cpu->t[0], cpu->t[2],
                 cpu->xsp & C55X_WORD_MASK, cpu->reta & C55X_PC_MASK,
                 (unsigned long long)cpu->insn_count);
        return;
    }
    if (pc == BIOS_PC_MUMDRC_PROLOGUE) {
        c55x_log(cpu,
                 "MUMDRC-PROLOGUE XAR0=%06x XAR6=%06x XAR7=%06x "
                 "XSP=%06x delta=%d insn=%llu\n",
                 cpu->xar[0] & C55X_WORD_MASK,
                 cpu->xar[6] & C55X_WORD_MASK,
                 cpu->xar[7] & C55X_WORD_MASK,
                 cpu->xsp & C55X_WORD_MASK,
                 (int)((cpu->xar[0] - cpu->xsp) & C55X_WORD_MASK),
                 (unsigned long long)cpu->insn_count);
        return;
    }
    if (pc == BIOS_PC_MUMDRC_MAIN_T2) {
        c55x_log(cpu,
                 "MUMDRC-MAIN-T2 T0=%04x T2=%04x T3=%04x "
                 "XAR0=%06x XAR2=%06x ST1=%04x ST2=%04x "
                 "BSA23=%04x BK03=%04x "
                 "SP0=%04x SP1=%04x XSP=%06x insn=%llu\n",
                 cpu->t[0], cpu->t[2], cpu->t[3],
                 cpu->xar[0] & C55X_WORD_MASK,
                 cpu->xar[2] & C55X_WORD_MASK, cpu->st1, cpu->st2,
                 cpu->bsa23, cpu->bk03,
                 peek16(cpu, cpu->xsp & C55X_WORD_MASK),
                 peek16(cpu, (cpu->xsp + 1u) & C55X_WORD_MASK),
                 cpu->xsp & C55X_WORD_MASK,
                 (unsigned long long)cpu->insn_count);
        return;
    }
    if (pc == BIOS_PC_MUMDRC_T2_STOMP) {
        uint32_t ea = ar_ea(cpu, 2u, cpu->xar[2], (int16_t)cpu->t[0]);

        /* Only when the EA overlaps the watched T2 save slot. */
        if ((ea & C55X_WORD_MASK) == 0x66bau ||
            ((ea ^ 1u) & C55X_WORD_MASK) == 0x66bau) {
            c55x_log(cpu,
                     "MUMDRC-T2-STOMP XAR2=%06x T0=%04x ea=%06x "
                     "ST2=%04x AR2LC=%u BSA23=%04x BK03=%04x "
                     "slot=%04x XSP=%06x insn=%llu\n",
                     cpu->xar[2] & C55X_WORD_MASK, cpu->t[0], ea,
                     cpu->st2, ar_circular(cpu, 2u) ? 1u : 0u,
                     cpu->bsa23, cpu->bk03,
                     peek16(cpu, 0x66bau),
                     cpu->xsp & C55X_WORD_MASK,
                     (unsigned long long)cpu->insn_count);
        }
        return;
    }
    if (pc == BIOS_PC_MUMDRC_CALLSP6) {
        int32_t off = -(int16_t)cpu->t[0];
        uint32_t ea = ar_ea(cpu, 2u, cpu->xar[2], off);

        c55x_log(cpu,
                 "MUMDRC-CALLSP6 XAR2=%06x XAR3=%06x T0=%04x T1=%04x "
                 "ea=%06x ARMS=%u "
                 "w66ba=%04x w66bc=%04x w66bd=%04x w66be=%04x "
                 "w66c0=%04x w66c1=%04x w66c2=%04x "
                 "XSP=%06x XSSP=%06x insn=%llu\n",
                 cpu->xar[2] & C55X_WORD_MASK,
                 cpu->xar[3] & C55X_WORD_MASK,
                 cpu->t[0], cpu->t[1], ea & C55X_WORD_MASK,
                 !!(cpu->st2 & C55X_ST2_ARMS),
                 peek16(cpu, 0x66bau), peek16(cpu, 0x66bcu),
                 peek16(cpu, 0x66bdu), peek16(cpu, 0x66beu),
                 peek16(cpu, 0x66c0u), peek16(cpu, 0x66c1u),
                 peek16(cpu, 0x66c2u),
                 cpu->xsp & C55X_WORD_MASK,
                 cpu->xssp & C55X_WORD_MASK,
                 (unsigned long long)cpu->insn_count);
        return;
    }
    if (pc == BIOS_PC_MUMDRC_MAIN_POP) {
        c55x_log(cpu,
                 "MUMDRC-MAIN-POP pre T2=%04x T3=%04x "
                 "SP0=%04x SP1=%04x "
                 "w66ba=%04x w66bc=%04x w66bd=%04x w66be=%04x "
                 "XAR6=%06x XAR7=%06x "
                 "XSP=%06x XSSP=%06x insn=%llu\n",
                 cpu->t[2], cpu->t[3],
                 peek16(cpu, cpu->xsp & C55X_WORD_MASK),
                 peek16(cpu, (cpu->xsp + 1u) & C55X_WORD_MASK),
                 peek16(cpu, 0x66bau), peek16(cpu, 0x66bcu),
                 peek16(cpu, 0x66bdu), peek16(cpu, 0x66beu),
                 cpu->xar[6] & C55X_WORD_MASK,
                 cpu->xar[7] & C55X_WORD_MASK,
                 cpu->xsp & C55X_WORD_MASK,
                 cpu->xssp & C55X_WORD_MASK,
                 (unsigned long long)cpu->insn_count);
        return;
    }
    if (pc == BIOS_PC_MUMDRC_ANALYZE_ST) {
        uint32_t ar0 = cpu->xar[0] & C55X_WORD_MASK;
        uint32_t addr = (ar0 + 0x18u) & C55X_WORD_MASK;

        c55x_log(cpu,
                 "MUMDRC-ANALYZE-SIZE AR0=%06x addr=%06x T0=%04x "
                 "old=%04x XSP=%06x insn=%llu\n",
                 ar0, addr, cpu->t[0], peek16(cpu, addr),
                 cpu->xsp & C55X_WORD_MASK,
                 (unsigned long long)cpu->insn_count);
        return;
    }
    if (pc == BIOS_PC_MUMDRC_COPY_AR) {
        uint32_t ar5 = cpu->xar[5] & C55X_WORD_MASK;

        c55x_log(cpu,
                 "MUMDRC-COPY-AR XAR5=%06x *XAR5=%06x XAR6=%06x XAR7=%06x "
                 "T2=%04x T0=%04x T3=%04x SP0=%04x SP1=%04x "
                 "XSP=%06x insn=%llu\n",
                 ar5, peek_dbl_ram(cpu, ar5) & C55X_WORD_MASK,
                 cpu->xar[6] & C55X_WORD_MASK, cpu->xar[7] & C55X_WORD_MASK,
                 cpu->t[2], cpu->t[0], cpu->t[3],
                 peek16(cpu, cpu->xsp & C55X_WORD_MASK),
                 peek16(cpu, (cpu->xsp + 1u) & C55X_WORD_MASK),
                 cpu->xsp & C55X_WORD_MASK,
                 (unsigned long long)cpu->insn_count);
        return;
    }
    if (pc == BIOS_PC_MUMDRC_COPY_ST) {
        uint32_t ar2 = cpu->xar[2] & C55X_WORD_MASK;
        uint32_t ar3 = cpu->xar[3] & C55X_WORD_MASK;
        uint32_t dest = (ar2 + 0x18u) & C55X_WORD_MASK;

        c55x_log(cpu,
                 "MUMDRC-COPY-ST XAR2=%06x XAR3=%06x dest=%06x "
                 "XSP=%06x insn=%llu\n",
                 ar2, ar3, dest, cpu->xsp & C55X_WORD_MASK,
                 (unsigned long long)cpu->insn_count);
        return;
    }
    if (pc == BIOS_PC_MUMDRC_QMF_SIZE) {
        uint32_t ar0 = cpu->xar[0] & C55X_WORD_MASK;
        uint32_t addr = (ar0 + 0x18u) & C55X_WORD_MASK;

        c55x_log(cpu,
                 "MUMDRC-QMF-SIZE AR0=%06x addr=%06x size=%04x "
                 "XSP=%06x RETA=%06x insn=%llu\n",
                 ar0, addr, peek16(cpu, addr),
                 cpu->xsp & C55X_WORD_MASK, cpu->reta & C55X_PC_MASK,
                 (unsigned long long)cpu->insn_count);
        return;
    }
    if (pc == BIOS_PC_EAP_COPYCH_ZERO) {
        uint32_t ar5 = cpu->xar[5] & C55X_WORD_MASK;
        uint32_t csr = cpu->csr;
        uint32_t len = csr + 1u;

        c55x_log(cpu,
                 "EAP-COPYCH-ZERO AR5=%06x CSR=%04x len=%u "
                 "AR2=%06x SP1=%04x RETA=%06x insn=%llu\n",
                 ar5, csr, len,
                 cpu->xar[2] & C55X_WORD_MASK,
                 peek16(cpu, (cpu->xsp + 1u) & C55X_WORD_MASK),
                 cpu->reta & C55X_PC_MASK,
                 (unsigned long long)cpu->insn_count);
        if (ar5 <= 0x636eu && ar5 + len > 0x636eu) {
            c55x_log(cpu,
                     "EAP-COPYCH-ZERO-SIO-OVERLAP AR5=%06x len=%u "
                     "covers 636e insn=%llu\n",
                     ar5, len, (unsigned long long)cpu->insn_count);
        }
        return;
    }
    if (pc == BIOS_PC_REQ_STREAM) {
        c55x_log(cpu,
                 "EAP-REQ enter T0=%04x T1=%04x AR0=%04x AR1=%04x AR2=%04x "
                 "caller=%06x insn=%llu\n",
                 cpu->t[0], cpu->t[1],
                 cpu->xar[0] & 0xffffu, cpu->xar[1] & 0xffffu,
                 cpu->xar[2] & 0xffffu, cpu->reta & C55X_PC_MASK,
                 (unsigned long long)cpu->insn_count);
        log_eap_id(cpu, "RequestStream.T0_arg", cpu->t[0]);
        log_eap_id(cpu, "RequestStream.AR1_arg",
                   (uint16_t)cpu->xar[1]);
        log_eap_name(cpu, BIOS_WORD_EAP_NAME_A, "req_enter_09cf4e");
        log_eap_name(cpu, BIOS_WORD_EAP_NAME_B, "req_enter_09ceca");
        log_eap_name(cpu, BIOS_WORD_EAP_NAME_C, "req_enter_09cf24");
        return;
    }
    if (pc == BIOS_PC_REQ_T2) {
        log_eap_id(cpu, "RequestStream.T2_from_requested_T0", cpu->t[0]);
        return;
    }
    if (pc == BIOS_PC_REQ_SCAN) {
        log_eap_id(cpu, "RequestStream.T2_from_scan", cpu->t[2]);
        return;
    }
    if (pc == BIOS_PC_REQ_FAIL) {
        log_eap_id(cpu, "RequestStream.fail_-1", 0xffffu);
        return;
    }
    if (pc == BIOS_PC_REQ_OK) {
        log_eap_id(cpu, "RequestStream.ok_T2", cpu->t[2]);
        return;
    }
    name = eap_name_pc(pc);
    if (name && (pc == BIOS_PC_NAME4_A || pc == BIOS_PC_NAME4_B ||
                 pc == BIOS_PC_NAME4_C)) {
        uint16_t id = (uint16_t)cpu->xar[1];

        c55x_log(cpu, "EAP-NAME-BUILD store name[4] base=%06x\n", name);
        log_eap_id(cpu, "name[4]_src_AR1", id);
        log_eap_id(cpu, "name[4]_09cf58", peek16(cpu, BIOS_WORD_EAP_ID_A));
        log_eap_name(cpu, name, "before_name4");
        return;
    }
    if (name) {
        c55x_log(cpu, "EAP-NAME-BUILD store name[5]=0 base=%06x\n", name);
        log_eap_name(cpu, name, "before_name5");
        return;
    }
    if (pc == BIOS_PC_DEV_MATCH) {
        uint32_t in = cpu->xar[0] & C55X_WORD_MASK;

        devm_in = in;
        devm_cand = 0;
        devm_step = 0;
        devm_on = devm_watch_input(in);
        c55x_log(cpu, "EAP-DEV-MATCH input=%06x watch=%u\n", in, devm_on);
        log_eap_name(cpu, in, "dev_match_input");
        if (devm_on) {
            log_dev_list(cpu);
        }
        return;
    }
    if (!devm_on) {
        /* fall through to remaining EAP hooks */
    } else if (pc == BIOS_PC_DEVM_CAND) {
        uint32_t dev = (uint32_t)cpu->ac[0] & C55X_WORD_MASK;

        log_dev_device(cpu, dev, devm_cand, "candidate");
        devm_step = 0;
        return;
    } else if (pc == BIOS_PC_DEVM_STRLEN) {
        uint32_t namereg = cpu->xar[4] & C55X_WORD_MASK;
        uint32_t nptr = peek_dbl(cpu, namereg) & C55X_WORD_MASK;

        c55x_log(cpu, "DEV-MATCH strlen T1=%04x name_ptr=%06x device+6=%06x\n",
                 cpu->t[1], nptr, namereg);
        return;
    } else if (pc == BIOS_PC_DEVM_HIT) {
        uint32_t rem = (cpu->xar[0] + cpu->t[1]) & C55X_WORD_MASK;
        uint32_t field = cpu->xar[4] & C55X_WORD_MASK;
        uint32_t dev = (field >= 6u) ? (field - 6u) : field;

        c55x_log(cpu,
                 "DEV-MATCH SELECT T1=%04x remainder=%06x *rem=%04x "
                 "XAR0=%06x XAR4=%06x rptb0=%u/%04x/%06x/%06x "
                 "rptb1=%u/%04x insn=%llu\n",
                 cpu->t[1], rem, peek16(cpu, rem),
                 cpu->xar[0] & C55X_WORD_MASK, field,
                 cpu->rptb0_active, cpu->brc0, cpu->rsa0, cpu->rea0,
                 cpu->rptb1_active, cpu->brc1,
                 (unsigned long long)cpu->insn_count);
        log_dev_device(cpu, dev, devm_cand, "SELECT");
        return;
    } else if (pc == BIOS_PC_DEVM_NEXT) {
        c55x_log(cpu, "DEV-MATCH next-after-mismatch #%u T3=%04x\n",
                 devm_cand, cpu->t[3]);
        devm_cand++;
        return;
    }
    if (pc == BIOS_PC_EAP_OPEN) {
        uint32_t rem = cpu->xar[1] & C55X_WORD_MASK;

        c55x_log(cpu, "EAP-OPEN XAR0=%06x XAR1=%06x *XAR1=%04x\n",
                 cpu->xar[0] & C55X_WORD_MASK, rem, peek16(cpu, rem));
        log_eap_id(cpu, "open.*XAR1", peek16(cpu, rem));
        log_eap_name(cpu, rem, "open_remainder");
        log_eap_name(cpu, BIOS_WORD_EAP_NAME_A, "open_09cf4e");
        return;
    }
    if (pc == BIOS_PC_EAP_OPEN_PARSE) {
        uint32_t rem = cpu->xar[6] & C55X_WORD_MASK;

        log_eap_id(cpu, "open_parse.*XAR6", peek16(cpu, rem));
        log_eap_name(cpu, rem, "open_parse_remainder");
        return;
    }
    if (pc == BIOS_PC_EAP_OPEN_FAIL) {
        log_eap_id(cpu, "open_fail.T2", cpu->t[2]);
        return;
    }
}

static void eap_note_after(C55xCPU *cpu, uint32_t pc)
{
    uint32_t name = eap_name_pc(pc);

    if (pc == BIOS_PC_REQ_RET) {
        log_eap_id(cpu, "RequestStream.return_T0", cpu->t[0]);
        return;
    }
    if (devm_on && pc == BIOS_PC_DEVM_SUB) {
        uint16_t t2 = cpu->t[2];
        uint16_t t3 = cpu->t[3];
        uint32_t ar2 = cpu->xar[2] & C55X_WORD_MASK;
        uint32_t ar3 = cpu->xar[3] & C55X_WORD_MASK;

        c55x_log(cpu,
                 "DEV-MATCH cmp #%u step=%u T2=%04x '%c' *AR2=%04x "
                 "T3=%04x *AR3=%04x '%c' XAR2=%06x XAR3=%06x "
                 "equal=%u insn=%llu\n",
                 devm_cand, devm_step, t2, eap_ascii(t2), peek16(cpu, ar2),
                 t3, peek16(cpu, ar3), eap_ascii(peek16(cpu, ar3)),
                 ar2, ar3, t3 == 0,
                 (unsigned long long)cpu->insn_count);
        devm_step++;
        return;
    }
    if (devm_on && pc == BIOS_PC_DEVM_MIS) {
        int taken = (cpu->pc == 0x101e76u);

        c55x_log(cpu,
                 "DEV-MATCH mismatch-bcc #%u step=%u T3=%04x taken=%u "
                 "next=%06x TC1=%u ST0=%04x insn=%llu\n",
                 devm_cand, devm_step, cpu->t[3], taken,
                 cpu->pc & C55X_PC_MASK, !!(cpu->st0 & C55X_ST0_TC1),
                 cpu->st0, (unsigned long long)cpu->insn_count);
        return;
    }
    if (pc == BIOS_PC_DEV_MATCH_RET) {
        uint32_t rem = cpu->xar[0] & C55X_WORD_MASK;

        c55x_log(cpu, "EAP-DEV-MATCH remainder=%06x *rem=%04x watch=%u\n",
                 rem, peek16(cpu, rem), devm_on);
        log_eap_id(cpu, "DEV_match.remainder_word0", peek16(cpu, rem));
        log_eap_name(cpu, rem, "dev_match_remainder");
        devm_on = 0;
        return;
    }
    if (name && (pc == BIOS_PC_NAME4_A || pc == BIOS_PC_NAME4_B ||
                 pc == BIOS_PC_NAME4_C)) {
        log_eap_name(cpu, name, "after_name4");
        return;
    }
    if (name) {
        log_eap_name(cpu, name, "after_name5");
    }
}

static void sort_log_words(C55xCPU *cpu, uint32_t base, unsigned n,
                             const char *tag)
{
    char buf[192];
    unsigned i, pos = 0;

    buf[0] = 0;
    for (i = 0; i < n && i < 24u; i++) {
        uint16_t w = peek16_ram(cpu, xar_plus(base, (int32_t)i));
        int wr = snprintf(buf + pos, sizeof(buf) - pos, "%s%04x",
                          i ? " " : "", w);

        if (wr < 0 || (unsigned)wr >= sizeof(buf) - pos) {
            break;
        }
        pos += (unsigned)wr;
        if (w == 0x00ffu) {
            break;
        }
    }
    c55x_log(cpu, "SORTNET %s base=%06x %s\n", tag, base & C55X_WORD_MASK,
             buf);
}

/*
 * Third _EAP_sortNetwork call never returns: T1 stays 0 while
 * CMPU AR2 < AR3 at 127fac skips the increment. Dump the XAR0 list
 * at entry and SP(#52)–SP(#56) at the loop head.
 */
static void sort_note(C55xCPU *cpu, uint32_t pc)
{
    static unsigned calls;
    static unsigned hits;
    uint32_t sp = cpu->xsp & C55X_WORD_MASK;
    uint32_t xar0 = cpu->xar[0] & C55X_WORD_MASK;

    if (pc == BIOS_PC_EAP_SORT) {
        calls++;
        hits = 0;
        if (calls > 6u) {
            return;
        }
        c55x_log(cpu,
                 "SORTNET enter n=%u XAR0=%06x T0=%04x T1=%04x "
                 "XSP=%06x RETA=%06x AC3=%010llx CPL=%u insn=%llu\n",
                 calls, xar0, cpu->t[0], cpu->t[1], sp,
                 cpu->reta & C55X_PC_MASK,
                 (unsigned long long)(cpu->ac[3] & C55X_AC_MASK),
                 !!(cpu->st1 & C55X_ST1_CPL),
                 (unsigned long long)cpu->insn_count);
        sort_log_words(cpu, xar0, 24u, "xar0");
        return;
    }
    if (pc != BIOS_PC_EAP_SORT_LOOP || calls == 0 || calls > 6u) {
        return;
    }
    hits++;
    if (hits != 1u && hits != 2u && hits != 4096u) {
        return;
    }
    {
        uint16_t s52 = peek16_ram(cpu, xar_plus(sp, 0x52));
        uint16_t s53 = peek16_ram(cpu, xar_plus(sp, 0x53));
        uint16_t s54 = peek16_ram(cpu, xar_plus(sp, 0x54));
        uint16_t s55 = peek16_ram(cpu, xar_plus(sp, 0x55));
        uint16_t s56 = peek16_ram(cpu, xar_plus(sp, 0x56));
        uint16_t s4f = peek16_ram(cpu, xar_plus(sp, 0x4f));

        c55x_log(cpu,
                 "SORTNET loop n=%u hit=%u T1=%04x T2=%04x AR2=%04x "
                 "AR3=%04x SP4f=%04x SP52=%04x SP53=%04x SP54=%04x "
                 "SP55=%04x SP56=%04x TC1=%u "
                 "inner_skip=%u outer_stay=%u XSP=%06x AC3=%010llx "
                 "insn=%llu\n",
                 calls, hits, cpu->t[1], cpu->t[2],
                 (uint16_t)cpu->xar[2], (uint16_t)cpu->xar[3],
                 s4f, s52, s53, s54, s55, s56,
                 !!(cpu->st0 & C55X_ST0_TC1),
                 s54 < s55, cpu->t[1] < s53, sp,
                 (unsigned long long)(cpu->ac[3] & C55X_AC_MASK),
                 (unsigned long long)cpu->insn_count);
        if (hits == 1u) {
            sort_log_words(cpu, xar0, 24u, "xar0");
            sort_log_words(cpu, sp, 24u, "sp0");
        }
    }
}

static void bios_note_before(C55xCPU *cpu, uint32_t pc)
{
    int gated = (pc == BIOS_PC_KNL_SWITCH || pc == BIOS_PC_KNL_RUN ||
                 pc == BIOS_PC_BALANCE);

    sort_note(cpu, pc);
    knlq_note_before(cpu);
    eap_note_before(cpu, pc);
    poll_note_before(cpu, pc);
    poll_chain(cpu, pc);
    eapq_note_api(cpu, pc);
    eapiss_note_pc(cpu, pc);
    if (bios_pc_always(pc)) {
        bios_log(cpu, pc, "enter", pc);
        if (pc == BIOS_PC_SLEEP_DSP || pc == BIOS_PC_ISSUE_IDLE) {
            c55x_l2intc_log_state(cpu, pc == BIOS_PC_SLEEP_DSP ?
                                  "before-sleep" : "at-idle");
        }
        if (pc == BIOS_PC_SIO_CREATE) {
            c55x_log(cpu,
                     "DEV-SIO-CREATE name=%06x attrs=%06x T0=%04x T1=%04x "
                     "name0=%04x %04x %04x %04x %04x %04x %04x %04x "
                     "req=%04x insn=%llu\n",
                     cpu->xar[0] & C55X_WORD_MASK,
                     cpu->xar[1] & C55X_WORD_MASK, cpu->t[0], cpu->t[1],
                     peek16(cpu, cpu->xar[0]),
                     peek16(cpu, (cpu->xar[0] + 1u) & C55X_WORD_MASK),
                     peek16(cpu, (cpu->xar[0] + 2u) & C55X_WORD_MASK),
                     peek16(cpu, (cpu->xar[0] + 3u) & C55X_WORD_MASK),
                     peek16(cpu, (cpu->xar[0] + 4u) & C55X_WORD_MASK),
                     peek16(cpu, (cpu->xar[0] + 5u) & C55X_WORD_MASK),
                     peek16(cpu, (cpu->xar[0] + 6u) & C55X_WORD_MASK),
                     peek16(cpu, (cpu->xar[0] + 7u) & C55X_WORD_MASK),
                     peek16(cpu, 0x09cf58u),
                     (unsigned long long)cpu->insn_count);
        }
        if (pc == BIOS_PC_SIO_FXNS_COPY) {
            uint32_t sio = cpu->xar[5] & C55X_WORD_MASK;
            uint32_t src = cpu->xar[3] & C55X_WORD_MASK;

            dev_watch_add(cpu, sio);
            c55x_log(cpu,
                     "DEV-FXNS-SRC sio=%06x src_table=%06x "
                     "close=%06x ctrl=%06x idle=%06x issue=%06x "
                     "open=%06x ready=%06x reclaim=%06x insn=%llu\n",
                     sio, src,
                     peek_dbl(cpu, src + 0x00u) & C55X_PC_MASK,
                     peek_dbl(cpu, src + 0x02u) & C55X_PC_MASK,
                     peek_dbl(cpu, src + 0x04u) & C55X_PC_MASK,
                     peek_dbl(cpu, src + 0x06u) & C55X_PC_MASK,
                     peek_dbl(cpu, src + 0x08u) & C55X_PC_MASK,
                     peek_dbl(cpu, src + 0x0au) & C55X_PC_MASK,
                     peek_dbl(cpu, src + 0x0cu) & C55X_PC_MASK,
                     (unsigned long long)cpu->insn_count);
            log_idle_code(cpu, peek_dbl(cpu, src + 0x04u) & C55X_PC_MASK,
                          "src_table_idle");
        }
        if (pc == BIOS_PC_SIO_FXNS_OPEN) {
            uint32_t sio = cpu->xar[5] & C55X_WORD_MASK;

            dev_watch_add(cpu, sio);
            log_dev_fxns(cpu, sio, "create/open");
        }
        if (pc == BIOS_PC_TCFG_REPLY || pc == BIOS_PC_TCFG_DISP) {
            uint32_t sio = sio_eap_handle(cpu);

            dev_watch_add(cpu, sio);
            log_dev_fxns(cpu, sio, "after_TCFG");
        }
        if (pc == BIOS_PC_REMOVE_STREAM) {
            uint32_t sio = sio_eap_handle(cpu);

            dev_watch_add(cpu, sio);
            log_dev_fxns(cpu, sio, "pre_RemoveStream");
        }
        if (pc == BIOS_PC_SIO_DELETE) {
            uint32_t sio = cpu->xar[0] & C55X_WORD_MASK;

            dev_watch_add(cpu, sio);
            log_dev_fxns(cpu, sio, "pre_SIO_delete");
            if (!sio) {
                c55x_log(cpu,
                         "DEV-SIO-DELETE-NULL XAR5=%06x "
                         "word12=%04x word13=%04x dbl12=%06x "
                         "eap_handle=%06x RETA=%06x insn=%llu\n",
                         cpu->xar[5] & C55X_WORD_MASK,
                         peek16(cpu, 0x12u), peek16(cpu, 0x13u),
                         peek_dbl(cpu, 0x12u) & C55X_PC_MASK,
                         sio_eap_handle(cpu),
                         cpu->reta & C55X_PC_MASK,
                         (unsigned long long)cpu->insn_count);
            }
        }
        return;
    }
    if ((pc == BIOS_PC_SEM_POST || pc == BIOS_PC_SEM_PEND) && bios_watch) {
        bios_log(cpu, pc, "enter", pc);
        return;
    }
    if (gated && bios_watch) {
        bios_watch--;
        bios_log(cpu, pc, "enter", pc);
    }
}

static void bios_note_after(C55xCPU *cpu, uint32_t pc, uint32_t next_pc)
{
    knlq_note_after(cpu, pc, next_pc);
    eap_note_after(cpu, pc);
    poll_note_after(cpu, pc, next_pc);
    eapiss_note_after(cpu, pc, next_pc);
    if (pc == BIOS_PC_HWI_NEST_BCC || pc == BIOS_PC_HWI_READY_BCC ||
        pc == BIOS_PC_HWI_SWI_CALL || pc == BIOS_PC_HWI_ISR_CALL ||
        pc == BIOS_PC_HWI_RETI || pc == BIOS_PC_MBX_SEQ_BCC ||
        pc == BIOS_PC_MBX_NULL_BCC || pc == BIOS_PC_MBX_CALL ||
        pc == BIOS_PC_MBX_SFTL) {
        bios_log(cpu, pc, (next_pc == pc) ? "stay" : "leave", next_pc);
    }
    if (pc == BIOS_PC_MBQ_TIDGE || pc == BIOS_PC_MBQ_NULLB ||
        pc == BIOS_PC_MBQ_STAT || pc == BIOS_PC_MBQ_FULL ||
        pc == BIOS_PC_MBQ_WRAP || pc == BIOS_PC_MBQ_OVF) {
        uint32_t sp = cpu->xsp & C55X_WORD_MASK;
        uint16_t tid = peek16_ram(cpu, sp + 8u);
        uint32_t task = (((uint32_t)peek16_ram(cpu, sp + 2u) << 16) |
                         peek16_ram(cpu, sp + 3u));
        uint32_t cmd = (((uint32_t)peek16_ram(cpu, sp) << 16) |
                        peek16_ram(cpu, sp + 1u));
        int taken = (next_pc != ((pc + 3u) & C55X_PC_MASK));
        const char *why = "?";

        if (pc == BIOS_PC_MBQ_TIDGE) {
            taken = (next_pc == 0x1297f5u);
            why = taken ? "tid>=32 →16" : "tid ok";
        } else if (pc == BIOS_PC_MBQ_NULLB) {
            taken = (next_pc == 0x1297fcu);
            why = taken ? "task!=0" : "task==0 →16";
        } else if (pc == BIOS_PC_MBQ_STAT) {
            taken = !!(cpu->st0 & C55X_ST0_TC1);
            why = taken ? "*task(#0xc)==2" : "*task(#0xc)!=2";
        } else if (pc == BIOS_PC_MBQ_FULL) {
            taken = (next_pc == 0x12989du);
            why = taken ? "already-full →225" : "not full";
        } else if (pc == BIOS_PC_MBQ_WRAP) {
            taken = (next_pc == 0x129886u);
            why = taken ? "wr'!=rd enqueue" : "wr'==rd →225";
        } else if (pc == BIOS_PC_MBQ_OVF) {
            taken = 1;
            why = "ring overflow →225";
        }
        c55x_log(cpu,
                 "MBQ-BCC pc=%06x next=%06x taken=%u %s tid=%u "
                 "AR1=%04x AR2=%04x AR3=%06x AC0=%010llx +0c=%04x "
                 "wr=%04x rd=%04x T0=%04x TC1=%u insn=%llu\n",
                 pc, next_pc, taken, why, tid,
                 cpu->xar[1] & 0xffffu, cpu->xar[2] & 0xffffu,
                 cpu->xar[3] & C55X_WORD_MASK,
                 (unsigned long long)(cpu->ac[0] & C55X_AC_MASK),
                 peek_word_safe(task) ? peek16_ram(cpu, task + 12u) : 0,
                 peek_word_safe(task) ? peek16_ram(cpu, task + 16u) : 0,
                 peek_word_safe(task) ? peek16_ram(cpu, task + 17u) : 0,
                 cpu->t[0], !!(cpu->st0 & C55X_ST0_TC1),
                 (unsigned long long)cpu->insn_count);
        log_mbq_task(cpu, tid, task ? task : mbq_task_of(cpu, tid), cmd,
                     why);
    }
    if (pc == BIOS_PC_POLL_BTST0 || pc == BIOS_PC_POLL_BTST1 ||
        pc == BIOS_PC_POLL_LAST) {
        int taken = 0;
        const char *why = "?";

        if (pc == BIOS_PC_POLL_BTST0) {
            taken = (next_pc == 0x131c42u);
            why = taken ? "BTST tid skip bit0" : "clear bit0 / cnt0--";
        } else if (pc == BIOS_PC_POLL_BTST1) {
            taken = (next_pc == 0x131c8cu);
            why = taken ? "BTST T1 skip bit1" : "clear bit1 / cnt1--";
        } else {
            taken = (next_pc == 0x131c8cu);
            why = taken ? "cnt1!=0 skip send" : "cnt1==0 POLL_send";
        }
        c55x_log(cpu,
                 "POLL-BCC pc=%06x next=%06x taken=%u %s\n",
                 pc, next_pc, taken, why);
        log_poll_state(cpu, why);
    }
}

static void mem_init_dump_state(C55xCPU *cpu, const char *why)
{
    uint16_t fl_hi = peek16(cpu, 0x80296u);
    uint16_t fl_lo = peek16(cpu, 0x80297u);
    uint32_t fl = ((uint32_t)fl_hi << 16) | fl_lo;

    c55x_log(cpu,
             "MEM-init %s freelist=%06x "
             "DARAM@a30=%04x %04x %04x %04x "
             "SARAM@800c=%04x %04x %04x %04x XAR3=%06x\n",
             why, fl,
             peek16(cpu, 0x00000a30u), peek16(cpu, 0x00000a31u),
             peek16(cpu, 0x00000a32u), peek16(cpu, 0x00000a33u),
             peek16(cpu, 0x0000800cu), peek16(cpu, 0x0000800du),
             peek16(cpu, 0x0000800eu), peek16(cpu, 0x0000800fu),
             cpu->xar[3] & C55X_WORD_MASK);
}

static int insn_writes_st2(const C55xDecodedInsn *in)
{
    unsigned i;

    for (i = 0; i < in->op_count; i++) {
        const C55xOp *op = &in->op[i];

        if ((op->kind == C55X_OP_BSET_ST ||
             op->kind == C55X_OP_BCLR_ST) && op->st == 2) {
            return 1;
        }
        if (in->mmap && op->smem.kind == C55X_AM_DIRECT &&
            op->smem.off == C55X_MMR_ST2) {
            switch (op->kind) {
            case C55X_OP_MOV_K8_SMEM:
            case C55X_OP_MOV_K16_SMEM:
            case C55X_OP_MOV_SRC_SMEM:
            case C55X_OP_AND_K16_SMEM:
            case C55X_OP_OR_K16_SMEM:
            case C55X_OP_XOR_K16_SMEM:
            case C55X_OP_ADD_K16_SMEM:
                return 1;
            default:
                break;
            }
        }
    }
    return 0;
}

static unsigned archhash_period(void)
{
    static int env = -1;
    static unsigned period;

    if (env < 0) {
        const char *e = getenv("C55X_ARCHHASH_PERIOD");

        env = 1;
        period = 0;
        if (e && e[0]) {
            period = (unsigned)strtoul(e, NULL, 0);
        }
    }
    return period;
}

static uint64_t archhash_mix(uint64_t h, uint64_t v)
{
    h ^= v;
    h *= 1099511628211ull;
    return h;
}

static void c55x_archhash(C55xCPU *cpu)
{
    unsigned period = archhash_period();
    uint64_t h = 14695981039346656037ull;
    unsigned i;
    uint32_t f140;

    if (period == 0 || cpu->insn_count == 0 ||
        (cpu->insn_count % period) != 0) {
        return;
    }
    h = archhash_mix(h, cpu->pc);
    h = archhash_mix(h, cpu->reta);
    h = archhash_mix(h, cpu->cfct);
    h = archhash_mix(h, cpu->st0);
    h = archhash_mix(h, cpu->st1);
    h = archhash_mix(h, cpu->st2);
    h = archhash_mix(h, cpu->st3);
    h = archhash_mix(h, ((uint64_t)cpu->rpt_armed << 16) |
                      ((uint64_t)cpu->rpt_active << 8) | cpu->rpt_cc);
    h = archhash_mix(h, cpu->rpt_left);
    h = archhash_mix(h, cpu->brc0);
    h = archhash_mix(h, cpu->brc1);
    for (i = 0; i < 8; i++) {
        h = archhash_mix(h, cpu->xar[i]);
    }
    for (i = 0; i < 4; i++) {
        h = archhash_mix(h, cpu->ac[i]);
        h = archhash_mix(h, cpu->t[i]);
    }
    h = archhash_mix(h, peek_dbl_ram(cpu, BIOS_WORD_KNL_CURTASK));
    f140 = peek16_ram(cpu, BIOS_WORD_EAP_F140);
    h = archhash_mix(h, f140);
    h = archhash_mix(h, peek16_ram(cpu, BIOS_WORD_EAP_F140 + 1u));
    h = archhash_mix(h, cpu->ier0);
    h = archhash_mix(h, cpu->ifr0);
    h = archhash_mix(h, cpu->irq_nest);
    h = archhash_mix(h, cpu->last_irq_bit);
    h = archhash_mix(h, cpu->audio_isr_n);
    c55x_log(cpu,
             "ARCHHASH n=%llu h=%016llx pc=%06x reta=%06x cfct=%02x "
             "st0=%04x st1=%04x st2=%04x rpt=%u/%u/%u cur=%06x "
             "f140=%04x irq=%u audio=%u\n",
             (unsigned long long)cpu->insn_count,
             (unsigned long long)h,
             cpu->pc & C55X_PC_MASK, cpu->reta & C55X_PC_MASK,
             cpu->cfct & 0xff, cpu->st0, cpu->st1, cpu->st2,
             cpu->rpt_armed, cpu->rpt_active, cpu->rpt_cc,
             peek_dbl_ram(cpu, BIOS_WORD_KNL_CURTASK) & C55X_WORD_MASK,
             f140, cpu->last_irq_bit, cpu->audio_isr_n);
}

int c55x_step(C55xCPU *cpu)
{
    C55xDecodedInsn in;
    uint32_t next;
    uint32_t insn_pc;
    unsigned i, pass;
    int rptc_rewound = 0;
    int delay_fired = 0;
    C55xRptbLast rptb_last;
    uint16_t st2_before;

    if (cpu->halt == C55X_HALT_UNDEF || cpu->halt == C55X_HALT_RESET ||
        cpu->halt == C55X_HALT_MEM) {
        return cpu->halt;
    }
    if (cpu->halt == C55X_HALT_IDLE) {
        /*
         * SPRU371F: IDLE exits when an enabled IFR bit is set, even
         * if INTM=1. Vectoring still waits for INTM=0. tokliBIOS
         * `_sleep_dsp` / `_issue_idle` idles under HWI_disable so
         * TCFG can wake the core without taking INT5 until restore.
         */
        if (!irq_pending(cpu)) {
            return C55X_HALT_IDLE;
        }
        cpu->halt = C55X_OK;
        c55x_log(cpu,
                 "IDLE-wake pc=%06x IER0=%04x IFR0=%04x IER1=%04x IFR1=%04x "
                 "INTM=%u insn=%llu\n",
                 cpu->pc & C55X_PC_MASK, cpu->ier0, cpu->ifr0,
                 cpu->ier1, cpu->ifr1, !!(cpu->st1 & C55X_ST1_INTM),
                 (unsigned long long)cpu->insn_count);
        c55x_l2intc_log_state(cpu, "after-idle");
    }
    accept_irq(cpu);
    insn_pc = cpu->pc;
    if (c55x_decode(cpu, insn_pc, &in) || in.undef) {
        if (!cpu->mem_init_logged &&
            insn_pc >= 0x103340u && insn_pc < 0x1036b8u) {
            cpu->mem_init_logged = 1;
            mem_init_dump_state(cpu, "MEM-init-halt");
        }
        set_undef(cpu, &in);
        return C55X_HALT_UNDEF;
    }
    c55x_history_add(cpu, &in);
    st2_before = cpu->st2;
    bios_note_before(cpu, insn_pc);
    if (knlq_take_skip(cpu)) {
        cpu->pc = return_taken(cpu, "RET", 0);
        cpu->insn_count++;
        return C55X_OK;
    }
    if (insn_pc == 0x100e59u || insn_pc == 0x100e66u ||
        insn_pc == 0x1298feu || insn_pc == 0x129904u ||
        insn_pc == 0x1299f4u) {
        c55x_log(cpu,
                 "MEM-alloc-trace pc=%06x T0=%04x T1=%04x AR0=%04x "
                 "XAR0=%06x XAR1=%06x XAR3=%06x AC0=%010llx IER0=%04x\n",
                 insn_pc, cpu->t[0], cpu->t[1],
                 (uint16_t)cpu->xar[0],
                 cpu->xar[0] & C55X_WORD_MASK,
                 cpu->xar[1] & C55X_WORD_MASK,
                 cpu->xar[3] & C55X_WORD_MASK,
                 (unsigned long long)(cpu->ac[0] & C55X_AC_MASK),
                 cpu->ier0);
    }
    if (insn_pc == 0x103340u) {
        c55x_log(cpu, "MEM-init entry ST2=%04x ARMS=%u C54CM=%u\n",
                 cpu->st2, !!(cpu->st2 & C55X_ST2_ARMS),
                 !!(cpu->st1 & C55X_ST1_C54CM));
    }
    next = (insn_pc + in.length) & C55X_PC_MASK;
    rptb_last = rptb_begin_last(cpu, insn_pc);
    {
        int cond_true = 1;
        int xcc_part = 0;
        int have_xcc = 0;

        if (cpu->xcc_pending) {
            have_xcc = 1;
            xcc_part = (cpu->xcc_pending == 2);
            cond_true = cpu->xcc_cond_true;
            cpu->xcc_pending = 0;
        } else {
            /*
             * In a decoded parallel packet XCC/XCCPART qualifies its peer
             * operation regardless of whether the condition opcode appears
             * first or second in the byte stream.  Only an unpaired XCC
             * carries forward to the next decoded instruction.
             */
            for (i = 0; i < in.op_count; i++) {
                const C55xOp *op = &in.op[i];

                if (op->kind != C55X_OP_XCC &&
                    op->kind != C55X_OP_XCCPART) {
                    continue;
                }
                have_xcc = 1;
                xcc_part = (op->kind == C55X_OP_XCCPART);
                cond_true = c55x_eval_cond(cpu, op->cond);
                if (in.op_count == 1) {
                    cpu->xcc_pending = xcc_part ? 2 : 1;
                    cpu->xcc_cond_true = (uint8_t)cond_true;
                }
                break;
            }
        }
        pkt_begin(cpu, in.op_count > 1);
        for (pass = 0; pass < 2; pass++) {
        for (i = 0; i < in.op_count; i++) {
            const C55xOp *op = &in.op[i];
            int rc;
            int xar_store = (op->kind == C55X_OP_MOV_XREG_DBL);

            if (op->kind == C55X_OP_XCC || op->kind == C55X_OP_XCCPART) {
                continue;
            }
            if (xar_store != (pass == 1)) {
                continue;
            }
            if (have_xcc && !cond_true && !xcc_part) {
                continue;
            }
            if (have_xcc && !cond_true && xcc_part) {
                rc = exec_address_only(cpu, &in, op);
            } else {
                rc = exec_op(cpu, &in, op, &next);
            }
            if (rc) {
                pkt_abort(cpu);
                xar3_note(cpu, insn_pc, &in);
                ac0_note(cpu, insn_pc, &in);
                if (!cpu->mem_init_logged &&
                    insn_pc >= 0x103340u && insn_pc < 0x1036b8u) {
                    cpu->mem_init_logged = 1;
                    mem_init_dump_state(cpu, "MEM-init-halt");
                }
                set_undef(cpu, &in);
                return C55X_HALT_UNDEF;
            }
            if (cpu->halt == C55X_HALT_UNDEF) {
                pkt_abort(cpu);
                xar3_note(cpu, insn_pc, &in);
                ac0_note(cpu, insn_pc, &in);
                if (!cpu->mem_init_logged &&
                    insn_pc >= 0x103340u && insn_pc < 0x1036b8u) {
                    cpu->mem_init_logged = 1;
                    mem_init_dump_state(cpu, "MEM-init-halt");
                }
                return C55X_HALT_UNDEF;
            }
        }
        }
        if (pkt_commit(cpu)) {
            xar3_note(cpu, insn_pc, &in);
            ac0_note(cpu, insn_pc, &in);
            set_undef(cpu, &in);
            return C55X_HALT_UNDEF;
        }
    }
    if (insn_writes_st2(&in)) {
        char dis[128];

        c55x_disasm(&in, dis, sizeof(dis));
        c55x_log(cpu,
                 "ST2-WRITE pc=%06x raw=%02x %02x %02x %02x %02x %s "
                 "old=%04x new=%04x ARMS=%u->%u\n",
                 insn_pc, in.bytes[0], in.bytes[1], in.bytes[2],
                 in.bytes[3], in.bytes[4], dis, st2_before, cpu->st2,
                 !!(st2_before & C55X_ST2_ARMS),
                 !!(cpu->st2 & C55X_ST2_ARMS));
    }
    cpu->pc = next;
    cpu->insn_count++;
    c55x_archhash(cpu);
    if (cpu->br_delay_fire) {
        uint32_t dest = cpu->br_delay_target & C55X_PC_MASK;

        cpu->pc = dest;
        cpu->br_delay_fire = 0;
        cpu->br_delay_pending = 0;
        delay_fired = 1;
        if (cpu->flow_verbose || pc_is_wild(dest)) {
            c55x_log(cpu,
                     "DELAY-FIRE from=%06x dest=%06x RETA=%06x CFCT=%02x "
                     "insn=%llu\n",
                     insn_pc, dest, cpu->reta & C55X_PC_MASK,
                     cpu->cfct & 0xff, (unsigned long long)cpu->insn_count);
        }
    } else if (cpu->br_delay_pending) {
        cpu->br_delay_fire = 1;
        cpu->br_delay_pending = 0;
    }
    /*
     * SPRU374: RPT repeats the next instruction or the next paralleled
     * pair. A packet that contains RPT (including AMAR || RPT) is the
     * setup, not the body. Checking only op[0] rewound stock
     * `b445_4da7` at 0x130016 and re-armed RPTC forever.
     */
    {
        unsigned oi;
        int rpt_setup = 0;

        for (oi = 0; oi < in.op_count; oi++) {
            C55xOpKind k = in.op[oi].kind;

            if (k == C55X_OP_RPT_K8 || k == C55X_OP_RPT_K16 ||
                k == C55X_OP_RPT_CSR || k == C55X_OP_RPTCC ||
                k == C55X_OP_RPTADD || k == C55X_OP_RPTSUB) {
                rpt_setup = 1;
                break;
            }
        }
        if (insn_is_ctrlflow(&in)) {
            /*
             * SPRU374: CALL/RET/B/IRQ vectoring are not RPT bodies.
             * Rewinding a RET would pop the next FAST16 frame and jump
             * to the stacked previous RETA (the 0x01f411 shape). A
             * CFCT restore on RET applies to the target, not the RET.
             */
        } else if (rpt_setup) {
            /* keep rpt_armed for the following packet */
        } else if (in.nonrepeatable) {
            cpu->rpt_armed = 0;
            cpu->rpt_active = 0;
        } else {
            if (cpu->rpt_armed) {
                cpu->rpt_armed = 0;
                cpu->rpt_active = 1;
            }
            if (cpu->rpt_active) {
                if (cpu->rpt_left) {
                    cpu->rpt_left--;
                    cpu->rptc = cpu->rpt_left;
                    cpu->pc = (cpu->pc - in.length) & C55X_PC_MASK;
                    rptc_rewound = 1;
                } else {
                    cpu->rpt_active = 0;
                    /* Drop stale CFCT RPT bits so a later FAST16 RET
                     * cannot re-arm a finished single-repeat. */
                    cpu->cfct = (uint16_t)(cpu->cfct &
                                (uint16_t)~(C55X_CFCT_RPT | C55X_CFCT_RPTCC));
                }
            }
        }
    }
    if (!rptc_rewound) {
        uint32_t seq = (insn_pc + in.length) & C55X_PC_MASK;
        int taken_branch = insn_is_branch(&in) && cpu->pc != seq &&
                           !delay_fired;

        if (taken_branch) {
            rptb_escape(cpu, insn_pc, cpu->pc);
        } else {
            rptb_finish_last(cpu, insn_pc, rptb_last);
        }
    }
    xar3_note(cpu, insn_pc, &in);
    ac0_note(cpu, insn_pc, &in);
    if (pc_in_avs_text(insn_pc) && pc_is_wild(cpu->pc) &&
        !cpu->flow_escape_logged) {
        cpu->flow_escape_logged = 1;
        cpu->flow_verbose = 1;
        c55x_log(cpu,
                 "FLOW-ESCAPE from=%06x to=%06x RETA=%06x CFCT=%02x "
                 "XSP=%06x XSSP=%06x SP[top]=%04x SSP[top]=%04x "
                 "rpt=%u/%u/%u left=%u INTM=%u nest=%u "
                 "delay=%u/%06x insn=%llu\n",
                 insn_pc, cpu->pc & C55X_PC_MASK,
                 cpu->reta & C55X_PC_MASK, cpu->cfct & 0xff,
                 cpu->xsp & C55X_WORD_MASK, cpu->xssp & C55X_WORD_MASK,
                 peek16(cpu, cpu->xsp), peek16(cpu, cpu->xssp),
                 cpu->rpt_armed, cpu->rpt_active, cpu->rpt_cc,
                 cpu->rpt_left, !!(cpu->st1 & C55X_ST1_INTM),
                 cpu->irq_nest, cpu->br_delay_pending,
                 cpu->br_delay_target & C55X_PC_MASK,
                 (unsigned long long)cpu->insn_count);
    }
    bios_note_after(cpu, insn_pc, cpu->pc);
    if (eapq_flow) {
        unsigned iop;
        int is_bcc = 0;

        for (iop = 0; iop < in.op_count; iop++) {
            switch (in.op[iop].kind) {
            case C55X_OP_BCC_L8:
            case C55X_OP_BCC_L16:
            case C55X_OP_BCC_P24:
            case C55X_OP_BCC_SRC_K8:
            case C55X_OP_BCC_ARN:
                is_bcc = 1;
                break;
            default:
                break;
            }
        }
        if (is_bcc) {
            eapq_note_bcc(cpu, insn_pc, cpu->pc,
                          cpu->pc != ((insn_pc + in.length) & C55X_PC_MASK));
        }
    }
    if (insn_pc >= 0x1033f6u && insn_pc <= 0x103445u) {
        char dis[96];
        unsigned iop;

        c55x_disasm(&in, dis, sizeof(dis));
        for (iop = 0; iop < in.op_count; iop++) {
            const C55xOp *op = &in.op[iop];

            if (op->kind == C55X_OP_CMP || op->kind == C55X_OP_CMPAND ||
                op->kind == C55X_OP_CMPOR) {
                c55x_log(cpu,
                         "MEM-split pc=%06x %s AC0=%010llx AC1=%010llx "
                         "AC2=%010llx AC3=%010llx uns=%u cc=%u TC1=%u "
                         "XAR2=%06x XAR3=%06x T1=%04x\n",
                         insn_pc, dis,
                         (unsigned long long)(cpu->ac[0] & C55X_AC_MASK),
                         (unsigned long long)(cpu->ac[1] & C55X_AC_MASK),
                         (unsigned long long)(cpu->ac[2] & C55X_AC_MASK),
                         (unsigned long long)(cpu->ac[3] & C55X_AC_MASK),
                         op->st, op->cond,
                         !!(cpu->st0 & C55X_ST0_TC1),
                         cpu->xar[2] & C55X_WORD_MASK,
                         cpu->xar[3] & C55X_WORD_MASK, cpu->t[1]);
            } else if (op->kind == C55X_OP_BCC_L8 ||
                       op->kind == C55X_OP_BCC_L16) {
                c55x_log(cpu,
                         "MEM-split pc=%06x %s taken=%u next=%06x "
                         "TC1=%u XAR2=%06x\n",
                         insn_pc, dis, cpu->pc !=
                         ((insn_pc + in.length) & C55X_PC_MASK),
                         cpu->pc, !!(cpu->st0 & C55X_ST0_TC1),
                         cpu->xar[2] & C55X_WORD_MASK);
            } else if (op->kind == C55X_OP_MOV_AC_DBL &&
                       op->smem.mod == C55X_MOD_MINUS_T1) {
                c55x_log(cpu,
                         "MEM-split store pc=%06x %s word=%06x AC0=%010llx "
                         "in-heap=%s\n",
                         insn_pc, dis, cpu->lmem_word,
                         (unsigned long long)(cpu->ac[op->src & 3] &
                                              C55X_AC_MASK),
                         (cpu->lmem_word < 0x20000u) ? "yes" : "NO");
            }
        }
    }
    if (insn_pc == 0x1033d4u) {
        mem_init_dump_state(cpu, "RPTB-end");
    }
    if (insn_pc == 0x103409u && cpu->pc == 0x103448u) {
        mem_init_dump_state(cpu, "BCC-L60");
    }
    /*
     * _MEM_init starts at 0x103340. The reset vector 0x1036b8 is later
     * in .sysinit and must not look like a leave from this function.
     */
    if (!cpu->mem_init_logged &&
        insn_pc >= 0x103340u && insn_pc < 0x1036b8u &&
        (cpu->pc < 0x103340u || cpu->pc >= 0x1036b8u)) {
        cpu->mem_init_logged = 1;
        mem_init_dump_state(cpu, "MEM-init-leave");
    }
    return cpu->halt;
}

int c55x_run(C55xCPU *cpu, uint32_t max_insns)
{
    uint32_t i;
    int rc = C55X_OK;

    for (i = 0; i < max_insns; i++) {
        rc = c55x_step(cpu);
        /*
         * SPRU371F: IDLE exits when an enabled IFR bit is set, even
         * with INTM=1. The IDLE opcode still reports HALT_IDLE so
         * single-step tests can see the enter/wake pair; the run
         * loop must not drop the slice on that report or a later
         * IODMA CLNK partner can complete before audio_isr flips
         * ENABLE_LNK.
         */
        if (rc == C55X_HALT_IDLE && irq_pending(cpu)) {
            continue;
        }
        if (rc != C55X_OK) {
            return rc;
        }
    }
    return rc;
}
