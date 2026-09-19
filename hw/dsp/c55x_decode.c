#include "c55x.h"

#include <stdio.h>
#include <string.h>

/* Leading-form sizes from the SPRU374 / rizin baseline C55x table. */
static const uint8_t c55x_lead_size[256] = {
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1, 1, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 5, 5, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    3, 3, 4, 4, 4, 4, 4, 4, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 1, 1
};

static uint16_t be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

/*
 * TAx/TAy in A-unit opcodes (SPRU374 AADD/AMOV/ASUB, MOV ctl→TAx):
 * FSSS/FDDD 0–3 encode T0–T3, 8–15 encode AR0–AR7 — not ACx.
 */
static unsigned tax_fsss(unsigned f)
{
    f &= 15u;
    if (f < 4u) {
        return f + 4u;
    }
    return f;
}

/* SPRU374: E=1 on 0x00-0x5f (odd, multi-byte) enables a parallel pair. */
static int opcode_has_e(uint8_t op0)
{
    return (op0 <= 0x5f) && (op0 & 1) && (c55x_lead_size[op0] > 1);
}

/*
 * A first opcode outside 0x00–0x5f has no E field. It still forms a
 * pair when the follower has E=1 (SPRU374). So do E=0 encodings in
 * 0x00–0x5f: the LSB is the E bit of that opcode, not a ban on a
 * follower that sets its own E. Stock examples:
 *   22 89 || 3d 00         MOV AR0, AR1 || MOV #0, AC0
 *   90 0b || 27 20         MOV AC0, XAR3 || SUB AC2, AC0
 *   eb 55 08 || 1b 00 03   MOV AC0, dbl(...) || OR #0, AC3, AC0
 *   7a ff ff 2a || 25 10   MOV #-1<<#16, AC2 || ADD AC1, AC0
 *   7a ff ff 0a || 27 02   MOV #-1<<#16, AC0 || SUB AC0, AC2
 *   0e 00 6b || 3d 05      RPTB || MOV #0, T1
 * dis55 `7affff0a_2702` at 0x10338c, then singleton `7efffc00`.
 */
static int next_declares_pair(const uint8_t *b, unsigned avail, unsigned len0)
{
    uint8_t next;
    unsigned next_lead;

    if (len0 >= avail) {
        return 0;
    }
    /*
     * Follower E=1 forms a pair even when the first opcode is E=0 or
     * has no E field (SPRU374). Stock _MEM_alloc is
     * `2289_3d00` then `eb1408_3d06` (dis55). Treating 0x22 as a
     * singleton lets `3d00` steal `eb1408` and store the pre-packet
     * AC0 into *SP(#0ah). A following 4-byte insn does not steal the
     * 2-byte E=1 mate: `eb1408` pairs with its own `3d06`.
     */
    next = b[len0];
    if (!opcode_has_e(next)) {
        return 0;
    }
    next_lead = c55x_lead_size[next];
    if (next_lead < 2 || len0 + next_lead > 6 || len0 + next_lead > avail) {
        return 0;
    }
    return 1;
}

static int is_ivec_slot(const C55xCPU *cpu, uint32_t pc)
{
    uint32_t base = ((uint32_t)cpu->ivpd << 8) & C55X_PC_MASK;

    return pc >= base && pc < ((base + 0x100u) & C55X_PC_MASK) &&
           (pc & 7u) == 0;
}

/*
 * SPRU374: AADD/AMOV/ASUB P8,TAx have two 3-byte encodings. The low
 * nibble of the third byte selects the parallel-pair slot:
 *   x0xx = first / standalone (0100 AADD P8, …)
 *   x1xx = second in a pair   (1100 AADD P8, …)
 * The first opcode may have no E bit (MOV ACx,dbl does not), so the
 * follower has to declare the pair.
 */
static int second_pos_adr(const uint8_t *b, unsigned avail, unsigned len0)
{
    uint8_t extra;

    if (len0 + 3 > avail || len0 + 3 > 6) {
        return 0;
    }
    if (b[len0] != 0x14 && b[len0] != 0x15) {
        return 0;
    }
    extra = b[len0 + 2] & 0x0f;
    return (extra & 0x08) != 0;
}

static uint32_t be24(const uint8_t *p)
{
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

static int8_t sex7(unsigned v)
{
    v &= 0x7f;
    return (int8_t)((v & 0x40) ? (int)v - 128 : (int)v);
}

int c55x_fetch(C55xCPU *cpu, uint32_t pc, uint8_t *buf, unsigned n)
{
    unsigned i;

    if (!cpu->bus.fetch8) {
        return -1;
    }
    for (i = 0; i < n; i++) {
        if (cpu->bus.fetch8(cpu->bus.opaque, (pc + i) & C55X_PC_MASK, &buf[i])) {
            return -1;
        }
    }
    return 0;
}

static unsigned smem_ext_len(uint8_t field)
{
    unsigned low;

    if ((field & 1) == 0) {
        return 0;
    }
    if (field == 0x11 || field == 0x51 || field == 0xd1 || field == 0xf1) {
        return 2;
    }
    if (field == 0x31) {
        return 3;
    }
    low = field & 0x1f;
    if (low == 0x0d || low == 0x0f) {
        return 2;
    }
    return 0;
}

static int parse_smem(uint8_t field, const uint8_t *ext, C55xSmem *sm)
{
    unsigned ppp, low;

    memset(sm, 0, sizeof(*sm));
    sm->field = field;
    sm->ext_len = smem_ext_len(field);
    if ((field & 1) == 0) {
        sm->kind = C55X_AM_DIRECT;
        sm->off = field >> 1;
        return 0;
    }
    if (field == 0x11) {
        sm->kind = C55X_AM_ABS16;
        sm->abs = be16(ext);
        return 0;
    }
    if (field == 0x31) {
        sm->kind = C55X_AM_ABS23;
        sm->abs = be24(ext) & C55X_WORD_MASK;
        return 0;
    }
    if (field == 0x51) {
        sm->kind = C55X_AM_PORT16;
        sm->abs = be16(ext);
        return 0;
    }
    if (field == 0x71 || field == 0x91 || field == 0xb1 ||
        field == 0xd1 || field == 0xf1) {
        sm->kind = C55X_AM_CDP;
        if (field == 0x91) {
            sm->mod = C55X_MOD_POSTINC;
        } else if (field == 0xb1) {
            sm->mod = C55X_MOD_POSTDEC;
        } else if (field == 0xd1) {
            sm->mod = C55X_MOD_K16;
            sm->off = (int16_t)be16(ext);
        } else if (field == 0xf1) {
            sm->mod = C55X_MOD_PRE_K16;
            sm->off = (int16_t)be16(ext);
        }
        return 0;
    }
    ppp = field >> 5;
    low = field & 0x1f;
    sm->kind = C55X_AM_AR;
    sm->ar = ppp;
    switch (low) {
    case 0x01:
        sm->mod = C55X_MOD_NONE;
        break;
    case 0x03:
        sm->mod = C55X_MOD_POSTINC;
        break;
    case 0x05:
        sm->mod = C55X_MOD_POSTDEC;
        break;
    case 0x07:
        sm->mod = C55X_MOD_PLUS_T0;
        break;
    case 0x09:
        /*
         * PPP0 1001 mnemonic *(ARn-T0).  Stock mumdrc (ARMS=0) needs this
         * indexed — post-modify walked AR2 from the SP scratch base onto
         * the saved T2 slot (T2SLOT-WR @ 134d8c/134dc9).  Matches Xmem
         * MMM=101 INDEX_MINUS_T0.
         */
        sm->mod = C55X_MOD_INDEX_MINUS_T0;
        break;
    case 0x0b:
        sm->mod = C55X_MOD_INDEX_T0;
        break;
    case 0x0d:
        sm->mod = C55X_MOD_K16;
        sm->off = (int16_t)be16(ext);
        break;
    case 0x0f:
        sm->mod = C55X_MOD_PRE_K16;
        sm->off = (int16_t)be16(ext);
        break;
    case 0x13:
        sm->mod = C55X_MOD_PLUS_T1;
        break;
    case 0x15:
        sm->mod = C55X_MOD_MINUS_T1;
        break;
    case 0x17:
        sm->mod = C55X_MOD_INDEX_T1;
        break;
    case 0x19:
        sm->mod = C55X_MOD_PREINC;
        break;
    case 0x1b:
        sm->mod = C55X_MOD_PREDEC;
        break;
    case 0x1d:
        /* SPRU374 table 6-2: *(ARn+T0B) / ARMS *ARn(short(#6)) */
        sm->mod = C55X_MOD_NONE;
        break;
    case 0x1f:
        /* SPRU374 table 6-2: *(ARn-T0B) / ARMS *ARn(short(#7)) */
        sm->mod = C55X_MOD_NONE;
        break;
    default:
        return -1;
    }
    return 0;
}

/*
 * Extra byte shared by 0xdc MOV Smem,ctl and the 6-byte 0x8d
 * MOV Smem,ctl || A-unit pack. dis55 dc6103 / 8d6bbc180370
 * both use 0x03 = CSR; dc5912 / 8d6bbc1a1270 use 0x12 = CDP.
 */
static int parse_mov_smem_ctl_extra(uint8_t extra, uint8_t *dst)
{
    if ((extra & 0x0f) == 0x02) {
        static const uint8_t ctl[] = {
            C55X_CTL_DP, C55X_CTL_CDP, C55X_CTL_BSA01, C55X_CTL_BSA23,
            C55X_CTL_BSA45, C55X_CTL_BSA67, C55X_CTL_BSAC, C55X_CTL_SP,
            C55X_CTL_SSP, C55X_CTL_BK03, C55X_CTL_BK47, C55X_CTL_BKC,
            C55X_CTL_DPH, 0xff, 0xff, C55X_CTL_PDP
        };
        unsigned hi = extra >> 4;

        if (hi >= sizeof(ctl) || ctl[hi] == 0xff) {
            return -1;
        }
        *dst = ctl[hi];
        return 0;
    }
    if ((extra & 0x0f) == 0x03) {
        static const uint8_t ctl[] = {
            C55X_CTL_CSR, C55X_CTL_BRC0, C55X_CTL_BRC1, C55X_CTL_TRN0,
            C55X_CTL_TRN1, C55X_CTL_RPTC
        };
        unsigned hi = extra >> 4;

        if (hi >= sizeof(ctl)) {
            return -1;
        }
        *dst = ctl[hi];
        return 0;
    }
    return -1;
}

static int parse_xmem(unsigned ar, unsigned mmm, C55xSmem *sm)
{
    memset(sm, 0, sizeof(*sm));
    sm->kind = C55X_AM_AR;
    sm->ar = ar & 7;
    /*
     * SPRU374 Xmem/Ymem MMM (3-bit), not Smem:
     *  000 *ARn  001 *ARn+  010 *ARn-
     *  011 *(ARn+T0)  100 *(ARn+T1)  — indexed, ARn unchanged
     *  101 *(ARn-T0)  110 *(ARn-T1)  — indexed, ARn unchanged
     *  111 *ARn(T0)
     * Smem post-modify *ARn±T0/T1 uses a different field encoding in
     * parse_smem; do not map those here.
     */
    switch (mmm & 7) {
    case 0:
        sm->mod = C55X_MOD_NONE;
        break;
    case 1:
        sm->mod = C55X_MOD_POSTINC;
        break;
    case 2:
        sm->mod = C55X_MOD_POSTDEC;
        break;
    case 3:
        sm->mod = C55X_MOD_INDEX_T0;
        break;
    case 4:
        sm->mod = C55X_MOD_INDEX_T1;
        break;
    case 5:
        sm->mod = C55X_MOD_INDEX_MINUS_T0;
        break;
    case 6:
        sm->mod = C55X_MOD_INDEX_MINUS_T1;
        break;
    default:
        sm->mod = C55X_MOD_INDEX_T0;
        break;
    }
    return 0;
}

static int parse_8f_xmem_ymem(uint8_t b1, uint8_t b2, C55xSmem *x, C55xSmem *y);

static void set_raw(C55xDecodedInsn *out, const uint8_t *b, unsigned n)
{
    unsigned i;

    out->length = n;
    out->raw = 0;
    memset(out->bytes, 0, sizeof(out->bytes));
    for (i = 0; i < n && i < C55X_FETCH_MAX; i++) {
        out->bytes[i] = b[i];
        if (i < 4) {
            out->raw |= (uint32_t)b[i] << (8 * i);
        }
    }
}

static void mark_undef(C55xDecodedInsn *out, const uint8_t *b, unsigned n)
{
    out->undef = 1;
    out->op_count = 1;
    out->op[0].kind = C55X_OP_UNDEF;
    set_raw(out, b, n ? n : 1);
}

static int decode_one(const uint8_t *b, unsigned avail, C55xOp *op,
                      unsigned *len_out, C55xDecodedInsn *packet)
{
    uint8_t op0, extra, smem_field;
    unsigned lead, ext, need;
    const uint8_t *after_smem;
    C55xSmem smem;

    memset(op, 0, sizeof(*op));
    if (!avail) {
        return -1;
    }
    op0 = b[0];
    lead = c55x_lead_size[op0];
    if (lead > avail) {
        lead = avail;
    }

    /*
     * SPRU374 Table 5–1: 0000 000E k8 cond RPTCC; 0000 001E cond RETCC.
     * Existing 0x50 PSHBOTH/POPBOTH stays the 2-byte form.
     */
    if (op0 == 0x00 || op0 == 0x01) {
        if (avail < 3) {
            return -1;
        }
        op->kind = C55X_OP_RPTCC;
        op->imm = b[1];
        op->cond = b[2] & 0x7f;
        *len_out = 3;
        return 0;
    }
    if (op0 == 0x02 || op0 == 0x03) {
        if (avail < 3) {
            return -1;
        }
        op->kind = C55X_OP_RETCC;
        op->cond = b[1] & 0x7f;
        *len_out = 3;
        return 0;
    }
    if (op0 == 0x20 || op0 == 0x21) {
        op->kind = C55X_OP_NOP;
        *len_out = 1;
        return 0;
    }
    if (op0 == 0x98) {
        op->kind = C55X_OP_QUAL_MMAP;
        *len_out = 1;
        return 0;
    }
    if (op0 == 0x9a) {
        op->kind = C55X_OP_QUAL_PORT;
        *len_out = 1;
        return 0;
    }
    if (op0 == 0x99) {
        op->kind = C55X_OP_QUAL_PORT_SMEM;
        *len_out = 1;
        return 0;
    }

    /* 2-byte register / status / short-immediate families */
    if (op0 == 0x22 || op0 == 0x23) {
        if (avail < 2) {
            return -1;
        }
        op->kind = C55X_OP_MOV_REG_REG;
        op->src = b[1] >> 4;
        op->dst = b[1] & 0x0f;
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x24 || op0 == 0x25) {
        if (avail < 2) {
            return -1;
        }
        op->kind = C55X_OP_ADD_REG;
        op->src = b[1] >> 4;
        op->dst = b[1] & 0x0f;
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x26 || op0 == 0x27) {
        if (avail < 2) {
            return -1;
        }
        op->kind = C55X_OP_SUB_REG;
        op->src = b[1] >> 4;
        op->dst = b[1] & 0x0f;
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x28 || op0 == 0x29) {
        if (avail < 2) {
            return -1;
        }
        op->kind = C55X_OP_AND_REG;
        op->src = b[1] >> 4;
        op->dst = b[1] & 0x0f;
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x2a || op0 == 0x2b) {
        if (avail < 2) {
            return -1;
        }
        op->kind = C55X_OP_OR_REG;
        op->src = b[1] >> 4;
        op->dst = b[1] & 0x0f;
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x2c || op0 == 0x2d) {
        if (avail < 2) {
            return -1;
        }
        op->kind = C55X_OP_XOR_REG;
        op->src = b[1] >> 4;
        op->dst = b[1] & 0x0f;
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x2e || op0 == 0x2f) {
        if (avail < 2) {
            return -1;
        }
        op->kind = C55X_OP_MAX_REG;
        op->src = b[1] >> 4;
        op->dst = b[1] & 0x0f;
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x30 || op0 == 0x31) {
        if (avail < 2) {
            return -1;
        }
        op->kind = C55X_OP_MIN_REG;
        op->src = b[1] >> 4;
        op->dst = b[1] & 0x0f;
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x32 || op0 == 0x33) {
        if (avail < 2) {
            return -1;
        }
        op->kind = C55X_OP_ABS_REG;
        op->src = b[1] >> 4;
        op->dst = b[1] & 0x0f;
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x34 || op0 == 0x35) {
        if (avail < 2) {
            return -1;
        }
        op->kind = C55X_OP_NEG_REG;
        op->src = b[1] >> 4;
        op->dst = b[1] & 0x0f;
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x36 || op0 == 0x37) {
        if (avail < 2) {
            return -1;
        }
        op->kind = C55X_OP_NOT_REG;
        op->src = b[1] >> 4;
        op->dst = b[1] & 0x0f;
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x38 || op0 == 0x39) {
        /* SPRU374: 0011100E FSSSFDDD — PSH src1, src2 */
        if (avail < 2) {
            return -1;
        }
        op->kind = C55X_OP_PSH_PAIR;
        op->src = b[1] >> 4;
        op->dst = b[1] & 0x0f;
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x3a || op0 == 0x3b) {
        /* SPRU374: 0011101E FSSSFDDD — POP dst1, dst2 */
        if (avail < 2) {
            return -1;
        }
        op->kind = C55X_OP_POP_PAIR;
        op->dst = b[1] >> 4;
        op->src = b[1] & 0x0f;
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x3c || op0 == 0x3d) {
        if (avail < 2) {
            return -1;
        }
        op->kind = C55X_OP_MOV_K4;
        op->imm = b[1] >> 4;
        op->dst = b[1] & 0x0f;
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x3e || op0 == 0x3f) {
        if (avail < 2) {
            return -1;
        }
        op->kind = C55X_OP_MOV_NK4;
        op->imm = -(int)(b[1] >> 4);
        op->dst = b[1] & 0x0f;
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x40 || op0 == 0x41) {
        if (avail < 2) {
            return -1;
        }
        op->kind = C55X_OP_ADD_K4;
        op->imm = b[1] >> 4;
        op->dst = b[1] & 0x0f;
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x42 || op0 == 0x43) {
        if (avail < 2) {
            return -1;
        }
        op->kind = C55X_OP_SUB_K4;
        op->imm = b[1] >> 4;
        op->dst = b[1] & 0x0f;
        *len_out = 2;
        return 0;
    }
    /*
     * SPRU374: 0100010E + second byte. Distinct from MOV k4 (0011110E).
     * 00SSFDDD MOV HI(ACx), TAx
     * 01x0FDDD SFTS dst, #-1
     * 01x1FDDD SFTS dst, #1
     * 1000FDDD MOV SP, dst
     * 1001FDDD MOV SSP, dst
     * 1010FDDD MOV CDP, dst
     * 1100FDDD MOV BRC0, dst
     * 1101FDDD MOV BRC1, dst
     * 1110FDDD MOV RPTC, dst
     * FDDD is any FSSS (stock 449a = MOV SSP, AR2).
     */
    if (op0 == 0x44 || op0 == 0x45) {
        unsigned top;

        if (avail < 2) {
            return -1;
        }
        extra = b[1];
        op->dst = extra & 0x0f;
        top = extra >> 4;
        if ((extra & 0xc0) == 0x00) {
            /* SPRU374 TAx is AR0–AR7 or T0–T3 (FSSS >= 4). */
            if (op->dst < 4) {
                return -1;
            }
            op->kind = C55X_OP_MOV_HI_TAX;
            op->src = (extra >> 4) & 3;
            *len_out = 2;
            return 0;
        }
        if ((extra & 0xc0) == 0x40) {
            /* SFTS dst, #±1 — FDDD is ACx or TAx (stock 4442 = AC2). */
            op->kind = C55X_OP_SFTS_TAX;
            op->imm = (extra & 0x10) ? 1 : -1;
            *len_out = 2;
            return 0;
        }
        op->kind = C55X_OP_MOV_CTL_TAX;
        switch (top) {
        case 0x8:
            op->src = C55X_CTL_SP;
            break;
        case 0x9:
            op->src = C55X_CTL_SSP;
            break;
        case 0xa:
            op->src = C55X_CTL_CDP;
            break;
        case 0xc:
            op->src = C55X_CTL_BRC0;
            break;
        case 0xd:
            op->src = C55X_CTL_BRC1;
            break;
        case 0xe:
            op->src = C55X_CTL_RPTC;
            break;
        default:
            return -1;
        }
        op->dst = tax_fsss(op->dst);
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x46 || op0 == 0x47) {
        if (avail < 2) {
            return -1;
        }
        extra = b[1] & 0x0f;
        op->bit = b[1] >> 4;
        op->st = (uint8_t)(extra >> 1);
        op->kind = (extra & 1) ? C55X_OP_BSET_ST : C55X_OP_BCLR_ST;
        if (op->st > 3) {
            return -1;
        }
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x48 || op0 == 0x49) {
        if (avail < 2) {
            return -1;
        }
        extra = b[1] & 7;
        if (extra == 0) {
            op->kind = C55X_OP_RPT_CSR;
        } else if (extra == 1 || extra == 2) {
            /* SPRU374: FSSSx001 RPTADD CSR, TAx; kkkkx010 RPTADD CSR, k4 */
            op->kind = C55X_OP_RPTADD;
            op->src = b[1] >> 4;
        } else if (extra == 3) {
            op->kind = C55X_OP_RPTSUB;
            op->src = b[1] >> 4;
        } else if (extra == 4) {
            op->kind = C55X_OP_RET;
        } else if (extra == 5) {
            op->kind = C55X_OP_RETI;
        } else {
            return -1;
        }
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x4a || op0 == 0x4b) {
        if (avail < 2) {
            return -1;
        }
        if (b[1] & 0x80) {
            /* SPRU374: 0100 101E 1lllllll RPTBLOCAL pmad */
            op->kind = C55X_OP_RPTBLOCAL;
            op->target = b[1] & 0x7f;
            *len_out = 2;
            return 0;
        }
        op->kind = C55X_OP_B_L7;
        op->imm = sex7(b[1]);
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x4e || op0 == 0x4f) {
        if (avail < 2) {
            return -1;
        }
        op->kind = C55X_OP_AADD_K8_SP;
        op->imm = (int8_t)b[1];
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x4c || op0 == 0x4d) {
        if (avail < 2) {
            return -1;
        }
        op->kind = C55X_OP_RPT_K8;
        op->imm = b[1];
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x50 || op0 == 0x51) {
        if (avail < 2) {
            return -1;
        }
        extra = b[1] & 0x0f;
        if ((extra & 7) == 0) {
            /* SPRU374: 0101 000E FDDD x000 SFTL dst, #1 */
            op->kind = C55X_OP_SFTL_TAX;
            op->dst = b[1] >> 4;
            op->imm = 1;
        } else if ((extra & 7) == 1) {
            /* SPRU374: 0101 000E FDDD x001 SFTL dst, #-1 */
            op->kind = C55X_OP_SFTL_TAX;
            op->dst = b[1] >> 4;
            op->imm = -1;
        } else if (extra == 0x04) {
            op->kind = C55X_OP_POPBOTH;
            op->dst = b[1] >> 4;
        } else if (extra == 0x05) {
            op->kind = C55X_OP_PSHBOTH;
            op->src = b[1] >> 4;
        } else if ((extra & 7) == 2) {
            op->kind = C55X_OP_POP_DST;
            op->dst = b[1] >> 4;
        } else if ((extra & 7) == 3) {
            /* SPRU374: 0101 000E xxDD x011 POP dbl(ACx) */
            op->kind = C55X_OP_POP_DBL_AC;
            op->dst = (b[1] >> 4) & 3;
        } else if ((extra & 7) == 6) {
            op->kind = C55X_OP_PSH_SRC;
            op->src = b[1] >> 4;
        } else if ((extra & 7) == 7) {
            /* SPRU374: 0101 000E xxSS x111 PSH dbl(ACx) */
            op->kind = C55X_OP_PSH_DBL_AC;
            op->src = (b[1] >> 4) & 3;
        } else {
            return -1;
        }
        *len_out = 2;
        return 0;
    }
    /* 0101001E FSSS… — MOV TAx, HI(ACx) / SP / SSP / CDP / CSR / BRCx */
    if (op0 == 0x52 || op0 == 0x53) {
        if (avail < 2) {
            return -1;
        }
        extra = b[1];
        op->src = tax_fsss(extra >> 4);
        if ((extra & 0x0c) == 0) {
            op->kind = C55X_OP_MOV_TAX_HI;
            op->dst = extra & 3;
            *len_out = 2;
            return 0;
        }
        op->kind = C55X_OP_MOV_TAX_CTL;
        switch (extra & 0x0f) {
        case 0x08:
            op->dst = C55X_CTL_SP;
            break;
        case 0x09:
            op->dst = C55X_CTL_SSP;
            break;
        case 0x0a:
            op->dst = C55X_CTL_CDP;
            break;
        case 0x0c:
            op->dst = C55X_CTL_CSR;
            break;
        case 0x0d:
            op->dst = C55X_CTL_BRC1;
            break;
        case 0x0e:
            op->dst = C55X_CTL_BRC0;
            break;
        default:
            return -1;
        }
        *len_out = 2;
        return 0;
    }
    /*
     * SPRU374 0101010E / 0101011E / 0101100E: D-unit register MAC/ALU.
     *   0101010E DDSS xxx%  ADDV / SQA / SQS / MPY / SQR / RND / SAT
     *   0101011E DDSS ss0%  MAC[R] ACx, Tx, ACy
     *   0101011E DDSS ss1%  MAS[R] Tx, [ACx,] ACy
     *   0101100E DDSS ss0%  MPY[R] Tx, [ACx,] ACy
     *   0101100E DDSS ss1%  MAC[R] ACy, Tx, ACx, ACy
     */
    if (op0 == 0x54 || op0 == 0x55) {
        unsigned form;

        if (avail < 2) {
            return -1;
        }
        extra = b[1];
        op->dst = extra >> 6;
        op->src = (extra >> 4) & 3;
        op->bit = extra & 1;
        form = (extra >> 1) & 7;
        switch (form) {
        case 0:
            op->kind = C55X_OP_ADDV;
            break;
        case 1:
            op->kind = C55X_OP_SQA;
            break;
        case 2:
            op->kind = C55X_OP_SQS;
            break;
        case 3:
            op->kind = C55X_OP_MPY_AC;
            break;
        case 4:
            op->kind = C55X_OP_SQR;
            break;
        case 5:
            op->kind = C55X_OP_ROUND;
            break;
        case 6:
            op->kind = C55X_OP_SAT;
            break;
        default:
            return -1;
        }
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x56 || op0 == 0x57 || op0 == 0x58 || op0 == 0x59) {
        if (avail < 2) {
            return -1;
        }
        extra = b[1];
        op->dst = extra >> 6;
        op->src = (extra >> 4) & 3;
        op->imm = (extra >> 2) & 3;
        op->bit = extra & 1;
        if (op0 == 0x56 || op0 == 0x57) {
            op->kind = (extra & 2) ? C55X_OP_MAS_TX : C55X_OP_MAC_TX;
            op->st = 0;
        } else {
            op->kind = (extra & 2) ? C55X_OP_MAC_TX : C55X_OP_MPY_TX;
            /* SPRU374: 0x58 MAC is ACy = (ACy * Tx) + ACx, not ACy += ACx * Tx. */
            op->st = 1;
        }
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x5a || op0 == 0x5b) {
        /* SPRU374: 0101 101E DDSS xx00/01 ADD/SUB ACx << Tx, ACy */
        if (avail < 2) {
            return -1;
        }
        extra = b[1];
        op->dst = extra >> 6;
        op->src = (extra >> 4) & 3;
        op->imm = (extra >> 2) & 3;
        if (extra & 2) {
            /* SPRU374: 0101 101E DDxxxx1t — SFTCC ACx, TCx */
            op->kind = C55X_OP_SFTS_AC;
            op->bit = 2;
            op->st = extra & 1;
            *len_out = 2;
            return 0;
        }
        op->kind = (extra & 1) ? C55X_OP_SUB_AC_SHFT : C55X_OP_ADD_AC_SHFT;
        op->st = 1; /* shift amount is Tx, not #SHIFTW */
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x5c || op0 == 0x5d) {
        unsigned form;

        if (avail < 2) {
            return -1;
        }
        extra = b[1];
        form = extra & 3;
        if (form > 2) {
            return -1;
        }
        /* SPRU374: 0101 110E DDSS ss00/01/10 SFTL/SFTS/SFTSC ACx, Tx, ACy */
        op->kind = C55X_OP_SFTS_AC_TX;
        op->dst = extra >> 6;
        op->src = (extra >> 4) & 3;
        op->imm = (extra >> 2) & 3;
        op->st = (form == 0);
        op->bit = (form == 2);
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x5e || op0 == 0x5f) {
        unsigned k, src, dst;

        if (avail < 2) {
            return -1;
        }
        /* dis55: 5e80/5f80 is NOP_16. SPRU374 SWAP is 00kkkkkk. */
        if (b[1] == 0x80) {
            op->kind = C55X_OP_NOP;
            *len_out = 2;
            return 0;
        }
        if (b[1] & 0xc0) {
            return -1;
        }
        k = b[1] & 0x3f;
        /* Named simple pairs from SPRU374 SWAP ( ) / dis55. pair()
         * and block() k values stay UNDEF. */
        switch (k) {
        case 0x00:
            src = C55X_REG_AC0;
            dst = C55X_REG_AC2;
            break;
        case 0x01:
            src = C55X_REG_AC1;
            dst = C55X_REG_AC3;
            break;
        case 0x04:
            src = C55X_REG_T0;
            dst = C55X_REG_T2;
            break;
        case 0x05:
            src = C55X_REG_T1;
            dst = C55X_REG_T3;
            break;
        case 0x0c:
            src = C55X_REG_AR0 + 4;
            dst = C55X_REG_T0;
            break;
        case 0x0d:
            src = C55X_REG_AR0 + 5;
            dst = C55X_REG_T1;
            break;
        case 0x0e:
            src = C55X_REG_AR0 + 6;
            dst = C55X_REG_T2;
            break;
        default:
            return -1;
        }
        op->kind = C55X_OP_SWAP;
        op->src = src;
        op->dst = dst;
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x14 || op0 == 0x15) {
        if (avail < 3) {
            return -1;
        }
        extra = b[2] & 0x0f;
        op->src = tax_fsss(b[1] >> 4);
        op->dst = tax_fsss(b[2] >> 4);
        op->imm = b[1];
        if (extra == 0x04 || extra == 0x0c) {
            op->kind = C55X_OP_AADD_K8_TAX;
            op->imm = (int8_t)b[1];
        } else if (extra == 0x05 || extra == 0x0d) {
            op->kind = C55X_OP_AMOV_K8_TAX;
            op->imm = (int8_t)b[1];
        } else if (extra == 0x06 || extra == 0x0e) {
            op->kind = C55X_OP_ASUB_K8_TAX;
            op->imm = (int8_t)b[1];
        } else if (extra == 0x00 || extra == 0x08) {
            op->kind = C55X_OP_AADD_TAX;
        } else if (extra == 0x01 || extra == 0x09) {
            op->kind = C55X_OP_AMOV_TAX;
        } else if (extra == 0x02 || extra == 0x0a) {
            op->kind = C55X_OP_ASUB_TAX;
        } else {
            return -1;
        }
        *len_out = 3;
        return 0;
    }
    if (op0 == 0x04 || op0 == 0x05) {
        if (avail < 3) {
            return -1;
        }
        op->kind = C55X_OP_BCC_L8;
        op->cond = b[1] & 0x7f;
        op->imm = (int8_t)b[2];
        *len_out = 3;
        return 0;
    }
    if (op0 == 0x06 || op0 == 0x07) {
        if (avail < 3) {
            return -1;
        }
        op->kind = C55X_OP_B_L16;
        op->imm = (int16_t)be16(b + 1);
        *len_out = 3;
        return 0;
    }
    if (op0 == 0x08 || op0 == 0x09) {
        if (avail < 3) {
            return -1;
        }
        op->kind = C55X_OP_CALL_L16;
        op->imm = (int16_t)be16(b + 1);
        *len_out = 3;
        return 0;
    }
    if (op0 == 0x0c || op0 == 0x0d) {
        if (avail < 3) {
            return -1;
        }
        op->kind = C55X_OP_RPT_K16;
        op->imm = be16(b + 1);
        *len_out = 3;
        return 0;
    }
    if (op0 == 0x0e || op0 == 0x0f) {
        if (avail < 3) {
            return -1;
        }
        op->kind = C55X_OP_RPTB;
        op->target = be16(b + 1);
        *len_out = 3;
        return 0;
    }
    /* 0001000E … — SPRU374 Table 5–1 ACx specials / shift ALU */
    if (op0 == 0x10 || op0 == 0x11) {
        unsigned lo;

        if (avail < 3) {
            return -1;
        }
        extra = b[1];
        lo = extra & 0x0f;
        if (lo <= 7) {
            /*
             * 0001000E DDSS0xxx xxSHIFTW — AND/OR/XOR/ADD/SUB/SFTS/SFTSC/SFTL
             */
            op->dst = extra >> 6;
            op->src = (extra >> 4) & 3;
            op->shft = b[2] & 0x3f;
            switch (lo) {
            case 0:
                op->kind = C55X_OP_AND_AC_SHFT;
                break;
            case 1:
                op->kind = C55X_OP_OR_AC_SHFT;
                break;
            case 2:
                op->kind = C55X_OP_XOR_AC_SHFT;
                break;
            case 3:
                op->kind = C55X_OP_ADD_AC_SHFT;
                break;
            case 4:
                op->kind = C55X_OP_SUB_AC_SHFT;
                break;
            case 5:
                op->kind = C55X_OP_SFTS_AC;
                break;
            case 6:
                op->kind = C55X_OP_SFTS_AC;
                op->bit = 1; /* SFTSC: update CARRY */
                break;
            default:
                op->kind = C55X_OP_SFTL_AC;
                break;
            }
            *len_out = 3;
            return 0;
        }
        if (lo == 0x08) {
            /* 0001000E xxSS1000 xxddxxxx — EXP ACx, Tx */
            op->kind = C55X_OP_EXP;
            op->src = (extra >> 4) & 3;
            op->dst = (b[2] >> 4) & 3;
            *len_out = 3;
            return 0;
        }
        if (lo == 0x09) {
            /*
             * 0001000E DDSS1001 xxddxxxx —
             *   MANT ACx, ACy :: NEXP ACx, Tx
             * Stock mumdrc `10 49 00` at 0x134a30.
             */
            unsigned ss = (extra >> 4) & 3;
            unsigned dd = extra >> 6;
            unsigned tx = (b[2] >> 4) & 3;

            op->kind = C55X_OP_MANT;
            op->src = ss;
            op->dst = dd;
            *len_out = 3;
            if (packet) {
                packet->op[0] = *op;
                memset(&packet->op[1], 0, sizeof(packet->op[1]));
                packet->op[1].kind = C55X_OP_NEXP;
                packet->op[1].src = ss;
                packet->op[1].dst = tx;
                packet->op_count = 2;
                packet->length = 3;
            }
            return 0;
        }
        if (lo == 0x0a) {
            /* 0001000E xxSS1010 SSddxxxt — BCNT ACx, ACy, TCx, Tx (Tx dest) */
            op->kind = C55X_OP_BCNT;
            op->src = (extra >> 4) & 3;
            op->dst = (b[2] >> 4) & 3;
            op->st = b[2] & 1; /* TCx select bit */
            *len_out = 3;
            return 0;
        }
        if (lo == 0x0c || lo == 0x0d || lo == 0x0e || lo == 0x0f) {
            /*
             * MAXDIFF / DMAXDIFF / MINDIFF / DMINDIFF —
             * 0001000E DDSS11xx SSDD….
             */
            op->kind = C55X_OP_MAXDIFF;
            op->src = (extra >> 4) & 3;
            op->dst = extra >> 6;
            op->imm = (int32_t)(((b[2] >> 6) & 3) | (((b[2] >> 4) & 3) << 2));
            if (lo == 0x0c) {
                op->st = 0; /* MAXDIFF */
            } else if (lo == 0x0d) {
                op->st = 1; /* DMAXDIFF */
            } else if (lo == 0x0e) {
                op->st = 2; /* MINDIFF */
            } else {
                op->st = 3; /* DMINDIFF */
            }
            *len_out = 3;
            return 0;
        }
        return -1;
    }
    if (op0 == 0x12 || op0 == 0x13) {
        unsigned form;

        if (avail < 3) {
            return -1;
        }
        /* SPRU374: 0001001E FSSSccxx — CMP / CMPAND / CMPOR / ROL */
        form = b[1] & 3;
        op->src = b[1] >> 4;
        op->cond = (b[1] >> 2) & 3;
        op->dst = b[2] >> 4;
        op->bit = b[2] & 1;
        op->st = (b[2] >> 2) & 1;
        op->shft = (b[2] >> 1) & 1;
        op->imm = (b[2] >> 3) & 1;
        if (form == 0) {
            op->kind = C55X_OP_CMP;
        } else if (form == 1) {
            op->kind = C55X_OP_CMPAND;
        } else if (form == 2) {
            op->kind = C55X_OP_CMPOR;
        } else if (op->imm) {
            op->kind = C55X_OP_ROR;
        } else {
            op->kind = C55X_OP_ROL;
        }
        *len_out = 3;
        return 0;
    }
    if (op0 == 0x16 || op0 == 0x17) {
        unsigned which;

        if (avail < 3) {
            return -1;
        }
        /* SPRU374: 0001011E k12 / k7 / k9 into CSR, BRC, BK* */
        which = b[2] & 0x0f;
        if (which != 0x00 && which != 0x03 && which != 0x04 &&
            which != 0x05 && which != 0x06 && which != 0x08 &&
            which != 0x09 && which != 0x0a) {
            return -1;
        }
        op->kind = C55X_OP_MOV_K12_CTL;
        op->dst = (uint8_t)which;
        op->imm = ((unsigned)b[1] << 4) | (b[2] >> 4);
        *len_out = 3;
        return 0;
    }
    /* 0001100E / 0001101E / 0001110E k8, src, dst */
    if (op0 == 0x18 || op0 == 0x19 || op0 == 0x1a || op0 == 0x1b ||
        op0 == 0x1c || op0 == 0x1d) {
        if (avail < 3) {
            return -1;
        }
        op->imm = b[1];
        op->dst = b[2] >> 4;
        op->src = b[2] & 0x0f;
        if (op0 <= 0x19) {
            op->kind = C55X_OP_AND_K8;
        } else if (op0 <= 0x1b) {
            op->kind = C55X_OP_OR_K8;
        } else {
            op->kind = C55X_OP_XOR_K8;
        }
        *len_out = 3;
        return 0;
    }
    if (op0 == 0x1e || op0 == 0x1f) {
        /*
         * SPRU374: 0001 111E K8 SSDD xx0% — MPYK[R] K8, ACx, ACy
         *           0001 111E K8 SSDD ss1% — MACK[R] Tx, K8, ACx, ACy
         */
        if (avail < 3) {
            return -1;
        }
        extra = b[2];
        op->imm = (int8_t)b[1];
        op->src = extra >> 6;
        op->dst = (extra >> 4) & 3;
        op->bit = extra & 1;
        if (extra & 2) {
            /* ss1% — MACK[R] Tx, K8, ACx, ACy */
            op->kind = C55X_OP_MACK;
            op->st = (extra >> 2) & 3;
        } else {
            op->kind = C55X_OP_MPYK_K16;
        }
        *len_out = 3;
        return 0;
    }
    /* 01100lll lCCCCCCC BCC l4, cond — Parallel Enable = No */
    if ((op0 & 0xf8) == 0x60) {
        unsigned raw;

        if (avail < 2) {
            return -1;
        }
        op->kind = C55X_OP_BCC_L8;
        op->cond = b[1] & 0x7f;
        raw = ((unsigned)(op0 & 7) << 1) | (b[1] >> 7);
        /* dis55: l4 is a 0..15 byte offset. All 1100 avs.dis sites are
         * forward; 64 90 is +9 (0x101d76 → 0x101d81), 66 36 is +12. */
        op->imm = (int)raw;
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x6a) {
        if (avail < 4) {
            return -1;
        }
        op->kind = C55X_OP_B_P24;
        op->target = be24(b + 1) & C55X_PC_MASK;
        *len_out = 4;
        return 0;
    }
    if (op0 == 0x6c) {
        if (avail < 4) {
            return -1;
        }
        op->kind = C55X_OP_CALL_P24;
        op->target = be24(b + 1) & C55X_PC_MASK;
        *len_out = 4;
        return 0;
    }
    if (op0 == 0x68) {
        if (avail < 5) {
            return -1;
        }
        op->kind = C55X_OP_BCC_P24;
        op->cond = b[1] & 0x7f;
        op->target = be24(b + 2) & C55X_PC_MASK;
        *len_out = 5;
        return 0;
    }
    if (op0 == 0x69) {
        if (avail < 5) {
            return -1;
        }
        op->kind = C55X_OP_CALLCC_P24;
        op->cond = b[1] & 0x7f;
        op->target = be24(b + 2) & C55X_PC_MASK;
        *len_out = 5;
        return 0;
    }
    if (op0 == 0x6d) {
        if (avail < 4) {
            return -1;
        }
        op->kind = C55X_OP_BCC_L16;
        op->cond = b[1] & 0x7f;
        op->imm = (int16_t)be16(b + 2);
        *len_out = 4;
        return 0;
    }
    /* SPRU374: 0110 1110 CCCCCCCC L16 — CALLCC L16, cond */
    if (op0 == 0x6e) {
        if (avail < 4) {
            return -1;
        }
        op->kind = C55X_OP_CALLCC_L16;
        op->cond = b[1] & 0x7f;
        op->imm = (int16_t)be16(b + 2);
        *len_out = 4;
        return 0;
    }
    if (op0 == 0x6f) {
        if (avail < 4) {
            return -1;
        }
        extra = b[1];
        op->kind = C55X_OP_BCC_SRC_K8;
        op->src = extra >> 4;
        op->cond = (extra >> 2) & 3;
        op->st = extra & 1;
        op->imm = (int8_t)b[2];
        op->target = (uint32_t)(int32_t)(int8_t)b[3];
        *len_out = 4;
        return 0;
    }
    if (op0 >= 0x70 && op0 <= 0x74) {
        /* SPRU374: 01110xxx K16 SSDDSHFT — ADD/SUB/AND/OR/XOR K16 << #SHFT */
        if (avail < 4) {
            return -1;
        }
        op->kind = C55X_OP_ADD_K16_SHFT;
        op->st = (uint8_t)(op0 - 0x70);
        op->imm = (int16_t)be16(b + 1);
        /* SSDDSHFT: SS in bits 7:6, DD in bits 5:4 (same as 0x7a). */
        op->src = (b[3] >> 6) & 3;
        op->dst = (b[3] >> 4) & 3;
        op->shft = b[3] & 0x3f;
        *len_out = 4;
        return 0;
    }
    if (op0 == 0x76) {
        if (avail < 4) {
            return -1;
        }
        extra = b[3];
        op->imm = (int16_t)be16(b + 1);
        /*
         * SPRU374 0x76: FDDD00SS BFXTR / FDDD01SS BFXPA. Source is
         * ACx (SS); destination is the FDDD register. Using FDDD for
         * both made tokliBIOS `76fffc90` extract AR1 instead of AC0.
         */
        op->src = extra & 3;
        op->dst = extra >> 4;
        if ((extra & 0x0c) == 0x00) {
            op->kind = C55X_OP_BFXTR;
            *len_out = 4;
            return 0;
        }
        if ((extra & 0x0c) == 0x04) {
            op->kind = C55X_OP_BFXPA;
            *len_out = 4;
            return 0;
        }
        if (((extra >> 2) & 3) == 2) {
            op->kind = C55X_OP_MOV_K16_DST;
            *len_out = 4;
            return 0;
        }
        return -1;
    }
    if (op0 == 0x75) {
        if (avail < 4) {
            return -1;
        }
        op->kind = C55X_OP_MOV_K16_AC_SHFT;
        op->imm = (int16_t)be16(b + 1);
        op->dst = (b[3] >> 4) & 3;
        op->shft = b[3] & 0x0f;
        *len_out = 4;
        return 0;
    }
    if (op0 == 0x77) {
        if (avail < 4) {
            return -1;
        }
        op->kind = C55X_OP_AMOV_D16;
        op->imm = (int16_t)be16(b + 1);
        op->dst = tax_fsss(b[3] >> 4);
        *len_out = 4;
        return 0;
    }
    if (op0 == 0x78) {
        if (avail < 4) {
            return -1;
        }
        op->kind = C55X_OP_MOV_K16_CTL;
        op->imm = (int16_t)be16(b + 1);
        op->dst = (b[3] >> 1) & 0x0f;
        *len_out = 4;
        return 0;
    }
    if (op0 == 0x79) {
        /* SPRU374: 0111 1001 K16 SSDD xx0% — MPYK[R] K16, ACx, ACy */
        if (avail < 4) {
            return -1;
        }
        extra = b[3];
        op->imm = (int16_t)be16(b + 1);
        op->src = extra >> 6;
        op->dst = (extra >> 4) & 3;
        op->bit = extra & 1;
        if (extra & 2) {
            op->kind = C55X_OP_MACK;
            op->st = (extra >> 2) & 3;
        } else {
            op->kind = C55X_OP_MPYK_K16;
        }
        *len_out = 4;
        return 0;
    }
    if (op0 == 0x7a) {
        unsigned form;

        if (avail < 4) {
            return -1;
        }
        /*
         * SPRU374: 01111010 K16 SSDDxxx
         * 000 ADD / 001 SUB / 010 AND / 011 OR / 100 XOR
         * 101 MOV K16<<#16 / 110 IDLE. 111 stays undefined.
         */
        extra = b[3];
        form = (extra >> 1) & 7;
        op->imm = (int16_t)be16(b + 1);
        op->src = (extra >> 6) & 3;
        op->dst = (extra >> 4) & 3;
        switch (form) {
        case 0:
            op->kind = C55X_OP_ADD_K16_SH16;
            break;
        case 1:
            op->kind = C55X_OP_SUB_K16_SH16;
            break;
        case 2:
            op->kind = C55X_OP_AND_K16_SH16;
            break;
        case 3:
            op->kind = C55X_OP_OR_K16_SH16;
            break;
        case 4:
            op->kind = C55X_OP_XOR_K16_SH16;
            break;
        case 5:
            op->kind = C55X_OP_MOV_K16_AC_SH16;
            break;
        case 6:
            op->kind = C55X_OP_IDLE;
            break;
        default:
            return -1;
        }
        *len_out = 4;
        return 0;
    }
    if (op0 == 0x7b) {
        if (avail < 4) {
            return -1;
        }
        op->kind = C55X_OP_ADD_K16_DST;
        op->imm = (int16_t)be16(b + 1);
        op->dst = b[3] >> 4;
        op->src = b[3] & 0x0f;
        *len_out = 4;
        return 0;
    }
    if (op0 == 0x7c) {
        if (avail < 4) {
            return -1;
        }
        op->kind = C55X_OP_SUB_K16_DST;
        op->imm = (int16_t)be16(b + 1);
        op->dst = b[3] >> 4;
        op->src = b[3] & 0x0f;
        *len_out = 4;
        return 0;
    }
    if (op0 == 0x7d) {
        if (avail < 4) {
            return -1;
        }
        op->kind = C55X_OP_AND_K16_DST;
        op->imm = (int16_t)be16(b + 1);
        op->dst = b[3] >> 4;
        op->src = b[3] & 0x0f;
        *len_out = 4;
        return 0;
    }
    if (op0 == 0x7e) {
        if (avail < 4) {
            return -1;
        }
        op->kind = C55X_OP_OR_K16_DST;
        op->imm = (int16_t)be16(b + 1);
        op->dst = b[3] >> 4;
        op->src = b[3] & 0x0f;
        *len_out = 4;
        return 0;
    }
    if (op0 == 0x7f) {
        if (avail < 4) {
            return -1;
        }
        op->kind = C55X_OP_XOR_K16_DST;
        op->imm = (int16_t)be16(b + 1);
        op->dst = b[3] >> 4;
        op->src = b[3] & 0x0f;
        *len_out = 4;
        return 0;
    }
    if (op0 == 0x80) {
        unsigned packed = ((unsigned)b[1] << 8) | b[2];
        unsigned xy;

        if (avail < 3) {
            return -1;
        }
        /*
         * 1000 0000 XXXMMM YYYMMM 01xx — MOV Xmem, Ymem
         * 1000 0000 XXXMMM YYYMMM 00xx — MOV dbl(Xmem), dbl(Ymem)
         * Other 0x80 low-bit pairs are a different family.
         */
        xy = packed & 0x0c;
        if (parse_xmem(packed >> 13, (packed >> 10) & 7, &op->smem) ||
            parse_xmem((packed >> 7) & 7, (packed >> 4) & 7, &op->ymem)) {
            return -1;
        }
        if (xy == 0x04) {
            op->kind = C55X_OP_MOV_XMEM_YMEM;
        } else if (xy == 0x00) {
            op->kind = C55X_OP_MOV_DBL_XY;
        } else if (xy == 0x08) {
            /* SPRU374: 1000 000E … 10SS MOV ACx, Xmem, Ymem */
            op->kind = C55X_OP_MOV_AC_XY;
            op->src = packed & 3;
        } else {
            return -1;
        }
        *len_out = 3;
        return 0;
    }
    if (op0 == 0x81) {
        unsigned packed = ((unsigned)b[1] << 8) | b[2];
        unsigned xy;

        if (avail < 3) {
            return -1;
        }
        /* SPRU374: ADD/SUB/MOV Xmem, Ymem, ACx */
        xy = packed & 0x0c;
        if (xy > 0x08) {
            return -1;
        }
        if (parse_xmem(packed >> 13, (packed >> 10) & 7, &op->smem) ||
            parse_xmem((packed >> 7) & 7, (packed >> 4) & 7, &op->ymem)) {
            return -1;
        }
        op->dst = packed & 3;
        if (xy == 0x00) {
            op->kind = C55X_OP_ADD_XY_AC;
        } else if (xy == 0x04) {
            op->kind = C55X_OP_SUB_XY_AC;
        } else {
            op->kind = C55X_OP_MOV_XY_AC;
        }
        *len_out = 3;
        return 0;
    }
    if (op0 == 0x86) {
        unsigned packed;
        unsigned form;

        if (avail < 4) {
            return -1;
        }
        packed = ((unsigned)b[1] << 8) | b[2];
        form = b[3] >> 5;
        if (parse_xmem(packed >> 13, (packed >> 10) & 7, &op->smem) ||
            parse_xmem((packed >> 7) & 7, (packed >> 4) & 7, &op->ymem)) {
            return -1;
        }
        op->bit = b[3] & 1;
        op->st = (b[3] >> 1) & 1;
        op->shft = (b[3] >> 2) & 3; /* uu: X uns, Y uns */
        op->src = (packed >> 2) & 3;
        op->dst = packed & 3;
        if (form == 0) {
            op->kind = C55X_OP_MPYM_XY;
            op->src = 0;
        } else if (form == 1) {
            op->kind = C55X_OP_MACM_XY;
            op->cond = 0;
        } else if (form == 2) {
            op->kind = C55X_OP_MACM_XY;
            op->cond = 1; /* ACx >> #16 */
        } else if (form == 3) {
            op->kind = C55X_OP_MASM_XY;
        } else if (form == 4 || form == 5) {
            /*
             * YMMMDDDD 100/101 xss U% :
             * MASM/MACM Xmem, Tx, ACx :: MOV Ymem << #16, ACy.
             * DDDD is ACy in [3:2] and ACx in [1:0].
             */
            op->kind = (form == 4) ? C55X_OP_MASM_XY : C55X_OP_MACM_XY;
            op->dst = b[2] & 3;             /* ACx */
            op->src = (b[2] >> 2) & 3;      /* ACy */
            op->imm = (b[3] >> 2) & 7;      /* Tx */
            op->st = (b[3] >> 1) & 1;       /* T3 = Xmem */
            op->bit = b[3] & 1;             /* round */
            op->cond = 3;
        } else if (form == 6) {
            op->kind = C55X_OP_LMS;
            op->dst = b[2] & 3;
            op->src = (b[2] >> 2) & 3;
        } else if ((b[3] & 0x10) == 0) {
            op->kind = C55X_OP_SQDST;
            op->dst = b[2] & 3;
            op->src = (b[2] >> 2) & 3;
        } else {
            op->kind = C55X_OP_ABDST;
            op->dst = b[2] & 3;
            op->src = (b[2] >> 2) & 3;
        }
        *len_out = 4;
        return 0;
    }
    if (op0 == 0x82 || op0 == 0x83 || op0 == 0x84 || op0 == 0x85) {
        uint32_t p;
        unsigned mm, form;

        if (avail < 4) {
            return -1;
        }
        p = ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
        if (parse_xmem((p >> 21) & 7, (p >> 18) & 7, &op->smem) ||
            parse_xmem((p >> 15) & 7, (p >> 12) & 7, &op->ymem)) {
            return -1;
        }
        mm = (p >> 10) & 3;
        op->src = (p >> 8) & 3;
        op->dst = (p >> 6) & 3;
        form = p & 0x3f;
        op->shft = (uint8_t)mm;
        op->bit = form & 1;
        op->cond = (form >> 2) & 3;
        op->st = (form >> 4) & 3;
        op->imm = (op0 == 0x83) || (op0 == 0x84) || ((form >> 1) & 1);
        if (op0 == 0x84) {
            op->cond = 1;
            op->st = 1;
            op->imm = 1;
        } else if (op0 == 0x85) {
            op->cond = 2;
            op->st = 2;
            if (((b[2] >> 2) & 3) == 3) {
                /* DDx0/1 DDU% : the '1' is bit 4, not bit 3. */
                op->kind = (b[3] & 0x10) ? C55X_OP_FIRSSUB : C55X_OP_FIRSADD;
                op->src = b[3] >> 6;          /* ACx */
                op->dst = (b[3] >> 2) & 3;    /* ACy */
                *len_out = 4;
                return 0;
            }
        }
        op->kind = C55X_OP_DUAL_MAC;
        *len_out = 4;
        return 0;
    }
    if (op0 == 0x87) {
        unsigned packed;

        if (avail < 4) {
            return -1;
        }
        packed = ((unsigned)b[1] << 8) | b[2];
        if (parse_xmem(packed >> 13, (packed >> 10) & 7, &op->smem) ||
            parse_xmem((packed >> 7) & 7, (packed >> 4) & 7, &op->ymem)) {
            return -1;
        }
        /*
         * 000/001/010: MPYM/MACM/MASM Xmem, Tx, ACy :: MOV HI(ACx << T2), Ymem
         * 100/101/110: ADD/SUB/MOV Xmem << #16, ACx, ACy :: MOV HI(...), Ymem
         * SS = ACx, DD = ACy, xss = Tx.
         */
        op->src = (b[2] >> 2) & 3;          /* ACx */
        op->dst = b[2] & 3;                 /* ACy */
        op->imm = (b[3] >> 2) & 7;          /* Tx */
        op->st = (b[3] >> 1) & 1;           /* T3 = Xmem */
        op->bit = b[3] & 1;                 /* round */
        op->cond = b[3] >> 5;
        if (op->cond == 3 || op->cond > 6) {
            return -1;
        }
        op->kind = C55X_OP_MAC_HI_Y;
        *len_out = 4;
        return 0;
    }
    if (op0 == 0x90) {
        if (avail < 2) {
            return -1;
        }
        op->kind = C55X_OP_MOV_XREG;
        op->src = b[1] >> 4;
        op->dst = b[1] & 0x0f;
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x91) {
        if (avail < 2) {
            return -1;
        }
        op->kind = C55X_OP_B_AC;
        op->src = b[1] & 3;
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x92) {
        if (avail < 2) {
            return -1;
        }
        op->kind = C55X_OP_CALL_AC;
        op->src = b[1] & 3;
        *len_out = 2;
        return 0;
    }
    if (op0 == 0x94) {
        op->kind = C55X_OP_RESET;
        *len_out = 2;
        return avail >= 2 ? 0 : -1;
    }
    if (op0 == 0x95) {
        if (avail < 2) {
            return -1;
        }
        op->kind = (b[1] & 0x80) ? C55X_OP_TRAP : C55X_OP_INTR;
        op->imm = b[1] & 0x1f;
        *len_out = 2;
        return 0;
    }
    /*
     * SPRU374: 10010110 / 10011110 / 10011111 + 0CCCCCCC = XCC,
     * same leads + 1CCCCCCC = XCCPART. The three leads are the
     * position-dependent parallel encodings of one instruction.
     */
    if (op0 == 0x96 || op0 == 0x9e || op0 == 0x9f) {
        if (avail < 2) {
            return -1;
        }
        op->cond = b[1] & 0x7f;
        op->kind = (b[1] & 0x80) ? C55X_OP_XCCPART : C55X_OP_XCC;
        *len_out = 2;
        return 0;
    }

    /*
     * Smem/Lmem: AAAAAAAI is the second byte. Remaining opcode bytes
     * follow it in table order; k16/k23 address extensions come after
     * the complete base opcode (SPRU374 size column + Table 6–2).
     */
    if (avail < 2) {
        return -1;
    }
    smem_field = b[1];
    ext = smem_ext_len(smem_field);
    if (lead < 2) {
        lead = 2;
    }
    need = lead + ext;
    if (avail < need) {
        return -1;
    }
    after_smem = b + 2;
    extra = (lead >= 3) ? b[2] : 0;
    if (parse_smem(smem_field, b + lead, &smem)) {
        return -1;
    }

    if ((op0 & 0xf0) == 0xa0) {
        need = 2 + ext;
        if (avail < need) {
            return -1;
        }
        op->kind = C55X_OP_MOV_SMEM_DST;
        op->dst = op0 & 0x0f;
        op->smem = smem;
        *len_out = need;
        return 0;
    }
    if ((op0 & 0xfc) == 0xb0) {
        /* SPRU374: 101100DD AAAAAAAI — MOV Smem << #16, ACx */
        need = 2 + ext;
        if (avail < need) {
            return -1;
        }
        op->kind = C55X_OP_MOV_SMEM_SHFT;
        op->smem = smem;
        op->dst = op0 & 3;
        op->shft = 16;
        *len_out = need;
        return 0;
    }
    if (op0 == 0xb4) {
        need = 2 + ext;
        if (avail < need) {
            return -1;
        }
        op->kind = C55X_OP_AMAR_SMEM;
        op->smem = smem;
        *len_out = need;
        return 0;
    }
    if (op0 == 0xb5) {
        need = 2 + ext;
        if (avail < need) {
            return -1;
        }
        op->kind = C55X_OP_PSH_SMEM;
        op->smem = smem;
        *len_out = need;
        return 0;
    }
    if (op0 == 0xb6) {
        need = 2 + ext;
        if (avail < need) {
            return -1;
        }
        op->kind = C55X_OP_DELAY;
        op->smem = smem;
        *len_out = need;
        return 0;
    }
    if (op0 == 0xb7) {
        /* SPRU374: 1011 0111 AAAAAAAI — PSH dbl(Lmem) */
        need = 2 + ext;
        if (avail < need) {
            return -1;
        }
        op->kind = C55X_OP_PSH_DBL_LMEM;
        op->smem = smem;
        *len_out = need;
        return 0;
    }
    if (op0 == 0xb8) {
        /* SPRU374: 1011 1000 AAAAAAAI — POP dbl(Lmem) */
        need = 2 + ext;
        if (avail < need) {
            return -1;
        }
        op->kind = C55X_OP_POP_DBL_LMEM;
        op->smem = smem;
        *len_out = need;
        return 0;
    }
    if (op0 == 0xbb) {
        need = 2 + ext;
        if (avail < need) {
            return -1;
        }
        op->kind = C55X_OP_POP_SMEM;
        op->smem = smem;
        *len_out = need;
        return 0;
    }
    if ((op0 & 0xfc) == 0xbc) {
        /* SPRU374: 101111SS AAAAAAAI — MOV HI(ACx), Smem */
        need = 2 + ext;
        if (avail < need) {
            return -1;
        }
        op->kind = C55X_OP_MOV_HI_SMEM;
        op->smem = smem;
        op->src = op0 & 3;
        *len_out = need;
        return 0;
    }
    if ((op0 & 0xf0) == 0xc0) {
        /* SPRU374: 1100FSSS AAAAAAAI is a 2-byte base; k23 follows Smem. */
        need = 2 + ext;
        if (avail < need || parse_smem(smem_field, b + 2, &smem)) {
            return -1;
        }
        op->kind = C55X_OP_MOV_SRC_SMEM;
        op->src = op0 & 0x0f;
        op->smem = smem;
        *len_out = need;
        return 0;
    }
    if (op0 == 0xd0 || op0 == 0xd1) {
        unsigned form;

        need = 3 + ext;
        if (avail < need) {
            return -1;
        }
        extra = after_smem[0];
        form = extra & 0x0c;
        op->smem = smem;
        op->dst = (extra >> 4) & 3;
        op->bit = (extra >> 6) & 1;
        op->st = extra >> 7;
        op->shft = extra & 3; /* mm */
        if (op0 == 0xd0) {
            op->kind = C55X_OP_MACMZ;
            *len_out = need;
            return 0;
        }
        if (form == 0x00) {
            op->kind = C55X_OP_MPYM_CMEM;
        } else if (form == 0x04) {
            op->kind = C55X_OP_MACM_CMEM;
        } else if (form == 0x08) {
            op->kind = C55X_OP_MASM_CMEM;
        } else {
            return -1;
        }
        *len_out = need;
        return 0;
    }
    if (op0 == 0xdc) {
        /* SPRU374: BTST k4, Smem, TCx (xxxx000x) or MOV Smem, ctl */
        need = 3 + ext;
        if (avail < need) {
            return -1;
        }
        extra = after_smem[0];
        op->smem = smem;
        if ((extra & 0x0e) == 0) {
            op->kind = C55X_OP_BTST_K4_SMEM;
            op->imm = extra >> 4;
            op->bit = extra & 1;
            *len_out = need;
            return 0;
        }
        op->kind = C55X_OP_MOV_SMEM_CTL;
        /* dis55 dc5912 MOV Smem,CDP; dc6103 CSR; dc5e13 BRC0 */
        if (parse_mov_smem_ctl_extra(extra, &op->dst)) {
            return -1;
        }
        *len_out = need;
        return 0;
    }
    if (op0 == 0xdd) {
        need = 3 + ext;
        if (avail < need) {
            return -1;
        }
        extra = after_smem[0];
        /*
         * Low 2 bits select the form (not bits 3:2):
         * 00 ADD, 01 SUB, 10 ADDSUB2CC, 11 MOV.
         * SSDDss.. : SS=ACx, DD=ACy, ss=Tx.
         */
        op->smem = smem;
        op->src = extra >> 6;
        op->dst = (extra >> 4) & 3;
        op->imm = (extra >> 2) & 3;
        op->bit = extra >> 7;
        if ((extra & 3) == 0) {
            op->kind = C55X_OP_ADD_SMEM;
            op->st = 1;
            op->cond = 3; /* Smem << Tx */
        } else if ((extra & 3) == 1) {
            op->kind = C55X_OP_SUB_SMEM;
            op->st = 1;
            op->cond = 3;
        } else if ((extra & 3) == 2) {
            op->kind = C55X_OP_ADDSUBCC;
            op->cond = 2; /* ADDSUB2CC */
        } else {
            op->kind = C55X_OP_MOV_SMEM_TX;
        }
        *len_out = need;
        return 0;
    }
    if (op0 == 0xde) {
        need = 3 + ext;
        if (avail < need) {
            return -1;
        }
        extra = after_smem[0];
        /*
         * Exact low nibble, SPRU374 11011110:
         * 0000/0001/0010 ADDSUBCC, 0011 SUBC,
         * 0100 ADD<<16, 0101 SUB<<16, 0110 reverse SUB,
         * 1000 ADDSUB, 1001 SUBADD.
         */
        op->smem = smem;
        op->dst = (extra >> 4) & 3;
        op->src = extra >> 6;
        op->imm = extra >> 6;
        switch (extra & 0x0f) {
        case 0x00:
            op->kind = C55X_OP_ADDSUBCC;
            op->cond = 0; /* TC1 */
            break;
        case 0x01:
            op->kind = C55X_OP_ADDSUBCC;
            op->cond = 1; /* TC2 */
            break;
        case 0x02:
            op->kind = C55X_OP_ADDSUBCC;
            op->cond = 3; /* TC1 and TC2 */
            break;
        case 0x03:
            op->kind = C55X_OP_SUBC;
            break;
        case 0x04:
            op->kind = C55X_OP_ADD_SMEM16;
            op->st = 0;
            break;
        case 0x05:
            op->kind = C55X_OP_ADD_SMEM16;
            op->st = 1;
            break;
        case 0x06:
            /* ACy = (Smem << #16) - ACx */
            op->kind = C55X_OP_ADD_SMEM16;
            op->st = 1;
            op->cond = 1;
            break;
        case 0x08:
            op->kind = C55X_OP_ADDSUB;
            op->cond = 0;
            break;
        case 0x09:
            op->kind = C55X_OP_SUBADD;
            op->cond = 0;
            break;
        default:
            return -1;
        }
        *len_out = need;
        return 0;
    }
    if (op0 == 0xd2 || op0 == 0xd3 || op0 == 0xd4 || op0 == 0xd5) {
        unsigned form;

        need = 3 + ext;
        if (avail < need) {
            return -1;
        }
        extra = after_smem[0];
        form = extra & 0x0c;
        op->smem = smem;
        op->dst = (extra >> 4) & 3;
        op->bit = (extra >> 6) & 1;
        op->st = extra >> 7;
        if (op0 == 0xd3) {
            if (extra & 4) {
                /* U%DDu1ss MPYM[R][U] Smem, Tx, ACx */
                op->kind = C55X_OP_MPYM;
                op->imm = extra & 3;
                op->src = 0xff;
                op->shft = (extra >> 3) & 1;
                *len_out = need;
                return 0;
            }
            if (form == 0x08) {
                op->kind = C55X_OP_SQRM;
                *len_out = need;
                return 0;
            }
            if (form == 0x00) {
                op->kind = C55X_OP_MPYM;
                op->src = extra & 3;
                op->imm = 0xff;
                op->shft = 0;
                *len_out = need;
                return 0;
            }
            return -1;
        }
        if (op0 == 0xd2) {
            op->src = extra & 3;
            op->imm = 0xff;
            if (form == 0x00) {
                op->kind = C55X_OP_MACM;
            } else if (form == 0x04) {
                op->kind = C55X_OP_MASM;
            } else if (form == 0x08) {
                op->kind = C55X_OP_SQAM;
            } else {
                op->kind = C55X_OP_SQSM;
            }
            *len_out = need;
            return 0;
        }
        /* 0xd4 MACM / 0xd5 MASM Smem, Tx, ACx, ACy */
        op->kind = (op0 == 0xd4) ? C55X_OP_MACM : C55X_OP_MASM;
        op->imm = (extra >> 2) & 3;
        op->src = extra & 3;
        *len_out = need;
        return 0;
    }
    if (op0 == 0xd6 || op0 == 0xd7 || op0 == 0xd8 ||
        op0 == 0xd9 || op0 == 0xda || op0 == 0xdb) {
        /* SPRU374: ADD/SUB/AND/OR/XOR Smem, [src,] dst; 0xd8 is SUB src, Smem */
        need = 3 + ext;
        if (avail < need) {
            return -1;
        }
        extra = after_smem[0];
        op->smem = smem;
        op->dst = extra >> 4;
        op->src = extra & 0x0f;
        if (op0 == 0xd6) {
            op->kind = C55X_OP_ADD_SMEM;
        } else if (op0 == 0xd7 || op0 == 0xd8) {
            op->kind = C55X_OP_SUB_SMEM;
            op->bit = (op0 == 0xd8);
        } else if (op0 == 0xd9) {
            op->kind = C55X_OP_AND_SMEM;
        } else if (op0 == 0xda) {
            op->kind = C55X_OP_OR_SMEM;
        } else {
            op->kind = C55X_OP_XOR_SMEM;
        }
        *len_out = need;
        return 0;
    }
    if (op0 == 0xdf) {
        unsigned form;

        need = 3 + ext;
        if (avail < need) {
            return -1;
        }
        extra = after_smem[0];
        form = extra & 0x0e;
        op->smem = smem;
        op->bit = extra & 1; /* uns */
        op->dst = (extra >> 4) & 3;
        op->src = (extra >> 6) & 3;
        /* SPRU374 11011111: byte MOV, uns MOV/ADD/SUB, CARRY/BORROW. */
        if (form == 0x00 || form == 0x02) {
            op->kind = C55X_OP_MOV_SMEM_DST;
            op->dst = extra >> 4;
            op->cond = (form == 0x00) ? 2 : 1; /* high / low byte */
            *len_out = need;
            return 0;
        }
        if (form == 0x04) {
            op->kind = C55X_OP_MOV_SMEM_AC;
            *len_out = need;
            return 0;
        }
        if (form == 0x08) {
            op->kind = C55X_OP_ADD_SMEM;
            op->st = 1;
            op->cond = 1; /* + CARRY */
            *len_out = need;
            return 0;
        }
        if (form == 0x0a) {
            op->kind = C55X_OP_SUB_SMEM;
            op->st = 1;
            op->cond = 1; /* − BORROW */
            *len_out = need;
            return 0;
        }
        if (form == 0x0c) {
            op->kind = C55X_OP_ADD_SMEM;
            op->st = 1;
            *len_out = need;
            return 0;
        }
        if (form == 0x0e) {
            op->kind = C55X_OP_SUB_SMEM;
            op->st = 1;
            *len_out = need;
            return 0;
        }
        return -1;
    }
    if (op0 == 0xe0) {
        /* SPRU374: 11100000 AAAAAAAI FSSSxxxt — BTST src, Smem, TCx */
        need = 3 + ext;
        if (avail < need) {
            return -1;
        }
        extra = after_smem[0];
        op->kind = C55X_OP_BTST_SRC_SMEM;
        op->smem = smem;
        op->src = extra >> 4;
        op->bit = extra & 1;
        *len_out = need;
        return 0;
    }
    if (op0 == 0xe4) {
        /* SPRU374: 11100100 FSSSx0xx PSH src,Smem / FDDDx1xx POP dst,Smem */
        need = 3 + ext;
        if (avail < need) {
            return -1;
        }
        extra = after_smem[0];
        op->smem = smem;
        if (extra & 0x04) {
            op->kind = C55X_OP_POP_DST_SMEM;
            op->dst = extra >> 4;
        } else {
            op->kind = C55X_OP_PSH_SRC_SMEM;
            op->src = extra >> 4;
        }
        *len_out = need;
        return 0;
    }
    if (op0 == 0xfc) {
        /* SPRU374: 11111100 AAAAAAAI L16 — BCC L16, ARn_mod != #0 */
        need = 4 + ext;
        if (avail < need) {
            return -1;
        }
        op->kind = C55X_OP_BCC_ARN;
        op->smem = smem;
        op->imm = (int16_t)be16(after_smem);
        *len_out = need;
        return 0;
    }
    if (op0 == 0xe1 || op0 == 0xe2) {
        need = 3 + ext;
        if (avail < need) {
            return -1;
        }
        extra = after_smem[0];
        op->kind = C55X_OP_MOV_AC_SHFT_SMEM;
        op->smem = smem;
        op->src = extra >> 6;
        op->shft = extra & 0x3f;
        op->cond = 1; /* byte */
        op->bit = (op0 == 0xe2);
        *len_out = need;
        return 0;
    }
    if (op0 == 0xe5) {
        need = 3 + ext;
        if (avail < need) {
            return -1;
        }
        extra = after_smem[0];
        op->smem = smem;
        if ((extra & 0x0c) == 0x04) {
            /* SPRU374: FSSS01x0/01x1 MOV src, high/low_byte(Smem) */
            op->kind = C55X_OP_MOV_SRC_SMEM;
            op->src = extra >> 4;
            op->cond = (extra & 1) ? 1 : 2;
        } else if ((extra & 0x0c) == 0x08) {
            static const uint8_t ctl[] = {
                C55X_CTL_DP, C55X_CTL_CDP, C55X_CTL_BSA01, C55X_CTL_BSA23,
                C55X_CTL_BSA45, C55X_CTL_BSA67, C55X_CTL_BSAC, C55X_CTL_SP,
                C55X_CTL_SSP, C55X_CTL_BK03, C55X_CTL_BK47, C55X_CTL_BKC,
                C55X_CTL_DPH, 0xff, 0xff, C55X_CTL_PDP
            };
            unsigned hi = extra >> 4;

            if (hi >= sizeof(ctl) || ctl[hi] == 0xff) {
                return -1;
            }
            op->kind = C55X_OP_MOV_CTL_SMEM;
            op->src = ctl[hi];
        } else if ((extra & 0x0c) == 0x0c) {
            static const uint8_t ctl[] = {
                C55X_CTL_CSR, C55X_CTL_BRC0, C55X_CTL_BRC1, C55X_CTL_TRN0,
                C55X_CTL_TRN1
            };
            unsigned hi = extra >> 4;

            if (hi >= sizeof(ctl)) {
                return -1;
            }
            op->kind = C55X_OP_MOV_CTL_SMEM;
            op->src = ctl[hi];
        } else {
            return -1;
        }
        *len_out = need;
        return 0;
    }
    if (op0 == 0xe7 || op0 == 0xe8) {
        need = 3 + ext;
        if (avail < need) {
            return -1;
        }
        extra = after_smem[0];
        op->kind = C55X_OP_MOV_HI_AC_SHFT_SMEM;
        op->smem = smem;
        op->src = extra >> 6;
        op->shft = extra & 0x3f;
        op->st = (op0 == 0xe7) ? 1 : 2;
        *len_out = need;
        return 0;
    }
    if (op0 == 0xfa) {
        /* SPRU374: AAAAAAAI xxSHIFTW SSxxx0x% / uxSHIFTW SSxxx1x%. */
        need = 4 + ext;
        if (avail < need) {
            return -1;
        }
        extra = after_smem[1];
        op->kind = C55X_OP_MOV_HI_AC_SHFT_SMEM;
        op->smem = smem;
        op->src = extra >> 6;
        op->shft = after_smem[0] & 0x3f;
        op->bit = (after_smem[0] >> 7) & 1; /* uns on the saturate form */
        /* bit2 selects saturate; % (bit0) selects round. */
        op->st = ((extra & 0x04) ? 2 : 0) | ((extra & 1) ? 1 : 0);
        *len_out = need;
        return 0;
    }
    if (op0 == 0xe3) {
        unsigned form;

        need = 3 + ext;
        if (avail < need) {
            return -1;
        }
        extra = after_smem[0];
        form = extra & 0x0e;
        op->smem = smem;
        if (form <= 0x0a) {
            /* SPRU374: kkkk000/001 SET, 010/011 CLR, 100/101 NOT. */
            op->kind = C55X_OP_BTST_K4_SMEM;
            op->imm = extra >> 4;
            op->bit = extra & 1;
            op->st = (form >> 2) + 1;
            *len_out = need;
            return 0;
        }
        op->src = extra >> 4;
        if ((extra & 0x0f) == 0x0c) {
            op->kind = C55X_OP_BSET_SMEM;
        } else if ((extra & 0x0f) == 0x0d) {
            op->kind = C55X_OP_BCLR_SMEM;
        } else if (form == 0x0e) {
            op->kind = C55X_OP_BNOT_SMEM;
        } else {
            return -1;
        }
        *len_out = need;
        return 0;
    }
    if (op0 == 0xea) {
        /*
         * SPRU374: 1110 1010 AAAAAAAI SS0SHIFTW —
         * MOV HI(ACx << #SHIFTW), Smem (dis55 ea4303 / ea2600).
         * Vector-table .ivec is 4 bytes and is handled in c55x_decode.
         */
        need = 3 + ext;
        if (avail < need) {
            return -1;
        }
        extra = after_smem[0];
        op->kind = C55X_OP_MOV_HI_AC_SHFT_SMEM;
        op->smem = smem;
        op->src = extra >> 6;
        op->shft = extra & 0x3f;
        *len_out = need;
        return 0;
    }
    if (op0 == 0xe9) {
        /* SPRU374: 11101001 AAAAAAAI SSSHIFTW — MOV ACx << #SHIFTW, Smem */
        need = 3 + ext;
        if (avail < need) {
            return -1;
        }
        extra = after_smem[0];
        op->kind = C55X_OP_MOV_AC_SHFT_SMEM;
        op->smem = smem;
        op->src = extra >> 6;
        op->shft = extra & 0x3f;
        *len_out = need;
        return 0;
    }
    if (op0 == 0xf0 || op0 == 0xf1) {
        /* SPRU374: CMP Smem == K16, TC1 / TC2 */
        need = 4 + ext;
        if (avail < need) {
            return -1;
        }
        op->kind = C55X_OP_CMP_SMEM_K16;
        op->smem = smem;
        op->imm = (int16_t)be16(after_smem);
        op->bit = (op0 == 0xf1);
        *len_out = need;
        return 0;
    }
    if (op0 == 0xf2 || op0 == 0xf3) {
        /* SPRU374: BAND Smem, k16, TC1 / TC2 */
        need = 4 + ext;
        if (avail < need) {
            return -1;
        }
        op->kind = C55X_OP_BAND;
        op->smem = smem;
        op->imm = (int16_t)be16(after_smem);
        op->bit = (op0 == 0xf3);
        *len_out = need;
        return 0;
    }
    if (op0 == 0xe6) {
        need = 3 + ext;
        if (avail < need) {
            return -1;
        }
        op->kind = C55X_OP_MOV_K8_SMEM;
        op->smem = smem;
        op->imm = (int8_t)after_smem[0];
        *len_out = need;
        return 0;
    }
    if (op0 == 0xf9) {
        unsigned form;

        need = 4 + ext;
        if (avail < need) {
            return -1;
        }
        extra = after_smem[1];
        form = extra & 0x0c;
        op->smem = smem;
        op->src = extra >> 6;
        op->dst = (extra >> 4) & 3;
        op->shft = after_smem[0] & 0x3f;
        op->bit = (after_smem[0] >> 7) & 1; /* uns */
        if (form == 0x00) {
            op->kind = C55X_OP_ADD_SMEM;
            op->st = 1;
            op->cond = 2;
        } else if (form == 0x04) {
            op->kind = C55X_OP_SUB_SMEM;
            op->st = 1;
            op->cond = 2;
        } else if (form == 0x08) {
            op->kind = C55X_OP_MOV_SMEM_SHFT;
        } else {
            return -1;
        }
        *len_out = need;
        return 0;
    }
    if (op0 == 0xfb) {
        need = 4 + ext;
        if (avail < need) {
            return -1;
        }
        op->kind = C55X_OP_MOV_K16_SMEM;
        op->smem = smem;
        op->imm = (int16_t)be16(after_smem);
        *len_out = need;
        return 0;
    }
    if (op0 == 0xf8) {
        /*
         * SPRU374 / dis55: 1111 1000 AAAAAAAI k8 SSDD xmtR
         *   bit2 m = 0 MPYMK / 1 MACMK
         *   bit1 t = T3 = Smem
         *   bit0 R = round (MPYMKR/MACMKR); unused in avs.dis
         * Stock `f831240009d06c` at 0x1298ee is
         * `MPYMK *(#09d06ch), #36, AC0`.
         */
        need = 4 + ext;
        if (avail < need) {
            return -1;
        }
        extra = after_smem[1];
        if (extra & 0x09) {
            return -1;
        }
        op->smem = smem;
        op->imm = (int8_t)after_smem[0];
        op->src = extra >> 6;
        op->dst = (extra >> 4) & 3;
        op->bit = (extra >> 1) & 1;
        op->kind = (extra & 0x04) ? C55X_OP_MACMK : C55X_OP_MPYMK;
        *len_out = need;
        return 0;
    }
    if (op0 == 0xf4) {
        need = 4 + ext;
        if (avail < need) {
            return -1;
        }
        op->kind = C55X_OP_AND_K16_SMEM;
        op->smem = smem;
        op->imm = (int16_t)be16(after_smem);
        *len_out = need;
        return 0;
    }
    if (op0 == 0xf5) {
        need = 4 + ext;
        if (avail < need) {
            return -1;
        }
        op->kind = C55X_OP_OR_K16_SMEM;
        op->smem = smem;
        op->imm = (int16_t)be16(after_smem);
        *len_out = need;
        return 0;
    }
    if (op0 == 0xf6) {
        need = 4 + ext;
        if (avail < need) {
            return -1;
        }
        op->kind = C55X_OP_XOR_K16_SMEM;
        op->smem = smem;
        op->imm = (int16_t)be16(after_smem);
        *len_out = need;
        return 0;
    }
    if (op0 == 0xf7) {
        need = 4 + ext;
        if (avail < need) {
            return -1;
        }
        op->kind = C55X_OP_ADD_K16_SMEM;
        op->smem = smem;
        op->imm = (int16_t)be16(after_smem);
        *len_out = need;
        return 0;
    }
    if (op0 == 0xec) {
        need = 3 + ext;
        if (avail < need) {
            return -1;
        }
        extra = after_smem[0];
        op->src = extra >> 4;
        op->dst = extra >> 4;
        op->smem = smem;
        if ((extra & 0x0f) == 0x0c) {
            op->kind = C55X_OP_MOV_PAIR_DBL;
            *len_out = need;
            return 0;
        }
        switch (extra & 0x0e) {
        case 0x00:
            op->kind = C55X_OP_BSET_BADDR;
            break;
        case 0x02:
            op->kind = C55X_OP_BCLR_BADDR;
            break;
        case 0x04:
            /* SPRU374: FSSS010x — BTSTP Baddr, src */
            op->kind = C55X_OP_BTST_BADDR;
            op->st = 1;
            op->bit = extra & 1;
            break;
        case 0x06:
            op->kind = C55X_OP_BNOT_BADDR;
            break;
        case 0x08:
            op->kind = C55X_OP_BTST_BADDR;
            op->bit = extra & 1;
            break;
        case 0x0e:
            if ((extra & 0x0f) != 0x0e) {
                return -1;
            }
            op->kind = C55X_OP_AMAR_XDST;
            break;
        default:
            return -1;
        }
        *len_out = need;
        return 0;
    }
    if (op0 == 0xeb) {
        static const struct {
            uint8_t mask;
            uint8_t value;
            C55xOpKind kind;
        } forms[] = {
            /* dis55: RETA is extra 0x04 only; XSSS0101 is MOV XARn/XSP. */
            { 0x0f, 0x04, C55X_OP_MOV_RETA_DBL }, /* 00000100 */
            { 0x0f, 0x05, C55X_OP_MOV_XREG_DBL }, /* XSSS0101 */
            { 0x0c, 0x08, C55X_OP_MOV_AC_DBL },   /* xxSS10xx sat/plain */
            { 0x0f, 0x0c, C55X_OP_MOV_PAIR_DBL }, /* FSSS1100 */
            { 0x0f, 0x0d, C55X_OP_MOV_AC_DBL },   /* xxSS1101 ACx >> #1 */
            { 0x0f, 0x0e, C55X_OP_MOV_AC_DBL },   /* pair(HI) */
            { 0x0f, 0x0f, C55X_OP_MOV_AC_DBL },   /* pair(LO) */
        };
        unsigned i;

        need = 3 + ext;
        if (avail < need) {
            return -1;
        }
        extra = after_smem[0];
        op->smem = smem;
        for (i = 0; i < sizeof(forms) / sizeof(forms[0]); i++) {
            if ((extra & forms[i].mask) == forms[i].value) {
                op->kind = forms[i].kind;
                if (op->kind == C55X_OP_MOV_AC_DBL) {
                    op->src = (extra >> 4) & 3;
                } else if (op->kind == C55X_OP_MOV_XREG_DBL ||
                           op->kind == C55X_OP_MOV_PAIR_DBL) {
                    op->src = extra >> 4;
                }
                *len_out = need;
                return 0;
            }
        }
        return -1;
    }
    if (op0 == 0xed) {
        /* Most-specific mask first so xxxx011x cannot swallow XDDD1111. */
        static const struct {
            uint8_t mask;
            uint8_t value;
            C55xOpKind kind;
        } forms[] = {
            { 0x0f, 0x0f, C55X_OP_MOV_DBL_XDST }, /* XDDD1111 */
            { 0x0f, 0x0e, C55X_OP_MOV_DBL_PAIR }, /* XDDD1110 */
            { 0x0e, 0x0c, C55X_OP_MOV_DBL_PAIR }, /* xxDD110x pair(LO) */
            { 0x0e, 0x0a, C55X_OP_MOV_DBL_PAIR }, /* xxDD101x pair(HI) */
            { 0x0f, 0x06, C55X_OP_MOV_DBL_RETA }, /* 00000110 */
            { 0x0e, 0x08, C55X_OP_MOV_DBL_AC },   /* xxDD100g */
            { 0x0e, 0x00, C55X_OP_ADD_DBL_AC },   /* SSDD000n */
            { 0x0e, 0x02, C55X_OP_SUB_DBL_AC },   /* SSDD001n */
            { 0x0e, 0x04, C55X_OP_RSUB_DBL_AC },  /* SSDD010x */
        };
        unsigned i;

        extra = after_smem[0];
        need = 3 + ext;
        if (avail < need) {
            return -1;
        }
        op->smem = smem;
        for (i = 0; i < sizeof(forms) / sizeof(forms[0]); i++) {
            if ((extra & forms[i].mask) == forms[i].value) {
                op->kind = forms[i].kind;
                if (op->kind == C55X_OP_MOV_DBL_XDST ||
                    op->kind == C55X_OP_MOV_DBL_PAIR) {
                    op->dst = extra >> 4;
                    if (op->kind == C55X_OP_MOV_DBL_PAIR) {
                        /* 101x pair(HI), 110x pair(LO), 111x pair(TAx). */
                        if ((extra & 0x0e) == 0x0e) {
                            op->cond = 2;
                        } else if ((extra & 0x0e) == 0x0c) {
                            op->cond = 1;
                        } else {
                            op->cond = 0;
                        }
                    }
                } else {
                    op->src = extra >> 6;
                    op->dst = (extra >> 4) & 3;
                    if (op->kind == C55X_OP_MOV_DBL_AC) {
                        op->bit = extra & 1; /* g: MOV[40] */
                    }
                }
                *len_out = need;
                return 0;
            }
        }
        return -1;
    }
    if (op0 == 0xee) {
        /* SPRU374 / dis55: ADD/SUB dual(Lmem), ACx, ACy */
        extra = after_smem[0];
        need = 3 + ext;
        if (avail < need) {
            return -1;
        }
        op->smem = smem;
        op->src = extra >> 6;
        op->dst = (extra >> 4) & 3;
        op->imm = extra >> 6;
        if ((extra & 0x0e) == 0x00) {
            op->kind = C55X_OP_ADD_DBL_AC;
        } else if ((extra & 0x0e) == 0x02) {
            op->kind = C55X_OP_SUB_DBL_AC;
        } else if ((extra & 0x0e) == 0x04) {
            /* SUB ACx, dual(Lmem), ACy → ACy = dual - ACx */
            op->kind = C55X_OP_RSUB_DBL_AC;
        } else if ((extra & 0x0e) == 0x06) {
            op->kind = C55X_OP_ADDSUB;
            op->cond = 1;
            op->bit = 0; /* Tx - each half */
        } else if ((extra & 0x0e) == 0x08) {
            op->kind = C55X_OP_ADDSUB;
            op->cond = 1;
            op->bit = 1; /* each half + Tx */
        } else if ((extra & 0x0e) == 0x0a) {
            op->kind = C55X_OP_ADDSUB;
            op->cond = 1;
            op->bit = 2; /* each half - Tx */
        } else if ((extra & 0x0e) == 0x0c) {
            op->kind = C55X_OP_ADDSUB;
            op->cond = 1;
            op->bit = 3; /* HI + Tx, LO - Tx */
        } else {
            op->kind = C55X_OP_SUBADD;
            op->cond = 1;
            op->bit = 4; /* HI - Tx, LO + Tx */
        }
        *len_out = need;
        return 0;
    }
    if (op0 == 0xef) {
        /*
         * SPRU374 bits [3:2]:
         * 00 MOV Cmem, Smem  01 MOV Smem, Cmem
         * 10 MOV Cmem, dbl   11 MOV dbl, Cmem
         * mm is extra[1:0].
         */
        extra = after_smem[0];
        need = 3 + ext;
        if (avail < need) {
            return -1;
        }
        op->kind = C55X_OP_MOV_SMEM_CMEM;
        op->smem = smem;
        op->shft = extra & 3;
        op->cond = (extra >> 2) & 3;
        *len_out = need;
        return 0;
    }

    (void)packet;
    return -1;
}

/*
 * SPRU374 Table 5–1 A-unit ops are 0001010E (0x14/0x15). Packed
 * 0x8a/0x8e packets store the same low-3-bit kind in Aop 0001 0xxx:
 *   x000 AADD TAx    x001 AMOV TAx    x010 ASUB TAx
 *   x100 AADD #k8    x101 AMOV #k8    x110 ASUB #k8
 * Register last-byte: FSSSxxxx, bit0 = 23-bit XAR (dis55).
 */
static int aunit_aop_ok(uint8_t aop)
{
    unsigned kind = aop & 7;

    return ((aop & 0xf0) == 0x10) && kind != 3 && kind != 7;
}

static int decode_aunit_aop(uint8_t aop, uint8_t last, unsigned dest,
                            C55xOp *op)
{
    unsigned kind = aop & 7;

    op->dst = tax_fsss(dest);
    switch (kind) {
    case 0:
        op->kind = C55X_OP_AADD_TAX;
        break;
    case 1:
        op->kind = C55X_OP_AMOV_TAX;
        break;
    case 2:
        op->kind = C55X_OP_ASUB_TAX;
        break;
    case 4:
        op->kind = C55X_OP_AADD_K8_TAX;
        op->imm = (int8_t)last;
        return 0;
    case 5:
        op->kind = C55X_OP_AMOV_K8_TAX;
        op->imm = (int8_t)last;
        return 0;
    case 6:
        op->kind = C55X_OP_ASUB_K8_TAX;
        op->imm = (int8_t)last;
        return 0;
    default:
        return -1;
    }
    if (last & 0x0e) {
        return -1;
    }
    op->src = tax_fsss(last >> 4);
    op->bit = last & 1;
    return 0;
}

/*
 * TI dis55: 8b6680ebb5 at _EAP_processNetwork 0x12ca54 is
 *   MOV *AR3+ << #16, AC0 || MOV XAR3, dbl(*AR5)
 * Byte1 is Xmem (not AAAAAAAI; 0x66 would be direct @0x33).
 * Byte2 0x80 is <<#16 into AC0. Byte3 0xeb / byte4 0xb5 are the
 * standalone EB extra XSSS0101 (MOV XAR3) with Lmem *AR5, the
 * list head that processNetwork just loaded (eda1bf).
 */
static int decode_8b_sh16_xar_dbl(const uint8_t *b, unsigned avail,
                                  C55xDecodedInsn *out)
{
    C55xSmem smem, lmem;

    if (avail < 5 || b[2] != 0x80 || b[3] != 0xeb ||
        (b[4] & 0x0f) != 0x05) {
        return -1;
    }
    if (parse_xmem((b[1] >> 5) & 7, (b[1] >> 2) & 7, &smem)) {
        return -1;
    }
    memset(&lmem, 0, sizeof(lmem));
    lmem.kind = C55X_AM_AR;
    lmem.ar = 5;
    lmem.mod = C55X_MOD_NONE;
    out->op[0].kind = C55X_OP_MOV_SMEM_SHFT;
    out->op[0].smem = smem;
    out->op[0].dst = 0;
    out->op[0].shft = 16;
    out->op[1].kind = C55X_OP_MOV_XREG_DBL;
    out->op[1].smem = lmem;
    out->op[1].src = b[4] >> 4;
    out->op_count = 2;
    out->length = 5;
    return 0;
}

/*
 * TI dis55 v4.2.3: 0x8a is MOV Smem, dst || A-unit (5 bytes).
 *   8a Smem (Adest:4 Mdest:4) Aop last
 * Stock 8a00ba18a1 at 0x126443 is
 *   MOV *SP(#00h), AR2 || AADD XAR2, XAR3
 * 4-byte 8a is soft-dual MOV Xmem || MOV Ymem (decode_8a_dual).
 */
static int decode_8a_pair(const uint8_t *b, unsigned avail,
                          C55xDecodedInsn *out)
{
    C55xSmem smem;

    if (avail < 5 || !aunit_aop_ok(b[3]) || smem_ext_len(b[1]) ||
        parse_smem(b[1], b + 5, &smem)) {
        return -1;
    }
    out->op[0].kind = C55X_OP_MOV_SMEM_DST;
    out->op[0].smem = smem;
    out->op[0].dst = b[2] & 0x0f;
    if (decode_aunit_aop(b[3], b[4], b[2] >> 4, &out->op[1])) {
        return -1;
    }
    out->op_count = 2;
    out->length = 5;
    return 0;
}

/*
 * Soft-dual 4-byte 0x8a (SPRU374 Rule 2 / Xmem,Ymem):
 *   8a XXXMMMYY YMMMdddd hhhhssss
 *   h=0xa MOV Ymem, dst    h=0xc MOV src, Ymem
 * Stock 8a6b99a4 is MOV *AR3-,AR1 || MOV *AR7+,T0.
 */
static int decode_8a_dual(const uint8_t *b, unsigned avail,
                          C55xDecodedInsn *out)
{
    unsigned packed;
    C55xSmem xmem, ymem;
    unsigned dest1, dest2, hi;

    if (avail < 4) {
        return -1;
    }
    packed = ((unsigned)b[1] << 8) | b[2];
    if (parse_xmem(packed >> 13, (packed >> 10) & 7, &xmem) ||
        parse_xmem((packed >> 7) & 7, (packed >> 4) & 7, &ymem)) {
        return -1;
    }
    dest1 = packed & 0x0f;
    dest2 = b[3] & 0x0f;
    hi = b[3] >> 4;
    out->op[0].kind = C55X_OP_MOV_SMEM_DST;
    out->op[0].smem = xmem;
    out->op[0].dst = dest1;
    if (hi == 0x0a) {
        out->op[1].kind = C55X_OP_MOV_SMEM_DST;
        out->op[1].smem = ymem;
        out->op[1].dst = dest2;
    } else if (hi == 0x0c) {
        out->op[1].kind = C55X_OP_MOV_SRC_SMEM;
        out->op[1].smem = ymem;
        out->op[1].src = dest2;
    } else {
        return -1;
    }
    out->op_count = 2;
    out->length = 4;
    return 0;
}

/*
 * TI dis55: 5-byte 0x8d is MOV Xmem, ctl || MOV Ymem, dst when
 * the 8a-style dest nibble is 0xc (ctl extra in byte4).
 * Stock 8d7f9ca903 at _SRC_TII_asmDoubleStageConvert 0x136128
 * is MOV *AR3(T0),CSR || MOV *AR7+,AR1.
 */
static int decode_8d_xy_ctl(const uint8_t *b, unsigned avail,
                            C55xDecodedInsn *out)
{
    unsigned packed;
    C55xSmem xmem, ymem;
    uint8_t ctl;

    if (b[0] != 0x8d || avail < 5) {
        return -1;
    }
    packed = ((unsigned)b[1] << 8) | b[2];
    if ((packed & 0x0f) != 0x0c || (b[3] >> 4) != 0x0a ||
        parse_xmem(packed >> 13, (packed >> 10) & 7, &xmem) ||
        parse_xmem((packed >> 7) & 7, (packed >> 4) & 7, &ymem) ||
        parse_mov_smem_ctl_extra(b[4], &ctl)) {
        return -1;
    }
    out->op[0].kind = C55X_OP_MOV_SMEM_CTL;
    out->op[0].smem = xmem;
    out->op[0].dst = ctl;
    out->op[1].kind = C55X_OP_MOV_SMEM_DST;
    out->op[1].smem = ymem;
    out->op[1].dst = b[3] & 0x0f;
    out->op_count = 2;
    out->length = 5;
    return 0;
}

/*
 * TI dis55: 4-byte 0x8c is MOV src, Xmem || MOV src, Ymem when
 * byte3[7:4] is 0xc (same XXXMMMYY YMMMssss packing as 0x8a dual).
 * Stock 8c6615c0 at 0x12a43e is MOV T1,*AR3+ || MOV AC0,*AR4+.
 */
static int decode_8c_dual(const uint8_t *b, unsigned avail,
                          C55xDecodedInsn *out)
{
    unsigned packed;
    C55xSmem xmem, ymem;

    if (avail < 4 || (b[3] >> 4) != 0x0c) {
        return -1;
    }
    packed = ((unsigned)b[1] << 8) | b[2];
    if (parse_xmem(packed >> 13, (packed >> 10) & 7, &xmem) ||
        parse_xmem((packed >> 7) & 7, (packed >> 4) & 7, &ymem)) {
        return -1;
    }
    out->op[0].kind = C55X_OP_MOV_SRC_SMEM;
    out->op[0].smem = xmem;
    out->op[0].src = packed & 0x0f;
    out->op[1].kind = C55X_OP_MOV_SRC_SMEM;
    out->op[1].smem = ymem;
    out->op[1].src = b[3] & 0x0f;
    out->op_count = 2;
    out->length = 4;
    return 0;
}

/*
 * TI dis55: 6-byte 0x8d D-unit || A-unit. Byte2 low nibble is
 * the D-unit klass; byte4 is the D-unit extra; byte5 is A-unit
 * last. Named klasses in _SRC_TII_asmDoubleStageConvert:
 *   0xc  MOV Smem, ctl (ctl extra as 0xdc)
 *        8d6bbc180370 MOV *AR3(T0),CSR || AADD T3,AR3
 *        8d6bbc1a1270 MOV *AR3(T0),CDP || ASUB T3,AR3
 *   0x7  SUB Smem, src, dst (extra as 0xd7)
 *        8de3e7194490 SUB *AR7+,T0,T0 || AMOV AR1,AR6
 *   0x6  ADD Smem, src, dst (extra as 0xd6)
 *        8de3b61a4480 ADD *AR7+,T0,T0 || ASUB AR0,AR3
 * Other 8d klasses stay UNDEF.
 */
static int decode_8c_smem_ctl_aunit(const uint8_t *b, unsigned avail,
                                    C55xDecodedInsn *out)
{
    C55xSmem smem;
    unsigned klass = b[2] & 0x0f;
    uint8_t ctl;

    if (avail < 6 || !aunit_aop_ok(b[3]) ||
        smem_ext_len(b[1]) || parse_smem(b[1], b + 6, &smem)) {
        return -1;
    }
    if (klass == 0x0c) {
        if (parse_mov_smem_ctl_extra(b[4], &ctl)) {
            return -1;
        }
        out->op[0].kind = C55X_OP_MOV_SMEM_CTL;
        out->op[0].smem = smem;
        out->op[0].dst = ctl;
    } else if (b[0] == 0x8d && klass == 0x07) {
        out->op[0].kind = C55X_OP_SUB_SMEM;
        out->op[0].smem = smem;
        out->op[0].dst = b[4] >> 4;
        out->op[0].src = b[4] & 0x0f;
    } else if (b[0] == 0x8d && klass == 0x06) {
        out->op[0].kind = C55X_OP_ADD_SMEM;
        out->op[0].smem = smem;
        out->op[0].dst = b[4] >> 4;
        out->op[0].src = b[4] & 0x0f;
    } else {
        return -1;
    }
    if (decode_aunit_aop(b[3], b[5], b[2] >> 4, &out->op[1])) {
        return -1;
    }
    out->op_count = 2;
    out->length = 6;
    return 0;
}

/*
 * TI dis55: 0x8c is MOV src, Smem || A-unit (5 bytes).
 *   8c Smem (Adest:4 Msrc:4) Aop last
 * Stock 8c04f910c0 is MOV AR1,*SP(#02h) || AADD AR4,AR7.
 */
static int decode_8c_pair(const uint8_t *b, unsigned avail,
                          C55xDecodedInsn *out)
{
    C55xSmem smem;

    if (avail < 5 || !aunit_aop_ok(b[3]) || smem_ext_len(b[1]) ||
        parse_smem(b[1], b + 5, &smem)) {
        return -1;
    }
    out->op[0].kind = C55X_OP_MOV_SRC_SMEM;
    out->op[0].smem = smem;
    out->op[0].src = b[2] & 0x0f;
    if (decode_aunit_aop(b[3], b[4], b[2] >> 4, &out->op[1])) {
        return -1;
    }
    out->op_count = 2;
    out->length = 5;
    return 0;
}

/*
 * TI dis55 v4.2.3: 0x8e is a 6-byte built-in packet.
 *   8e Smem dest:class Aop src k
 *   class 0xb = MOV src, dbl(Smem)
 *   class 0xd = MOV dbl(Smem), ACx (A-unit Aops, or D||D when Aop is 0xeb)
 *   class 0x6 = MOV #k8, Smem
 * Other 8e classes stay UNDEF; do not invent them.
 *
 * Stock 8ee33deb3808 at 0x1347cd is not D||A. Byte3 0xeb is SPRU374
 * MOV ACx, dbl(Lmem), packed as Xmem/Ymem (same XXXMMMYY YMMM layout
 * as 0x8a/0x8c/0x8f). dis55:
 *   MOV dbl(*AR7),AC3 || MOV AC0,dbl(*(AR6+T0))
 */
static int decode_8e_pair(const uint8_t *b, unsigned avail,
                          C55xDecodedInsn *out)
{
    C55xSmem smem, xmem, ymem;
    unsigned src, dest, klass, aop;

    if (avail < 6) {
        return -1;
    }
    dest = b[2] >> 4;
    klass = b[2] & 0x0f;
    aop = b[3];
    src = b[4] >> 4;
    if (klass == 0x0d && aop == 0xeb) {
        unsigned form = b[4] & 0x0e;
        unsigned ssdd = b[4] >> 4;
        uint8_t extra = b[5];

        if (parse_8f_xmem_ymem(b[1], b[2], &xmem, &ymem)) {
            return -1;
        }
        /*
         * Xmem MMM=011 is dis55 *(ARn+T0) (indexed). parse_xmem maps
         * that to INDEX; keep a remap if an older PLUS encoding reaches
         * here. MMM=100 is ARMS-dual in this pack (C55X_MOD_ARMS_T1):
         * ARMS=0 post *ARn+T1 (mumdrc 134d16 with T1=8), ARMS=1
         * *ARn(short(#1)) (resynthesize 134904 with T1=1). Soft-dual
         * 0x80 XY *(ARn+T1) stays plain INDEX via parse_xmem.
         */
        if (xmem.mod == C55X_MOD_PLUS_T0) {
            xmem.mod = C55X_MOD_INDEX_T0;
        }
        if (ymem.mod == C55X_MOD_PLUS_T0) {
            ymem.mod = C55X_MOD_INDEX_T0;
        }
        if (xmem.mod == C55X_MOD_INDEX_T1 || xmem.mod == C55X_MOD_PLUS_T1) {
            xmem.mod = C55X_MOD_ARMS_T1;
        }
        if (ymem.mod == C55X_MOD_INDEX_T1 || ymem.mod == C55X_MOD_PLUS_T1) {
            ymem.mod = C55X_MOD_ARMS_T1;
        }
        if ((extra & 0x0d) != 0x08) {
            return -1;
        }
        out->op[0].smem = xmem;
        out->op[0].src = (ssdd >> 2) & 3;
        out->op[0].dst = ssdd & 3;
        if (form == 0x08) {
            out->op[0].kind = C55X_OP_MOV_DBL_AC;
        } else if (form == 0x00) {
            out->op[0].kind = C55X_OP_ADD_DBL_AC;
        } else if (form == 0x02) {
            out->op[0].kind = C55X_OP_SUB_DBL_AC;
        } else if (form == 0x04) {
            out->op[0].kind = C55X_OP_RSUB_DBL_AC;
        } else {
            return -1;
        }
        out->op[1].kind = C55X_OP_MOV_AC_DBL;
        out->op[1].src = (extra >> 4) & 3;
        out->op[1].smem = ymem;
        out->op_count = 2;
        out->length = 6;
        return 0;
    }
    if (smem_ext_len(b[1]) || parse_smem(b[1], b + 6, &smem)) {
        return -1;
    }
    if (klass != 0x0b && klass != 0x06 && klass != 0x0d) {
        return -1;
    }
    if (!aunit_aop_ok(aop)) {
        return -1;
    }
    out->op[0].smem = smem;
    if (klass == 0x0b) {
        out->op[0].src = src;
        if (src < 4) {
            out->op[0].kind = C55X_OP_MOV_AC_DBL;
        } else if (src >= 8) {
            out->op[0].kind = C55X_OP_MOV_XREG_DBL;
        } else {
            return -1;
        }
    } else if (klass == 0x0d) {
        unsigned form = b[4] & 0x0e;
        unsigned ssdd = b[4] >> 4;

        /*
         * SPRU374 dbl(Lmem) ALU + A-unit. Byte4 low nibble selects
         * the D-unit (dis55): x000 ADD, x010 SUB, x100 SUB ACx,dbl,
         * x1000 MOV dbl. Aop 0x1e is still ASUB #k when form is MOV.
         */
        out->op[0].src = (ssdd >> 2) & 3;
        out->op[0].dst = ssdd & 3;
        if (form == 0x08) {
            out->op[0].kind = C55X_OP_MOV_DBL_AC;
        } else if (form == 0x00) {
            out->op[0].kind = C55X_OP_ADD_DBL_AC;
        } else if (form == 0x02) {
            out->op[0].kind = C55X_OP_SUB_DBL_AC;
        } else if (form == 0x04) {
            out->op[0].kind = C55X_OP_RSUB_DBL_AC;
        } else {
            return -1;
        }
    } else {
        out->op[0].kind = C55X_OP_MOV_K8_SMEM;
        out->op[0].imm = (int8_t)b[4];
    }
    if (decode_aunit_aop(aop, b[5], dest, &out->op[1])) {
        return -1;
    }
    out->op_count = 2;
    out->length = 6;
    return 0;
}

/*
 * 0x80-style Xmem/Ymem packed into 8f byte1/byte2:
 *   byte1 = XXXMMMYY
 *   byte2 = YMMMklass  (low nibble is the 8f class)
 */
static int parse_8f_xmem_ymem(uint8_t b1, uint8_t b2, C55xSmem *x, C55xSmem *y)
{
    unsigned ypack = ((unsigned)(b1 & 3) << 4) | (b2 >> 4);

    return parse_xmem((b1 >> 5) & 7, (b1 >> 2) & 7, x) ||
           parse_xmem((ypack >> 3) & 7, ypack & 7, y);
}

/*
 * TI dis55: 0x8f is a 6/7-byte D-unit || A-unit pack (not MAC||HI).
 * Named classes only:
 *   0x0b + k16 — MOV k16, Smem || A-unit (7)
 *   0x0b + 0xe6 — MOV k16, Xmem || MOV K8, Ymem (7)
 *                 stock 8f261be6ffff00 at 0x127257 is
 *                 MOV #-1,*AR1+ || MOV #0,*AR4+
 *   0x08       — MPYMK/MACMK Smem, K8, ACx || A-unit (7)
 *                 stock 8f61a818060060 at 0x128005 is
 *                 MPYMK *AR3,#6,AC0 || AADD T2,AR2
 *   0x09       — ADD/SUB Smem<<SHIFTW, ACx || A-unit (7)
 * Other 8f bit patterns stay UNDEF.
 */
static int decode_8f_pair(const uint8_t *b, unsigned avail,
                          C55xDecodedInsn *out)
{
    C55xSmem smem, xmem, ymem;
    unsigned dest, klass, aop;

    dest = b[2] >> 4;
    klass = b[2] & 0x0f;
    aop = b[3];
    /*
     * SPRU374 11100110 is MOV K8, Smem. Combined with klass 0x0b the
     * Smem field is Xmem/Ymem, not AAAAAAAI dest:class.
     */
    if (klass == 0x0b && aop == 0xe6 && avail >= 7 &&
        parse_8f_xmem_ymem(b[1], b[2], &xmem, &ymem) == 0) {
        out->op[0].kind = C55X_OP_MOV_K16_SMEM;
        out->op[0].smem = xmem;
        out->op[0].imm = (int16_t)be16(b + 4);
        out->op[1].kind = C55X_OP_MOV_K8_SMEM;
        out->op[1].smem = ymem;
        out->op[1].imm = (int8_t)b[6];
        out->op_count = 2;
        out->length = 7;
        return 0;
    }
    if (smem_ext_len(b[1]) || parse_smem(b[1], b + 7, &smem)) {
        return -1;
    }
    if (klass == 0x08 && avail >= 7 && aunit_aop_ok(aop)) {
        unsigned extra = b[5];

        /* SPRU374 0xf8 extra: xxDDx0U%; bit2 selects MACMK. */
        if (extra & 0x09) {
            return -1;
        }
        out->op[0].kind = (extra & 0x04) ? C55X_OP_MACMK : C55X_OP_MPYMK;
        out->op[0].smem = smem;
        out->op[0].imm = (int8_t)b[4];
        out->op[0].src = extra >> 6;
        out->op[0].dst = (extra >> 4) & 3;
        out->op[0].bit = (extra >> 1) & 1;
        if (decode_aunit_aop(aop, b[6], dest, &out->op[1])) {
            return -1;
        }
        out->op_count = 2;
        out->length = 7;
        return 0;
    }
    if (klass == 0x0b && avail >= 7 && aunit_aop_ok(aop)) {
        out->op[0].kind = C55X_OP_MOV_K16_SMEM;
        out->op[0].smem = smem;
        out->op[0].imm = (int16_t)be16(b + 4);
        if (decode_aunit_aop(aop, b[6], dest, &out->op[1])) {
            return -1;
        }
        out->op_count = 2;
        out->length = 7;
        return 0;
    }
    if (klass == 0x09 && avail >= 7 && aunit_aop_ok(aop)) {
        out->op[0].kind = C55X_OP_SUB_SMEM;
        out->op[0].smem = smem;
        out->op[0].cond = 2;
        out->op[0].st = 1;
        out->op[0].shft = b[4] & 0x3f;
        out->op[0].src = (b[5] >> 4) & 3;
        out->op[0].dst = b[5] & 3;
        if (decode_aunit_aop(aop, b[6], dest, &out->op[1])) {
            return -1;
        }
        out->op_count = 2;
        out->length = 7;
        return 0;
    }
    return -1;
}

int c55x_decode(C55xCPU *cpu, uint32_t pc, C55xDecodedInsn *out)
{
    uint8_t b[C55X_FETCH_MAX];
    unsigned len0 = 0, len1 = 0;
    unsigned i;
    int rc;

    memset(out, 0, sizeof(*out));
    if (c55x_fetch(cpu, pc, b, C55X_FETCH_MAX)) {
        mark_undef(out, b, 1);
        return -1;
    }
    if (b[0] == 0x8a || b[0] == 0x8b) {
        if ((b[0] == 0x8b &&
             decode_8b_sh16_xar_dbl(b, C55X_FETCH_MAX, out) == 0) ||
            decode_8a_pair(b, C55X_FETCH_MAX, out) == 0 ||
            decode_8a_dual(b, C55X_FETCH_MAX, out) == 0) {
            set_raw(out, b, out->length);
            return 0;
        }
        mark_undef(out, b, aunit_aop_ok(b[3]) ? 5 : 4);
        return -1;
    }
    if (b[0] == 0x8c || b[0] == 0x8d) {
        if (decode_8d_xy_ctl(b, C55X_FETCH_MAX, out) == 0 ||
            decode_8c_smem_ctl_aunit(b, C55X_FETCH_MAX, out) == 0 ||
            decode_8c_pair(b, C55X_FETCH_MAX, out) == 0 ||
            decode_8c_dual(b, C55X_FETCH_MAX, out) == 0) {
            set_raw(out, b, out->length);
            return 0;
        }
        mark_undef(out, b, 5);
        return -1;
    }
    if (b[0] == 0x8e) {
        if (decode_8e_pair(b, C55X_FETCH_MAX, out) == 0) {
            set_raw(out, b, 6);
            return 0;
        }
        mark_undef(out, b, 6);
        return -1;
    }
    if (b[0] == 0x8f) {
        if (decode_8f_pair(b, C55X_FETCH_MAX, out) == 0) {
            set_raw(out, b, out->length);
            return 0;
        }
        mark_undef(out, b, 7);
        return -1;
    }
    /*
     * SPRU371F IVT / dis55 .ivec: an 8-byte slot is stack-mode + P24,
     * not a Table 5-1 opcode. Hardware delayed-branches to the 24-bit
     * dest and then runs the remaining 4 bytes (stock
     * `MOV #n, mmap(@BIOS)`).
     *   ea1028c4  .ivec _HWI_F_dispatch, C54X_STK
     *   ca1036b8  .ivec _c_int00, USE_RETA
     * C55_plug writes only the 24-bit dest as a dword (high byte 0),
     * so a plugged HWI slot is `00 10 2c 4c` rather than `ea 10 2c 4c`.
     * Outside the IVPD page the same leads are ordinary instructions.
     */
    if (is_ivec_slot(cpu, pc)) {
        out->op_count = 1;
        out->op[0].kind = C55X_OP_IVEC;
        out->op[0].target = be24(b + 1) & C55X_PC_MASK;
        out->op[0].bit = (b[0] != 0xca);
        set_raw(out, b, 4);
        return 0;
    }
    rc = decode_one(b, C55X_FETCH_MAX, &out->op[0], &len0, out);
    if (rc || !len0) {
        unsigned guess = c55x_lead_size[b[0]];
        if (!guess) {
            guess = 1;
        }
        if (guess > C55X_FETCH_MAX) {
            guess = C55X_FETCH_MAX;
        }
        mark_undef(out, b, guess);
        return -1;
    }
    /* Built-in parallel forms (e.g. MANT::NEXP) already set op_count. */
    if (out->op_count >= 2 && out->length) {
        set_raw(out, b, out->length);
        return 0;
    }
    out->op_count = 1;
    if (out->op[0].kind == C55X_OP_QUAL_MMAP) {
        out->mmap = 1;
    }
    if (out->op[0].kind == C55X_OP_QUAL_PORT ||
        out->op[0].kind == C55X_OP_QUAL_PORT_SMEM) {
        out->port = 1;
    }

    /*
     * XCC / XCCPART control the following packet. Keep that as op[1]
     * rather than flattening; 0x96 / 0x9e / 0x9f are the same insn at
     * different parallel-group positions (SPRU374).
     */
    if ((out->op[0].kind == C55X_OP_XCC ||
         out->op[0].kind == C55X_OP_XCCPART) &&
        len0 < C55X_FETCH_MAX) {
        rc = decode_one(b + len0, C55X_FETCH_MAX - len0, &out->op[1],
                        &len1, out);
        if (rc == 0 && len1) {
            out->op_count = 2;
            if (out->op[1].kind == C55X_OP_QUAL_MMAP) {
                out->mmap = 1;
            }
            if (out->op[1].kind == C55X_OP_QUAL_PORT ||
                out->op[1].kind == C55X_OP_QUAL_PORT_SMEM) {
                out->port = 1;
            }
        }
    } else if (len0 < C55X_FETCH_MAX) {
        uint8_t next = b[len0];
        int parallel = opcode_has_e(b[0]);
        /*
         * 0x9e / 0x9f are the parallel-slot XCC forms (dis55
         * `eb0cb5_9e00`, `3c4c_9e99`). 0x96 is standalone / first-slot
         * only: stock `_MEM_valloc` is `20 96 00 ec318e000000` =
         * NOP, then XCC || AMAR. Pairing 0x96 onto the NOP leaves
         * AMAR unconditional and zeros a good MEM pointer.
         */
        int xcc_next = (next == 0x9e || next == 0x9f);
        if (next == 0x98 || next == 0x99 || next == 0x9a || next == 0x21 ||
            parallel || next_declares_pair(b, C55X_FETCH_MAX, len0) ||
            xcc_next ||
            second_pos_adr(b, C55X_FETCH_MAX, len0)) {
            rc = decode_one(b + len0, C55X_FETCH_MAX - len0, &out->op[1],
                            &len1, out);
            if (rc == 0 && len1) {
                out->op_count = 2;
                if (out->op[1].kind == C55X_OP_QUAL_MMAP) {
                    out->mmap = 1;
                }
                if (out->op[1].kind == C55X_OP_QUAL_PORT ||
                    out->op[1].kind == C55X_OP_QUAL_PORT_SMEM) {
                    out->port = 1;
                }
            } else if (next == 0x98 || next == 0x99 || next == 0x9a ||
                       next == 0x21) {
                len1 = 1;
                out->op_count = 2;
                out->op[1].kind = (next == 0x98) ? C55X_OP_QUAL_MMAP :
                                  (next == 0x21) ? C55X_OP_NOP :
                                  C55X_OP_QUAL_PORT;
                if (next == 0x98) {
                    out->mmap = 1;
                }
                if (next == 0x99 || next == 0x9a) {
                    out->port = 1;
                }
            } else {
                len1 = 0;
            }
        }
    }
    set_raw(out, b, len0 + len1);
    for (i = 0; i < out->op_count; i++) {
        if (out->op[i].kind == C55X_OP_MOV_DBL_RETA ||
            out->op[i].kind == C55X_OP_MOV_RETA_DBL) {
            out->nonrepeatable = 1;
            out->pipeline_flush = 1;
        }
        if (out->op[i].kind == C55X_OP_RPTB ||
            out->op[i].kind == C55X_OP_RPTBLOCAL ||
            out->op[i].kind == C55X_OP_XCC ||
            out->op[i].kind == C55X_OP_XCCPART) {
            out->nonrepeatable = 1;
        }
    }
    return 0;
}

static void fmt_smem(const C55xSmem *sm, char *buf, size_t len)
{
    switch (sm->kind) {
    case C55X_AM_DIRECT:
        snprintf(buf, len, "@%#x", (unsigned)sm->off);
        break;
    case C55X_AM_ABS16:
        snprintf(buf, len, "*abs16(#%#x)", sm->abs);
        break;
    case C55X_AM_ABS23:
        snprintf(buf, len, "*(#%#x)", sm->abs);
        break;
    case C55X_AM_PORT16:
        snprintf(buf, len, "port(#%#x)", sm->abs);
        break;
    case C55X_AM_CDP:
        snprintf(buf, len, "*CDP");
        break;
    case C55X_AM_AR:
        switch (sm->mod) {
        case C55X_MOD_POSTINC:
            snprintf(buf, len, "*AR%u+", sm->ar);
            break;
        case C55X_MOD_POSTDEC:
            snprintf(buf, len, "*AR%u-", sm->ar);
            break;
        case C55X_MOD_PLUS_T0:
            snprintf(buf, len, "*AR%u+T0", sm->ar);
            break;
        case C55X_MOD_MINUS_T0:
            snprintf(buf, len, "*AR%u-T0", sm->ar);
            break;
        case C55X_MOD_PLUS_T1:
            snprintf(buf, len, "*AR%u+T1 [ARMS=1:*AR%u(short(#1))]",
                     sm->ar, sm->ar);
            break;
        case C55X_MOD_MINUS_T1:
            snprintf(buf, len, "*AR%u-T1 [ARMS=1:*AR%u(short(#2))]",
                     sm->ar, sm->ar);
            break;
        case C55X_MOD_INDEX_T0:
            snprintf(buf, len, "*(AR%u+T0)", sm->ar);
            break;
        case C55X_MOD_INDEX_T1:
            snprintf(buf, len, "*(AR%u+T1) [ARMS=1:*AR%u(short(#3))]",
                     sm->ar, sm->ar);
            break;
        case C55X_MOD_ARMS_T1:
            snprintf(buf, len, "*AR%u+T1 / *AR%u(short(#1))", sm->ar, sm->ar);
            break;
        case C55X_MOD_INDEX_MINUS_T0:
            snprintf(buf, len, "*(AR%u-T0)", sm->ar);
            break;
        case C55X_MOD_INDEX_MINUS_T1:
            snprintf(buf, len, "*(AR%u-T1)", sm->ar);
            break;
        case C55X_MOD_K16:
            snprintf(buf, len, "*(AR%u+#%d)", sm->ar, sm->off);
            break;
        case C55X_MOD_PRE_K16:
            snprintf(buf, len, "*+(AR%u(#%d))", sm->ar, sm->off);
            break;
        case C55X_MOD_PREINC:
            snprintf(buf, len, "*+AR%u [ARMS=1:*AR%u(short(#4))]",
                     sm->ar, sm->ar);
            break;
        case C55X_MOD_PREDEC:
            snprintf(buf, len, "*-AR%u [ARMS=1:*AR%u(short(#5))]",
                     sm->ar, sm->ar);
            break;
        case C55X_MOD_NONE:
        default:
            if ((sm->field & 0x1f) == 0x1d) {
                snprintf(buf, len,
                         "*(AR%u+T0B) [ARMS=1:*AR%u(short(#6))]",
                         sm->ar, sm->ar);
            } else if ((sm->field & 0x1f) == 0x1f) {
                snprintf(buf, len,
                         "*(AR%u-T0B) [ARMS=1:*AR%u(short(#7))]",
                         sm->ar, sm->ar);
            } else {
                snprintf(buf, len, "*AR%u", sm->ar);
            }
            break;
        }
        break;
    default:
        snprintf(buf, len, "Smem");
        break;
    }
}

static const char *ctl_name(unsigned which)
{
    switch (which) {
    case C55X_CTL_SP:
        return "SP";
    case C55X_CTL_SSP:
        return "SSP";
    case C55X_CTL_CDP:
        return "CDP";
    case C55X_CTL_CSR:
        return "CSR";
    case C55X_CTL_BRC0:
        return "BRC0";
    case C55X_CTL_BRC1:
        return "BRC1";
    case C55X_CTL_RPTC:
        return "RPTC";
    default:
        return "ctl";
    }
}

void c55x_disasm(const C55xDecodedInsn *in, char *buf, size_t len)
{
    char sm[40];
    const C55xOp *op;
    const char *q = "";

    if (!buf || !len) {
        return;
    }
    if (!in || !in->op_count) {
        snprintf(buf, len, "undef");
        return;
    }
    if (in->undef) {
        snprintf(buf, len, "undef");
        return;
    }
    if (in->mmap) {
        q = " || mmap";
    } else if (in->port) {
        q = " || port()";
    }
    op = &in->op[0];
    fmt_smem(&op->smem, sm, sizeof(sm));
    switch (op->kind) {
    case C55X_OP_MOV_XMEM_YMEM: {
        char ym[40];

        fmt_smem(&op->ymem, ym, sizeof(ym));
        snprintf(buf, len, "MOV %s, %s%s", sm, ym, q);
        break;
    }
    case C55X_OP_NOP:
        snprintf(buf, len, "NOP%s", q);
        break;
    case C55X_OP_MOV_REG_REG:
        snprintf(buf, len, "MOV %s, %s%s", c55x_reg_name(op->src),
                 c55x_reg_name(op->dst), q);
        break;
    case C55X_OP_MOV_XREG:
        snprintf(buf, len, "MOV %s, %s%s", c55x_xreg_name(op->src),
                 c55x_xreg_name(op->dst), q);
        break;
    case C55X_OP_MOV_K4:
    case C55X_OP_MOV_NK4:
    case C55X_OP_MOV_K16_DST:
        snprintf(buf, len, "MOV #%d, %s%s", op->imm, c55x_reg_name(op->dst), q);
        break;
    case C55X_OP_MOV_K8_SMEM:
    case C55X_OP_MOV_K16_SMEM:
        snprintf(buf, len, "MOV #%d, %s%s", op->imm, sm, q);
        break;
    case C55X_OP_MOV_SMEM_DST:
        snprintf(buf, len, "MOV %s, %s%s", sm, c55x_reg_name(op->dst), q);
        break;
    case C55X_OP_MOV_SRC_SMEM:
        snprintf(buf, len, "MOV %s, %s%s", c55x_reg_name(op->src), sm, q);
        break;
    case C55X_OP_ADD_REG:
        snprintf(buf, len, "ADD %s, %s%s", c55x_reg_name(op->src),
                 c55x_reg_name(op->dst), q);
        break;
    case C55X_OP_SUB_REG:
        snprintf(buf, len, "SUB %s, %s%s", c55x_reg_name(op->src),
                 c55x_reg_name(op->dst), q);
        break;
    case C55X_OP_AND_REG:
        snprintf(buf, len, "AND %s, %s%s", c55x_reg_name(op->src),
                 c55x_reg_name(op->dst), q);
        break;
    case C55X_OP_OR_REG:
        snprintf(buf, len, "OR %s, %s%s", c55x_reg_name(op->src),
                 c55x_reg_name(op->dst), q);
        break;
    case C55X_OP_XOR_REG:
        snprintf(buf, len, "XOR %s, %s%s", c55x_reg_name(op->src),
                 c55x_reg_name(op->dst), q);
        break;
    case C55X_OP_AND_K8:
        snprintf(buf, len, "AND #0x%x, %s, %s%s", (uint8_t)op->imm,
                 c55x_reg_name(op->src), c55x_reg_name(op->dst), q);
        break;
    case C55X_OP_OR_K8:
        snprintf(buf, len, "OR #0x%x, %s, %s%s", (uint8_t)op->imm,
                 c55x_reg_name(op->src), c55x_reg_name(op->dst), q);
        break;
    case C55X_OP_ADD_K4:
        snprintf(buf, len, "ADD #%d, %s%s", op->imm, c55x_reg_name(op->dst),
                 q);
        break;
    case C55X_OP_SUB_K4:
        snprintf(buf, len, "SUB #%d, %s%s", op->imm, c55x_reg_name(op->dst),
                 q);
        break;
    case C55X_OP_AND_K16_DST:
        snprintf(buf, len, "AND #0x%x, %s, %s%s", (uint16_t)op->imm,
                 c55x_reg_name(op->src), c55x_reg_name(op->dst), q);
        break;
    case C55X_OP_OR_K16_DST:
        snprintf(buf, len, "OR #0x%x, %s, %s%s", (uint16_t)op->imm,
                 c55x_reg_name(op->src), c55x_reg_name(op->dst), q);
        break;
    case C55X_OP_MOV_K16_AC_SH16:
        snprintf(buf, len, "MOV #0x%x<<#16, AC%u%s", (uint16_t)op->imm,
                 op->dst, q);
        break;
    case C55X_OP_OR_K16_SH16:
        snprintf(buf, len, "OR #0x%x<<#16, AC%u%s", (uint16_t)op->imm,
                 op->dst, q);
        break;
    case C55X_OP_SFTS_AC: {
        int sh = (int)(op->shft & 0x3f);

        if (sh & 32) {
            sh -= 64;
        }
        snprintf(buf, len, "SFTS AC%u, #%d, AC%u%s", op->src, sh, op->dst, q);
        break;
    }
    case C55X_OP_SFTS_AC_TX:
        snprintf(buf, len, "%s AC%u, T%u, AC%u%s",
                 op->st ? "SFTL" : (op->bit ? "SFTSC" : "SFTS"),
                 op->src, (unsigned)(op->imm & 3), op->dst, q);
        break;
    case C55X_OP_EXP:
        snprintf(buf, len, "EXP AC%u, T%u%s", op->src, op->dst, q);
        break;
    case C55X_OP_MANT:
        snprintf(buf, len, "MANT AC%u, AC%u%s", op->src, op->dst, q);
        break;
    case C55X_OP_NEXP:
        snprintf(buf, len, "NEXP AC%u, T%u%s", op->src, op->dst, q);
        break;
    case C55X_OP_MPYMK:
        snprintf(buf, len, "MPYMK%s %s, #%d, AC%u%s",
                 op->bit ? " T3 =" : "", sm, (int)op->imm, op->dst, q);
        break;
    case C55X_OP_MACMK:
        snprintf(buf, len, "MACMK%s %s, #%d, AC%u, AC%u%s",
                 op->bit ? " T3 =" : "", sm, (int)op->imm, op->src,
                 op->dst, q);
        break;
    case C55X_OP_MOV_SMEM_AC:
        snprintf(buf, len, "MOV%s %s, AC%u%s", op->bit ? " uns" : "", sm,
                 op->dst, q);
        break;
    case C55X_OP_BCC_L8:
    case C55X_OP_BCC_L16: {
        char cn[40];

        c55x_cond_name(op->cond, cn, sizeof(cn));
        snprintf(buf, len, "BCC L%d, %s%s", op->imm, cn, q);
        break;
    }
    case C55X_OP_BCC_SRC_K8: {
        static const char *const rel[] = { "==", "<", ">=", "!=" };

        snprintf(buf, len, "BCC%s L%d, %s %s #%d%s",
                 op->st ? "U" : "", (int32_t)op->target,
                 c55x_reg_name(op->src), rel[op->cond & 3],
                 (int)op->imm, q);
        break;
    }
    case C55X_OP_MOV_AC_DBL:
        snprintf(buf, len, "MOV AC%u, dbl(%s)%s", op->src, sm, q);
        break;
    case C55X_OP_MOV_XREG_DBL:
        snprintf(buf, len, "MOV %s, dbl(%s)%s", c55x_xreg_name(op->src), sm,
                 q);
        break;
    case C55X_OP_MOV_DBL_AC:
        snprintf(buf, len, "MOV%s dbl(%s), AC%u%s",
                 op->bit ? "[40]" : "", sm, op->dst, q);
        break;
    case C55X_OP_MOV_PAIR_DBL:
        snprintf(buf, len, "MOV pair, dbl(%s)%s", sm, q);
        break;
    case C55X_OP_MOV_DBL_XDST:
        snprintf(buf, len, "MOV dbl(%s), %s%s", sm, c55x_xreg_name(op->dst), q);
        break;
    case C55X_OP_MOV_DBL_PAIR:
        snprintf(buf, len, "MOV dbl(%s), pair(%s)%s", sm,
                 c55x_reg_name(op->dst), q);
        break;
    case C55X_OP_MOV_DBL_RETA:
        snprintf(buf, len, "MOV dbl(%s), RETA%s", sm, q);
        break;
    case C55X_OP_MOV_RETA_DBL:
        snprintf(buf, len, "MOV RETA, dbl(%s)%s", sm, q);
        break;
    case C55X_OP_ADD_DBL_AC:
        snprintf(buf, len, "ADD dbl(%s), AC%u, AC%u%s", sm, op->src, op->dst, q);
        break;
    case C55X_OP_SUB_DBL_AC:
        snprintf(buf, len, "SUB dbl(%s), AC%u, AC%u%s", sm, op->src, op->dst, q);
        break;
    case C55X_OP_RSUB_DBL_AC:
        snprintf(buf, len, "SUB AC%u, dbl(%s), AC%u%s", op->src, sm, op->dst, q);
        break;
    case C55X_OP_MOV_TAX_HI:
        snprintf(buf, len, "MOV %s, HI(AC%u)%s", c55x_reg_name(op->src),
                 op->dst, q);
        break;
    case C55X_OP_MOV_TAX_CTL:
        snprintf(buf, len, "MOV %s, %s%s", c55x_reg_name(op->src),
                 ctl_name(op->dst), q);
        break;
    case C55X_OP_MOV_HI_TAX:
        snprintf(buf, len, "MOV HI(AC%u), %s%s", op->src,
                 c55x_reg_name(op->dst), q);
        break;
    case C55X_OP_MOV_CTL_TAX:
        snprintf(buf, len, "MOV %s, %s%s", ctl_name(op->src),
                 c55x_reg_name(op->dst), q);
        break;
    case C55X_OP_SFTS_TAX:
        snprintf(buf, len, "SFTS %s, #%d%s", c55x_reg_name(op->dst),
                 op->imm, q);
        break;
    case C55X_OP_SFTL_TAX:
        snprintf(buf, len, "SFTL %s, #%d%s", c55x_reg_name(op->dst),
                 op->imm, q);
        break;
    case C55X_OP_BSET_ST:
        snprintf(buf, len, "BSET #%u, ST%u_55%s", op->bit, op->st, q);
        break;
    case C55X_OP_BCLR_ST:
        snprintf(buf, len, "BCLR #%u, ST%u_55%s", op->bit, op->st, q);
        break;
    case C55X_OP_RPTB:
        snprintf(buf, len, "RPTB #0x%x%s", op->target, q);
        break;
    case C55X_OP_RPTBLOCAL:
        snprintf(buf, len, "RPTBLOCAL #0x%x%s", op->target, q);
        break;
    case C55X_OP_XCC:
    case C55X_OP_XCCPART: {
        char cn[40];
        char rest[48] = "";

        c55x_cond_name(op->cond, cn, sizeof(cn));
        if (in->op_count > 1) {
            snprintf(rest, sizeof(rest), "; %s", c55x_op_name(in->op[1].kind));
        }
        snprintf(buf, len, "%s %s%s%s",
                 op->kind == C55X_OP_XCCPART ? "XCCPART" : "XCC",
                 cn, rest, q);
        break;
    }
    case C55X_OP_ADD_SMEM:
        snprintf(buf, len, "ADD %s, %s%s", sm, c55x_reg_name(op->dst), q);
        break;
    case C55X_OP_B_L7:
    case C55X_OP_B_L16:
        snprintf(buf, len, "B L%d%s", op->imm, q);
        break;
    case C55X_OP_B_P24:
        snprintf(buf, len, "B #%#x%s", op->target, q);
        break;
    case C55X_OP_IVEC:
        snprintf(buf, len, ".ivec #%#x, %s%s", op->target,
                 op->bit ? "C54X_STK" : "USE_RETA", q);
        break;
    case C55X_OP_MOV_HI_AC_SHFT_SMEM:
        snprintf(buf, len, "MOV HI(AC%u << #%u), %s%s",
                 op->src & 3, op->shft & 0x3f, sm, q);
        break;
    case C55X_OP_B_AC:
        snprintf(buf, len, "B AC%u%s", op->src, q);
        break;
    case C55X_OP_CALL_P24:
        snprintf(buf, len, "CALL #%#x%s", op->target, q);
        break;
    case C55X_OP_CALL_AC:
        snprintf(buf, len, "CALL AC%u%s", op->src, q);
        break;
    case C55X_OP_PSH_DBL_AC:
        snprintf(buf, len, "PSH dbl(AC%u)%s", op->src & 3, q);
        break;
    case C55X_OP_POP_DBL_AC:
        snprintf(buf, len, "POP dbl(AC%u)%s", op->dst & 3, q);
        break;
    case C55X_OP_PSH_DBL_LMEM:
        snprintf(buf, len, "PSH dbl(%s)%s", sm, q);
        break;
    case C55X_OP_POP_DBL_LMEM:
        snprintf(buf, len, "POP dbl(%s)%s", sm, q);
        break;
    case C55X_OP_CALLCC_L16: {
        char cn[40];

        c55x_cond_name(op->cond, cn, sizeof(cn));
        snprintf(buf, len, "CALLCC L%d, %s%s", op->imm, cn, q);
        break;
    }
    case C55X_OP_RET:
        snprintf(buf, len, "RET%s", q);
        break;
    case C55X_OP_RETI:
        snprintf(buf, len, "RETI%s", q);
        break;
    case C55X_OP_AADD_K8_SP:
        snprintf(buf, len, "AADD #%d, SP%s", op->imm, q);
        break;
    case C55X_OP_AADD_K8_TAX:
        snprintf(buf, len, "AADD #%d, %s%s", op->imm, c55x_reg_name(op->dst),
                 q);
        break;
    case C55X_OP_AADD_TAX:
        snprintf(buf, len, "AADD %s, %s%s",
                 op->bit ? c55x_xreg_name(op->src) : c55x_reg_name(op->src),
                 op->bit ? c55x_xreg_name(op->dst) : c55x_reg_name(op->dst),
                 q);
        break;
    case C55X_OP_AMOV_K8_TAX:
        snprintf(buf, len, "AMOV #%d, %s%s", op->imm, c55x_reg_name(op->dst),
                 q);
        break;
    case C55X_OP_ASUB_K8_TAX:
        snprintf(buf, len, "ASUB #%d, %s%s", op->imm, c55x_reg_name(op->dst),
                 q);
        break;
    case C55X_OP_AMAR_SMEM:
        snprintf(buf, len, "AMAR %s%s", sm, q);
        break;
    case C55X_OP_BTST_K4_SMEM:
        snprintf(buf, len, "BTST #%d, %s, TC%u%s", op->imm, sm,
                 op->bit + 1u, q);
        break;
    case C55X_OP_AMAR_XDST:
        snprintf(buf, len, "AMAR %s, %s%s", sm, c55x_xreg_name(op->dst), q);
        break;
    case C55X_OP_CMP:
    case C55X_OP_CMPAND:
    case C55X_OP_CMPOR: {
        static const char *const rel[] = { "==", "<", ">=", "!=" };
        const char *name = (op->kind == C55X_OP_CMPAND) ? "CMPAND" :
                           (op->kind == C55X_OP_CMPOR) ? "CMPOR" : "CMP";

        snprintf(buf, len, "%s%s %s %s %s, TC%u%s",
                 name, op->st ? " uns" : "",
                 c55x_reg_name(op->src), rel[op->cond & 3],
                 c55x_reg_name(op->dst), (op->bit & 1) + 1u, q);
        break;
    }
    case C55X_OP_ADD_K16_SH16:
        snprintf(buf, len, "ADD #0x%x<<#16, AC%u%s", (uint16_t)op->imm,
                 op->dst, q);
        break;
    case C55X_OP_SUB_K16_SH16:
        snprintf(buf, len, "SUB #0x%x<<#16, AC%u%s", (uint16_t)op->imm,
                 op->dst, q);
        break;
    case C55X_OP_AND_K16_SH16:
        snprintf(buf, len, "AND #0x%x<<#16, AC%u%s", (uint16_t)op->imm,
                 op->dst, q);
        break;
    case C55X_OP_IDLE:
        snprintf(buf, len, "IDLE%s", q);
        break;
    case C55X_OP_MPY_TX:
        snprintf(buf, len, "MPY%s T%u, AC%u, AC%u%s",
                 op->bit ? "R" : "", (unsigned)(op->imm & 3),
                 op->src, op->dst, q);
        break;
    case C55X_OP_MAC_TX:
        if (op->st) {
            snprintf(buf, len, "MAC%s AC%u, T%u, AC%u, AC%u%s",
                     op->bit ? "R" : "", op->dst, (unsigned)(op->imm & 3),
                     op->src, op->dst, q);
        } else {
            snprintf(buf, len, "MAC%s AC%u, T%u, AC%u%s",
                     op->bit ? "R" : "", op->src, (unsigned)(op->imm & 3),
                     op->dst, q);
        }
        break;
    case C55X_OP_MAS_TX:
        snprintf(buf, len, "MAS%s T%u, AC%u, AC%u%s",
                 op->bit ? "R" : "", (unsigned)(op->imm & 3),
                 op->src, op->dst, q);
        break;
    case C55X_OP_MPY_AC:
        snprintf(buf, len, "MPY%s AC%u, AC%u%s",
                 op->bit ? "R" : "", op->src, op->dst, q);
        break;
    case C55X_OP_SQA:
        snprintf(buf, len, "SQA%s AC%u, AC%u%s",
                 op->bit ? "R" : "", op->src, op->dst, q);
        break;
    case C55X_OP_SQS:
        snprintf(buf, len, "SQS%s AC%u, AC%u%s",
                 op->bit ? "R" : "", op->src, op->dst, q);
        break;
    case C55X_OP_SQR:
        snprintf(buf, len, "SQR%s AC%u, AC%u%s",
                 op->bit ? "R" : "", op->src, op->dst, q);
        break;
    case C55X_OP_ADDV:
        snprintf(buf, len, "ADDV%s AC%u, AC%u%s",
                 op->bit ? "R" : "", op->src, op->dst, q);
        break;
    case C55X_OP_ROUND:
        snprintf(buf, len, "ROUND AC%u, AC%u%s", op->src, op->dst, q);
        break;
    case C55X_OP_SAT:
        snprintf(buf, len, "SAT%s AC%u, AC%u%s",
                 op->bit ? "R" : "", op->src, op->dst, q);
        break;
    case C55X_OP_BSET_SMEM:
        snprintf(buf, len, "BSET %s, %s%s", c55x_reg_name(op->src), sm, q);
        break;
    case C55X_OP_BCLR_SMEM:
        snprintf(buf, len, "BCLR %s, %s%s", c55x_reg_name(op->src), sm, q);
        break;
    case C55X_OP_BNOT_SMEM:
        snprintf(buf, len, "BNOT %s, %s%s", c55x_reg_name(op->src), sm, q);
        break;
    case C55X_OP_MPYM:
        if (op->imm != 0xff) {
            snprintf(buf, len, "MPYM%s%s %s, T%u, AC%u%s",
                     op->shft ? "U" : "", op->bit ? "R" : "", sm,
                     (unsigned)(op->imm & 3), op->dst, q);
        } else {
            snprintf(buf, len, "MPYM%s %s, AC%u, AC%u%s",
                     op->bit ? "R" : "", sm, op->src, op->dst, q);
        }
        break;
    case C55X_OP_SQRM:
        snprintf(buf, len, "SQRM%s %s, AC%u%s",
                 op->bit ? "R" : "", sm, op->dst, q);
        break;
    case C55X_OP_MACM:
    case C55X_OP_MASM:
        snprintf(buf, len, "%s%s %s, %s, AC%u, AC%u%s",
                 op->kind == C55X_OP_MACM ? "MACM" : "MASM",
                 op->bit ? "R" : "", sm,
                 op->imm != 0xff ? "Tx" : "ACx", op->src, op->dst, q);
        break;
    case C55X_OP_SQAM:
        snprintf(buf, len, "SQAM%s %s, AC%u, AC%u%s",
                 op->bit ? "R" : "", sm, op->src, op->dst, q);
        break;
    case C55X_OP_SQSM:
        snprintf(buf, len, "SQSM%s %s, AC%u, AC%u%s",
                 op->bit ? "R" : "", sm, op->src, op->dst, q);
        break;
    case C55X_OP_MPYM_XY:
    case C55X_OP_MACM_XY:
    case C55X_OP_MASM_XY:
        snprintf(buf, len, "%s%s Xmem, Ymem, AC%u%s",
                 op->kind == C55X_OP_MPYM_XY ? "MPYM" :
                 op->kind == C55X_OP_MACM_XY ? "MACM" : "MASM",
                 op->bit ? "R" : "", op->dst, q);
        break;
    case C55X_OP_BAND:
        snprintf(buf, len, "BAND %s, #0x%x, TC%u%s",
                 sm, (uint16_t)op->imm, op->bit + 1u, q);
        break;
    case C55X_OP_ADD_XY_AC:
        snprintf(buf, len, "ADD Xmem, Ymem, AC%u%s", op->dst, q);
        break;
    case C55X_OP_SUB_XY_AC:
        snprintf(buf, len, "SUB Xmem, Ymem, AC%u%s", op->dst, q);
        break;
    case C55X_OP_MOV_XY_AC:
        snprintf(buf, len, "MOV Xmem, Ymem, AC%u%s", op->dst, q);
        break;
    case C55X_OP_BFXTR:
        snprintf(buf, len, "BFXTR #%d, %s, %s%s", (int)(int16_t)op->imm,
                 c55x_reg_name(op->src), c55x_reg_name(op->dst), q);
        break;
    case C55X_OP_BFXPA:
        snprintf(buf, len, "BFXPA #%d, %s, %s%s", (int)(int16_t)op->imm,
                 c55x_reg_name(op->src), c55x_reg_name(op->dst), q);
        break;
    default:
        snprintf(buf, len, "%s%s", c55x_op_name(op->kind), q);
        break;
    }
    if (in->op_count > 1 &&
        (in->op[1].kind == C55X_OP_XCC || in->op[1].kind == C55X_OP_XCCPART)) {
        char cn[40];
        size_t used = strlen(buf);

        c55x_cond_name(in->op[1].cond, cn, sizeof(cn));
        snprintf(buf + used, len - used, " || %s %s",
                 in->op[1].kind == C55X_OP_XCCPART ? "XCCPART" : "XCC", cn);
    } else if (in->op_count > 1) {
        size_t used = strlen(buf);
        const C55xOp *op1 = &in->op[1];

        if (op1->kind == C55X_OP_MOV_DBL_XDST) {
            char sm2[40];

            fmt_smem(&op1->smem, sm2, sizeof(sm2));
            snprintf(buf + used, len - used, " || MOV dbl(%s), %s", sm2,
                     c55x_xreg_name(op1->dst));
        } else if (op1->kind == C55X_OP_MOV_DBL_AC) {
            char sm2[40];

            fmt_smem(&op1->smem, sm2, sizeof(sm2));
            snprintf(buf + used, len - used, " || MOV%s dbl(%s), AC%u",
                     op1->bit ? "[40]" : "", sm2, op1->dst);
        } else if (op1->kind == C55X_OP_MOV_AC_DBL) {
            char sm2[40];

            fmt_smem(&op1->smem, sm2, sizeof(sm2));
            snprintf(buf + used, len - used, " || MOV AC%u, dbl(%s)",
                     op1->src, sm2);
        } else if (op1->kind == C55X_OP_ADD_DBL_AC) {
            char sm2[40];

            fmt_smem(&op1->smem, sm2, sizeof(sm2));
            snprintf(buf + used, len - used, " || ADD dbl(%s), AC%u, AC%u",
                     sm2, op1->src, op1->dst);
        } else if (op1->kind == C55X_OP_SUB_DBL_AC) {
            char sm2[40];

            fmt_smem(&op1->smem, sm2, sizeof(sm2));
            snprintf(buf + used, len - used, " || SUB dbl(%s), AC%u, AC%u",
                     sm2, op1->src, op1->dst);
        } else if (op1->kind == C55X_OP_RSUB_DBL_AC) {
            char sm2[40];

            fmt_smem(&op1->smem, sm2, sizeof(sm2));
            snprintf(buf + used, len - used, " || SUB AC%u, dbl(%s), AC%u",
                     op1->src, sm2, op1->dst);
        } else if (op1->kind == C55X_OP_OR_K16_DST) {
            snprintf(buf + used, len - used, " || OR #0x%x, %s, %s",
                     (uint16_t)op1->imm, c55x_reg_name(op1->src),
                     c55x_reg_name(op1->dst));
        } else if (op1->kind == C55X_OP_AND_REG) {
            snprintf(buf + used, len - used, " || AND %s, %s",
                     c55x_reg_name(op1->src), c55x_reg_name(op1->dst));
        } else if (op1->kind == C55X_OP_SUB_REG) {
            snprintf(buf + used, len - used, " || SUB %s, %s",
                     c55x_reg_name(op1->src), c55x_reg_name(op1->dst));
        } else if (op1->kind == C55X_OP_ADD_REG) {
            snprintf(buf + used, len - used, " || ADD %s, %s",
                     c55x_reg_name(op1->src), c55x_reg_name(op1->dst));
        } else if (op1->kind == C55X_OP_SUB_K4) {
            snprintf(buf + used, len - used, " || SUB #%d, %s",
                     op1->imm, c55x_reg_name(op1->dst));
        } else if (op1->kind == C55X_OP_MOV_K16_AC_SH16) {
            snprintf(buf + used, len - used, " || MOV #0x%x<<#16, AC%u",
                     (uint16_t)op1->imm, op1->dst);
        } else if (op1->kind == C55X_OP_MOV_XREG) {
            snprintf(buf + used, len - used, " || MOV %s, %s",
                     c55x_xreg_name(op1->src), c55x_xreg_name(op1->dst));
        } else if (op1->kind == C55X_OP_AADD_K8_TAX) {
            snprintf(buf + used, len - used, " || AADD #%d, %s",
                     op1->imm, c55x_reg_name(op1->dst));
        } else if (op1->kind == C55X_OP_AMOV_K8_TAX) {
            snprintf(buf + used, len - used, " || AMOV #%d, %s",
                     op1->imm, c55x_reg_name(op1->dst));
        } else if (op1->kind == C55X_OP_ASUB_K8_TAX) {
            snprintf(buf + used, len - used, " || ASUB #%d, %s",
                     op1->imm, c55x_reg_name(op1->dst));
        } else if (op1->kind == C55X_OP_MOV_SMEM_DST) {
            char sm2[40];

            fmt_smem(&op1->smem, sm2, sizeof(sm2));
            snprintf(buf + used, len - used, " || MOV %s, %s",
                     sm2, c55x_reg_name(op1->dst));
        } else if (op1->kind == C55X_OP_MOV_SRC_SMEM) {
            char sm2[40];

            fmt_smem(&op1->smem, sm2, sizeof(sm2));
            snprintf(buf + used, len - used, " || MOV %s, %s",
                     c55x_reg_name(op1->src), sm2);
        } else if (op1->kind == C55X_OP_AADD_TAX ||
                   op1->kind == C55X_OP_AMOV_TAX ||
                   op1->kind == C55X_OP_ASUB_TAX) {
            const char *nm = (op1->kind == C55X_OP_AMOV_TAX) ? "AMOV" :
                             (op1->kind == C55X_OP_ASUB_TAX) ? "ASUB" : "AADD";

            snprintf(buf + used, len - used, " || %s %s, %s", nm,
                     op1->bit ? c55x_xreg_name(op1->src) :
                     c55x_reg_name(op1->src),
                     op1->bit ? c55x_xreg_name(op1->dst) :
                     c55x_reg_name(op1->dst));
        } else {
            snprintf(buf + used, len - used, " || %s",
                     c55x_op_name(op1->kind));
        }
    }
}
