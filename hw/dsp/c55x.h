/*
 * OMAP2420 TMS320C55x interpreter (baseline / 23-bit), not C55x+.
 *
 * Functional architectural model only. QEMU embeds this in the DSP
 * device; host unit tests compile the same files without QEMU headers.
 *
 * Encodings follow TI SPRU374E. Reset / register / addressing follow
 * SPRU371F. Data addresses are DSP word addresses; program PC is a
 * 24-bit byte address. Byte/word conversion is centralized here.
 */

#ifndef HW_DSP_C55X_H
#define HW_DSP_C55X_H

#include <stddef.h>
#include <stdint.h>

#define C55X_PC_MASK        0x00ffffffu
#define C55X_WORD_MASK      0x007fffffu
#define C55X_AC_MASK        0xffffffffffull
#define C55X_DSPSPACE_BYTES 0x01000000u
/*
 * OMAP2420 IVA L2 INTC in C55x data-word space. DSP/BIOS HWI.INTC_BASE
 * is 0x7e4800 (SPRU404Q). Word address = byte offset / 2 of the OMAP2
 * INTC map in hw/intc/omap_intc.c (omap2-intc) and Linux irq-omap-intc.
 */
#define C55X_L2INTC_BASE        0x7e4800u
#define C55X_L2INTC_WORDS       0x100u
#define C55X_L2INTC_SYSCONFIG   0x7e4808u
#define C55X_L2INTC_SYSSTATUS   0x7e480au
#define C55X_L2INTC_SIR_IRQ     0x7e4820u
#define C55X_L2INTC_SIR_FIQ     0x7e4822u
#define C55X_L2INTC_CONTROL     0x7e4824u
#define C55X_L2INTC_MIR         0x7e4842u
#define C55X_L2INTC_MIR_CLEAR   0x7e4844u
#define C55X_L2INTC_MIR_SET     0x7e4846u
#define C55X_L2INTC_ILR0        0x7e4880u
#define C55X_L2INTC_SOFTRESET   2u
#define C55X_L2INTC_MAIL_SRC    14u
#define C55X_L2INTC_CMD         C55X_L2INTC_SYSCONFIG
#define C55X_L2INTC_STAT        C55X_L2INTC_SYSSTATUS
#define C55X_L2INTC_INIT        C55X_L2INTC_SOFTRESET
#define C55X_IFR_INT2           (1u << 2)
#define C55X_IFR_INT3           (1u << 3)
#define C55X_HISTORY        64
#define C55X_FETCH_MAX      8

#define C55X_ST0_ACOV1 (1u << 9)
#define C55X_ST0_ACOV0 (1u << 10)
#define C55X_ST0_CARRY (1u << 11)
#define C55X_ST0_TC2   (1u << 12)
#define C55X_ST0_TC1   (1u << 13)
#define C55X_ST0_ACOV3 (1u << 14)
#define C55X_ST0_ACOV2 (1u << 15)

#define C55X_ST1_ASM_MASK 0x001fu
#define C55X_ST1_C54CM    (1u << 5)
#define C55X_ST1_FRCT     (1u << 6)
#define C55X_ST1_C16      (1u << 7)
#define C55X_ST1_SXMD     (1u << 8)
#define C55X_ST1_SATD     (1u << 9)
#define C55X_ST1_M40      (1u << 10)
#define C55X_ST1_INTM     (1u << 11)
#define C55X_ST1_HM       (1u << 12)
#define C55X_ST1_XF       (1u << 13)
#define C55X_ST1_CPL      (1u << 14)
#define C55X_ST1_BRAF     (1u << 15)

#define C55X_ST2_AR0LC    (1u << 0)
#define C55X_ST2_AR1LC    (1u << 1)
#define C55X_ST2_AR2LC    (1u << 2)
#define C55X_ST2_AR3LC    (1u << 3)
#define C55X_ST2_AR4LC    (1u << 4)
#define C55X_ST2_AR5LC    (1u << 5)
#define C55X_ST2_AR6LC    (1u << 6)
#define C55X_ST2_AR7LC    (1u << 7)
#define C55X_ST2_CDPLC    (1u << 8)
#define C55X_ST2_DBGM     (1u << 13)
#define C55X_ST2_ARMS     (1u << 15)

#define C55X_ST3_CACLR    (1u << 13)
#define C55X_ST3_CAEN     (1u << 14)

/* SPRU371F FAST16 CFCT: bit 7 single-repeat, bit 6 conditional single-repeat. */
#define C55X_CFCT_RPT     0x80u
#define C55X_CFCT_RPTCC   0x40u
#define C55X_FLOW_MAX     32
#define C55X_FLOW_CALL    0
#define C55X_FLOW_IRQ     1
#define C55X_DEV_WATCH_MAX 8

#define C55X_REG_AC0  0
#define C55X_REG_AC1  1
#define C55X_REG_AC2  2
#define C55X_REG_AC3  3
#define C55X_REG_T0   4
#define C55X_REG_T1   5
#define C55X_REG_T2   6
#define C55X_REG_T3   7
#define C55X_REG_AR0  8
#define C55X_REG_AR7  15

#define C55X_MMR_IER0  0x00u
#define C55X_MMR_IFR0  0x01u
#define C55X_MMR_ST0   0x02u
#define C55X_MMR_ST1   0x03u
#define C55X_MMR_ST3   0x04u
#define C55X_MMR_IER1  0x45u
#define C55X_MMR_IFR1  0x46u
#define C55X_MMR_ST2   0x4bu
#define C55X_MMR_SSP   0x4cu
#define C55X_MMR_SP    0x4du
/* SPRU371F: MMRs occupy data word addresses 0x000000–0x00005F. */
#define C55X_MMR_WORDS 0x60u

typedef enum {
    C55X_OK = 0,
    C55X_HALT_RESET = 1,
    C55X_HALT_UNDEF = 2,
    C55X_HALT_MEM = 3,
    C55X_HALT_IDLE = 4
} C55xHalt;

typedef enum {
    C55X_OP_UNDEF = 0,
    C55X_OP_NOP,
    C55X_OP_QUAL_MMAP,
    C55X_OP_QUAL_PORT,
    C55X_OP_QUAL_PORT_SMEM,
    C55X_OP_MOV_REG_REG,
    C55X_OP_MOV_XREG,
    C55X_OP_MOV_K4,
    C55X_OP_MOV_NK4,
    C55X_OP_MOV_K16_DST,
    C55X_OP_MOV_K16_AC_SHFT,
    C55X_OP_MOV_K16_AC_SH16,
    C55X_OP_MOV_K8_SMEM,
    C55X_OP_MOV_K16_SMEM,
    C55X_OP_MOV_SMEM_DST,
    C55X_OP_MOV_SMEM_SHFT,
    C55X_OP_MOV_SMEM_AC,
    C55X_OP_MOV_SRC_SMEM,
    C55X_OP_MOV_AC_DBL,
    C55X_OP_MOV_DBL_AC,
    C55X_OP_MOV_K16_CTL,
    C55X_OP_ADD_REG,
    C55X_OP_SUB_REG,
    C55X_OP_AND_REG,
    C55X_OP_OR_REG,
    C55X_OP_XOR_REG,
    C55X_OP_NOT_REG,
    C55X_OP_NEG_REG,
    C55X_OP_ABS_REG,
    C55X_OP_MAX_REG,
    C55X_OP_MIN_REG,
    C55X_OP_ADD_K4,
    C55X_OP_SUB_K4,
    C55X_OP_AND_K16_SMEM,
    C55X_OP_OR_K16_SMEM,
    C55X_OP_XOR_K16_SMEM,
    C55X_OP_ADD_K16_SMEM,
    C55X_OP_OR_K16_SH16,
    C55X_OP_AND_K16_DST,
    C55X_OP_OR_K16_DST,
    C55X_OP_XOR_K16_DST,
    C55X_OP_ADD_K16_DST,
    C55X_OP_SUB_K16_DST,
    C55X_OP_BSET_ST,
    C55X_OP_BCLR_ST,
    C55X_OP_BSET_BADDR,
    C55X_OP_BCLR_BADDR,
    C55X_OP_BNOT_BADDR,
    C55X_OP_BTST_BADDR,
    C55X_OP_AMAR_XDST,
    C55X_OP_B_L7,
    C55X_OP_B_L16,
    C55X_OP_B_P24,
    C55X_OP_B_AC,
    C55X_OP_CALL_P24,
    C55X_OP_CALL_AC,
    C55X_OP_CALL_L16,
    C55X_OP_CALLCC_L16,
    C55X_OP_BCC_L8,
    C55X_OP_BCC_L16,
    C55X_OP_BCC_P24,
    C55X_OP_RET,
    C55X_OP_RETI,
    C55X_OP_PSH_SRC,
    C55X_OP_POP_DST,
    C55X_OP_AADD_K8_SP,
    C55X_OP_AADD_K8_TAX,
    C55X_OP_AMOV_K8_TAX,
    C55X_OP_ASUB_K8_TAX,
    C55X_OP_AADD_TAX,
    C55X_OP_AMOV_TAX,
    C55X_OP_ASUB_TAX,
    C55X_OP_AMOV_D16,
    C55X_OP_RPT_K8,
    C55X_OP_RPT_K16,
    C55X_OP_RPTB,
    C55X_OP_IDLE,
    C55X_OP_INTR,
    C55X_OP_TRAP,
    C55X_OP_RESET,
    C55X_OP_MOV_TAX_HI,
    C55X_OP_MOV_TAX_CTL,
    C55X_OP_AND_AC_SHFT,
    C55X_OP_OR_AC_SHFT,
    C55X_OP_XOR_AC_SHFT,
    C55X_OP_ADD_AC_SHFT,
    C55X_OP_SUB_AC_SHFT,
    C55X_OP_SFTS_AC,
    C55X_OP_SFTL_AC,
    C55X_OP_AND_K8,
    C55X_OP_OR_K8,
    C55X_OP_XOR_K8,
    C55X_OP_RPT_CSR,
    C55X_OP_MOV_XMEM_YMEM,
    C55X_OP_MOV_DBL_XY,
    C55X_OP_PSHBOTH,
    C55X_OP_POPBOTH,
    C55X_OP_PSH_DBL_AC,
    C55X_OP_POP_DBL_AC,
    C55X_OP_MOV_PAIR_DBL,
    C55X_OP_MOV_DBL_XDST,
    C55X_OP_MOV_DBL_RETA,
    C55X_OP_MOV_RETA_DBL,
    C55X_OP_XCC,
    C55X_OP_XCCPART,
    C55X_OP_ADD_SMEM,
    C55X_OP_ADD_K16_SH16,
    C55X_OP_SUB_K16_SH16,
    C55X_OP_AND_K16_SH16,
    C55X_OP_XOR_K16_SH16,
    C55X_OP_PSH_PAIR,
    C55X_OP_POP_PAIR,
    C55X_OP_AMAR_SMEM,
    C55X_OP_PSH_SMEM,
    C55X_OP_POP_SMEM,
    C55X_OP_MOV_HI_SMEM,
    C55X_OP_SUB_SMEM,
    C55X_OP_AND_SMEM,
    C55X_OP_OR_SMEM,
    C55X_OP_XOR_SMEM,
    C55X_OP_CMP,
    C55X_OP_CMPAND,
    C55X_OP_CMPOR,
    C55X_OP_MOV_K12_CTL,
    C55X_OP_MOV_AC_SHFT_SMEM,
    C55X_OP_CMP_SMEM_K16,
    C55X_OP_ADD_DBL_AC,
    C55X_OP_SUB_DBL_AC,
    C55X_OP_RSUB_DBL_AC,
    C55X_OP_MOV_HI_TAX,
    C55X_OP_MOV_CTL_TAX,
    C55X_OP_SFTS_TAX,
    C55X_OP_SFTL_TAX,
    C55X_OP_BTST_K4_SMEM,
    C55X_OP_RPTBLOCAL,
    C55X_OP_MPYK_K16,
    C55X_OP_MOV_XREG_DBL,
    C55X_OP_BCC_SRC_K8,
    C55X_OP_SFTS_AC_TX,
    C55X_OP_EXP,
    C55X_OP_MPYMK,
    C55X_OP_MACMK,
    C55X_OP_MOV_DBL_PAIR,
    C55X_OP_IVEC,
    C55X_OP_MOV_HI_AC_SHFT_SMEM,
    C55X_OP_PSH_DBL_LMEM,
    C55X_OP_POP_DBL_LMEM,
    C55X_OP_MPY_TX,
    C55X_OP_MAC_TX,
    C55X_OP_MAS_TX,
    C55X_OP_MPY_AC,
    C55X_OP_SQA,
    C55X_OP_SQS,
    C55X_OP_SQR,
    C55X_OP_ADDV,
    C55X_OP_ROUND,
    C55X_OP_SAT,
    C55X_OP_BSET_SMEM,
    C55X_OP_BCLR_SMEM,
    C55X_OP_BNOT_SMEM,
    C55X_OP_MPYM,
    C55X_OP_SQRM,
    C55X_OP_MACM,
    C55X_OP_MASM,
    C55X_OP_SQAM,
    C55X_OP_SQSM,
    C55X_OP_MPYM_XY,
    C55X_OP_MACM_XY,
    C55X_OP_MASM_XY,
    C55X_OP_BAND,
    C55X_OP_ADD_XY_AC,
    C55X_OP_SUB_XY_AC,
    C55X_OP_MOV_XY_AC,
    C55X_OP_MACK,
    C55X_OP_BFXTR,
    C55X_OP_BFXPA,
    C55X_OP_ADD_K16_SHFT,
    C55X_OP_MOV_SMEM_CTL,
    C55X_OP_MOV_CTL_SMEM,
    C55X_OP_MACMZ,
    C55X_OP_MPYM_CMEM,
    C55X_OP_MACM_CMEM,
    C55X_OP_MASM_CMEM,
    C55X_OP_DUAL_MAC,
    C55X_OP_AMAR_XYC,
    C55X_OP_FIRSADD,
    C55X_OP_FIRSSUB,
    C55X_OP_LMS,
    C55X_OP_SQDST,
    C55X_OP_ABDST,
    C55X_OP_MAC_HI_Y,
    C55X_OP_MOV_AC_XY,
    C55X_OP_SUBC,
    C55X_OP_ADDSUBCC,
    C55X_OP_ADDSUB,
    C55X_OP_SUBADD,
    C55X_OP_ADD_SMEM16,
    C55X_OP_MOV_SMEM_TX,
    C55X_OP_RETCC,
    C55X_OP_CALLCC_P24,
    C55X_OP_RPTCC,
    C55X_OP_RPTADD,
    C55X_OP_RPTSUB,
    C55X_OP_SWAP,
    C55X_OP_DELAY,
    C55X_OP_MANT,
    C55X_OP_NEXP,
    C55X_OP_BCNT,
    C55X_OP_MAXDIFF,
    C55X_OP_ROL,
    C55X_OP_ROR,
    C55X_OP_MOV_SMEM_CMEM,
    C55X_OP_BTST_SRC_SMEM,
    C55X_OP_PSH_SRC_SMEM,
    C55X_OP_POP_DST_SMEM,
    C55X_OP_BCC_ARN
} C55xOpKind;

#define C55X_CTL_SP    0
#define C55X_CTL_SSP   1
#define C55X_CTL_CDP   2
#define C55X_CTL_CSR   3
#define C55X_CTL_BRC0  4
#define C55X_CTL_BRC1  5
#define C55X_CTL_RPTC  6
#define C55X_CTL_DP    7
#define C55X_CTL_BSA01 8
#define C55X_CTL_BSA23 9
#define C55X_CTL_BSA45 10
#define C55X_CTL_BSA67 11
#define C55X_CTL_BSAC  12
#define C55X_CTL_TRN0  13
#define C55X_CTL_TRN1  14
#define C55X_CTL_BK03  15
#define C55X_CTL_BK47  16
#define C55X_CTL_BKC   17
#define C55X_CTL_DPH   18
#define C55X_CTL_PDP   19

typedef enum {
    C55X_AM_DIRECT = 0,
    C55X_AM_ABS16,
    C55X_AM_ABS23,
    C55X_AM_PORT16,
    C55X_AM_AR,
    C55X_AM_CDP
} C55xAddrKind;

typedef enum {
    C55X_MOD_NONE = 0,
    C55X_MOD_POSTINC,
    C55X_MOD_POSTDEC,
    C55X_MOD_PREINC,
    C55X_MOD_PREDEC,
    C55X_MOD_PLUS_T0,
    C55X_MOD_MINUS_T0,
    C55X_MOD_INDEX_T0,
    C55X_MOD_PLUS_T1,
    C55X_MOD_MINUS_T1,
    C55X_MOD_INDEX_T1,
    /* Xmem/Ymem MMM=101/110: *(ARn-T0/T1) — indexed, ARn unchanged */
    C55X_MOD_INDEX_MINUS_T0,
    C55X_MOD_INDEX_MINUS_T1,
    /*
     * 8e||eb Ymem MMM=100: ARMS=1 → *ARn(short(#1)); ARMS=0 → *ARn+T1 post.
     * Matches Smem field 0x13 duality used by the stereo pair at 134d1c.
     */
    C55X_MOD_ARMS_T1,
    C55X_MOD_K16,
    C55X_MOD_PRE_K16
} C55xAddrMod;

typedef struct {
    C55xAddrKind kind;
    C55xAddrMod mod;
    unsigned ar;
    int32_t off;
    uint32_t abs;
    unsigned ext_len;
    uint8_t field;
} C55xSmem;

typedef struct {
    C55xOpKind kind;
    uint8_t dst;
    uint8_t src;
    uint8_t st;
    uint8_t bit;
    uint8_t cond;
    uint8_t shft;
    C55xSmem smem;
    C55xSmem ymem;
    int32_t imm;
    uint32_t target;
} C55xOp;

typedef struct {
    C55xOp op[2];
    unsigned op_count;
    unsigned length;
    uint32_t raw;
    uint8_t bytes[C55X_FETCH_MAX];
    uint8_t mmap;
    uint8_t port;
    uint8_t undef;
    uint8_t nonrepeatable;
    uint8_t pipeline_flush;
} C55xDecodedInsn;

typedef struct {
    uint32_t pc;
    uint8_t bytes[C55X_FETCH_MAX];
    unsigned length;
    C55xOpKind kind;
} C55xHist;

typedef struct C55xBus {
    void *opaque;
    int (*fetch8)(void *opaque, uint32_t byte_addr, uint8_t *out);
    int (*read16)(void *opaque, uint32_t word_addr, uint16_t *out);
    int (*write16)(void *opaque, uint32_t word_addr, uint16_t value);
    int (*read32)(void *opaque, uint32_t word_addr, uint32_t *out);
    int (*write32)(void *opaque, uint32_t word_addr, uint32_t value);
    int (*io_read)(void *opaque, uint16_t port, uint16_t *out);
    int (*io_write)(void *opaque, uint16_t port, uint16_t value);
    void (*log)(void *opaque, const char *fmt, ...)
        __attribute__((format(gnu_printf, 2, 3)));
    void (*snapshot)(void *opaque, const char *tag);
} C55xBus;

typedef struct {
    uint8_t *mem;
    size_t size;
    void (*io_write)(void *opaque, uint16_t port, uint16_t value);
    uint16_t (*io_read)(void *opaque, uint16_t port);
    void *io_opaque;
    uint32_t last_io_port;
    uint16_t last_io_value;
    unsigned last_io_writes;
    void (*data_write)(void *opaque, uint32_t word_addr,
                       uint16_t old_value, uint16_t new_value);
    void *data_write_opaque;
    struct C55xCPU *cpu;
} C55xFlat;

typedef struct C55xL2Intc {
    uint32_t sysconfig;
    uint32_t autoidle;
    uint32_t mir;
    uint32_t itr;
    uint32_t inputs;
    uint32_t swi;
    uint32_t fiq;
    uint32_t ilr[32];
    uint8_t priority[32];
    uint32_t new_agr_irq;
    uint32_t new_agr_fiq;
    uint32_t global;
    int sir_irq;
    int sir_fiq;
    int parent_irq;
    int parent_fiq;
    struct C55xCPU *cpu;
} C55xL2Intc;

typedef struct C55xCPU {
    C55xBus bus;
    uint32_t pc;
    uint32_t ret_pc;
    uint64_t ac[4];
    uint16_t t[4];
    uint32_t xar[8];
    uint32_t xsp;
    uint32_t xssp;
    uint32_t xdp;
    uint32_t xcdp;
    uint16_t st0;
    uint16_t st1;
    uint16_t st2;
    uint16_t st3;
    uint16_t ier0;
    uint16_t ifr0;
    uint16_t ier1;
    uint16_t ifr1;
    uint16_t dbier0;
    uint16_t dbier1;
    uint16_t ivpd;
    uint16_t ivph;
    uint16_t brc0;
    uint16_t brc1;
    uint16_t brs1;
    uint16_t csr;
    uint16_t rptc;
    uint32_t rsa0;
    uint32_t rea0;
    uint32_t rsa1;
    uint32_t rea1;
    uint16_t bk03;
    uint16_t bk47;
    uint16_t bkc;
    uint16_t bsa01;
    uint16_t bsa23;
    uint16_t bsa45;
    uint16_t bsa67;
    uint16_t bsac;
    uint16_t trn0;
    uint16_t trn1;
    uint16_t pdp;
    uint16_t rpt_left;
    uint8_t rpt_active;
    uint8_t rpt_armed;
    /* Distinguishes RPT (CFCT bit 7) from RPTCC (CFCT bit 6). */
    uint8_t rpt_cc;
    uint8_t rptb0_active;
    uint8_t rptb1_active;
    /* 0 = none, 1 = XCC, 2 = XCCPART; applies to the next packet. */
    uint8_t xcc_pending;
    uint8_t xcc_cond_true;
    /*
     * Parallel packet transaction: sources and EAs come from this
     * snapshot; data writes are staged until commit.
     */
    uint64_t pkt_ac[4];
    uint16_t pkt_t[4];
    uint32_t pkt_xar[8];
    uint32_t pkt_xsp;
    uint32_t pkt_xssp;
    uint32_t pkt_xdp;
    uint32_t pkt_xcdp;
    uint16_t pkt_st0;
    uint16_t pkt_st2;
    uint16_t pkt_csr;
    uint8_t pkt_src_valid;
    uint8_t mem_init_logged;
    uint32_t pkt_wr_word[8];
    uint16_t pkt_wr_value[8];
    uint8_t pkt_wr_n;
    uint8_t sp_written;
    uint8_t ssp_written;
    uint32_t reta;
    uint16_t cfct;
    uint16_t dbstat;
    uint8_t fast_return;
    /*
     * Per-taken-IRQ return mode (independent of CALL/RET fast_return).
     * Low bit is the most recent IRQ: 1 = C54X_STK (slow), 0 = USE_RETA.
     * Stock bios2420 HWI slots are `.ivec …, C54X_STK` (`ea`).
     */
    uint32_t irq_ret_slow;
    uint8_t irq_nest;
    /*
     * Interrupted RPT/RPTCC count per nested IRQ. CFCT only carries the
     * active bit; an ISR that itself runs RPT must not clobber the
     * outer rpt_left (SWI_F_exec RPT #10 POP under nested audio IRQ).
     */
    uint16_t irq_rpt_left[32];
    uint32_t irq_rpt_saved; /* bit n => irq_rpt_left[n] holds a live count */
    /*
     * Unnamed SPRU371F MMR words 0x00–0x5F. Named registers are not
     * stored here; tokliBIOS mmap(@BIOS) is word 0x37.
     */
    uint16_t mmr_unk[C55X_MMR_WORDS];
    uint32_t br_delay_target;
    uint8_t br_delay_pending;
    uint8_t br_delay_fire;
    /* Reset-vector bit 25 (OMAP1710 rumor: 16- vs 23-bit DAGEN). Untested
     * on OMAP2420; stored for tracing only until confirmed. */
    uint8_t vector_bit25;
    C55xHalt halt;
    uint32_t xar3_prev;
    uint32_t lmem_word;
    uint16_t lmem_even;
    uint16_t lmem_odd;
    uint16_t lmem_msw;
    uint16_t lmem_lsw;
    uint8_t xar3_watch;
    uint16_t xar3_nlogged;
    uint64_t ac0_prev;
    uint8_t ac0_watch;
    uint16_t ac0_nlogged;
    uint32_t undef_pc;
    uint8_t undef_bytes[C55X_FETCH_MAX];
    unsigned undef_length;
    C55xDecodedInsn undef_insn;
    C55xHist hist[C55X_HISTORY];
    unsigned hist_count;
    unsigned hist_next;
    uint32_t last_irq_from;
    uint32_t last_irq_vec;
    uint8_t last_irq_bit;
    uint32_t last_reti_from;
    uint32_t last_reti_to;
    uint32_t audio_isr_n;
    uint8_t in_audio_isr;
    uint8_t snap_1012fb;
    uint32_t host_tc_n;
    uint32_t host_clnk_n;
    uint64_t insn_count;
    uint8_t flow_verbose;
    uint8_t flow_mismatch_n;
    uint8_t flow_escape_logged;
    uint8_t flow_depth;
    uint32_t flow_seq;
    uint32_t flow_id[C55X_FLOW_MAX];
    uint32_t flow_expect[C55X_FLOW_MAX];
    uint32_t flow_caller[C55X_FLOW_MAX];
    uint8_t flow_kind[C55X_FLOW_MAX];
    uint32_t dev_watch[C55X_DEV_WATCH_MAX];
    uint8_t dev_watch_n;
    C55xL2Intc l2;
} C55xCPU;

static inline uint32_t c55x_word_to_byte(uint32_t word)
{
    return (word & C55X_WORD_MASK) << 1;
}

static inline uint32_t c55x_byte_to_word(uint32_t byte)
{
    return (byte >> 1) & C55X_WORD_MASK;
}

static inline uint32_t c55x_xar(const C55xCPU *cpu, unsigned n)
{
    return cpu->xar[n & 7] & C55X_WORD_MASK;
}

static inline uint16_t c55x_ar(const C55xCPU *cpu, unsigned n)
{
    return (uint16_t)cpu->xar[n & 7];
}

void c55x_init(C55xCPU *cpu, const C55xBus *bus);
void c55x_reset(C55xCPU *cpu);
void c55x_poll_trace_reset(C55xCPU *cpu);
void c55x_task_census(C55xCPU *cpu, const char *why);
/*
 * Latch PC and stack configuration from a 32-bit reset vector (SPRU371F
 * Table 4-2). Bits 29:28 select FAST16 / SLOW16 / SLOW32; bits 23:0 are
 * the entry PC. RETA and CFCT are cleared on reset.
 */
void c55x_apply_reset_vector(C55xCPU *cpu, uint32_t vector);
const char *c55x_stack_config_name(const C55xCPU *cpu);
const char *c55x_dagen_mode_name(const C55xCPU *cpu);

uint64_t c55x_get_reg(const C55xCPU *cpu, unsigned fsss);
void c55x_set_reg(C55xCPU *cpu, unsigned fsss, uint64_t value);
int64_t c55x_get_reg_signed(const C55xCPU *cpu, unsigned fsss);
uint32_t c55x_get_xreg(const C55xCPU *cpu, unsigned xsss);
void c55x_set_xreg(C55xCPU *cpu, unsigned xsss, uint32_t value);
const char *c55x_xreg_name(unsigned xsss);

uint16_t c55x_mmr_read(C55xCPU *cpu, unsigned addr);
void c55x_mmr_write(C55xCPU *cpu, unsigned addr, uint16_t value);
void c55x_st3_write(C55xCPU *cpu, uint16_t value);

int c55x_fetch(C55xCPU *cpu, uint32_t pc, uint8_t *buf, unsigned n);
int c55x_decode(C55xCPU *cpu, uint32_t pc, C55xDecodedInsn *out);
void c55x_disasm(const C55xDecodedInsn *in, char *buf, size_t len);

int c55x_step(C55xCPU *cpu);
int c55x_run(C55xCPU *cpu, uint32_t max_insns);
void c55x_knlq_note_iodma(C55xCPU *cpu, int clnk, unsigned n, unsigned ch);
void c55x_knlq_flush(C55xCPU *cpu, const char *why);

void c55x_history_add(C55xCPU *cpu, const C55xDecodedInsn *in);
void c55x_dump(const C55xCPU *cpu, const C55xDecodedInsn *in,
               char *buf, size_t len);
const char *c55x_reg_name(unsigned fsss);
const char *c55x_op_name(C55xOpKind kind);
int c55x_eval_cond(const C55xCPU *cpu, unsigned cond);
void c55x_cond_name(unsigned cond, char *buf, size_t len);

void c55x_l2intc_reset(C55xL2Intc *l2);
int c55x_l2intc_owns(uint32_t word_addr);
int c55x_l2intc_read16(C55xL2Intc *l2, uint32_t word_addr, uint16_t *out);
int c55x_l2intc_write16(C55xL2Intc *l2, uint32_t word_addr, uint16_t value);
void c55x_l2intc_set_irq(C55xL2Intc *l2, unsigned src, int level);
void c55x_l2intc_log_state(const C55xCPU *cpu, const char *why);

void c55x_flat_init(C55xFlat *flat, uint8_t *mem, size_t size);
void c55x_flat_bind(C55xFlat *flat, C55xCPU *cpu);
C55xBus c55x_flat_bus(C55xFlat *flat);

/* SPRU280H Appendix A: C55x COFF2 (22-byte filehdr, 48-byte sechdr). */
#define C55X_COFF_MAGIC        0x00c2u
#define C55X_COFF_FILEHDR      22u
#define C55X_COFF_OPTHDR       28u
#define C55X_COFF_SECHDR       48u
#define C55X_COFF_SYMESZ       18u
#define C55X_COFF_NAME_MAX     64u

#define C55X_STYP_DSECT        0x0001u
#define C55X_STYP_NOLOAD       0x0002u
#define C55X_STYP_GROUP        0x0004u
#define C55X_STYP_PAD          0x0008u
#define C55X_STYP_COPY         0x0010u
#define C55X_STYP_TEXT         0x0020u
#define C55X_STYP_DATA         0x0040u
#define C55X_STYP_BSS          0x0080u
#define C55X_STYP_BLOCK        0x1000u
#define C55X_STYP_PASS         0x2000u
#define C55X_STYP_CLINK        0x4000u

#define C55X_STYP_SKIP \
    (C55X_STYP_DSECT | C55X_STYP_NOLOAD | C55X_STYP_COPY | C55X_STYP_PAD)

typedef struct {
    char name[C55X_COFF_NAME_MAX];
    uint32_t paddr;
    uint32_t vaddr;
    uint32_t size;
    uint32_t raw_ptr;
    uint32_t reloc_ptr;
    uint32_t reloc_count;
    uint32_t flags;
    uint16_t page;
} C55xCoffSection;

typedef struct {
    uint16_t magic;
    uint16_t nscns;
    uint32_t symptr;
    uint32_t nsyms;
    uint16_t opthdr;
    uint16_t flags;
    uint16_t target;
    uint32_t entry;
    uint32_t text_start;
    uint32_t data_start;
    uint32_t tsize;
    uint32_t dsize;
    uint32_t bsize;
    unsigned nsections;
    C55xCoffSection *sec;
} C55xCoffImage;

int c55x_coff_parse(const uint8_t *file, size_t file_size,
                    C55xCoffImage *out, char *err, size_t err_len);
void c55x_coff_image_free(C55xCoffImage *img);
int c55x_coff_should_load(const C55xCoffSection *s);
void c55x_coff_flags_str(uint32_t flags, char *buf, size_t len);
const C55xCoffSection *c55x_coff_section_at(const C55xCoffImage *img,
                                            uint32_t byte_addr);

int c55x_coff_load(uint8_t *image, size_t image_size,
                   const uint8_t *file, size_t file_size,
                   uint32_t *entry_out, char *err, size_t err_len);

const C55xCoffSection *c55x_coff_section_named(const C55xCoffImage *img,
                                               const char *name);

/* SPRU281: C55x .cinit record is size(16) + dest(24) + space(8) + data.
 * Object-file words are stored big-endian (high byte at even address). */
#define C55X_CINIT_SPACE_IO    0x01u
#define C55X_CINIT_MAX_WORDS   0x1fffu

typedef struct {
    uint16_t nwords;
    uint32_t dest;
    uint8_t space;
    uint32_t rec_off;
    uint32_t data_off;
} C55xCinitRecord;

int c55x_cinit_parse(const uint8_t *sec, size_t sec_size,
                     C55xCinitRecord **out, unsigned *n_out,
                     char *err, size_t err_len);
void c55x_cinit_free(C55xCinitRecord *recs);
uint16_t c55x_cinit_word(const uint8_t *sec, const C55xCinitRecord *r,
                         unsigned i);
int c55x_cinit_find(const C55xCinitRecord *recs, unsigned n,
                    uint32_t word_addr);

#define C55X_C_EXT      2
#define C55X_C_STAT     3
#define C55X_C_LABEL    6
#define C55X_C_USTATIC  8
#define C55X_C_BLOCK    100
#define C55X_C_FCN      101
#define C55X_C_FILE     103

typedef struct {
    char name[C55X_COFF_NAME_MAX];
    uint32_t value;
    int16_t scnum;
    uint16_t type;
    uint8_t sclass;
    uint8_t naux;
} C55xCoffSymbol;

int c55x_coff_parse_syms(const uint8_t *file, size_t file_size,
                         const C55xCoffImage *img,
                         C55xCoffSymbol **out, unsigned *n_out,
                         char *err, size_t err_len);
void c55x_coff_syms_free(C55xCoffSymbol *syms);
const char *c55x_coff_sclass_str(unsigned sclass);
const C55xCoffSymbol *c55x_coff_sym_at(const C55xCoffSymbol *syms, unsigned n,
                                       uint32_t byte_addr);
const C55xCoffSymbol *c55x_coff_sym_nearest(const C55xCoffSymbol *syms,
                                            unsigned n, uint32_t byte_addr);

#endif /* HW_DSP_C55X_H */
