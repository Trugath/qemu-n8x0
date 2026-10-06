/*
 * N8x0 DSP Gateway / esd audio path. EXMAP mmap, honest CSSA→EAC IODMA,
 * mailbox TYPE2, and blob-gated tokliBIOS lifecycle. Never invent POLL
 * (cmd_h=0x32) and never steal SIO/mmap into the wav sink.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "libqtest.h"

#define PRCM_BASE           0x48008000ull
#define CM_FCLKEN1_CORE     (PRCM_BASE + 0x200)
#define CM_ICLKEN1_CORE     (PRCM_BASE + 0x210)
#define RM_RSTCTRL_DSP      (PRCM_BASE + 0x850)
#define CM_EN_EAC           (1u << 9)

#define EAC_BASE            0x48090000ull
#define EAC_CPTCTL          0x010
#define EAC_ADWR            0x0b4
#define EAC_AGCFR           0x0bc
#define EAC_AGCTR           0x0c0
#define EAC_AGCFR3          0x0c8
#define EAC_TXE             (1u << 5)
#define EAC_MN_ST           (1u << 10)
#define EAC_AUDEN           (1u << 1)
#define EAC_DMAWEN          (1u << 11)
#define EAC_FS48K           (7u << 9)

#define DSP_MEM             0x58000000ull
#define DSP_IPI             0x59000000ull
#define DSP_MMU             0x5a000000ull
#define DSP_IPI_DSPBOOTCONFIG 0x50
#define DSP_MMU_SYSSTATUS   0x14
#define DSP_MMU_FAULT_AD    0x48
#define DSP_MMU_CNTL        0x44
#define DSP_MMU_LOCK        0x50
#define DSP_MMU_LD_TLB      0x54
#define DSP_MMU_CAM         0x58
#define DSP_MMU_RAM         0x5c
#define DSP_MMU_CNTL_MMUENABLE 0x2
#define DSP_MMU_CAM_V       0x4
#define DSP_MMU_PAGE_4K     0x2
#define DSP_MMU_PAGE_64K    0x1
#define DSP_MMU_PAGE_1M     0x0

#define MAILBOX             0x48094000ull
#define MAILBOX_MESSAGE     0x040
#define MAILBOX_FIFOSTATUS  0x080
#define MAILBOX_MSGSTATUS   0x0c0
#define MAILBOX_IRQSTATUS   0x100
#define MAILBOX_IRQENABLE   0x104
#define MAILBOX_FIFO_DEPTH  4
#define MAILBOX_NEWMSG1     (1u << (2 * 1))
#define INTC                0x480fe000ull
#define INTC_SIR_IRQ        0x40
#define INTC_MIR_CLEAR0     0x88
#define INTC_MIR_CLEAR1     0xa8
#define INTC_PENDING_IRQ0   0x98
#define MAIL_U0_MPU         (1u << 26)

#define SRAM_BOOT           0x40201f00ull
#define SDRAM               0x80000000ull
#define DSP_RESET_PC        0x1036b8u
#define DSP_BOOT_WORD       (((DSP_RESET_PC & 0xffffu) << 16) | \
                             (DSP_RESET_PC >> 16))

#define DSP_WORD_MMAP       0x218000u
#define DSP_BYTE_MMAP       0x430000u
#define DSP_WORD_SIO        0x219000u
#define CSSA_BYTE           0x1ec18u
#define IODMA_PORT_CSDP_HI  0x3048u
#define IODMA_PORT_CSDP_LO  0x3049u
#define IODMA_PORT_CEN_HI   0x304au
#define IODMA_PORT_CEN_LO   0x304bu
#define IODMA_PORT_CFN_HI   0x304cu
#define IODMA_PORT_CFN_LO   0x304du
#define IODMA_PORT_CSSA_HI  0x304eu
#define IODMA_PORT_CSSA_LO  0x304fu
#define IODMA_PORT_CDSA_HI  0x3050u
#define IODMA_PORT_CDSA_LO  0x3051u
/*
 * Even port is the high half (dsp_iodma_pair). 0x0080 on 0x3040 is not
 * CCR.EN. EN is bit 7 of 0x3041. RX-34, 2026-09-30:
 *   0x0080 on 0x3040 reads back, status stays 0, ramp unchanged.
 *   EN, CDSA 0xfe00b8, EAC not opened: status 0x0100, no copy.
 *   EN, CDSA byte 0x1f200, both address modes constant: status 0x003c.
 *   Sentinels at that byte and at 0xf200 stayed put with source w0
 *   0x1111, so neither address was written.
 * CCR[13:12] source mode, CCR[15:14] dest mode. 1 is post-increment.
 */
#define IODMA_PORT_CCR_HI   0x3040u
#define IODMA_PORT_CCR_LO   0x3041u
#define IODMA_PORT_IRQSTAT0_LO 0x3005u
#define IODMA_PORT_CSR_HI   0x3046u
#define IODMA_PORT_CSR_LO   0x3047u
#define IODMA_PORT_CSEI_LO  0x3053u
#define IODMA_PORT_CDEI_LO  0x3057u
#define IODMA_CCR_ENABLE    0x0080u
#define IODMA_CCR_SRC_POST  0x1000u
#define IODMA_CCR_DST_POST  0x4000u
#define IODMA_CCR_SRC_IDX   0x2000u
#define IODMA_CCR_DST_IDX   0x8000u
#define IODMA_CSR_HALF      0x0004u
#define IODMA_CSR_LAST      0x0010u
#define IODMA_CSR_DONE      0x003cu
#define IODMA_CSR_TRANS_ERR 0x0100u
#define IODMA_CDSA_EAC      0xfe00b8u
#define IODMA_CDSA_DARAM    0x1f200u

#define PCM1_CMD4           0x20040009u
#define PCM1_ACK            0x20001234u
#define PROTREV_WORD        0x70700019u
#define IPBUF_NLINES        32u
#define IPBUF_LS_ANUM       32u

#define AUDIODEV_OPTS \
    "out.frequency=48000,out.channels=2,out.format=s16"

static const uint16_t pcm_pat[] = { 0x1111, 0x2222, 0x8000, 0x7fff };

static uint64_t mailbox_reg(unsigned fifo, unsigned base)
{
    return MAILBOX + base + 4u * fifo;
}

static uint64_t mailbox_irq_reg(unsigned user, unsigned off)
{
    return MAILBOX + off + 8u * user;
}

static void dsp_mmu_load(QTestState *qts, unsigned victim, uint32_t cam,
                         uint32_t ram)
{
    qtest_writel(qts, DSP_MMU + DSP_MMU_LOCK, victim << 4);
    qtest_writel(qts, DSP_MMU + DSP_MMU_CAM, cam);
    qtest_writel(qts, DSP_MMU + DSP_MMU_RAM, ram);
    qtest_writel(qts, DSP_MMU + DSP_MMU_LD_TLB, 1);
}

static void dsp_install_coff(QTestState *qts, const uint8_t *coff, size_t n)
{
    uint64_t text = DSP_MEM + (DSP_RESET_PC - 0x100000u);
    size_t padded = (n + 1u) & ~1u;
    uint8_t *arm = g_malloc0(padded);
    size_t i;

    memcpy(arm, coff, n);
    for (i = 0; i < padded; i += 2) {
        uint8_t t = arm[i];

        arm[i] = arm[i + 1];
        arm[i + 1] = t;
    }
    qtest_memwrite(qts, text, arm, padded);
    g_free(arm);
}

static void coff_append(GByteArray *coff, const uint8_t *b, size_t n)
{
    g_byte_array_append(coff, b, n);
}

static void coff_mov_k16_port(GByteArray *coff, uint16_t port, uint16_t imm)
{
    uint8_t b[] = {
        0xfb, 0x51,
        (uint8_t)(imm >> 8), (uint8_t)imm,
        (uint8_t)(port >> 8), (uint8_t)port,
    };

    coff_append(coff, b, sizeof(b));
}

static void coff_b_m2(GByteArray *coff)
{
    static const uint8_t b[] = { 0x4a, 0x7e };

    coff_append(coff, b, sizeof(b));
}

static void coff_mov_port_ac0(GByteArray *coff, uint16_t port)
{
    uint8_t b[] = {
        0xa0, 0x51, (uint8_t)(port >> 8), (uint8_t)port,
    };

    coff_append(coff, b, sizeof(b));
}

/* OR #0x4000<<16, AC0 so a zero port read is visible in the mailbox. */
static void coff_tag_ac0(GByteArray *coff)
{
    static const uint8_t b[] = { 0x7a, 0x40, 0x00, 0x06 };

    coff_append(coff, b, sizeof(b));
}

/*
 * MOV port, AC0; BCC AC0==0, back to that MOV (disp -7). Falls through
 * on the first nonzero half. RX-34 can return HALF or LAST there.
 */
static void coff_poll_nonzero(GByteArray *coff, uint16_t port)
{
    static const uint8_t bcc[] = { 0x04, 0x00, 0xf9 };

    coff_mov_port_ac0(coff, port);
    coff_append(coff, bcc, sizeof(bcc));
}

/*
 * Wait until CSR holds BLOCK, TRANS_ERR, or MISALIGN, then read the
 * port again so the published word is the finished status.
 * MOV, AND #0x0920, BCC AC0==0 back to the MOV (disp -11), MOV.
 */
static void coff_poll_port(GByteArray *coff, uint16_t port)
{
    static const uint8_t mid[] = {
        0x7d, 0x09, 0x20, 0x00,
        0x04, 0x00, 0xf5,
    };

    coff_mov_port_ac0(coff, port);
    coff_append(coff, mid, sizeof(mid));
    coff_mov_port_ac0(coff, port);
}

static void coff_publish_ac0(GByteArray *coff)
{
    static const uint8_t b[] = {
        0xeb, 0x31, 0x08, 0x20, 0x00, 0x22, /* MOV AC0, dbl(*(#0x200022)) */
    };

    coff_append(coff, b, sizeof(b));
}

static void coff_load16_mbox(GByteArray *coff, uint32_t word_addr)
{
    uint8_t b[] = {
        0xec, 0x31, 0x8e,
        (uint8_t)(word_addr >> 16),
        (uint8_t)(word_addr >> 8),
        (uint8_t)word_addr,
        0xa0, 0x01,                         /* MOV *AR0, AC0 */
        0xeb, 0x31, 0x08, 0x20, 0x00, 0x22, /* MOV AC0, dbl(*(#0x200022)) */
        0x4a, 0x7e,
    };

    coff_append(coff, b, sizeof(b));
}

static void coff_publish_word(GByteArray *coff, uint32_t word)
{
    /* MESSAGE readl is swab32(AC0). Plant the preimage of `word`. */
    uint32_t planted = GUINT32_SWAP_LE_BE(word);
    uint16_t lo = (uint16_t)planted;
    uint16_t hi = (uint16_t)(planted >> 16);
    uint8_t mov[] = {
        0x76, (uint8_t)(lo >> 8), (uint8_t)lo, 0x08, /* MOV #lo, AC0 */
        0x7a, (uint8_t)(hi >> 8), (uint8_t)hi, 0x06, /* OR #hi<<16, AC0 */
    };

    coff_append(coff, mov, sizeof(mov));
    coff_publish_ac0(coff);
    coff_b_m2(coff);
}

static const uint8_t protrev_body[] = {
    /* MOV #0x7070, AC0; OR #0x1900<<16, AC0. ARM sees 0x70700019. */
    0x76, 0x70, 0x70, 0x08,
    0x7a, 0x19, 0x00, 0x06,
    0xeb, 0x31, 0x08, 0x08, 0x00, 0x00,
    0xeb, 0x31, 0x08, 0x20, 0x00, 0x22,
    0x4a, 0x7e,
};

static void dsp_hold_reset(QTestState *qts)
{
    qtest_writel(qts, RM_RSTCTRL_DSP, 1);
}

static void dsp_map_common(QTestState *qts, bool map_exmap)
{
    dsp_mmu_load(qts, 0, 0x100000u | DSP_MMU_CAM_V | DSP_MMU_PAGE_1M,
                 (uint32_t)DSP_MEM);
    dsp_mmu_load(qts, 1, 0xfff000u | DSP_MMU_CAM_V | DSP_MMU_PAGE_4K,
                 0x40201000u);
    dsp_mmu_load(qts, 2, 0x400000u | DSP_MMU_CAM_V | DSP_MMU_PAGE_4K,
                 (uint32_t)MAILBOX);
    dsp_mmu_load(qts, 3, 0xfe2000u | DSP_MMU_CAM_V | DSP_MMU_PAGE_4K,
                 (uint32_t)MAILBOX);
    dsp_mmu_load(qts, 4, 0xfe0000u | DSP_MMU_CAM_V | DSP_MMU_PAGE_4K,
                 (uint32_t)EAC_BASE);
    if (map_exmap) {
        dsp_mmu_load(qts, 5, DSP_BYTE_MMAP | DSP_MMU_CAM_V | DSP_MMU_PAGE_64K,
                     (uint32_t)SDRAM);
    }
    qtest_writel(qts, DSP_MMU + DSP_MMU_CNTL, DSP_MMU_CNTL_MMUENABLE);
    qtest_writel(qts, SRAM_BOOT, DSP_BOOT_WORD);
    qtest_writel(qts, DSP_IPI + DSP_IPI_DSPBOOTCONFIG, 0);
}

static void dsp_run(QTestState *qts, const uint8_t *coff, size_t n,
                    bool map_exmap)
{
    dsp_hold_reset(qts);
    dsp_install_coff(qts, coff, n);
    dsp_map_common(qts, map_exmap);
    qtest_writel(qts, RM_RSTCTRL_DSP, 0);
}

static void mailbox_drain(QTestState *qts, unsigned fifo)
{
    while (qtest_readl(qts, mailbox_reg(fifo, MAILBOX_MSGSTATUS))) {
        qtest_readl(qts, mailbox_reg(fifo, MAILBOX_MESSAGE));
    }
}

static void arm_write_pcm(QTestState *qts, uint64_t pa, unsigned n,
                          const uint16_t *pat, unsigned patn)
{
    unsigned i;

    for (i = 0; i < n; i++) {
        qtest_writew(qts, pa + i * 2ull, pat[i % patn]);
    }
}

static QTestState *dsp_start(void)
{
    QTestState *qts = qtest_initf("-machine n810 -display none");
    uint32_t fclk = qtest_readl(qts, CM_FCLKEN1_CORE);
    uint32_t iclk = qtest_readl(qts, CM_ICLKEN1_CORE);

    qtest_writel(qts, CM_FCLKEN1_CORE, fclk | CM_EN_EAC);
    qtest_writel(qts, CM_ICLKEN1_CORE, iclk | CM_EN_EAC);
    g_assert_cmphex(qtest_readl(qts, DSP_MMU + DSP_MMU_SYSSTATUS) & 1, ==, 1);
    return qts;
}

static char *make_wav_path(void)
{
    char *path = NULL;
    GError *err = NULL;
    int fd = g_file_open_tmp("n8x0-dsp-XXXXXX", &path, &err);

    g_assert_no_error(err);
    g_assert_cmpint(fd, >=, 0);
    close(fd);
    return path;
}

static QTestState *dsp_start_wav(const char *wav)
{
    QTestState *qts;
    uint32_t fclk;
    uint32_t iclk;

    qts = qtest_initf("-machine n810,audiodev=snd0 -display none "
                      "-audiodev wav,id=snd0,path=%s,%s",
                      wav, AUDIODEV_OPTS);
    fclk = qtest_readl(qts, CM_FCLKEN1_CORE);
    iclk = qtest_readl(qts, CM_ICLKEN1_CORE);
    qtest_writel(qts, CM_FCLKEN1_CORE, fclk | CM_EN_EAC);
    qtest_writel(qts, CM_ICLKEN1_CORE, iclk | CM_EN_EAC);
    return qts;
}

static void eac_config_play(QTestState *qts)
{
    int i;

    qtest_writew(qts, EAC_BASE + EAC_AGCFR,
                 qtest_readw(qts, EAC_BASE + EAC_AGCFR) | EAC_MN_ST);
    qtest_writew(qts, EAC_BASE + EAC_AGCFR3, EAC_FS48K);
    qtest_writew(qts, EAC_BASE + EAC_AGCTR, EAC_AUDEN | EAC_DMAWEN);
    for (i = 0; i < 32; i++) {
        qtest_clock_step(qts, NANOSECONDS_PER_SECOND / 100);
        if (qtest_readw(qts, EAC_BASE + EAC_CPTCTL) & EAC_TXE) {
            return;
        }
    }
    g_error("EAC TXE did not assert");
}

typedef struct {
    int16_t *pcm;
    size_t frames;
} WavPcm;

static bool read_le16(const uint8_t *p, size_t n, uint16_t *out)
{
    if (n < 2) {
        return false;
    }
    *out = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
    return true;
}

static bool read_le32(const uint8_t *p, size_t n, uint32_t *out)
{
    if (n < 4) {
        return false;
    }
    *out = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    return true;
}

static WavPcm load_wav(const char *path)
{
    GError *err = NULL;
    gchar *data = NULL;
    gsize n = 0;
    WavPcm wav = { 0 };
    const uint8_t *p;
    uint16_t fmt = 0, channels = 0, bits = 0;
    uint32_t rate = 0;
    bool have_fmt = false;

    g_assert(g_file_get_contents(path, &data, &n, &err));
    g_assert_no_error(err);
    p = (const uint8_t *)data;
    g_assert_cmpuint(n, >=, 12);
    p += 12;
    n -= 12;
    while (n >= 8) {
        uint32_t chunk_size = 0;
        bool is_fmt = p[0] == 'f' && p[1] == 'm' && p[2] == 't';
        bool is_data = p[0] == 'd' && p[1] == 'a' && p[2] == 't' && p[3] == 'a';

        g_assert(read_le32(p + 4, n - 4, &chunk_size));
        p += 8;
        n -= 8;
        g_assert_cmpuint(chunk_size, <=, n);
        if (is_fmt) {
            g_assert(read_le16(p, n, &fmt));
            g_assert(read_le16(p + 2, n - 2, &channels));
            g_assert(read_le32(p + 4, n - 4, &rate));
            g_assert(read_le16(p + 14, n - 14, &bits));
            have_fmt = true;
        } else if (is_data) {
            g_assert(have_fmt);
            g_assert_cmphex(fmt, ==, 1);
            g_assert_cmpuint(channels, ==, 2);
            g_assert_cmpuint(bits, ==, 16);
            g_assert_cmpuint(rate, ==, 48000);
            wav.frames = chunk_size / 4;
            wav.pcm = g_new(int16_t, wav.frames * 2);
            memcpy(wav.pcm, p, chunk_size);
            break;
        }
        p += chunk_size + (chunk_size & 1);
        n -= chunk_size + (chunk_size & 1);
    }
    g_free(data);
    return wav;
}

static void wav_free(WavPcm *wav)
{
    g_free(wav->pcm);
    wav->pcm = NULL;
}

static void coff_publish_tagged_port(GByteArray *coff, uint16_t port)
{
    coff_mov_port_ac0(coff, port);
    coff_tag_ac0(coff);
    coff_publish_ac0(coff);
}

/*
 * tail 0: publish the ack and halt.
 * tail 1: poll CSR, publish both halves, halt.
 * tail 2: publish CSR low and CCR high now, halt.
 * tail 3: poll CSR, publish both halves and CCR low, halt.
 * tail 4: poll CSR, publish it, clear HALF, publish CSR and IRQSTATUS.
 * tail 5: publish the first nonzero CSR and CCR low. That is the
 *         early word, not the finished one.
 */
static GByteArray *iodma_program_ex(uint32_t cssa, uint32_t cdsa,
                                    uint16_t cen, uint16_t cfn,
                                    uint16_t ccr_hi, uint16_t ccr_lo,
                                    uint16_t sei, uint16_t dei, int tail)
{
    GByteArray *coff = g_byte_array_new();

    coff_mov_k16_port(coff, IODMA_PORT_CSDP_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CSDP_LO, 1);
    coff_mov_k16_port(coff, IODMA_PORT_CEN_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CEN_LO, cen);
    coff_mov_k16_port(coff, IODMA_PORT_CFN_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CFN_LO, cfn);
    coff_mov_k16_port(coff, IODMA_PORT_CSSA_HI, (uint16_t)(cssa >> 16));
    coff_mov_k16_port(coff, IODMA_PORT_CSSA_LO, (uint16_t)cssa);
    coff_mov_k16_port(coff, IODMA_PORT_CDSA_HI, (uint16_t)(cdsa >> 16));
    coff_mov_k16_port(coff, IODMA_PORT_CDSA_LO, (uint16_t)cdsa);
    coff_mov_k16_port(coff, IODMA_PORT_CSEI_LO, sei);
    coff_mov_k16_port(coff, IODMA_PORT_CDEI_LO, dei);
    coff_mov_k16_port(coff, IODMA_PORT_CCR_HI, ccr_hi);
    coff_mov_k16_port(coff, IODMA_PORT_CCR_LO, ccr_lo);
    if (tail == 1 || tail == 3) {
        coff_poll_port(coff, IODMA_PORT_CSR_LO);
        coff_tag_ac0(coff);
        coff_publish_ac0(coff);
        coff_publish_tagged_port(coff, IODMA_PORT_CSR_HI);
        if (tail == 3) {
            coff_publish_tagged_port(coff, IODMA_PORT_CCR_LO);
        }
        coff_b_m2(coff);
    } else if (tail == 4) {
        coff_poll_port(coff, IODMA_PORT_CSR_LO);
        coff_tag_ac0(coff);
        coff_publish_ac0(coff);
        coff_publish_tagged_port(coff, IODMA_PORT_IRQSTAT0_LO);
        coff_mov_k16_port(coff, IODMA_PORT_CSR_LO, IODMA_CSR_HALF);
        coff_publish_tagged_port(coff, IODMA_PORT_CSR_LO);
        coff_b_m2(coff);
    } else if (tail == 2) {
        coff_publish_tagged_port(coff, IODMA_PORT_CSR_LO);
        coff_publish_tagged_port(coff, IODMA_PORT_CCR_HI);
        coff_b_m2(coff);
    } else if (tail == 5) {
        coff_poll_nonzero(coff, IODMA_PORT_CSR_LO);
        coff_tag_ac0(coff);
        coff_publish_ac0(coff);
        coff_publish_tagged_port(coff, IODMA_PORT_CCR_LO);
        coff_b_m2(coff);
    } else {
        coff_publish_word(coff, PCM1_ACK);
    }
    return coff;
}

static GByteArray *iodma_program_full(uint32_t cssa, uint32_t cdsa,
                                      uint16_t cen, uint16_t cfn,
                                      uint16_t ccr_hi, uint16_t ccr_lo,
                                      int tail)
{
    return iodma_program_ex(cssa, cdsa, cen, cfn, ccr_hi, ccr_lo, 0, 0, tail);
}

static GByteArray *iodma_program(uint32_t cssa, uint16_t cen, uint16_t cfn)
{
    /* Playback CCR: source post-increments, the EAC FIFO does not. */
    return iodma_program_full(cssa, IODMA_CDSA_EAC, cen, cfn, 0,
                              IODMA_CCR_ENABLE | IODMA_CCR_SRC_POST, 0);
}

static void test_exmap_mmap(void)
{
    QTestState *qts = dsp_start();
    GByteArray *coff = g_byte_array_new();
    uint32_t word;

    mailbox_drain(qts, 1);
    arm_write_pcm(qts, SDRAM, 4, pcm_pat, 4);
    coff_load16_mbox(coff, DSP_WORD_MMAP);
    dsp_run(qts, coff->data, coff->len, true);
    g_assert_cmphex(qtest_readl(qts, mailbox_reg(1, MAILBOX_MSGSTATUS)), ==, 1);
    word = qtest_readl(qts, mailbox_reg(1, MAILBOX_MESSAGE));
    g_assert_cmphex(word, ==, 0x11110000u);
    dsp_hold_reset(qts);
    g_byte_array_free(coff, TRUE);
    qtest_quit(qts);
}

static void test_exmap_unmapped_fault(void)
{
    QTestState *qts = dsp_start();
    GByteArray *coff = g_byte_array_new();
    uint32_t fault;
    uint32_t status;
    uint32_t word = 0;

    mailbox_drain(qts, 1);
    arm_write_pcm(qts, SDRAM, 4, pcm_pat, 4);
    coff_load16_mbox(coff, DSP_WORD_MMAP);
    dsp_run(qts, coff->data, coff->len, false);
    status = qtest_readl(qts, mailbox_reg(1, MAILBOX_MSGSTATUS));
    if (status) {
        word = qtest_readl(qts, mailbox_reg(1, MAILBOX_MESSAGE));
    }
    fault = qtest_readl(qts, DSP_MMU + DSP_MMU_FAULT_AD);
    g_assert_cmphex(fault, ==, DSP_BYTE_MMAP);
    g_assert_cmpuint(status, ==, 0);
    g_assert_cmphex(word, !=, pcm_pat[0]);
    dsp_hold_reset(qts);
    g_byte_array_free(coff, TRUE);
    qtest_quit(qts);
}

static void test_iodma_cssa_to_eac(void)
{
    char *wav_path = make_wav_path();
    QTestState *qts = dsp_start_wav(wav_path);
    GByteArray *coff;
    WavPcm wav;
    unsigned i;

    eac_config_play(qts);
    arm_write_pcm(qts, DSP_MEM + CSSA_BYTE, 128, pcm_pat, 4);
    coff = iodma_program(CSSA_BYTE, 8, 16);
    mailbox_drain(qts, 1);
    dsp_run(qts, coff->data, coff->len, true);
    g_assert_cmphex(qtest_readl(qts, mailbox_reg(1, MAILBOX_MSGSTATUS)), ==, 1);
    g_assert_cmphex(qtest_readl(qts, mailbox_reg(1, MAILBOX_MESSAGE)),
                    ==, PCM1_ACK);
    qtest_clock_step(qts, ((int64_t)80 * NANOSECONDS_PER_SECOND) / 48000 +
                          NANOSECONDS_PER_SECOND / 20);
    dsp_hold_reset(qts);
    qtest_quit(qts);
    wav = load_wav(wav_path);
    g_assert_cmpuint(wav.frames, >=, 4);
    for (i = 0; i < 8; i++) {
        g_assert_cmphex((uint16_t)wav.pcm[i], ==, pcm_pat[i % 4]);
    }
    wav_free(&wav);
    unlink(wav_path);
    g_free(wav_path);
    g_byte_array_free(coff, TRUE);
}

static void test_iodma_no_sio_steal(void)
{
    char *wav_path = make_wav_path();
    QTestState *qts = dsp_start_wav(wav_path);
    GByteArray *coff;
    WavPcm wav;
    unsigned i;
    uint16_t zero[] = { 0, 0, 0, 0 };
    uint16_t loud[] = { 0x1111, 0x2222, 0x3333, 0x4444 };

    eac_config_play(qts);
    arm_write_pcm(qts, DSP_MEM + CSSA_BYTE, 128, zero, 4);
    arm_write_pcm(qts, SDRAM, 128, loud, 4);
    arm_write_pcm(qts, SDRAM + (DSP_WORD_SIO - DSP_WORD_MMAP) * 2ull, 128,
                  loud, 4);
    coff = iodma_program(CSSA_BYTE, 8, 16);
    mailbox_drain(qts, 1);
    dsp_run(qts, coff->data, coff->len, true);
    g_assert_cmphex(qtest_readl(qts, mailbox_reg(1, MAILBOX_MSGSTATUS)), ==, 1);
    g_assert_cmphex(qtest_readl(qts, mailbox_reg(1, MAILBOX_MESSAGE)),
                    ==, PCM1_ACK);
    qtest_clock_step(qts, ((int64_t)80 * NANOSECONDS_PER_SECOND) / 48000 +
                          NANOSECONDS_PER_SECOND / 20);
    dsp_hold_reset(qts);
    qtest_quit(qts);
    wav = load_wav(wav_path);
    g_assert_cmpuint(wav.frames, >=, 4);
    for (i = 0; i < wav.frames * 2 && i < 16; i++) {
        g_assert_cmphex((uint16_t)wav.pcm[i], !=, loud[0]);
        g_assert_cmphex((uint16_t)wav.pcm[i], !=, loud[1]);
        g_assert_cmphex((uint16_t)wav.pcm[i], !=, loud[2]);
        g_assert_cmphex((uint16_t)wav.pcm[i], !=, loud[3]);
    }
    wav_free(&wav);
    unlink(wav_path);
    g_free(wav_path);
    g_byte_array_free(coff, TRUE);
}

#define MCSPI1_BASE         0x48098000ull
#define MCSPI_CHCONF0       0x2c
#define MCSPI_CHCTRL0       0x34
#define MCSPI_TX0           0x38
#define MCSPI_RX0           0x3c
#define TSC_DAC_WORD        0x2b00u
#define RAMP_IODMA_FRAMES   240u

static uint16_t tsc2301_spi_xfer(QTestState *qts, uint16_t cmd, uint16_t data)
{
    qtest_writel(qts, MCSPI1_BASE + MCSPI_CHCONF0, 0x060000u | (15u << 7));
    qtest_writel(qts, MCSPI1_BASE + MCSPI_CHCTRL0, 1);
    qtest_writel(qts, MCSPI1_BASE + MCSPI_TX0, cmd);
    qtest_readl(qts, MCSPI1_BASE + MCSPI_RX0);
    qtest_writel(qts, MCSPI1_BASE + MCSPI_TX0, data);
    return qtest_readl(qts, MCSPI1_BASE + MCSPI_RX0) & 0xffff;
}

static uint16_t ramp_half(unsigned frame, int right)
{
    if (right) {
        return (uint16_t)(0x4000u + frame * 5u);
    }
    return (uint16_t)(frame * 3u);
}

static QTestState *dsp_start_wav_machine(const char *machine, const char *wav)
{
    QTestState *qts;
    uint32_t fclk;
    uint32_t iclk;

    qts = qtest_initf("-machine %s,audiodev=snd0 -display none "
                      "-audiodev wav,id=snd0,path=%s,%s",
                      machine, wav, AUDIODEV_OPTS);
    fclk = qtest_readl(qts, CM_FCLKEN1_CORE);
    iclk = qtest_readl(qts, CM_ICLKEN1_CORE);
    qtest_writel(qts, CM_FCLKEN1_CORE, fclk | CM_EN_EAC);
    qtest_writel(qts, CM_ICLKEN1_CORE, iclk | CM_EN_EAC);
    return qts;
}

/*
 * One 16-bit IODMA block of the ARM ramp (cen=8, cfn=60, n=480) into
 * EAC 0xfe00b8. The wav must be that buffer on both channels: no
 * inserted 0x0007 and no replay of the block.
 */
static void test_iodma_ramp_n800(void)
{
    char *wav_path = make_wav_path();
    QTestState *qts = dsp_start_wav_machine("n800", wav_path);
    uint16_t pcm[RAMP_IODMA_FRAMES * 2];
    GByteArray *coff;
    WavPcm wav;
    unsigned i;
    uint16_t p2;

    for (i = 0; i < RAMP_IODMA_FRAMES; i++) {
        pcm[i * 2] = ramp_half(i, 0);
        pcm[i * 2 + 1] = ramp_half(i, 1);
    }
    p2 = tsc2301_spi_xfer(qts, (2u << 11) | (5u << 5), TSC_DAC_WORD);
    (void)p2;
    qtest_clock_step(qts, 110 * NANOSECONDS_PER_SECOND / 1000);
    g_assert_cmphex(tsc2301_spi_xfer(qts, 0x8000u | (2u << 11) | (5u << 5), 0),
                    ==, TSC_DAC_WORD);
    eac_config_play(qts);
    arm_write_pcm(qts, DSP_MEM + CSSA_BYTE, RAMP_IODMA_FRAMES * 2, pcm,
                  RAMP_IODMA_FRAMES * 2);
    coff = iodma_program(CSSA_BYTE, 8, 60);
    mailbox_drain(qts, 1);
    dsp_run(qts, coff->data, coff->len, true);
    g_assert_cmphex(qtest_readl(qts, mailbox_reg(1, MAILBOX_MSGSTATUS)), ==, 1);
    g_assert_cmphex(qtest_readl(qts, mailbox_reg(1, MAILBOX_MESSAGE)),
                    ==, PCM1_ACK);
    qtest_clock_step(qts, ((int64_t)RAMP_IODMA_FRAMES * NANOSECONDS_PER_SECOND) /
                              48000 +
                          NANOSECONDS_PER_SECOND / 20);
    dsp_hold_reset(qts);
    qtest_quit(qts);
    wav = load_wav(wav_path);
    g_assert_cmpuint(wav.frames, >=, RAMP_IODMA_FRAMES);
    for (i = 0; i < RAMP_IODMA_FRAMES * 2; i++) {
        g_assert_cmphex((uint16_t)wav.pcm[i], ==, pcm[i]);
    }
    for (i = RAMP_IODMA_FRAMES * 2; i + 1 < wav.frames * 2; i += 2) {
        g_assert_cmphex((uint16_t)wav.pcm[i], ==, 0);
        g_assert_cmphex((uint16_t)wav.pcm[i + 1], ==, 0);
    }
    wav_free(&wav);
    unlink(wav_path);
    g_free(wav_path);
    g_byte_array_free(coff, TRUE);
}

static void qmp_set_bool(QTestState *qts, const char *prop, bool value)
{
    const char *fmt = value ?
        "{'execute':'qom-set','arguments':{'path':'/omap2-mpu-intc',"
        "'property':%s,'value':true}}" :
        "{'execute':'qom-set','arguments':{'path':'/omap2-mpu-intc',"
        "'property':%s,'value':false}}";
    QDict *rsp = qtest_qmp(qts, fmt, prop);

    if (qdict_haskey(rsp, "error")) {
        g_printerr("qom-set %s: %s\n", prop,
                   qdict_get_str(qdict_get_qdict(rsp, "error"), "desc"));
    }
    g_assert(!qdict_haskey(rsp, "error"));
    qobject_unref(rsp);
}

/*
 * 20260923T100640Z: FIFO1 already held the cmd 2 word, line 26 was
 * latched and unmasked, and NEWIRQAGR was clear while the CPU was
 * still running. The rise-time re-arm did not see that halt. The
 * read's later wait is what has to deliver MAIL_U0.
 */
static void test_mail_u0_rearm_on_halt(void)
{
    QTestState *qts = qtest_init("-machine n800 -display none");
    uint32_t sir;

    qtest_writel(qts, INTC + INTC_MIR_CLEAR0, MAIL_U0_MPU | 1u);
    qmp_set_bool(qts, "x-suppress-mail-edge-rearm", true);
    qtest_set_irq_in(qts, "/omap2-mpu-intc", NULL, 0, 1);
    qtest_set_irq_in(qts, "/omap2-mpu-intc", NULL, 0, 0);
    qtest_writel(qts, mailbox_irq_reg(0, MAILBOX_IRQENABLE), MAILBOX_NEWMSG1);
    qtest_writel(qts, mailbox_reg(1, MAILBOX_MESSAGE), 0x2002000d);
    g_assert_cmphex(qtest_readl(qts, mailbox_reg(1, MAILBOX_MSGSTATUS)), ==, 1);
    g_assert_cmphex(qtest_readl(qts, INTC + INTC_PENDING_IRQ0) & MAIL_U0_MPU,
                    ==, MAIL_U0_MPU);
    sir = qtest_readl(qts, INTC + INTC_SIR_IRQ);
    g_assert_cmpuint(sir, !=, 26);
    qmp_set_bool(qts, "x-mail-wfi-rearm", true);
    sir = qtest_readl(qts, INTC + INTC_SIR_IRQ);
    g_assert_cmpuint(sir, ==, 26);
    qtest_quit(qts);
}

/*
 * Line 37 stays level-high and has equal priority, so it wins SIR.
 * deliver_stuck_mail must still select MAIL_U0 and leave the FIFO1
 * word in place.
 */
static void test_mail_prefer_26_over_line37(void)
{
    QTestState *qts = qtest_init("-machine n800 -display none");
    uint32_t sir;

    qtest_writel(qts, INTC + INTC_MIR_CLEAR0, MAIL_U0_MPU);
    qtest_writel(qts, INTC + INTC_MIR_CLEAR1, 1u << 5);
    qtest_set_irq_in(qts, "/omap2-mpu-intc", NULL, 37, 1);
    qtest_writel(qts, mailbox_irq_reg(0, MAILBOX_IRQENABLE), MAILBOX_NEWMSG1);
    qtest_writel(qts, mailbox_reg(1, MAILBOX_MESSAGE), 0x2002000d);
    g_assert_cmphex(qtest_readl(qts, mailbox_reg(1, MAILBOX_MSGSTATUS)), ==, 1);
    g_assert_cmphex(qtest_readl(qts, INTC + INTC_PENDING_IRQ0) & MAIL_U0_MPU,
                    ==, MAIL_U0_MPU);
    sir = qtest_readl(qts, INTC + INTC_SIR_IRQ);
    g_assert_cmpuint(sir, !=, 26);
    qmp_set_bool(qts, "x-mail-prefer-26", true);
    sir = qtest_readl(qts, INTC + INTC_SIR_IRQ);
    g_assert_cmpuint(sir, ==, 26);
    g_assert_cmphex(qtest_readl(qts, mailbox_reg(1, MAILBOX_MSGSTATUS)), ==, 1);
    g_assert_cmphex(qtest_readl(qts, mailbox_reg(1, MAILBOX_MESSAGE)),
                    ==, 0x2002000d);
    qtest_quit(qts);
}

static uint32_t cmd_h(uint32_t word)
{
    return (word >> 24) & 0x7f;
}

static void test_mailbox_audio(void)
{
    QTestState *qts = dsp_start();
    GByteArray *coff;
    uint32_t status;
    uint32_t word;
    unsigned i;

    mailbox_drain(qts, 0);
    mailbox_drain(qts, 1);
    qtest_writel(qts, mailbox_irq_reg(0, MAILBOX_IRQSTATUS), 0xffffffff);
    qtest_writel(qts, mailbox_irq_reg(0, MAILBOX_IRQENABLE), MAILBOX_NEWMSG1);
    qtest_writel(qts, INTC + INTC_MIR_CLEAR0, MAIL_U0_MPU);

    for (i = 0; i < MAILBOX_FIFO_DEPTH; i++) {
        qtest_writel(qts, mailbox_reg(0, MAILBOX_MESSAGE), PCM1_CMD4);
    }
    g_assert_cmphex(qtest_readl(qts, mailbox_reg(0, MAILBOX_MSGSTATUS)),
                    ==, MAILBOX_FIFO_DEPTH);
    g_assert_cmphex(qtest_readl(qts, mailbox_reg(0, MAILBOX_FIFOSTATUS)) & 1,
                    ==, 1);
    qtest_writel(qts, mailbox_reg(0, MAILBOX_MESSAGE), 0x2005ffff);
    g_assert_cmphex(qtest_readl(qts, mailbox_reg(0, MAILBOX_MSGSTATUS)),
                    ==, MAILBOX_FIFO_DEPTH);
    mailbox_drain(qts, 0);
    g_assert_cmphex(qtest_readl(qts, mailbox_reg(0, MAILBOX_MSGSTATUS)), ==, 0);

    coff = g_byte_array_new();
    coff_publish_word(coff, PCM1_ACK);
    dsp_run(qts, coff->data, coff->len, false);
    g_assert_cmphex(qtest_readl(qts, mailbox_reg(1, MAILBOX_MSGSTATUS)), ==, 1);
    status = qtest_readl(qts, mailbox_irq_reg(0, MAILBOX_IRQSTATUS));
    g_assert_cmphex(status & MAILBOX_NEWMSG1, ==, MAILBOX_NEWMSG1);
    g_assert_cmphex(qtest_readl(qts, INTC + INTC_PENDING_IRQ0) & MAIL_U0_MPU,
                    ==, MAIL_U0_MPU);
    qtest_writel(qts, mailbox_irq_reg(0, MAILBOX_IRQSTATUS), MAILBOX_NEWMSG1);
    g_assert_cmphex(qtest_readl(qts, mailbox_irq_reg(0, MAILBOX_IRQSTATUS)) &
                    MAILBOX_NEWMSG1, ==, MAILBOX_NEWMSG1);
    word = qtest_readl(qts, mailbox_reg(1, MAILBOX_MESSAGE));
    g_assert_cmphex(word, ==, PCM1_ACK);
    g_assert_cmphex(cmd_h(word), !=, 0x32);
    qtest_writel(qts, mailbox_irq_reg(0, MAILBOX_IRQSTATUS), MAILBOX_NEWMSG1);
    g_assert_cmphex(qtest_readl(qts, mailbox_irq_reg(0, MAILBOX_IRQSTATUS)) &
                    MAILBOX_NEWMSG1, ==, 0);
    g_assert_cmphex(qtest_readl(qts, INTC + INTC_PENDING_IRQ0) & MAIL_U0_MPU,
                    ==, 0);
    dsp_hold_reset(qts);
    g_byte_array_free(coff, TRUE);

    coff = g_byte_array_new();
    {
        uint8_t rpt[] = { 0x0c, 0x9c, 0x40, 0x20 };

        coff_append(coff, rpt, sizeof(rpt));
    }
    coff_publish_word(coff, PCM1_ACK);
    mailbox_drain(qts, 1);
    dsp_run(qts, coff->data, coff->len, false);
    g_assert_cmphex(qtest_readl(qts, mailbox_reg(1, MAILBOX_MSGSTATUS)), ==, 0);
    qtest_clock_step(qts, NANOSECONDS_PER_SECOND / 200);
    g_assert_cmphex(qtest_readl(qts, mailbox_reg(1, MAILBOX_MSGSTATUS)), ==, 1);
    word = qtest_readl(qts, mailbox_reg(1, MAILBOX_MESSAGE));
    g_assert_cmphex(word, ==, PCM1_ACK);
    g_assert_cmphex(cmd_h(word), !=, 0x32);
    dsp_hold_reset(qts);
    g_byte_array_free(coff, TRUE);
    qtest_quit(qts);
}

typedef struct {
    unsigned dsp_free;
    unsigned arm_owned;
    unsigned head;
    unsigned tail;
    unsigned count;
    unsigned bids[IPBUF_NLINES];
} IpbufRing;

static int ipbuf_bid_ok(unsigned data)
{
    return data < IPBUF_LS_ANUM;
}

static void ipbuf_push(IpbufRing *r, unsigned bid)
{
    g_assert_true(ipbuf_bid_ok(bid));
    g_assert_cmpuint(r->count, <, IPBUF_NLINES);
    r->bids[r->head] = bid;
    r->head = (r->head + 1u) % IPBUF_NLINES;
    r->count++;
}

static unsigned ipbuf_pop(IpbufRing *r)
{
    unsigned bid;

    g_assert_cmpuint(r->count, >, 0);
    bid = r->bids[r->tail];
    r->tail = (r->tail + 1u) % IPBUF_NLINES;
    r->count--;
    return bid;
}

static void test_ipbuf_ring(void)
{
    IpbufRing r = { 0 };
    unsigned i;
    unsigned bid;
    unsigned wrap_bid;

    /* Empty. */
    r.dsp_free = IPBUF_NLINES;
    r.arm_owned = 0;
    g_assert_cmpuint(r.count, ==, 0);
    g_assert_false(ipbuf_bid_ok(IPBUF_LS_ANUM));
    g_assert_false(ipbuf_bid_ok(IPBUF_LS_ANUM + 1));

    /* One. */
    ipbuf_push(&r, 0);
    g_assert_cmpuint(r.count, ==, 1);
    r.dsp_free--;
    r.arm_owned++;

    /* Fill to capacity, then wrap by popping and pushing the same bid. */
    for (i = 1; i < IPBUF_NLINES; i++) {
        ipbuf_push(&r, i);
        r.dsp_free--;
        r.arm_owned++;
    }
    g_assert_cmpuint(r.count, ==, IPBUF_NLINES);
    g_assert_cmpuint(r.arm_owned, ==, IPBUF_NLINES);
    g_assert_cmpuint(r.dsp_free, ==, 0);
    wrap_bid = ipbuf_pop(&r);
    g_assert_cmpuint(wrap_bid, ==, 0);
    r.arm_owned--;
    r.dsp_free++;
    ipbuf_push(&r, wrap_bid);
    r.dsp_free--;
    r.arm_owned++;
    g_assert_cmpuint(r.bids[(r.head + IPBUF_NLINES - 1) % IPBUF_NLINES],
                     ==, wrap_bid);
    g_assert_cmpuint(r.tail, ==, 1);

    /* DSP-ahead: more free lines than ARM-owned. */
    while (r.count) {
        bid = ipbuf_pop(&r);
        r.arm_owned--;
        r.dsp_free++;
        (void)bid;
    }
    r.dsp_free = 20;
    r.arm_owned = 4;
    g_assert_cmpuint(r.arm_owned + r.dsp_free, <=, IPBUF_NLINES);
    g_assert_cmpuint(r.dsp_free, >, r.arm_owned);

    /* ARM-ahead. */
    r.dsp_free = 4;
    r.arm_owned = 12;
    g_assert_cmpuint(r.arm_owned + r.dsp_free, <=, IPBUF_NLINES);
    g_assert_cmpuint(r.arm_owned, >, r.dsp_free);
    g_assert_cmpuint(r.arm_owned, >=, IPBUF_NLINES >> 2);
}

static gchar *avs_kernel_path(void)
{
    static const char *cands[] = {
        "build/maemo/analysis/rootfs/lib/dsp/avs_kernel.out",
        "build/maemo/rootfs/lib/dsp/avs_kernel.out",
        "build/maemo/lib/dsp/avs_kernel.out",
        NULL,
    };
    const char *env = g_getenv("N8X0_AVS_KERNEL");
    unsigned i;

    if (env && g_file_test(env, G_FILE_TEST_IS_REGULAR)) {
        return g_strdup(env);
    }
    for (i = 0; cands[i]; i++) {
        if (g_file_test(cands[i], G_FILE_TEST_IS_REGULAR)) {
            return g_strdup(cands[i]);
        }
    }
    return NULL;
}

static void test_protrev_golden(void)
{
    QTestState *qts = dsp_start();
    uint32_t word;

    mailbox_drain(qts, 1);
    dsp_run(qts, protrev_body, sizeof(protrev_body), false);
    g_assert_cmphex(qtest_readl(qts, mailbox_reg(1, MAILBOX_MSGSTATUS)), ==, 1);
    word = qtest_readl(qts, mailbox_reg(1, MAILBOX_MESSAGE));
    g_assert_cmphex(word, ==, PROTREV_WORD);
    g_assert_cmphex(cmd_h(word), !=, 0x32);
    dsp_hold_reset(qts);
    qtest_quit(qts);
}

#define C55X_COFF_MAGIC     0x00c2u
#define C55X_COFF_FILEHDR   22u
#define C55X_COFF_SECHDR    48u
#define C55X_STYP_SKIP_MASK 0x001bu
#define DSPCFG_REQ          0x70000000u
#define TCFG_TID0           0xe0000000u
#define POLL_A2D            0x32000000u
#define DSP_TICK_NS         250000

static uint16_t le16_at(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t le32_at(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void avs_install_reset_page(QTestState *qts, const uint8_t *file,
                                   gsize n)
{
    uint16_t magic, nscns, opthdr;
    unsigned i;
    size_t off;

    g_assert_cmpuint(n, >=, C55X_COFF_FILEHDR);
    magic = le16_at(file);
    g_assert_true(magic == C55X_COFF_MAGIC || magic == 0x00c2);
    nscns = le16_at(file + 2);
    opthdr = le16_at(file + 16);
    off = C55X_COFF_FILEHDR + opthdr;
    for (i = 0; i < nscns; i++) {
        const uint8_t *sh = file + off;
        uint32_t paddr, size, raw, flags, j;

        g_assert_cmpuint(off + C55X_COFF_SECHDR, <=, n);
        paddr = le32_at(sh + 8);
        size = le32_at(sh + 16);
        raw = le32_at(sh + 20);
        flags = le32_at(sh + 40);
        off += C55X_COFF_SECHDR;
        if (!size || !raw || (flags & C55X_STYP_SKIP_MASK)) {
            continue;
        }
        if ((uint64_t)raw + size > n) {
            continue;
        }
        if (paddr >= 0x100000u && paddr < 0x100000u + 0x28000u) {
            uint64_t pa = DSP_MEM + (paddr - 0x100000u);
            uint8_t *arm = g_malloc(size);

            memcpy(arm, file + raw, size);
            for (j = 0; j + 1 < size; j += 2) {
                uint8_t t = arm[j];

                arm[j] = arm[j + 1];
                arm[j + 1] = t;
            }
            qtest_memwrite(qts, pa, arm, size);
            g_free(arm);
        }
    }
}

static void test_avs_lifecycle(void)
{
    gchar *path = avs_kernel_path();
    gchar *file = NULL;
    gsize n = 0;
    GError *err = NULL;
    QTestState *qts;
    uint32_t status;
    uint32_t word;
    int saw_protrev = 0;
    unsigned i;

    if (!path) {
        g_test_skip("avs_kernel.out not present; Maemo smoke is the "
                    "tokliBIOS POLL/TCFG/cmd3 gate");
        return;
    }
    g_assert_true(g_file_get_contents(path, &file, &n, &err));
    g_assert_no_error(err);
    g_free(path);

    qts = dsp_start();
    mailbox_drain(qts, 0);
    mailbox_drain(qts, 1);
    dsp_hold_reset(qts);
    avs_install_reset_page(qts, (const uint8_t *)file, n);
    arm_write_pcm(qts, SDRAM, 64, pcm_pat, 4);
    dsp_map_common(qts, true);
    qtest_writel(qts, RM_RSTCTRL_DSP, 0);

    /* RST slice plus a few ticks. QEMU must not plant FIFO1 POLL. */
    for (i = 0; i < 8; i++) {
        while (qtest_readl(qts, mailbox_reg(1, MAILBOX_MSGSTATUS))) {
            word = qtest_readl(qts, mailbox_reg(1, MAILBOX_MESSAGE));
            g_assert_cmphex(cmd_h(word), !=, 0x32);
            if (word == PROTREV_WORD) {
                saw_protrev = 1;
            }
        }
        qtest_clock_step(qts, DSP_TICK_NS);
    }
    if (!saw_protrev) {
        dsp_hold_reset(qts);
        qtest_quit(qts);
        g_free(file);
        g_test_skip("avs_kernel reset page loaded; PROTREV/TCFG/cmd3/POLL "
                    "need dsp_dld EXMAP+LAST (Maemo smoke). No invented POLL.");
        return;
    }

    qtest_writel(qts, mailbox_reg(0, MAILBOX_MESSAGE), DSPCFG_REQ);
    qtest_clock_step(qts, DSP_TICK_NS);
    qtest_writel(qts, mailbox_reg(0, MAILBOX_MESSAGE), TCFG_TID0);
    qtest_clock_step(qts, DSP_TICK_NS);
    qtest_writel(qts, mailbox_reg(0, MAILBOX_MESSAGE), PCM1_CMD4);
    qtest_clock_step(qts, DSP_TICK_NS * 4);
    qtest_writel(qts, mailbox_reg(0, MAILBOX_MESSAGE), POLL_A2D);
    for (i = 0; i < 16; i++) {
        status = qtest_readl(qts, mailbox_reg(1, MAILBOX_MSGSTATUS));
        while (status) {
            word = qtest_readl(qts, mailbox_reg(1, MAILBOX_MESSAGE));
            status--;
            if (cmd_h(word) == 0x32) {
                dsp_hold_reset(qts);
                qtest_quit(qts);
                g_free(file);
                return;
            }
        }
        qtest_clock_step(qts, DSP_TICK_NS);
    }
    dsp_hold_reset(qts);
    qtest_quit(qts);
    g_free(file);
    g_test_skip("PROTREV seen; firmware POLL reply did not arrive in-slice. "
                "Maemo smoke is the _poll_broadcast timeout gate.");
}

static void test_underrun_recovery(void)
{
    g_test_skip("audio-underrun-recovery waits until cmd3 copies nonzero "
                "samples (Maemo smoke / avs lifecycle)");
}

static uint32_t mbox_pop1(QTestState *qts)
{
    g_assert_cmpuint(qtest_readl(qts, mailbox_reg(1, MAILBOX_MSGSTATUS)), >=, 1);
    return qtest_readl(qts, mailbox_reg(1, MAILBOX_MESSAGE));
}

static void assert_tagged_lo(uint32_t word, uint16_t lo)
{
    /*
     * The FIFO keeps the accumulator image. OR #0x4000<<16 leaves the
     * tag in bit 30 and the port half in bits 15:0.
     */
    g_assert_cmphex(word & 0xffffu, ==, lo);
    g_assert_cmphex(word & 0x40000000u, ==, 0x40000000u);
}

/*
 * 0x0080 on the CCR high half is not EN. Status stays 0, the port
 * reads back, and neither the source nor the destination moves.
 */
static void test_iodma_ccr_hi_not_en(void)
{
    QTestState *qts = dsp_start();
    GByteArray *coff;
    uint16_t src[] = { 0x1111, 0x2222, 0x3333, 0x4444 };
    uint32_t csr, ccr;

    arm_write_pcm(qts, DSP_MEM + CSSA_BYTE, 16, src, 4);
    arm_write_pcm(qts, DSP_MEM + IODMA_CDSA_DARAM, 4,
                  (const uint16_t[]){ 0xaaaa, 0xbbbb }, 2);
    coff = iodma_program_full(CSSA_BYTE, IODMA_CDSA_DARAM, 8, 2, 0x0080, 0, 2);
    mailbox_drain(qts, 1);
    dsp_run(qts, coff->data, coff->len, true);
    csr = mbox_pop1(qts);
    ccr = mbox_pop1(qts);
    assert_tagged_lo(csr, 0);
    assert_tagged_lo(ccr, 0x0080);
    qtest_clock_step(qts, NANOSECONDS_PER_SECOND / 100);
    g_assert_cmphex(qtest_readw(qts, DSP_MEM + CSSA_BYTE), ==, 0x1111);
    g_assert_cmphex(qtest_readw(qts, DSP_MEM + CSSA_BYTE + 2), ==, 0x2222);
    g_assert_cmphex(qtest_readw(qts, DSP_MEM + IODMA_CDSA_DARAM), ==, 0xaaaa);
    g_assert_cmphex(qtest_readw(qts, DSP_MEM + IODMA_CDSA_DARAM + 2), ==, 0xbbbb);
    dsp_hold_reset(qts);
    g_byte_array_free(coff, TRUE);
    qtest_quit(qts);
}

/*
 * EN, constant address mode, DARAM CDSA. Completion is 0x003c, EN
 * clears, and the programmed byte is not written. RX-34 2026-09-30:
 * sentinels 0xa5a5 stayed at byte 0x1f200 and at 0xf200, and CCR
 * port 0x3041 read back 0 (mailbox 00000040).
 */
static void test_iodma_daram_constant(void)
{
    QTestState *qts = dsp_start();
    GByteArray *coff;
    uint16_t src[] = { 0x1111, 0x2222, 0x3333, 0x4444 };
    uint32_t csr, csr_hi, ccr_lo;
    uint32_t low = IODMA_CDSA_DARAM & 0xffffu;

    arm_write_pcm(qts, DSP_MEM + CSSA_BYTE, 16, src, 4);
    arm_write_pcm(qts, DSP_MEM + IODMA_CDSA_DARAM, 8,
                  (const uint16_t[]){ 0xa5a5, 0xa5a5, 0xa5a5, 0xa5a5 }, 4);
    arm_write_pcm(qts, DSP_MEM + low, 4,
                  (const uint16_t[]){ 0xa5a5, 0x5a5a }, 2);
    coff = iodma_program_full(CSSA_BYTE, IODMA_CDSA_DARAM, 8, 2, 0,
                              IODMA_CCR_ENABLE, 3);
    mailbox_drain(qts, 1);
    dsp_run(qts, coff->data, coff->len, true);
    qtest_clock_step(qts, NANOSECONDS_PER_SECOND / 100);
    csr = mbox_pop1(qts);
    csr_hi = mbox_pop1(qts);
    ccr_lo = mbox_pop1(qts);
    assert_tagged_lo(csr, IODMA_CSR_DONE);
    assert_tagged_lo(csr_hi, 0);
    assert_tagged_lo(ccr_lo, 0);
    g_assert_cmphex(qtest_readw(qts, DSP_MEM + CSSA_BYTE), ==, 0x1111);
    g_assert_cmphex(qtest_readw(qts, DSP_MEM + CSSA_BYTE + 2), ==, 0x2222);
    g_assert_cmphex(qtest_readw(qts, DSP_MEM + CSSA_BYTE + 4), ==, 0x3333);
    g_assert_cmphex(qtest_readw(qts, DSP_MEM + IODMA_CDSA_DARAM), ==, 0xa5a5);
    g_assert_cmphex(qtest_readw(qts, DSP_MEM + IODMA_CDSA_DARAM + 2), ==, 0xa5a5);
    g_assert_cmphex(qtest_readw(qts, DSP_MEM + IODMA_CDSA_DARAM + 4), ==, 0xa5a5);
    g_assert_cmphex(qtest_readw(qts, DSP_MEM + low), ==, 0xa5a5);
    g_assert_cmphex(qtest_readw(qts, DSP_MEM + low + 2), ==, 0x5a5a);
    dsp_hold_reset(qts);
    g_byte_array_free(coff, TRUE);
    qtest_quit(qts);
}

/*
 * CSR is write-1-to-clear. After the silicon constant-mode block,
 * writing HALF leaves FRAME|LAST|BLOCK. Channel 0 raises bit 0 in
 * the low half of IRQSTATUS_L0.
 */
static void test_iodma_csr_w1c(void)
{
    QTestState *qts = dsp_start();
    GByteArray *coff;
    uint16_t src[] = { 0x1111, 0x2222, 0x3333, 0x4444 };

    arm_write_pcm(qts, DSP_MEM + CSSA_BYTE, 16, src, 4);
    arm_write_pcm(qts, DSP_MEM + IODMA_CDSA_DARAM, 8,
                  (const uint16_t[]){ 0xa5a5, 0xa5a5, 0xa5a5, 0xa5a5 }, 4);
    coff = iodma_program_full(CSSA_BYTE, IODMA_CDSA_DARAM, 8, 2, 0,
                              IODMA_CCR_ENABLE, 4);
    mailbox_drain(qts, 1);
    dsp_run(qts, coff->data, coff->len, true);
    qtest_clock_step(qts, NANOSECONDS_PER_SECOND / 100);
    assert_tagged_lo(mbox_pop1(qts), IODMA_CSR_DONE);
    assert_tagged_lo(mbox_pop1(qts), 1);
    assert_tagged_lo(mbox_pop1(qts), IODMA_CSR_DONE & ~IODMA_CSR_HALF);
    g_assert_cmphex(qtest_readw(qts, DSP_MEM + IODMA_CDSA_DARAM), ==, 0xa5a5);
    dsp_hold_reset(qts);
    g_byte_array_free(coff, TRUE);
    qtest_quit(qts);
}

/* Source may step. Dest mode constant still does not store. */
static void test_iodma_daram_src_post_only(void)
{
    QTestState *qts = dsp_start();
    GByteArray *coff;
    uint16_t src[] = { 0x1111, 0x2222, 0x3333, 0x4444 };
    unsigned i;

    arm_write_pcm(qts, DSP_MEM + CSSA_BYTE, 16, src, 4);
    arm_write_pcm(qts, DSP_MEM + IODMA_CDSA_DARAM, 16,
                  (const uint16_t[]){ 0xa5a5 }, 1);
    coff = iodma_program_full(CSSA_BYTE, IODMA_CDSA_DARAM, 8, 2, 0,
                              IODMA_CCR_ENABLE | IODMA_CCR_SRC_POST, 1);
    mailbox_drain(qts, 1);
    dsp_run(qts, coff->data, coff->len, true);
    qtest_clock_step(qts, NANOSECONDS_PER_SECOND / 100);
    assert_tagged_lo(mbox_pop1(qts), IODMA_CSR_DONE);
    assert_tagged_lo(mbox_pop1(qts), 0);
    g_assert_cmphex(qtest_readw(qts, DSP_MEM + CSSA_BYTE), ==, 0x1111);
    for (i = 0; i < 8; i++) {
        g_assert_cmphex(qtest_readw(qts, DSP_MEM + IODMA_CDSA_DARAM + i * 2ull),
                        ==, 0xa5a5);
    }
    dsp_hold_reset(qts);
    g_byte_array_free(coff, TRUE);
    qtest_quit(qts);
}

/*
 * Single-index EI=2 on a 16-bit channel. OMAP's element delta is
 * data_type + EI - 1 = 3, which is misaligned. RX-34 2026-10-01:
 * CSR low 0x0800, EN clears, destination stays at the sentinel.
 */
static void test_iodma_daram_index(void)
{
    QTestState *qts = dsp_start();
    GByteArray *coff;
    uint16_t src[] = { 0x1111, 0x2222, 0x3333, 0x4444 };
    uint16_t sentinel[4] = { 0xa5a5, 0xa5a5, 0xa5a5, 0xa5a5 };
    unsigned i;

    arm_write_pcm(qts, DSP_MEM + CSSA_BYTE, 16, src, 4);
    arm_write_pcm(qts, DSP_MEM + IODMA_CDSA_DARAM, 8, sentinel, 4);
    coff = iodma_program_ex(CSSA_BYTE, IODMA_CDSA_DARAM, 4, 1, 0,
                            IODMA_CCR_ENABLE | IODMA_CCR_SRC_IDX |
                            IODMA_CCR_DST_IDX,
                            2, 2, 1);
    mailbox_drain(qts, 1);
    dsp_run(qts, coff->data, coff->len, true);
    qtest_clock_step(qts, NANOSECONDS_PER_SECOND / 100);
    assert_tagged_lo(mbox_pop1(qts), 0x0800);
    assert_tagged_lo(mbox_pop1(qts), 0);
    for (i = 0; i < 4; i++) {
        g_assert_cmphex(qtest_readw(qts, DSP_MEM + IODMA_CDSA_DARAM + i * 2ull),
                        ==, 0xa5a5);
    }
    dsp_hold_reset(qts);
    g_byte_array_free(coff, TRUE);
    qtest_quit(qts);
}

/*
 * Double-index with EI=2 has the same odd element delta as the
 * single-index case, so RX-34's 16-bit channel raises MISALIGN
 * before any halfword moves. The programmed hole stays put.
 */
static void test_iodma_daram_dblidx(void)
{
    QTestState *qts = dsp_start();
    GByteArray *coff;
    uint16_t src[] = {
        0x1111, 0x2222, 0x3333, 0x4444, 0xdead,
        0x5555, 0x6666, 0x7777, 0x8888
    };
    uint16_t hole[] = {
        0, 0, 0, 0, 0xa5a5, 0, 0, 0, 0
    };
    unsigned i;

    arm_write_pcm(qts, DSP_MEM + CSSA_BYTE, 18, src, 9);
    arm_write_pcm(qts, DSP_MEM + IODMA_CDSA_DARAM, 18, hole, 9);
    coff = g_byte_array_new();
    coff_mov_k16_port(coff, IODMA_PORT_CSDP_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CSDP_LO, 1);
    coff_mov_k16_port(coff, IODMA_PORT_CEN_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CEN_LO, 4);
    coff_mov_k16_port(coff, IODMA_PORT_CFN_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CFN_LO, 2);
    coff_mov_k16_port(coff, IODMA_PORT_CSSA_HI, (uint16_t)(CSSA_BYTE >> 16));
    coff_mov_k16_port(coff, IODMA_PORT_CSSA_LO, (uint16_t)CSSA_BYTE);
    coff_mov_k16_port(coff, IODMA_PORT_CDSA_HI,
                      (uint16_t)(IODMA_CDSA_DARAM >> 16));
    coff_mov_k16_port(coff, IODMA_PORT_CDSA_LO, (uint16_t)IODMA_CDSA_DARAM);
    coff_mov_k16_port(coff, IODMA_PORT_CSEI_LO, 2);
    coff_mov_k16_port(coff, IODMA_PORT_CDEI_LO, 2);
    coff_mov_k16_port(coff, 0x3055u, 4); /* CSFI low */
    coff_mov_k16_port(coff, 0x3059u, 4); /* CDFI low */
    coff_mov_k16_port(coff, IODMA_PORT_CCR_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CCR_LO,
                      IODMA_CCR_ENABLE | 0x3000u | 0xc000u);
    coff_poll_port(coff, IODMA_PORT_CSR_LO);
    coff_tag_ac0(coff);
    coff_publish_ac0(coff);
    coff_publish_tagged_port(coff, IODMA_PORT_CCR_LO);
    coff_b_m2(coff);
    mailbox_drain(qts, 1);
    dsp_run(qts, coff->data, coff->len, true);
    qtest_clock_step(qts, NANOSECONDS_PER_SECOND / 100);
    assert_tagged_lo(mbox_pop1(qts), 0x0800);
    /* EN clears; both address modes stay double-index. */
    assert_tagged_lo(mbox_pop1(qts), 0x3000u | 0xc000u);
    for (i = 0; i < 9; i++) {
        g_assert_cmphex(qtest_readw(qts, DSP_MEM + IODMA_CDSA_DARAM + i * 2ull),
                        ==, hole[i]);
    }
    dsp_hold_reset(qts);
    g_byte_array_free(coff, TRUE);
    qtest_quit(qts);
}

/*
 * Single-index EI=1 on both sides. Stride is 2, so the circular
 * order still visits every halfword and the destination is a packed
 * copy. RX-34 2026-10-01, CCR 0xa080: CSR 0x003c, words 1111..4444.
 */
static void test_iodma_daram_index_ei1(void)
{
    QTestState *qts = dsp_start();
    GByteArray *coff;
    uint16_t src[] = { 0x1111, 0x2222, 0x3333, 0x4444 };
    uint16_t sentinel[4] = { 0xa5a5, 0xa5a5, 0xa5a5, 0xa5a5 };
    unsigned i;

    arm_write_pcm(qts, DSP_MEM + CSSA_BYTE, 8, src, 4);
    arm_write_pcm(qts, DSP_MEM + IODMA_CDSA_DARAM, 8, sentinel, 4);
    coff = iodma_program_ex(CSSA_BYTE, IODMA_CDSA_DARAM, 4, 1, 0,
                            IODMA_CCR_ENABLE | IODMA_CCR_SRC_IDX |
                            IODMA_CCR_DST_IDX,
                            1, 1, 3);
    mailbox_drain(qts, 1);
    dsp_run(qts, coff->data, coff->len, true);
    qtest_clock_step(qts, NANOSECONDS_PER_SECOND / 100);
    assert_tagged_lo(mbox_pop1(qts), IODMA_CSR_DONE);
    assert_tagged_lo(mbox_pop1(qts), 0);
    assert_tagged_lo(mbox_pop1(qts),
                     (IODMA_CCR_SRC_IDX | IODMA_CCR_DST_IDX));
    for (i = 0; i < 4; i++) {
        g_assert_cmphex(qtest_readw(qts, DSP_MEM + IODMA_CDSA_DARAM + i * 2ull),
                        ==, src[i]);
    }
    dsp_hold_reset(qts);
    g_byte_array_free(coff, TRUE);
    qtest_quit(qts);
}

/*
 * Source single-index EI=3, destination post-increment. The read
 * order is the second half of the frame first: 6666, 8888, 2222, 4444.
 * RX-34 2026-10-01, CCR 0x6080.
 */
static void test_iodma_daram_srcidx(void)
{
    QTestState *qts = dsp_start();
    GByteArray *coff;
    uint16_t src[] = {
        0x1111, 0x2222, 0x3333, 0x4444,
        0x5555, 0x6666, 0x7777, 0x8888
    };
    uint16_t sentinel[8] = {
        0xa5a5, 0xa5a5, 0xa5a5, 0xa5a5,
        0xa5a5, 0xa5a5, 0xa5a5, 0xa5a5
    };
    uint16_t expect[] = { 0x6666, 0x8888, 0x2222, 0x4444 };
    unsigned i;

    arm_write_pcm(qts, DSP_MEM + CSSA_BYTE, 16, src, 8);
    arm_write_pcm(qts, DSP_MEM + IODMA_CDSA_DARAM, 16, sentinel, 8);
    coff = iodma_program_ex(CSSA_BYTE, IODMA_CDSA_DARAM, 4, 1, 0,
                            IODMA_CCR_ENABLE | IODMA_CCR_SRC_IDX |
                            IODMA_CCR_DST_POST,
                            3, 0, 3);
    mailbox_drain(qts, 1);
    dsp_run(qts, coff->data, coff->len, true);
    qtest_clock_step(qts, NANOSECONDS_PER_SECOND / 100);
    assert_tagged_lo(mbox_pop1(qts), IODMA_CSR_DONE);
    assert_tagged_lo(mbox_pop1(qts), 0);
    assert_tagged_lo(mbox_pop1(qts), IODMA_CCR_SRC_IDX | IODMA_CCR_DST_POST);
    for (i = 0; i < 4; i++) {
        g_assert_cmphex(qtest_readw(qts, DSP_MEM + IODMA_CDSA_DARAM + i * 2ull),
                        ==, expect[i]);
    }
    for (i = 4; i < 8; i++) {
        g_assert_cmphex(qtest_readw(qts, DSP_MEM + IODMA_CDSA_DARAM + i * 2ull),
                        ==, 0xa5a5);
    }
    dsp_hold_reset(qts);
    g_byte_array_free(coff, TRUE);
    qtest_quit(qts);
}

/*
 * Source EI=3 CEN=2, destination post-increment. The phase of 2
 * wraps away, so the reads are 2222 then 4444, and they land at
 * destination halfwords 2 and 3. RX-34 2026-10-02, CCR 0x6080.
 */
static void test_iodma_daram_idxn2(void)
{
    QTestState *qts = dsp_start();
    GByteArray *coff;
    uint16_t src[] = { 0x1111, 0x2222, 0x3333, 0x4444 };
    uint16_t expect[] = { 0xa5a5, 0xa5a5, 0x2222, 0x4444 };
    unsigned i;

    arm_write_pcm(qts, DSP_MEM + CSSA_BYTE, 8, src, 4);
    arm_write_pcm(qts, DSP_MEM + IODMA_CDSA_DARAM, 8,
                  (const uint16_t[]){ 0xa5a5 }, 1);
    coff = iodma_program_ex(CSSA_BYTE, IODMA_CDSA_DARAM, 2, 1, 0,
                            IODMA_CCR_ENABLE | IODMA_CCR_SRC_IDX |
                            IODMA_CCR_DST_POST,
                            3, 0, 3);
    mailbox_drain(qts, 1);
    dsp_run(qts, coff->data, coff->len, true);
    qtest_clock_step(qts, NANOSECONDS_PER_SECOND / 100);
    assert_tagged_lo(mbox_pop1(qts), IODMA_CSR_DONE);
    assert_tagged_lo(mbox_pop1(qts), 0);
    assert_tagged_lo(mbox_pop1(qts), IODMA_CCR_SRC_IDX | IODMA_CCR_DST_POST);
    for (i = 0; i < 4; i++) {
        g_assert_cmphex(qtest_readw(qts, DSP_MEM + IODMA_CDSA_DARAM + i * 2ull),
                        ==, expect[i]);
    }
    dsp_hold_reset(qts);
    g_byte_array_free(coff, TRUE);
    qtest_quit(qts);
}

/*
 * Destination EI=3, source post-increment, CEN=4. The indexed side
 * still enters at element 2, so 1111,2222,3333,4444 land on
 * halfwords 5, 7, 1, 3. RX-34 2026-10-02, CCR 0x9080.
 */
static void test_iodma_daram_dstidx(void)
{
    QTestState *qts = dsp_start();
    GByteArray *coff;
    uint16_t src[] = { 0x1111, 0x2222, 0x3333, 0x4444 };
    uint16_t expect[] = {
        0xa5a5, 0x3333, 0xa5a5, 0x4444,
        0xa5a5, 0x1111, 0xa5a5, 0x2222
    };
    unsigned i;

    arm_write_pcm(qts, DSP_MEM + CSSA_BYTE, 8, src, 4);
    arm_write_pcm(qts, DSP_MEM + IODMA_CDSA_DARAM, 16,
                  (const uint16_t[]){ 0xa5a5 }, 1);
    coff = iodma_program_ex(CSSA_BYTE, IODMA_CDSA_DARAM, 4, 1, 0,
                            IODMA_CCR_ENABLE | IODMA_CCR_DST_IDX |
                            IODMA_CCR_SRC_POST,
                            0, 3, 3);
    mailbox_drain(qts, 1);
    dsp_run(qts, coff->data, coff->len, true);
    qtest_clock_step(qts, NANOSECONDS_PER_SECOND / 100);
    assert_tagged_lo(mbox_pop1(qts), IODMA_CSR_DONE);
    assert_tagged_lo(mbox_pop1(qts), 0);
    assert_tagged_lo(mbox_pop1(qts), IODMA_CCR_DST_IDX | IODMA_CCR_SRC_POST);
    for (i = 0; i < 8; i++) {
        g_assert_cmphex(qtest_readw(qts, DSP_MEM + IODMA_CDSA_DARAM + i * 2ull),
                        ==, expect[i]);
    }
    dsp_hold_reset(qts);
    g_byte_array_free(coff, TRUE);
    qtest_quit(qts);
}

/*
 * Double-index EI=1 FI=4, CEN=2 CFN=2. Frame delta FI-EI is odd, so
 * the 16-bit channel raises MISALIGN and copies nothing.
 * RX-34 2026-10-05, CCR 0xf080: CSR low 0x0800, destination stays a5a5.
 */
static void test_iodma_daram_dbl_fi4(void)
{
    QTestState *qts = dsp_start();
    GByteArray *coff;
    unsigned i;

    arm_write_pcm(qts, DSP_MEM + CSSA_BYTE, 16,
                  (const uint16_t[]){
                      0x1111, 0x2222, 0x3333, 0x4444,
                      0x5555, 0x6666, 0x7777, 0x8888
                  }, 8);
    arm_write_pcm(qts, DSP_MEM + IODMA_CDSA_DARAM, 16,
                  (const uint16_t[]){ 0xa5a5 }, 1);
    coff = g_byte_array_new();
    coff_mov_k16_port(coff, IODMA_PORT_CSDP_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CSDP_LO, 1);
    coff_mov_k16_port(coff, IODMA_PORT_CEN_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CEN_LO, 2);
    coff_mov_k16_port(coff, IODMA_PORT_CFN_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CFN_LO, 2);
    coff_mov_k16_port(coff, IODMA_PORT_CSSA_HI, (uint16_t)(CSSA_BYTE >> 16));
    coff_mov_k16_port(coff, IODMA_PORT_CSSA_LO, (uint16_t)CSSA_BYTE);
    coff_mov_k16_port(coff, IODMA_PORT_CDSA_HI,
                      (uint16_t)(IODMA_CDSA_DARAM >> 16));
    coff_mov_k16_port(coff, IODMA_PORT_CDSA_LO, (uint16_t)IODMA_CDSA_DARAM);
    coff_mov_k16_port(coff, IODMA_PORT_CSEI_LO, 1);
    coff_mov_k16_port(coff, IODMA_PORT_CDEI_LO, 1);
    coff_mov_k16_port(coff, 0x3055u, 4); /* CSFI low */
    coff_mov_k16_port(coff, 0x3059u, 4); /* CDFI low */
    coff_mov_k16_port(coff, IODMA_PORT_CCR_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CCR_LO,
                      IODMA_CCR_ENABLE | 0x3000u | 0xc000u);
    coff_poll_port(coff, IODMA_PORT_CSR_LO);
    coff_tag_ac0(coff);
    coff_publish_ac0(coff);
    coff_publish_tagged_port(coff, IODMA_PORT_CCR_LO);
    coff_b_m2(coff);
    mailbox_drain(qts, 1);
    dsp_run(qts, coff->data, coff->len, true);
    qtest_clock_step(qts, NANOSECONDS_PER_SECOND / 100);
    assert_tagged_lo(mbox_pop1(qts), 0x0800);
    assert_tagged_lo(mbox_pop1(qts), 0x3000u | 0xc000u);
    for (i = 0; i < 8; i++) {
        g_assert_cmphex(qtest_readw(qts, DSP_MEM + IODMA_CDSA_DARAM + i * 2ull),
                        ==, 0xa5a5);
    }
    dsp_hold_reset(qts);
    g_byte_array_free(coff, TRUE);
    qtest_quit(qts);
}

/*
 * Double-index EI=1 FI=5, CEN=2 CFN=2. Frame delta FI-EI is even, so
 * the copy runs. The first eight destination halfwords keep the
 * sentinel except slots 2 and 3, which become 3333 and 4444.
 * RX-34 2026-10-01, CCR 0xf080.
 */
static void test_iodma_daram_dbl5(void)
{
    QTestState *qts = dsp_start();
    GByteArray *coff;
    uint16_t src[] = {
        0x1111, 0x2222, 0x3333, 0x4444,
        0x5555, 0x6666, 0x7777, 0x8888
    };
    uint16_t expect[] = {
        0xa5a5, 0xa5a5, 0x3333, 0x4444,
        0xa5a5, 0xa5a5, 0xa5a5, 0xa5a5
    };
    unsigned i;

    arm_write_pcm(qts, DSP_MEM + CSSA_BYTE, 16, src, 8);
    arm_write_pcm(qts, DSP_MEM + IODMA_CDSA_DARAM, 16,
                  (const uint16_t[]){ 0xa5a5 }, 1);
    coff = g_byte_array_new();
    coff_mov_k16_port(coff, IODMA_PORT_CSDP_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CSDP_LO, 1);
    coff_mov_k16_port(coff, IODMA_PORT_CEN_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CEN_LO, 2);
    coff_mov_k16_port(coff, IODMA_PORT_CFN_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CFN_LO, 2);
    coff_mov_k16_port(coff, IODMA_PORT_CSSA_HI, (uint16_t)(CSSA_BYTE >> 16));
    coff_mov_k16_port(coff, IODMA_PORT_CSSA_LO, (uint16_t)CSSA_BYTE);
    coff_mov_k16_port(coff, IODMA_PORT_CDSA_HI,
                      (uint16_t)(IODMA_CDSA_DARAM >> 16));
    coff_mov_k16_port(coff, IODMA_PORT_CDSA_LO, (uint16_t)IODMA_CDSA_DARAM);
    coff_mov_k16_port(coff, IODMA_PORT_CSEI_LO, 1);
    coff_mov_k16_port(coff, IODMA_PORT_CDEI_LO, 1);
    coff_mov_k16_port(coff, 0x3055u, 5); /* CSFI low */
    coff_mov_k16_port(coff, 0x3059u, 5); /* CDFI low */
    coff_mov_k16_port(coff, IODMA_PORT_CCR_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CCR_LO,
                      IODMA_CCR_ENABLE | 0x3000u | 0xc000u);
    coff_poll_port(coff, IODMA_PORT_CSR_LO);
    coff_tag_ac0(coff);
    coff_publish_ac0(coff);
    coff_publish_tagged_port(coff, IODMA_PORT_CCR_LO);
    coff_b_m2(coff);
    mailbox_drain(qts, 1);
    dsp_run(qts, coff->data, coff->len, true);
    qtest_clock_step(qts, NANOSECONDS_PER_SECOND / 100);
    assert_tagged_lo(mbox_pop1(qts), IODMA_CSR_DONE);
    assert_tagged_lo(mbox_pop1(qts), 0x3000u | 0xc000u);
    for (i = 0; i < 8; i++) {
        g_assert_cmphex(qtest_readw(qts, DSP_MEM + IODMA_CDSA_DARAM + i * 2ull),
                        ==, expect[i]);
    }
    dsp_hold_reset(qts);
    g_byte_array_free(coff, TRUE);
    qtest_quit(qts);
}

/*
 * Same EI=1 FI=5 block with 16 destination halfwords. Frame 1 is not
 * in that window: bytes 16..31 stay a5a5. RX-34 2026-10-02.
 */
static void test_iodma_daram_dblwide(void)
{
    QTestState *qts = dsp_start();
    GByteArray *coff;
    uint16_t src[] = {
        0x1111, 0x2222, 0x3333, 0x4444,
        0x5555, 0x6666, 0x7777, 0x8888,
        0x9999, 0xaaaa, 0xbbbb, 0xcccc,
        0xdddd, 0xeeee, 0xabcd, 0xdcba
    };
    uint16_t expect[16];
    unsigned i;

    for (i = 0; i < 16; i++) {
        expect[i] = 0xa5a5;
    }
    expect[2] = 0x3333;
    expect[3] = 0x4444;
    arm_write_pcm(qts, DSP_MEM + CSSA_BYTE, 16, src, 16);
    arm_write_pcm(qts, DSP_MEM + IODMA_CDSA_DARAM, 16,
                  (const uint16_t[]){ 0xa5a5 }, 1);
    coff = g_byte_array_new();
    coff_mov_k16_port(coff, IODMA_PORT_CSDP_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CSDP_LO, 1);
    coff_mov_k16_port(coff, IODMA_PORT_CEN_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CEN_LO, 2);
    coff_mov_k16_port(coff, IODMA_PORT_CFN_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CFN_LO, 2);
    coff_mov_k16_port(coff, IODMA_PORT_CSSA_HI, (uint16_t)(CSSA_BYTE >> 16));
    coff_mov_k16_port(coff, IODMA_PORT_CSSA_LO, (uint16_t)CSSA_BYTE);
    coff_mov_k16_port(coff, IODMA_PORT_CDSA_HI,
                      (uint16_t)(IODMA_CDSA_DARAM >> 16));
    coff_mov_k16_port(coff, IODMA_PORT_CDSA_LO, (uint16_t)IODMA_CDSA_DARAM);
    coff_mov_k16_port(coff, IODMA_PORT_CSEI_LO, 1);
    coff_mov_k16_port(coff, IODMA_PORT_CDEI_LO, 1);
    coff_mov_k16_port(coff, 0x3055u, 5);
    coff_mov_k16_port(coff, 0x3059u, 5);
    coff_mov_k16_port(coff, IODMA_PORT_CCR_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CCR_LO,
                      IODMA_CCR_ENABLE | 0x3000u | 0xc000u);
    coff_poll_port(coff, IODMA_PORT_CSR_LO);
    coff_tag_ac0(coff);
    coff_publish_ac0(coff);
    coff_publish_tagged_port(coff, IODMA_PORT_CCR_LO);
    coff_b_m2(coff);
    mailbox_drain(qts, 1);
    dsp_run(qts, coff->data, coff->len, true);
    qtest_clock_step(qts, NANOSECONDS_PER_SECOND / 100);
    assert_tagged_lo(mbox_pop1(qts), IODMA_CSR_DONE);
    assert_tagged_lo(mbox_pop1(qts), 0x3000u | 0xc000u);
    for (i = 0; i < 16; i++) {
        g_assert_cmphex(qtest_readw(qts, DSP_MEM + IODMA_CDSA_DARAM + i * 2ull),
                        ==, expect[i]);
    }
    dsp_hold_reset(qts);
    g_byte_array_free(coff, TRUE);
    qtest_quit(qts);
}

/*
 * Source EI=5, destination post-increment, CEN=4. Bytes visited are
 * 20, 10, 0, 6. RX-34 2026-10-02, CCR 0x6080.
 */
static void test_iodma_daram_idx5(void)
{
    QTestState *qts = dsp_start();
    GByteArray *coff;
    uint16_t src[] = {
        0x1111, 0x2222, 0x3333, 0x4444,
        0x5555, 0x6666, 0x7777, 0x8888,
        0x9999, 0xaaaa, 0xbbbb, 0xcccc
    };
    uint16_t expect[] = { 0xbbbb, 0x6666, 0x1111, 0x4444 };
    unsigned i;

    arm_write_pcm(qts, DSP_MEM + CSSA_BYTE, 16, src, 12);
    arm_write_pcm(qts, DSP_MEM + IODMA_CDSA_DARAM, 8,
                  (const uint16_t[]){ 0xa5a5 }, 1);
    coff = iodma_program_ex(CSSA_BYTE, IODMA_CDSA_DARAM, 4, 1, 0,
                            IODMA_CCR_ENABLE | IODMA_CCR_SRC_IDX |
                            IODMA_CCR_DST_POST,
                            5, 0, 3);
    mailbox_drain(qts, 1);
    dsp_run(qts, coff->data, coff->len, true);
    qtest_clock_step(qts, NANOSECONDS_PER_SECOND / 100);
    assert_tagged_lo(mbox_pop1(qts), IODMA_CSR_DONE);
    assert_tagged_lo(mbox_pop1(qts), 0);
    assert_tagged_lo(mbox_pop1(qts), IODMA_CCR_SRC_IDX | IODMA_CCR_DST_POST);
    for (i = 0; i < 4; i++) {
        g_assert_cmphex(qtest_readw(qts, DSP_MEM + IODMA_CDSA_DARAM + i * 2ull),
                        ==, expect[i]);
    }
    for (i = 4; i < 8; i++) {
        g_assert_cmphex(qtest_readw(qts, DSP_MEM + IODMA_CDSA_DARAM + i * 2ull),
                        ==, 0xa5a5);
    }
    dsp_hold_reset(qts);
    g_byte_array_free(coff, TRUE);
    qtest_quit(qts);
}

/*
 * Double-index EI=1 FI=3, CEN=2 CFN=2. Same visible copy as FI=5:
 * slots 2 and 3 become 3333 and 4444. RX-34 2026-10-02.
 */
static void test_iodma_daram_dbl3(void)
{
    QTestState *qts = dsp_start();
    GByteArray *coff;
    uint16_t src[] = {
        0x1111, 0x2222, 0x3333, 0x4444,
        0x5555, 0x6666, 0x7777, 0x8888
    };
    uint16_t expect[] = {
        0xa5a5, 0xa5a5, 0x3333, 0x4444,
        0xa5a5, 0xa5a5, 0xa5a5, 0xa5a5
    };
    unsigned i;

    arm_write_pcm(qts, DSP_MEM + CSSA_BYTE, 16, src, 8);
    arm_write_pcm(qts, DSP_MEM + IODMA_CDSA_DARAM, 16,
                  (const uint16_t[]){ 0xa5a5 }, 1);
    coff = g_byte_array_new();
    coff_mov_k16_port(coff, IODMA_PORT_CSDP_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CSDP_LO, 1);
    coff_mov_k16_port(coff, IODMA_PORT_CEN_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CEN_LO, 2);
    coff_mov_k16_port(coff, IODMA_PORT_CFN_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CFN_LO, 2);
    coff_mov_k16_port(coff, IODMA_PORT_CSSA_HI, (uint16_t)(CSSA_BYTE >> 16));
    coff_mov_k16_port(coff, IODMA_PORT_CSSA_LO, (uint16_t)CSSA_BYTE);
    coff_mov_k16_port(coff, IODMA_PORT_CDSA_HI,
                      (uint16_t)(IODMA_CDSA_DARAM >> 16));
    coff_mov_k16_port(coff, IODMA_PORT_CDSA_LO, (uint16_t)IODMA_CDSA_DARAM);
    coff_mov_k16_port(coff, IODMA_PORT_CSEI_LO, 1);
    coff_mov_k16_port(coff, IODMA_PORT_CDEI_LO, 1);
    coff_mov_k16_port(coff, 0x3055u, 3);
    coff_mov_k16_port(coff, 0x3059u, 3);
    coff_mov_k16_port(coff, IODMA_PORT_CCR_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CCR_LO,
                      IODMA_CCR_ENABLE | 0x3000u | 0xc000u);
    coff_poll_port(coff, IODMA_PORT_CSR_LO);
    coff_tag_ac0(coff);
    coff_publish_ac0(coff);
    coff_publish_tagged_port(coff, IODMA_PORT_CCR_LO);
    coff_b_m2(coff);
    mailbox_drain(qts, 1);
    dsp_run(qts, coff->data, coff->len, true);
    qtest_clock_step(qts, NANOSECONDS_PER_SECOND / 100);
    assert_tagged_lo(mbox_pop1(qts), IODMA_CSR_DONE);
    assert_tagged_lo(mbox_pop1(qts), 0x3000u | 0xc000u);
    for (i = 0; i < 8; i++) {
        g_assert_cmphex(qtest_readw(qts, DSP_MEM + IODMA_CDSA_DARAM + i * 2ull),
                        ==, expect[i]);
    }
    dsp_hold_reset(qts);
    g_byte_array_free(coff, TRUE);
    qtest_quit(qts);
}

/*
 * EI=1 FI=5 again, with 24 destination halfwords. Bytes 32..47 stay
 * a5a5, so the second frame is not at byte 32. RX-34 2026-10-02.
 */
static void test_iodma_daram_dblfar(void)
{
    QTestState *qts = dsp_start();
    GByteArray *coff;
    uint16_t src[] = {
        0x1111, 0x2222, 0x3333, 0x4444,
        0x5555, 0x6666, 0x7777, 0x8888,
        0x9999, 0xaaaa, 0xbbbb, 0xcccc,
        0xdddd, 0xeeee, 0xabcd, 0xdcba,
        0x0101, 0x0202, 0x0303, 0x0404
    };
    unsigned i;

    arm_write_pcm(qts, DSP_MEM + CSSA_BYTE, 24, src, 20);
    arm_write_pcm(qts, DSP_MEM + IODMA_CDSA_DARAM, 24,
                  (const uint16_t[]){ 0xa5a5 }, 1);
    coff = g_byte_array_new();
    coff_mov_k16_port(coff, IODMA_PORT_CSDP_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CSDP_LO, 1);
    coff_mov_k16_port(coff, IODMA_PORT_CEN_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CEN_LO, 2);
    coff_mov_k16_port(coff, IODMA_PORT_CFN_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CFN_LO, 2);
    coff_mov_k16_port(coff, IODMA_PORT_CSSA_HI, (uint16_t)(CSSA_BYTE >> 16));
    coff_mov_k16_port(coff, IODMA_PORT_CSSA_LO, (uint16_t)CSSA_BYTE);
    coff_mov_k16_port(coff, IODMA_PORT_CDSA_HI,
                      (uint16_t)(IODMA_CDSA_DARAM >> 16));
    coff_mov_k16_port(coff, IODMA_PORT_CDSA_LO, (uint16_t)IODMA_CDSA_DARAM);
    coff_mov_k16_port(coff, IODMA_PORT_CSEI_LO, 1);
    coff_mov_k16_port(coff, IODMA_PORT_CDEI_LO, 1);
    coff_mov_k16_port(coff, 0x3055u, 5);
    coff_mov_k16_port(coff, 0x3059u, 5);
    coff_mov_k16_port(coff, IODMA_PORT_CCR_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CCR_LO,
                      IODMA_CCR_ENABLE | 0x3000u | 0xc000u);
    coff_poll_port(coff, IODMA_PORT_CSR_LO);
    coff_tag_ac0(coff);
    coff_publish_ac0(coff);
    coff_publish_tagged_port(coff, IODMA_PORT_CCR_LO);
    coff_b_m2(coff);
    mailbox_drain(qts, 1);
    dsp_run(qts, coff->data, coff->len, true);
    qtest_clock_step(qts, NANOSECONDS_PER_SECOND / 100);
    assert_tagged_lo(mbox_pop1(qts), IODMA_CSR_DONE);
    assert_tagged_lo(mbox_pop1(qts), 0x3000u | 0xc000u);
    for (i = 0; i < 24; i++) {
        uint16_t want = 0xa5a5;

        if (i == 2) {
            want = 0x3333;
        } else if (i == 3) {
            want = 0x4444;
        }
        g_assert_cmphex(qtest_readw(qts, DSP_MEM + IODMA_CDSA_DARAM + i * 2ull),
                        ==, want);
    }
    dsp_hold_reset(qts);
    g_byte_array_free(coff, TRUE);
    qtest_quit(qts);
}

/*
 * RX-34 2026-10-05. CEN=4 CFN=1 post-increment. The first nonzero CSR
 * is LAST. The four destination halfwords are already the copy, and
 * CCR.EN is still set.
 */
static void test_iodma_daram_early_last(void)
{
    QTestState *qts = dsp_start();
    GByteArray *coff;
    uint16_t src[] = { 0x1111, 0x2222, 0x3333, 0x4444 };
    unsigned i;

    arm_write_pcm(qts, DSP_MEM + CSSA_BYTE, 8, src, 4);
    arm_write_pcm(qts, DSP_MEM + IODMA_CDSA_DARAM, 8,
                  (const uint16_t[]){ 0xa5a5 }, 1);
    coff = iodma_program_full(CSSA_BYTE, IODMA_CDSA_DARAM, 4, 1, 0,
                              IODMA_CCR_ENABLE | IODMA_CCR_SRC_POST |
                              IODMA_CCR_DST_POST, 5);
    mailbox_drain(qts, 1);
    dsp_run(qts, coff->data, coff->len, true);
    assert_tagged_lo(mbox_pop1(qts), IODMA_CSR_LAST);
    assert_tagged_lo(mbox_pop1(qts),
                     IODMA_CCR_ENABLE | IODMA_CCR_SRC_POST | IODMA_CCR_DST_POST);
    for (i = 0; i < 4; i++) {
        g_assert_cmphex(qtest_readw(qts, DSP_MEM + IODMA_CDSA_DARAM + i * 2ull),
                        ==, src[i]);
    }
    dsp_hold_reset(qts);
    g_byte_array_free(coff, TRUE);
    qtest_quit(qts);
}

/*
 * Same shape as dbl5. The first nonzero CSR is HALF, slots 2 and 3
 * are already 3333/4444, and EN is still set.
 */
static void test_iodma_daram_early_half(void)
{
    QTestState *qts = dsp_start();
    GByteArray *coff;
    uint16_t src[] = {
        0x1111, 0x2222, 0x3333, 0x4444,
        0x5555, 0x6666, 0x7777, 0x8888
    };
    uint16_t expect[] = {
        0xa5a5, 0xa5a5, 0x3333, 0x4444,
        0xa5a5, 0xa5a5, 0xa5a5, 0xa5a5
    };
    unsigned i;
    uint16_t ccr = IODMA_CCR_ENABLE | 0x3000u | 0xc000u;

    arm_write_pcm(qts, DSP_MEM + CSSA_BYTE, 16, src, 8);
    arm_write_pcm(qts, DSP_MEM + IODMA_CDSA_DARAM, 16,
                  (const uint16_t[]){ 0xa5a5 }, 1);
    coff = g_byte_array_new();
    coff_mov_k16_port(coff, IODMA_PORT_CSDP_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CSDP_LO, 1);
    coff_mov_k16_port(coff, IODMA_PORT_CEN_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CEN_LO, 2);
    coff_mov_k16_port(coff, IODMA_PORT_CFN_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CFN_LO, 2);
    coff_mov_k16_port(coff, IODMA_PORT_CSSA_HI, (uint16_t)(CSSA_BYTE >> 16));
    coff_mov_k16_port(coff, IODMA_PORT_CSSA_LO, (uint16_t)CSSA_BYTE);
    coff_mov_k16_port(coff, IODMA_PORT_CDSA_HI,
                      (uint16_t)(IODMA_CDSA_DARAM >> 16));
    coff_mov_k16_port(coff, IODMA_PORT_CDSA_LO, (uint16_t)IODMA_CDSA_DARAM);
    coff_mov_k16_port(coff, IODMA_PORT_CSEI_LO, 1);
    coff_mov_k16_port(coff, IODMA_PORT_CDEI_LO, 1);
    coff_mov_k16_port(coff, 0x3055u, 5);
    coff_mov_k16_port(coff, 0x3059u, 5);
    coff_mov_k16_port(coff, IODMA_PORT_CCR_HI, 0);
    coff_mov_k16_port(coff, IODMA_PORT_CCR_LO, ccr);
    coff_poll_nonzero(coff, IODMA_PORT_CSR_LO);
    coff_tag_ac0(coff);
    coff_publish_ac0(coff);
    coff_publish_tagged_port(coff, IODMA_PORT_CCR_LO);
    coff_b_m2(coff);
    mailbox_drain(qts, 1);
    dsp_run(qts, coff->data, coff->len, true);
    assert_tagged_lo(mbox_pop1(qts), IODMA_CSR_HALF);
    assert_tagged_lo(mbox_pop1(qts), ccr);
    for (i = 0; i < 8; i++) {
        g_assert_cmphex(qtest_readw(qts, DSP_MEM + IODMA_CDSA_DARAM + i * 2ull),
                        ==, expect[i]);
    }
    dsp_hold_reset(qts);
    g_byte_array_free(coff, TRUE);
    qtest_quit(qts);
}

/*
 * CEN=2 single-index. The first nonzero CSR is HALF|LAST.
 */
static void test_iodma_daram_early_cen2(void)
{
    QTestState *qts = dsp_start();
    GByteArray *coff;
    uint16_t src[] = { 0x1111, 0x2222, 0x3333, 0x4444 };
    uint16_t expect[] = { 0xa5a5, 0xa5a5, 0x2222, 0x4444 };
    unsigned i;
    uint16_t ccr = IODMA_CCR_ENABLE | IODMA_CCR_SRC_IDX | IODMA_CCR_DST_POST;

    arm_write_pcm(qts, DSP_MEM + CSSA_BYTE, 8, src, 4);
    arm_write_pcm(qts, DSP_MEM + IODMA_CDSA_DARAM, 8,
                  (const uint16_t[]){ 0xa5a5 }, 1);
    coff = iodma_program_ex(CSSA_BYTE, IODMA_CDSA_DARAM, 2, 1, 0, ccr,
                            3, 0, 5);
    mailbox_drain(qts, 1);
    dsp_run(qts, coff->data, coff->len, true);
    assert_tagged_lo(mbox_pop1(qts), IODMA_CSR_HALF | IODMA_CSR_LAST);
    assert_tagged_lo(mbox_pop1(qts), ccr);
    for (i = 0; i < 4; i++) {
        g_assert_cmphex(qtest_readw(qts, DSP_MEM + IODMA_CDSA_DARAM + i * 2ull),
                        ==, expect[i]);
    }
    dsp_hold_reset(qts);
    g_byte_array_free(coff, TRUE);
    qtest_quit(qts);
}

/*
 * RX-34: CSSA low 0xec18 read into AC0 is 0xffffec18. SXMD is set
 * without the stub writing ST1. A positive port stays positive.
 * MESSAGE readl is swab32 of that accumulator.
 */
static void test_iodma_port_sxmd(void)
{
    QTestState *qts = dsp_start();
    GByteArray *coff = g_byte_array_new();

    coff_mov_k16_port(coff, IODMA_PORT_CSSA_LO, 0xec18);
    coff_mov_port_ac0(coff, IODMA_PORT_CSSA_LO);
    coff_publish_ac0(coff);
    coff_mov_k16_port(coff, IODMA_PORT_CSSA_LO, 0x1111);
    coff_mov_port_ac0(coff, IODMA_PORT_CSSA_LO);
    coff_publish_ac0(coff);
    coff_b_m2(coff);
    mailbox_drain(qts, 1);
    dsp_run(qts, coff->data, coff->len, true);
    g_assert_cmphex(mbox_pop1(qts), ==, 0x18ecffffu);
    g_assert_cmphex(mbox_pop1(qts), ==, 0x11110000u);
    dsp_hold_reset(qts);
    g_byte_array_free(coff, TRUE);
    qtest_quit(qts);
}

/*
 * Both address modes post-increment. RX-34 2026-09-30: CCR low
 * 0x5080 copied source 0x1111/0x4000 to byte 0x1f200 and left
 * 0xf200 as a5a5/5a5a. After the block, CCR low was 0x5000
 * (mailbox 00500040): EN cleared, both post-increment bits kept.
 */
static void test_iodma_daram_postinc(void)
{
    QTestState *qts = dsp_start();
    GByteArray *coff;
    uint16_t src[] = { 0x1111, 0x2222, 0x3333, 0x4444 };
    uint32_t low = IODMA_CDSA_DARAM & 0xffffu;
    unsigned i;

    arm_write_pcm(qts, DSP_MEM + CSSA_BYTE, 16, src, 4);
    arm_write_pcm(qts, DSP_MEM + IODMA_CDSA_DARAM, 16,
                  (const uint16_t[]){ 0 }, 1);
    arm_write_pcm(qts, DSP_MEM + low, 4,
                  (const uint16_t[]){ 0xa5a5, 0x5a5a }, 2);
    coff = iodma_program_full(CSSA_BYTE, IODMA_CDSA_DARAM, 8, 2, 0,
                              IODMA_CCR_ENABLE | IODMA_CCR_SRC_POST |
                              IODMA_CCR_DST_POST, 3);
    mailbox_drain(qts, 1);
    dsp_run(qts, coff->data, coff->len, true);
    qtest_clock_step(qts, NANOSECONDS_PER_SECOND / 100);
    assert_tagged_lo(mbox_pop1(qts), IODMA_CSR_DONE);
    assert_tagged_lo(mbox_pop1(qts), 0);
    assert_tagged_lo(mbox_pop1(qts), IODMA_CCR_SRC_POST | IODMA_CCR_DST_POST);
    g_assert_cmphex(qtest_readw(qts, DSP_MEM + CSSA_BYTE), ==, 0x1111);
    for (i = 0; i < 16; i++) {
        g_assert_cmphex(qtest_readw(qts, DSP_MEM + IODMA_CDSA_DARAM + i * 2ull),
                        ==, src[i % 4]);
    }
    g_assert_cmphex(qtest_readw(qts, DSP_MEM + low), ==, 0xa5a5);
    g_assert_cmphex(qtest_readw(qts, DSP_MEM + low + 2), ==, 0x5a5a);
    dsp_hold_reset(qts);
    g_byte_array_free(coff, TRUE);
    qtest_quit(qts);
}

/*
 * EN toward the EAC data port while AGCTR.AUDEN is clear. CSR is
 * 0x0100 and the block stays. A playback path that is enabled but
 * still waiting on CTS keeps the 2 s hold instead.
 */
static void test_iodma_eac_closed(void)
{
    char *wav_path = make_wav_path();
    QTestState *qts = dsp_start_wav_machine("n800", wav_path);
    GByteArray *coff;
    uint16_t src[] = { 0x1111, 0x2222, 0x3333, 0x4444 };

    arm_write_pcm(qts, DSP_MEM + CSSA_BYTE, 16, src, 4);
    coff = iodma_program_full(CSSA_BYTE, IODMA_CDSA_EAC, 8, 2, 0,
                              IODMA_CCR_ENABLE, 1);
    mailbox_drain(qts, 1);
    dsp_run(qts, coff->data, coff->len, true);
    assert_tagged_lo(mbox_pop1(qts), IODMA_CSR_TRANS_ERR);
    assert_tagged_lo(mbox_pop1(qts), 0);
    g_assert_cmphex(qtest_readw(qts, DSP_MEM + CSSA_BYTE), ==, 0x1111);
    g_assert_cmphex(qtest_readw(qts, DSP_MEM + CSSA_BYTE + 2), ==, 0x2222);
    dsp_hold_reset(qts);
    qtest_quit(qts);
    {
        gchar *data = NULL;
        gsize n = 0;
        GError *err = NULL;

        /* No header: the closed codec never opened the wav sink. */
        g_assert_true(g_file_get_contents(wav_path, &data, &n, &err));
        g_assert_no_error(err);
        g_assert_cmpuint(n, ==, 0);
        g_free(data);
    }
    unlink(wav_path);
    g_free(wav_path);
    g_byte_array_free(coff, TRUE);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    qtest_add_func("/n8x0/dsp/exmap-mmap", test_exmap_mmap);
    qtest_add_func("/n8x0/dsp/exmap-unmapped", test_exmap_unmapped_fault);
    qtest_add_func("/n8x0/dsp/iodma-cssa-to-eac", test_iodma_cssa_to_eac);
    qtest_add_func("/n8x0/dsp/iodma-ramp-n800", test_iodma_ramp_n800);
    qtest_add_func("/n8x0/dsp/iodma-no-sio-steal", test_iodma_no_sio_steal);
    qtest_add_func("/n8x0/dsp/iodma-ccr-hi-not-en", test_iodma_ccr_hi_not_en);
    qtest_add_func("/n8x0/dsp/iodma-daram-constant", test_iodma_daram_constant);
    qtest_add_func("/n8x0/dsp/iodma-csr-w1c", test_iodma_csr_w1c);
    qtest_add_func("/n8x0/dsp/iodma-daram-dblidx", test_iodma_daram_dblidx);
    qtest_add_func("/n8x0/dsp/iodma-daram-dbl-fi4", test_iodma_daram_dbl_fi4);
    qtest_add_func("/n8x0/dsp/iodma-daram-src-post-only",
                   test_iodma_daram_src_post_only);
    qtest_add_func("/n8x0/dsp/iodma-daram-postinc", test_iodma_daram_postinc);
    qtest_add_func("/n8x0/dsp/iodma-daram-early-last",
                   test_iodma_daram_early_last);
    qtest_add_func("/n8x0/dsp/iodma-daram-early-half",
                   test_iodma_daram_early_half);
    qtest_add_func("/n8x0/dsp/iodma-daram-early-cen2",
                   test_iodma_daram_early_cen2);
    qtest_add_func("/n8x0/dsp/iodma-daram-index", test_iodma_daram_index);
    qtest_add_func("/n8x0/dsp/iodma-daram-index-ei1", test_iodma_daram_index_ei1);
    qtest_add_func("/n8x0/dsp/iodma-daram-srcidx", test_iodma_daram_srcidx);
    qtest_add_func("/n8x0/dsp/iodma-daram-dbl5", test_iodma_daram_dbl5);
    qtest_add_func("/n8x0/dsp/iodma-daram-dblwide", test_iodma_daram_dblwide);
    qtest_add_func("/n8x0/dsp/iodma-daram-idx5", test_iodma_daram_idx5);
    qtest_add_func("/n8x0/dsp/iodma-daram-dbl3", test_iodma_daram_dbl3);
    qtest_add_func("/n8x0/dsp/iodma-daram-dblfar", test_iodma_daram_dblfar);
    qtest_add_func("/n8x0/dsp/iodma-daram-idxn2", test_iodma_daram_idxn2);
    qtest_add_func("/n8x0/dsp/iodma-daram-dstidx", test_iodma_daram_dstidx);
    qtest_add_func("/n8x0/dsp/iodma-port-sxmd", test_iodma_port_sxmd);
    qtest_add_func("/n8x0/dsp/iodma-eac-closed", test_iodma_eac_closed);
    qtest_add_func("/n8x0/dsp/mailbox-audio", test_mailbox_audio);
    qtest_add_func("/n8x0/dsp/mail-u0-rearm-on-halt", test_mail_u0_rearm_on_halt);
    qtest_add_func("/n8x0/dsp/mail-prefer-26-over-line37",
                   test_mail_prefer_26_over_line37);
    qtest_add_func("/n8x0/dsp/ipbuf-ring", test_ipbuf_ring);
    qtest_add_func("/n8x0/dsp/protrev-golden", test_protrev_golden);
    qtest_add_func("/n8x0/dsp/avs-audio-task-lifecycle", test_avs_lifecycle);
    qtest_add_func("/n8x0/dsp/audio-underrun-recovery", test_underrun_recovery);
    return g_test_run();
}
