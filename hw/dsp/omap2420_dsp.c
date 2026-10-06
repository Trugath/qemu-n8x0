/*
 * OMAP2420 DSP subsystem: C55x interpreter, IPI, DSP MMU, internal RAM.
 *
 * This is not a qemu-system-c55x target. The ARM machine owns a bounded
 * C55x slice scheduled from a virtual-clock timer while RST1_DSP is clear.
 * Mailbox words are produced only by executed instructions.
 *
 * The slice used to run on the ARM thread and held the Big QEMU Lock for
 * the whole 4096 instructions, so the boot UI froze for each burst of
 * playback. A helper thread runs that slice. The ARM caller waits for
 * the slice to finish, with the lock dropped, so the mailbox handshake
 * stays ordered and the UI can paint between quanta.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "qemu/rcu.h"
#include "qemu/thread.h"
#include "qemu/timer.h"
#include "qapi/error.h"
#include "exec/memory.h"
#include "exec/cpu-common.h"
#include "exec/address-spaces.h"
#include "hw/irq.h"
#include "hw/arm/omap.h"
#include "sysemu/qtest.h"
#include "c55x.h"

#include <stdio.h>
#include <stdlib.h>

#define OMAP2420_DSP_MEM_BASE   0x58000000ull
#define OMAP2420_DSP_IPI_BASE   0x59000000ull
#define OMAP2420_DSP_MMU_BASE   0x5a000000ull
#define OMAP2420_MBOX_BASE      0x48094000ull
#define OMAP2420_DMA4_BASE      0x48056000ull
#define OMAP2420_DSP_MEM_SIZE   0x28000
/*
 * avs_kernel C55x port() window used by _Configure_DMA / _Enable_DMA /
 * audio_isr. Port P maps like DMA4 + (P-0x3000)*2 (IRQSTATUS_L0
 * at 0x3004 = +0x08, GCR at 0x303c = +0x78). Channels are
 * 0x3040 + ch*48 (12352+ch*48) = DMA4 ch n at +0x80 + n*0x60
 * (CCR bit 7, CLNK ENABLE_LNK bit 15 / next 4:0, CSR +6/+7
 * W1C). Block complete clears EN and, if ENABLE_LNK, sets EN
 * on the next channel (avs_kernel ping-pongs ch1↔ch3).
 * Terminal count kicks a C55x slice so `_issue_idle` can
 * take INT2 before the linked 10 ms partner expires.
 * DSP-private; CSSA is a C55x byte address, so it is not
 * forwarded into ARM sDMA.
 */
#define DSP_IODMA_PORT0         0x3000u
#define DSP_IODMA_CH0           0x3040u
#define DSP_IODMA_STRIDE        48u
#define DSP_IODMA_CHANS         8u
#define DSP_IODMA_GCR_PORT      0x303cu
#define DSP_IODMA_IRQSTAT0      0x3004u
#define DSP_IODMA_IRQSTAT1      0x3006u
#define DSP_IODMA_IRQEN0        0x300cu
#define DSP_IODMA_IRQEN1        0x300eu
#define DSP_IODMA_CCR           0u
#define DSP_IODMA_CLNK          2u
#define DSP_IODMA_CSR           6u
#define DSP_IODMA_CEN           10u
#define DSP_IODMA_CFN           12u
#define DSP_IODMA_CSDP          8u
#define DSP_IODMA_CSSA          14u
#define DSP_IODMA_CDSA          16u
#define DSP_IODMA_CSEI          18u
#define DSP_IODMA_CSFI          20u
#define DSP_IODMA_CDEI          22u
#define DSP_IODMA_CDFI          24u
#define DSP_IODMA_CCR_ENABLE    (1u << 7)
#define DSP_IODMA_CLNK_ENABLE   (1u << 15)
#define DSP_IODMA_CLNK_NEXT     0x1fu
/*
 * RX-34 completion word on a memory block is 0x003c: HALF|FRAME|LAST|BLOCK.
 * Bit 8 is TRANS_ERR (closed EAC, no copy).
 */
#define DSP_IODMA_CSR_HALF      (1u << 2)
#define DSP_IODMA_CSR_FRAME     (1u << 3)
#define DSP_IODMA_CSR_LAST      (1u << 4)
#define DSP_IODMA_CSR_BLOCK     (1u << 5)
#define DSP_IODMA_CSR_DONE      (DSP_IODMA_CSR_HALF | DSP_IODMA_CSR_FRAME | \
                                 DSP_IODMA_CSR_LAST | DSP_IODMA_CSR_BLOCK)
#define DSP_IODMA_CSR_TRANS_ERR (1u << 8)
/*
 * RX-34 2026-10-01, CEN=4 CFN=1, CCR 0x5080 (EN and both post-increment
 * modes), CDSA 0xfe00b8: CSR low is TRANS_ERR|LAST|HALF. EN clears.
 * The same word is returned after TSC2301 page-2 reg 5 is written
 * 0x2b00. Constant-mode EN (no address step) stays at TRANS_ERR only.
 */
#define DSP_IODMA_CSR_EAC_SHORT (DSP_IODMA_CSR_TRANS_ERR | \
                                 DSP_IODMA_CSR_LAST | DSP_IODMA_CSR_HALF)
/* OMAP DMA4 CSR bit 11. RX-34 sets it and copies nothing. */
#define DSP_IODMA_CSR_MISALIGN  (1u << 11)
#define DSP_IODMA_AMODE_CONST   0u
#define DSP_IODMA_AMODE_POSTINC 1u
#define DSP_IODMA_AMODE_SGLIDX  2u
#define DSP_IODMA_AMODE_DBLIDX  3u
#define DSP_IODMA_L2_OUT        2u
#define DSP_IODMA_L2_IN         3u
#define DSP_EAC_WORD_LO         0x07f0000u
#define DSP_EAC_WORD_HI         0x07f0100u
#define DSP_SCRATCH_LO          0x28000u
#define DSP_SCRATCH_HI          0x40000u
#define DSP_SCRATCH_SIZE        (DSP_SCRATCH_HI - DSP_SCRATCH_LO)
#define DSP_IO_MBOX_VA          0xfe2000u
#define DSP_IO_MBOX_SIZE        0x1000u
/* Stock TLB fe0000→48090000 (EAC). Same IOMAP hole as mailbox. */
#define DSP_IO_EAC_VA           0xfe0000u
#define DSP_IO_EAC_SIZE         0x1000u
#define OMAP2420_DSP_TLB        32
#define OMAP2420_DSP_SLICE      4096
/* Instructions run while holding the BQL. The helper drops it after. */
#define OMAP2420_DSP_QUANTUM    256
/* Keep the DSP ahead of host Pulse: 250 µs virtual ticks. */
#define OMAP2420_DSP_TICK_NS    250000
#define DSP_BYTE_PCM1_MMAP      0x430000u
#define DSP_BYTE_PCM1_SRC       0x43a000u
/* EAC host voice is stereo S16 @ 48 kHz (two IODMA words → one frame). */
#define OMAP2420_EAC_RATE       48000
#define OMAP2420_EAC_CHANS      2
/* avs_kernel HWI_INT5 (_mailbox_interrupt). INT4 is FXN_F_selfLoop. */
#define OMAP2420_DSP_IFR_MAIL   (1u << 5)

#define DSP_IPI_REVISION        0x00
#define DSP_IPI_SYSCONFIG       0x10
#define DSP_IPI_INDEX           0x40
#define DSP_IPI_ENTRY           0x44
#define DSP_IPI_ENABLE          0x48
#define DSP_IPI_IOMAP           0x4c
#define DSP_IPI_DSPBOOTCONFIG   0x50
#define DSP_IPI_ENABLE_EN       0x1
#define DSP_IPI_IOMAP_MASK      0x3f
#define DSP_IPI_PAGES           (OMAP2420_DSP_MEM_SIZE / 0x1000)

#define DSP_BOOT_CONFIG_DIRECT  0
#define DSP_BOOT_ADR_DIRECT     0x00ffff00u

#define DSP_MMU_REVISION        0x00
#define DSP_MMU_SYSCONFIG       0x10
#define DSP_MMU_SYSSTATUS       0x14
#define DSP_MMU_IRQSTATUS       0x18
#define DSP_MMU_IRQENABLE       0x1c
#define DSP_MMU_WALKING_ST      0x40
#define DSP_MMU_CNTL            0x44
#define DSP_MMU_FAULT_AD        0x48
#define DSP_MMU_TTB             0x4c
#define DSP_MMU_LOCK            0x50
#define DSP_MMU_LD_TLB          0x54
#define DSP_MMU_CAM             0x58
#define DSP_MMU_RAM             0x5c
#define DSP_MMU_GFLUSH          0x60
#define DSP_MMU_FLUSH_ENTRY     0x64
#define DSP_MMU_READ_CAM        0x68
#define DSP_MMU_READ_RAM        0x6c
#define DSP_MMU_EMU_FAULT_AD    0x70

#define DSP_MMU_SYSCONFIG_SOFTRESET 0x2
#define DSP_MMU_SYSSTATUS_RESETDONE 0x1
#define DSP_MMU_CNTL_MMUENABLE  0x2
#define DSP_MMU_IRQ_TRANSLATIONFAULT 0x2
#define DSP_MMU_LD_TLB_LD       0x1
#define DSP_MMU_CAM_V           0x4
#define DSP_MMU_CAM_PRESERVE    0x8
#define DSP_MMU_CAM_PAGESIZE    0x3
#define DSP_MMU_RAM_MIXED       (1u << 6)
#define DSP_MMU_RAM_ELSZ_SHIFT  7
#define DSP_MMU_RAM_ENDIAN      (1u << 9)
#define DSP_FAULT_VA            0x701460u

struct omap2420_dsp_s {
    MemoryRegion mem;
    MemoryRegion ipi;
    MemoryRegion mmu;
    uint8_t *iram;
    /*
     * DSP-private data for VAs in [0x28000, 0x40000). Stock _MEM_init
     * writes the large-model page-1 header at word 0x0169c8 (byte
     * 0x02d390). That address is not in avs_kernelcfg MEMORY, so it
     * must not become an ARM EXMAP. The host flat model already
     * accepts the store; this scratch keeps the same bytes on the
     * C55x side only. Addresses outside this gap still MMU-fault
     * (QTest 0xfe8000).
     */
    uint8_t *scratch; /* DSP-private [0x28000, 0x40000); not an ARM EXMAP */
    unsigned scratch_writes;
    unsigned mbox_logs;
    unsigned poll_pops;
    struct omap2_mailbox_s *mbox;
    qemu_irq irq_mmu;
    QEMUTimer *timer;
    struct {
        uint16_t glob[0x40];
        uint16_t ch[DSP_IODMA_CHANS][DSP_IODMA_STRIDE];
        uint8_t armed[DSP_IODMA_CHANS];
        uint8_t dac_hold[DSP_IODMA_CHANS];
        /* Early CSR is visible until the next port read or the timer. */
        uint8_t staged[DSP_IODMA_CHANS];
        uint8_t stage_seen[DSP_IODMA_CHANS];
        uint8_t stage_xfer[DSP_IODMA_CHANS];
        uint32_t stage_bits[DSP_IODMA_CHANS];
        int64_t deadline[DSP_IODMA_CHANS];
        int64_t dac_giveup;
        QEMUTimer *tmr[DSP_IODMA_CHANS];
        unsigned logs;
    } iodma;
    unsigned src_yields;
    unsigned eac_logs;
    unsigned watchdog_logged;
    unsigned iodma_tc_n;
    unsigned iodma_clnk_n;
    unsigned prefault_logged;
    unsigned mbox_irq_n;
    unsigned mbox_irq_logs;
    unsigned pcm1_exmap_logs;
    uint16_t mbox_d2a_msw;
    C55xCPU cpu;
    int rst1;
    int running;
    int in_kick;
    QemuThread thread;
    QemuMutex thread_mu;
    QemuCond thread_cv;
    QemuCond thread_done;
    int thread_on;
    int thread_stop;
    int thread_pending;
    int thread_busy;
    uint32_t ipi_sysconfig;
    uint32_t ipi_index;
    uint32_t ipi_entry;
    uint32_t ipi_enable;
    uint32_t ipi_iomap;
    uint32_t ipi_page[DSP_IPI_PAGES];
    uint32_t bootconfig;
    uint32_t boot_word[2];
    uint32_t mmu_sysconfig;
    uint32_t mmu_irqstatus;
    uint32_t mmu_irqenable;
    uint32_t mmu_cntl;
    uint32_t mmu_fault_ad;
    uint32_t mmu_ttb;
    uint32_t mmu_lock;
    uint32_t mmu_cam;
    uint32_t mmu_ram;
    uint32_t tlb_cam[OMAP2420_DSP_TLB];
    uint32_t tlb_ram[OMAP2420_DSP_TLB];
};

static void dsp_log(void *opaque, const char *fmt, ...)
    __attribute__((format(gnu_printf, 2, 3)));
static int dsp_map_word(struct omap2420_dsp_s *s, uint32_t word_addr,
                        uint32_t *pa);

static uint32_t dsp_page_mask(uint32_t cam)
{
    switch (cam & DSP_MMU_CAM_PAGESIZE) {
    case 0:
        return 0xfff00000u;
    case 1:
        return 0xffff0000u;
    case 3:
        return 0xff000000u;
    default:
        return 0xfffff000u;
    }
}

static uint32_t dsp_page_bytes(uint32_t cam)
{
    switch (cam & DSP_MMU_CAM_PAGESIZE) {
    case 0:
        return 1u << 20;
    case 1:
        return 1u << 16;
    case 3:
        return 1u << 24;
    default:
        return 1u << 12;
    }
}

static const char *dsp_page_name(uint32_t cam)
{
    switch (cam & DSP_MMU_CAM_PAGESIZE) {
    case 0:
        return "1M";
    case 1:
        return "64K";
    case 3:
        return "16M";
    default:
        return "4K";
    }
}

static void dsp_log_tlb_entry(int i, uint32_t cam, uint32_t ram,
                              const char *origin)
{
    uint32_t mask = dsp_page_mask(cam);
    uint32_t va = cam & mask;
    uint32_t pa = ram & mask;
    uint32_t size = dsp_page_bytes(cam);
    uint32_t end = va + size - 1u;
    unsigned elsz = (ram >> DSP_MMU_RAM_ELSZ_SHIFT) & 3u;

    qemu_log_mask(LOG_UNIMP,
                  "omap2420_dsp: tlb[%02d] va=%06x-%06x size=%s pa=%08x "
                  "preserve=%u endian=%s elsz=%u mixed=%u origin=%s "
                  "cam=%08x ram=%08x%s\n",
                  i, va, end, dsp_page_name(cam), pa,
                  !!(cam & DSP_MMU_CAM_PRESERVE),
                  (ram & DSP_MMU_RAM_ENDIAN) ? "LE" : "BE",
                  elsz, !!(ram & DSP_MMU_RAM_MIXED), origin, cam, ram,
                  ((DSP_FAULT_VA & mask) == va) ? " covers-701460" : "");
}

static void dsp_dump_tlb(struct omap2420_dsp_s *s, const char *why)
{
    int i;
    int valid = 0;
    int cover = 0;

    qemu_log_mask(LOG_UNIMP,
                  "omap2420_dsp: tlb-dump why=%s cntl=%x lock=%x "
                  "enable=%u\n",
                  why, s->mmu_cntl, s->mmu_lock,
                  !!(s->mmu_cntl & DSP_MMU_CNTL_MMUENABLE));
    for (i = 0; i < OMAP2420_DSP_TLB; i++) {
        uint32_t cam = s->tlb_cam[i];
        uint32_t mask;

        if (!(cam & DSP_MMU_CAM_V)) {
            continue;
        }
        valid++;
        mask = dsp_page_mask(cam);
        if ((DSP_FAULT_VA & mask) == (cam & mask)) {
            cover = 1;
        }
        dsp_log_tlb_entry(i, cam, s->tlb_ram[i], why);
    }
    qemu_log_mask(LOG_UNIMP,
                  "omap2420_dsp: tlb-dump why=%s valid=%d cover-701460=%s\n",
                  why, valid, cover ? "yes" : "no");
}

/*
 * IPI IOMAP is a 6-bit window into on-chip DARAM+SARAM, not an EXMAP.
 * DSP byte [IOMAP<<18, IOMAP<<18 + 0x28000) aliases ARM 0x58000000.
 * Route this before the DSP MMU.
 */
static int dsp_translate_iomap(struct omap2420_dsp_s *s, uint32_t va,
                               uint32_t *off)
{
    uint32_t base;

    if (!(s->ipi_enable & DSP_IPI_ENABLE_EN)) {
        return -1;
    }
    base = (s->ipi_iomap & DSP_IPI_IOMAP_MASK) << 18;
    if (va < base) {
        return -1;
    }
    *off = va - base;
    if (*off >= OMAP2420_DSP_MEM_SIZE) {
        return -1;
    }
    /*
     * hardware-map / RX-34: 4K I/O at DSP byte 0xfe2000 is the OMAP2 mailbox
     * (stock _mbx_send word 0x7f1022). Silicon requires a DSP MMU TLB for this
     * page (FAULT_AD=0xfe2040 without it, 2026-09-18). QEMU still accepts the
     * hardwired window below for older tests; prefer programming the TLB.
     */
    if (va >= DSP_IO_MBOX_VA && va < DSP_IO_MBOX_VA + DSP_IO_MBOX_SIZE) {
        return -1;
    }
    if (va >= DSP_IO_EAC_VA && va < DSP_IO_EAC_VA + DSP_IO_EAC_SIZE) {
        return -1;
    }
    return 0;
}

static int dsp_translate_io(uint32_t va, uint32_t *pa)
{
    if (va >= DSP_IO_MBOX_VA && va < DSP_IO_MBOX_VA + DSP_IO_MBOX_SIZE) {
        *pa = (uint32_t)OMAP2420_MBOX_BASE + (va - DSP_IO_MBOX_VA);
        return 0;
    }
    return -1;
}

static int dsp_mbox_offset(uint32_t va, uint32_t *off)
{
    if (va >= DSP_IO_MBOX_VA && va < DSP_IO_MBOX_VA + DSP_IO_MBOX_SIZE) {
        *off = va - DSP_IO_MBOX_VA;
        return 0;
    }
    return -1;
}

static uint32_t dsp_mbox_ldl(uint32_t off)
{
    return address_space_ldl_le(&address_space_memory,
                                OMAP2420_MBOX_BASE + (off & ~3u),
                                MEMTXATTRS_UNSPECIFIED, NULL);
}

static void dsp_mbox_stl(uint32_t off, uint32_t value)
{
    address_space_stl_le(&address_space_memory,
                         OMAP2420_MBOX_BASE + (off & ~3u), value,
                         MEMTXATTRS_UNSPECIFIED, NULL);
}

static void dsp_c55x_prefault(struct omap2420_dsp_s *s, uint32_t word);
static int dsp_read16(void *opaque, uint32_t word_addr, uint16_t *out);
static int dsp_write16(void *opaque, uint32_t word_addr, uint16_t value);
static void dsp_pcm_stat_line(const char *fmt, ...)
    __attribute__((format(gnu_printf, 1, 2)));

/*
 * tokliBIOS lines are 0x100000 + bid * (6 + bsz). Stock bsz is 512,
 * so the stride is 0x206 words. Linux prints "512 words" and adds the
 * 6-word header itself. Payload starts at line+6; libesd accepts the
 * reply only when the next halfword is 1.
 */
/* Last BKSND command. Cmd 3 is the buffer-complete the ARM must pop. */
static uint16_t pcm1_last_bksnd_cmd;

static int pcm1_bksnd_keep_status(struct omap2420_dsp_s *s, uint16_t bid,
                                   uint16_t *cmd_out)
{
    uint32_t line = 0x100000u + (uint32_t)bid * 0x206u;
    uint32_t pay = line + 6u;
    uint16_t cmd = 0;
    uint16_t st = 0;

    if (bid >= 16u) {
        return -1;
    }
    if (dsp_read16(s, pay, &cmd) || dsp_read16(s, pay + 1u, &st)) {
        return -1;
    }
    if (cmd_out) {
        *cmd_out = cmd;
    }
    /*
     * ARM copies this line as soon as the mailbox word commits.
     * 0x1266b3 plants IPBLINK 0xffff, but a later store in the same
     * _bksnd can put the next BID back. A non-terminating link makes
     * the pcm1 read wait for a line that is never sent.
     */
    {
        uint16_t link = 0;

        if (!dsp_read16(s, line + 1u, &link) && link != 0xffffu) {
            dsp_write16(s, line + 1u, 0xffffu);
            dsp_pcm_stat_line("pcm1-mbox-link bid=%04x line=%06x "
                              "%04x->ffff cmd=%04x\n",
                              bid, line, link, cmd);
        }
    }
    if ((cmd == 1u || cmd == 2u || cmd == 7u || cmd == 13u) && st != 1u) {
        dsp_write16(s, pay + 1u, 1);
        dsp_pcm_stat_line("pcm1-mbox-status1 bid=%04x line=%06x cmd=%04x "
                          "%04x->0001\n",
                          bid, line, cmd, st);
        st = 1;
    }
    dsp_pcm_stat_line("pcm1-mbox-bksnd bid=%04x line=%06x cmd=%04x st=%04x\n",
                      bid, line, cmd, st);
    pcm1_last_bksnd_cmd = cmd;
    return 0;
}

/*
 * C55x MOV dbl is MSW then LSW. ARM writew is LE (commit on +2). Do not
 * punch the MSW through MESSAGE+0 or PROTREV becomes 0x00197070.
 */
static void dsp_mbox_commit_word(struct omap2420_dsp_s *s, uint32_t off,
                                  uint32_t word);
static int dsp_read_bytes(struct omap2420_dsp_s *s, uint32_t byte_addr,
                          uint8_t *buf, unsigned n, int allow_scratch);
static int dsp_write_bytes(struct omap2420_dsp_s *s, uint32_t byte_addr,
                           const uint8_t *buf, unsigned n);

/*
 * 20260923T112316Z: read(4) is entered with FIFO1 empty. The cmd 2
 * BKSND is posted later, while NEWIRQAGR is still clear, and nothing
 * pops it. Remember that a pcm1 read is in the kernel so the slice
 * can re-arm that one stuck latch.
 */
static int pcm1_reads_open;
/* n=2 is the waiter. It must not postpone IODMA. */
static int pcm1_n2_open;
/* Virtual time when the current read(4/10/40) streak started. */
static int64_t pcm1_read_since;
static struct omap2420_dsp_s *pcm1_wfi_dsp;

/*
 * esd's memcpy lands in the guest mmap. cmd3 reads DSP word 0x218000
 * (byte 0x430000). When those views differ, the speaker plays the
 * DSP's stale page instead of the tune that just arrived.
 */
/*
 * Bytes esd copied into the mmap, in order. The live DSP page is a
 * 4-held pair by the time cmd3 peeks it; this queue is the copy from
 * the kick, before that rewrite.
 */
static uint8_t tune_q[256 * 1024];
static uint32_t tune_wr;
static uint32_t tune_rd;
static int tune_armed;
static int tune_latched;

void omap2420_dsp_pcm1_sync_mmap(const uint8_t *bytes, uint32_t n)
{
    static unsigned logs;
    int16_t w0, w1, w2, w3;

    if (!bytes || n < 16u || n > 0x2000u) {
        return;
    }
    w0 = (int16_t)(bytes[0] | (bytes[1] << 8));
    w1 = (int16_t)(bytes[2] | (bytes[3] << 8));
    w2 = (int16_t)(bytes[4] | (bytes[5] << 8));
    w3 = (int16_t)(bytes[6] | (bytes[7] << 8));
    logs++;
    if (logs <= 4u || (logs % 16u) == 0u) {
        int amp = abs((int)w0);

        if (abs((int)w1) > amp) {
            amp = abs((int)w1);
        }
        dsp_pcm_stat_line("t=sync n=%u k=%u amp=%d s=%d %d %d %d\n", n,
                          logs, amp, (int)w0, (int)w1, (int)w2, (int)w3);
    }
    /*
     * Queue only. Writing the chunk back through the DSP MMU from
     * the ARM helper races the task that owns the page.
     */
    if (qatomic_read(&tune_wr) + n <= sizeof(tune_q)) {
        uint32_t wr = qatomic_read(&tune_wr);

        memcpy(tune_q + wr, bytes, n);
        qatomic_set(&tune_wr, wr + n);
        qatomic_set(&tune_latched, 1);
    }
}

int omap2420_dsp_pcm1_tune_armed(void)
{
    return tune_armed;
}

int omap2420_dsp_pcm1_tune_next(int16_t *sample)
{
    int16_t v;

    if (!sample || tune_rd + 2 > qatomic_read(&tune_wr)) {
        return 0;
    }
    v = (int16_t)(tune_q[tune_rd] | (tune_q[tune_rd + 1] << 8));
    tune_rd += 2;
    tune_armed = 1;
    *sample = v;
    return 1;
}

uint32_t omap2420_dsp_pcm1_tune_take(uint8_t *out, uint32_t n)
{
    uint32_t wr;
    uint32_t have;

    if (!out || n < 4u) {
        return 0;
    }
    wr = qatomic_read(&tune_wr);
    if (tune_rd >= wr) {
        return 0;
    }
    have = wr - tune_rd;
    if (n > have) {
        n = have;
    }
    n &= ~3u;
    if (!n) {
        return 0;
    }
    memcpy(out, tune_q + tune_rd, n);
    tune_rd += n;
    tune_armed = 1;
    return n;
}

int omap2420_dsp_pcm1_capture(void)
{
    return qatomic_read(&tune_latched);
}

void omap2420_dsp_pcm1_read_entered(uint32_t nbytes)
{
    uint32_t itr = 0;
    uint32_t mir = 0;
    uint32_t agr = 0;
    int sir = 0;
    int halted = 0;
    uint32_t msg = dsp_mbox_ldl(0xc4);

    if (nbytes == 2u) {
        pcm1_n2_open++;
    } else if (nbytes == 4u || nbytes == 10u || nbytes == 40u) {
        if (pcm1_reads_open == 0) {
            pcm1_read_since = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        }
        pcm1_reads_open++;
    }
    omap2_intc_mpu_snapshot(&itr, &mir, &agr, &sir, &halted);
    dsp_pcm_stat_line(
        "pcm1-read-enter n=%u msgstatus=%u agr=%08x sir=%d halted=%d "
        "bit26=%d\n",
        nbytes, msg, agr, sir, halted, !!(itr & (1u << 26)));
}

void omap2420_dsp_pcm1_read_finished(void)
{
    if (pcm1_reads_open > 0) {
        pcm1_reads_open--;
    }
    if (pcm1_reads_open == 0) {
        pcm1_read_since = 0;
    }
}

void omap2420_dsp_pcm1_n2_finished(void)
{
    if (pcm1_n2_open > 0) {
        pcm1_n2_open--;
    }
}

void omap2420_dsp_pcm1_read_result(uint32_t nbytes, uint32_t got,
                                   const uint8_t *buf, uint32_t n)
{
    char hex[48];
    uint32_t i;
    uint32_t pos = 0;

    if (nbytes != 10u && nbytes != 40u) {
        return;
    }
    hex[0] = 0;
    if (buf && n > 16u) {
        n = 16u;
    }
    for (i = 0; buf && i < n && pos + 3 < sizeof(hex); i++) {
        pos += snprintf(hex + pos, sizeof(hex) - pos, "%02x", buf[i]);
    }
    dsp_pcm_stat_line("pcm1-read-done n=%u got=%u bytes=%s\n",
                      nbytes, got, hex);
}

int omap2420_dsp_pcm1_read_pending(void)
{
    return pcm1_reads_open > 0;
}

int omap2420_dsp_pcm1_flush_hold(void)
{
    int64_t now;

    if (pcm1_reads_open <= 0) {
        return 0;
    }
    /*
     * IODMA stays postponed for the whole read so the DSP does not
     * miss the Gateway poll. The EAC buffer is different: a read that
     * has already been in the kernel for a second is the dsp_init
     * reply that was consumed without a wakeup. Holding the flush
     * that long drops every later sample at the 1024 cap.
     */
    now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    if (pcm1_read_since && now - pcm1_read_since > 1000000000LL) {
        return 0;
    }
    return 1;
}

void omap2420_dsp_on_wfi(void)
{
    struct omap2420_dsp_s *s = pcm1_wfi_dsp;
    unsigned depth = 0;
    uint32_t head;
    static unsigned logs;
    static uint32_t delivered;

    if ((pcm1_reads_open <= 0 && pcm1_n2_open <= 0) || !s || !s->mbox) {
        return;
    }
    /* FIFO holds the accumulator image. pcm1 cmd 0x20 is in bits 30:24. */
    head = omap2_mailbox_peek(s->mbox, 1, &depth);
    if (depth && logs < 6u) {
        uint32_t itr = 0, mir = 0, agr = 0;
        int sir = 0, halted = 0;

        omap2_intc_mpu_snapshot(&itr, &mir, &agr, &sir, &halted);
        dsp_pcm_stat_line(
            "pcm1-wfi depth=%u head=%08x agr=%08x bit26=%d\n",
            depth, head, agr, !!(itr & (1u << 26)));
        logs++;
    }
    if (!depth || ((head >> 24) & 0x7f) != 0x20 ||
        ((head >> 16) & 0xff) != 2 || head == delivered) {
        return;
    }
    delivered = head;
    omap2_intc_deliver_stuck_mail();
}

static void dsp_mbox_message_write16(struct omap2420_dsp_s *s, uint32_t off,
                                     uint16_t value)
{
    uint32_t word;
    int pcm1_bksnd;
    uint16_t cmd = 0;

    if ((off & 2u) == 0) {
        s->mbox_d2a_msw = value;
        return;
    }
    word = ((uint32_t)s->mbox_d2a_msw << 16) | value;
    /*
     * Repair the payload status before the FIFO commit. The ARM IRQ
     * handler copies the line as soon as this word is visible.
     */
    pcm1_bksnd = ((word >> 24) & 0x7f) == 0x20 && ((word >> 16) & 0xff) == 2;
    if (pcm1_bksnd) {
        pcm1_bksnd_keep_status(s, (uint16_t)word, &cmd);
    }
    dsp_mbox_commit_word(s, off, word);
}

static void dsp_mbox_commit_word(struct omap2420_dsp_s *s, uint32_t off,
                                 uint32_t word)
{
    /*
     * The FIFO word is the accumulator image. MOV dbl of
     * AC0=0x70700019 is PROTREV on the ARM side. Swabbing here
     * turns that into 0x19007070 and the gateway never publishes
     * pcm1.
     */
    dsp_mbox_stl(off, word);
    if (((word >> 24) & 0x7f) == 0x20 && ((word >> 16) & 0xff) == 2) {
        uint32_t itr = 0;
        uint32_t mir = 0;
        uint32_t agr = 0;
        int sir = 0;
        int halted = 0;
        uint32_t msg = dsp_mbox_ldl(0xc4);
        uint32_t irqst = dsp_mbox_ldl(0x100);
        uint32_t irqen = dsp_mbox_ldl(0x104);

        omap2_intc_mpu_snapshot(&itr, &mir, &agr, &sir, &halted);
        dsp_pcm_stat_line(
            "pcm1-cmd2-stall word=%08x msgstatus=%u irqst=%08x irqen=%08x "
            "itr=%08x mir=%08x agr=%08x sir=%d halted=%d bit26=%d masked=%d\n",
            word, msg, irqst, irqen, itr, mir, agr, sir, halted,
            !!(itr & (1u << 26)), !!(mir & (1u << 26)));
    }
    if (((word >> 24) & 0x7f) == 0x20 &&
        ((word >> 16) & 0xff) == 0x03 &&
        (word & 0xffffu) == 0x000fu) {
        dsp_c55x_prefault(s, word);
    }
}

static int dsp_internal_offset(struct omap2420_dsp_s *s, uint32_t va,
                               uint32_t *off)
{
    if (va < OMAP2420_DSP_MEM_SIZE) {
        *off = va;
        return 0;
    }
    return dsp_translate_iomap(s, va, off);
}

static int dsp_scratch_offset(uint32_t va, uint32_t *off)
{
    if (va >= DSP_SCRATCH_LO && va < DSP_SCRATCH_HI) {
        *off = va - DSP_SCRATCH_LO;
        return 0;
    }
    return -1;
}

static int dsp_mmu_translate(struct omap2420_dsp_s *s, uint32_t va,
                             uint32_t *pa)
{
    int i;

    if (!(s->mmu_cntl & DSP_MMU_CNTL_MMUENABLE)) {
        return -1;
    }
    for (i = 0; i < OMAP2420_DSP_TLB; i++) {
        uint32_t cam = s->tlb_cam[i];
        uint32_t mask;

        if (!(cam & DSP_MMU_CAM_V)) {
            continue;
        }
        mask = dsp_page_mask(cam);
        if ((va & mask) == (cam & mask)) {
            *pa = (s->tlb_ram[i] & mask) | (va & ~mask);
            return 0;
        }
    }
    return -1;
}

static void dsp_mmu_fault(struct omap2420_dsp_s *s, uint32_t va)
{
    uint32_t xar3 = s->cpu.xar[3] & C55X_WORD_MASK;

    s->mmu_fault_ad = va;
    s->mmu_irqstatus |= DSP_MMU_IRQ_TRANSLATIONFAULT;
    qemu_set_irq(s->irq_mmu, !!(s->mmu_irqstatus & s->mmu_irqenable));
    qemu_log_mask(LOG_UNIMP,
                  "omap2420_dsp: mmu-fault va=%06x pc=%06x "
                  "XAR3=%06x dbl-base=%06x byte=%06x\n",
                  va, s->cpu.pc, xar3, xar3 & ~1u, c55x_word_to_byte(xar3 & ~1u));
    dsp_dump_tlb(s, "fault");
}

static int dsp_read_bytes(struct omap2420_dsp_s *s, uint32_t byte_addr,
                          uint8_t *buf, unsigned n, int allow_scratch)
{
    unsigned i;

    byte_addr &= C55X_PC_MASK;
    for (i = 0; i < n; i++) {
        uint32_t va = (byte_addr + i) & C55X_PC_MASK;
        uint32_t pa;

        if (dsp_internal_offset(s, va, &pa) == 0) {
            buf[i] = s->iram[pa];
            continue;
        }
        if (dsp_mbox_offset(va, &pa) == 0) {
            uint32_t word = dsp_mbox_ldl(pa);
            unsigned sh = 8u * (pa & 3u);

            buf[i] = (uint8_t)(word >> sh);
            continue;
        }
        if (dsp_translate_io(va, &pa) == 0) {
            cpu_physical_memory_read(pa, &buf[i], 1);
            continue;
        }
        if (dsp_mmu_translate(s, va, &pa) == 0) {
            cpu_physical_memory_read(pa, &buf[i], 1);
            continue;
        }
        if (va >= DSP_BOOT_ADR_DIRECT && va < DSP_BOOT_ADR_DIRECT + 8) {
            uint32_t word = s->boot_word[(va - DSP_BOOT_ADR_DIRECT) >> 2];
            buf[i] = (uint8_t)(word >> (8 * ((va - DSP_BOOT_ADR_DIRECT) & 3)));
            continue;
        }
        if (allow_scratch && s->scratch &&
            dsp_scratch_offset(va, &pa) == 0) {
            buf[i] = s->scratch[pa];
            continue;
        }
        if (s->cpu.diag_read) {
            buf[i] = 0;
            continue;
        }
        dsp_mmu_fault(s, va);
        return -1;
    }
    return 0;
}

static int dsp_write_bytes(struct omap2420_dsp_s *s, uint32_t byte_addr,
                           const uint8_t *buf, unsigned n)
{
    unsigned i;

    byte_addr &= C55X_PC_MASK;
    for (i = 0; i < n; i++) {
        uint32_t va = (byte_addr + i) & C55X_PC_MASK;
        uint32_t pa;

        if (dsp_internal_offset(s, va, &pa) == 0) {
            s->iram[pa] = buf[i];
            continue;
        }
        if (dsp_mbox_offset(va, &pa) == 0) {
            uint32_t word;
            unsigned sh = 8u * (pa & 3u);

            if (pa >= 0x40 && pa < 0x80) {
                cpu_physical_memory_write(OMAP2420_MBOX_BASE + pa, &buf[i], 1);
            } else {
                word = dsp_mbox_ldl(pa);
                word = (word & ~(0xffu << sh)) | ((uint32_t)buf[i] << sh);
                dsp_mbox_stl(pa, word);
            }
            continue;
        }
        if (dsp_translate_io(va, &pa) == 0) {
            cpu_physical_memory_write(pa, &buf[i], 1);
            continue;
        }
        if (dsp_mmu_translate(s, va, &pa) == 0) {
            cpu_physical_memory_write(pa, &buf[i], 1);
            continue;
        }
        if (va >= DSP_BOOT_ADR_DIRECT && va < DSP_BOOT_ADR_DIRECT + 8) {
            unsigned slot = (va - DSP_BOOT_ADR_DIRECT) >> 2;
            unsigned sh = 8 * ((va - DSP_BOOT_ADR_DIRECT) & 3);
            s->boot_word[slot] = (s->boot_word[slot] & ~(0xffu << sh)) |
                                 ((uint32_t)buf[i] << sh);
            continue;
        }
        if (s->scratch && dsp_scratch_offset(va, &pa) == 0) {
            if (s->scratch_writes < 8) {
                qemu_log_mask(LOG_UNIMP,
                              "omap2420_dsp: scratch-write va=%06x "
                              "pc=%06x val=%02x\n",
                              va, s->cpu.pc, buf[i]);
            }
            s->scratch_writes++;
            s->scratch[pa] = buf[i];
            continue;
        }
        dsp_mmu_fault(s, va);
        return -1;
    }
    return 0;
}

static int dsp_fetch8(void *opaque, uint32_t byte_addr, uint8_t *out)
{
    /*
     * Program fetch is not the data-byte helper. Stock dsp_dld writes
     * each COFF 16-bit unit little-endian into ARM backing memory
     * (46 b3 -> b3 46). C55x instruction bytes are the high byte of
     * that word first, i.e. address ^ 1. dsp_read16 must keep the
     * un-swapped pair so .cinit words stay 00f0 09ba.
     */
    return dsp_read_bytes(opaque, byte_addr ^ 1u, out, 1, 0);
}

static int dsp_read16(void *opaque, uint32_t word_addr, uint16_t *out)
{
    struct omap2420_dsp_s *s = opaque;
    uint8_t buf[2];
    uint32_t va = c55x_word_to_byte(word_addr);
    uint32_t off, word;

    if (c55x_l2intc_owns(word_addr)) {
        int rc = c55x_l2intc_read16(&s->cpu.l2, word_addr, out);

        if (rc <= 0) {
            return rc;
        }
    }
    if (dsp_mbox_offset(va, &off) == 0) {
        if (off >= 0x40 && off < 0x80) {
            *out = address_space_lduw_le(&address_space_memory,
                                         OMAP2420_MBOX_BASE + off,
                                         MEMTXATTRS_UNSPECIFIED, NULL);
            /*
             * MESSAGE(0) +0 is the protocol MSW. cmd_h 0x32 is POLL;
             * dump the C55x state at the FIFO pop, not a synthesized
             * reply.
             */
            if (off == 0x40 && ((*out >> 8) & 0x7f) == 0x32) {
                qemu_log_mask(LOG_UNIMP,
                              "omap2420_dsp: POLL pop pc=%06x word_hi=%04x "
                              "IFR0=%04x IER0=%04x INTM=%u DBGM=%u "
                              "ST1=%04x ST2=%04x nest=%u "
                              "XSP=%06x XSSP=%06x halt=%u insn=%llu\n",
                              s->cpu.pc, *out, s->cpu.ifr0, s->cpu.ier0,
                              !!(s->cpu.st1 & C55X_ST1_INTM),
                              !!(s->cpu.st2 & C55X_ST2_DBGM),
                              s->cpu.st1, s->cpu.st2, s->cpu.irq_nest,
                              s->cpu.xsp & C55X_WORD_MASK,
                              s->cpu.xssp & C55X_WORD_MASK,
                              s->cpu.halt,
                              (unsigned long long)s->cpu.insn_count);
                s->poll_pops++;
            }
        } else {
            word = dsp_mbox_ldl(off);
            /*
             * Stock MOV dbl of MSGSTATUS / IRQENABLE: first Lmem half
             * is the protocol MSW, second is the LSW. A little-endian
             * 32-bit register's high half is therefore +0.
             */
            *out = (off & 2u) ? (uint16_t)word : (uint16_t)(word >> 16);
        }
        if (s->mbox_logs < 16) {
            qemu_log_mask(LOG_UNIMP,
                          "omap2420_dsp: mbox-read16 +%02x = %04x pc=%06x\n",
                          off, *out, s->cpu.pc);
            s->mbox_logs++;
        }
        return 0;
    }
    if (dsp_read_bytes(s, va, buf, 2, 1)) {
        return -1;
    }
    *out = (uint16_t)(buf[0] | ((uint16_t)buf[1] << 8));
    return 0;
}

static int dsp_write16(void *opaque, uint32_t word_addr, uint16_t value)
{
    struct omap2420_dsp_s *s = opaque;
    uint8_t buf[2] = { (uint8_t)value, (uint8_t)(value >> 8) };
    uint32_t va = c55x_word_to_byte(word_addr) & C55X_PC_MASK;
    uint32_t off0, off1, pa0, pa1;
    int rc;

    if (c55x_l2intc_owns(word_addr)) {
        int l2rc = c55x_l2intc_write16(&s->cpu.l2, word_addr, value);

        if (l2rc < 0) {
            return -1;
        }
        if (l2rc == 0) {
            return 0;
        }
    }
    if (dsp_internal_offset(s, va, &off0) == 0 &&
        dsp_internal_offset(s, (va + 1) & C55X_PC_MASK, &off1) == 0) {
        s->iram[off0] = buf[0];
        s->iram[off1] = buf[1];
        rc = 0;
        /*
         * Command 2 at SYSCONFIG is IVA L2 SOFTRESET. RESETDONE is
         * readable from C55x SYSSTATUS and from the ARM alias at
         * 0x58009014 (nolo-tags verify_dsp_l2intc).
         */
        if (((word_addr & C55X_WORD_MASK) == (C55X_L2INTC_SYSCONFIG + 1u)) &&
            (value & C55X_L2INTC_SOFTRESET)) {
            uint32_t so, so1;
            uint32_t sva = c55x_word_to_byte(C55X_L2INTC_SYSSTATUS);

            if (dsp_internal_offset(s, sva, &so) == 0 &&
                dsp_internal_offset(s, (sva + 3) & C55X_PC_MASK, &so1) == 0) {
                s->iram[so] = 0;
                s->iram[so + 1u] = 0;
                s->iram[so + 2u] = 1;
                s->iram[so + 3u] = 0;
            }
        }
    } else if (dsp_mbox_offset(va, &off0) == 0 &&
               dsp_mbox_offset((va + 1) & C55X_PC_MASK, &off1) == 0 &&
               off1 == off0 + 1) {
        if (off0 >= 0x40 && off0 < 0x80) {
            dsp_mbox_message_write16(s, off0, value);
        } else {
            uint32_t word = dsp_mbox_ldl(off0);

            if (off0 & 2u) {
                word = (word & 0xffff0000u) | value;
            } else {
                word = (word & 0xffffu) | ((uint32_t)value << 16);
            }
            dsp_mbox_stl(off0, word);
        }
        if (s->mbox_logs < 16 || (off0 >= 0x40 && off0 < 0x80)) {
            qemu_log_mask(LOG_UNIMP,
                          "omap2420_dsp: mbox-write16 +%02x = %04x pc=%06x\n",
                          off0, value, s->cpu.pc);
            if (off0 < 0x40 || off0 >= 0x80) {
                s->mbox_logs++;
            }
        }
        rc = 0;
    } else if (dsp_mmu_translate(s, va, &pa0) == 0 &&
               dsp_mmu_translate(s, (va + 1) & C55X_PC_MASK, &pa1) == 0 &&
               pa1 == pa0 + 1) {
        if (pa0 >= (uint32_t)OMAP2420_MBOX_BASE + 0x40u &&
            pa0 < (uint32_t)OMAP2420_MBOX_BASE + 0x80u) {
            dsp_mbox_message_write16(s, pa0 - (uint32_t)OMAP2420_MBOX_BASE,
                                     value);
        } else {
            cpu_physical_memory_write(pa0, buf, 2);
        }
        rc = 0;
    } else {
        rc = dsp_write_bytes(s, va, buf, 2);
    }

    if (rc == 0 && (word_addr == 0x09cfd6u || word_addr == 0x09cfdau)) {
        qemu_log_mask(LOG_UNIMP,
                      "omap2420_dsp: bss-write %06x = %04x\n",
                      word_addr, value);
    }
    if (rc == 0 && word_addr >= 0x09ccfau && word_addr < 0x09ccfau + 64u) {
        qemu_log_mask(LOG_UNIMP,
                      "omap2420_dsp: tidtab-write %06x = %04x pc=%06x\n",
                      word_addr, value, s->cpu.pc);
    }
    if (rc == 0 && (word_addr == 0x010be8u || word_addr == 0x010a28u ||
                    word_addr == 0x0169c8u || word_addr == 0x0169cau ||
                    word_addr == 0x020000u || word_addr == 0x020001u)) {
        qemu_log_mask(LOG_UNIMP,
                      "omap2420_dsp: artefact-write %06x = %04x\n",
                      word_addr, value);
    }
    if (rc == 0 && word_addr >= DSP_EAC_WORD_LO &&
        word_addr < DSP_EAC_WORD_HI && s->eac_logs < 64u) {
        uint32_t pa = 0;

        dsp_map_word(s, word_addr, &pa);
        dsp_log(s, "eac-write word=%06x pa=%08x val=%04x pc=%06x\n",
                word_addr, pa, value, s->cpu.pc & C55X_PC_MASK);
        s->eac_logs++;
    }
    return rc;
}

static int dsp_map_word(struct omap2420_dsp_s *s, uint32_t word_addr,
                        uint32_t *pa)
{
    uint32_t va = c55x_word_to_byte(word_addr);
    uint32_t off;

    if (dsp_internal_offset(s, va, &off) == 0) {
        *pa = (uint32_t)OMAP2420_DSP_MEM_BASE + off;
        return 0;
    }
    if (dsp_translate_io(va, pa) == 0) {
        return 0;
    }
    if (dsp_mmu_translate(s, va, pa) == 0) {
        return 0;
    }
    return -1;
}

static int dsp_read32(void *opaque, uint32_t word_addr, uint32_t *out)
{
    struct omap2420_dsp_s *s = opaque;
    uint32_t pa;
    uint8_t buf[4];
    uint16_t msw, lsw;

    if (c55x_l2intc_owns(word_addr) &&
        c55x_l2intc_read16(&s->cpu.l2, word_addr, &msw) == 0 &&
        c55x_l2intc_read16(&s->cpu.l2, word_addr ^ 1u, &lsw) == 0) {
        *out = ((uint32_t)msw << 16) | lsw;
        return 0;
    }
    if (dsp_map_word(s, word_addr, &pa) == 0) {
        *out = address_space_ldl_le(&address_space_memory, pa,
                                    MEMTXATTRS_UNSPECIFIED, NULL);
        return 0;
    }
    if (dsp_read_bytes(s, c55x_word_to_byte(word_addr), buf, 4, 1)) {
        return -1;
    }
    *out = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) |
           ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
    return 0;
}

static int dsp_write32(void *opaque, uint32_t word_addr, uint32_t value)
{
    struct omap2420_dsp_s *s = opaque;
    uint32_t pa;
    uint8_t buf[4] = {
        (uint8_t)value,
        (uint8_t)(value >> 8),
        (uint8_t)(value >> 16),
        (uint8_t)(value >> 24),
    };

    if (c55x_l2intc_owns(word_addr)) {
        if (dsp_write16(s, word_addr, (uint16_t)(value >> 16)) ||
            dsp_write16(s, word_addr ^ 1u, (uint16_t)value)) {
            return -1;
        }
        return 0;
    }
    if (dsp_map_word(s, word_addr, &pa) == 0) {
        address_space_stl_le(&address_space_memory, pa, value,
                             MEMTXATTRS_UNSPECIFIED, NULL);
        return 0;
    }
    if (dsp_write_bytes(s, c55x_word_to_byte(word_addr), buf, 4)) {
        return -1;
    }
    if (word_addr == 0x0169c8u || word_addr == 0x0169cau) {
        qemu_log_mask(LOG_UNIMP,
                      "omap2420_dsp: artefact-write %06x = %08x\n",
                      word_addr, value);
    }
    return 0;
}

static void dsp_iodma_complete(void *opaque);

static void dsp_pcm_stat_line(const char *fmt, ...)
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

static void omap2420_dsp_kick(struct omap2420_dsp_s *s);
static void omap2420_dsp_request(struct omap2420_dsp_s *s);

/* Set on the helper that runs C55x slices. Callers on that thread stay sync. */
static __thread int dsp_on_worker;

static uint32_t dsp_iodma_pair(const uint16_t *p)
{
    return ((uint32_t)p[0] << 16) | p[1];
}

static void dsp_iodma_set_pair(uint16_t *p, uint32_t value)
{
    p[0] = (uint16_t)(value >> 16);
    p[1] = (uint16_t)value;
}

static int dsp_iodma_lookup(uint16_t port, uint32_t *pa,
                            unsigned *ch_out, unsigned *off_out)
{
    if (port >= DSP_IODMA_PORT0 && port < DSP_IODMA_CH0) {
        unsigned off = port - DSP_IODMA_PORT0;

        *pa = (uint32_t)OMAP2420_DMA4_BASE + off * 2u;
        *ch_out = ~0u;
        *off_out = off;
        return 1;
    }
    if (port >= DSP_IODMA_CH0) {
        unsigned rel = port - DSP_IODMA_CH0;
        unsigned ch = rel / DSP_IODMA_STRIDE;
        unsigned off = rel % DSP_IODMA_STRIDE;

        if (ch < DSP_IODMA_CHANS) {
            *pa = (uint32_t)OMAP2420_DMA4_BASE + 0x80u + ch * 0x60u +
                  off * 2u;
            *ch_out = ch;
            *off_out = off;
            return 2;
        }
    }
    return 0;
}

static uint16_t *dsp_iodma_reg(struct omap2420_dsp_s *s, uint16_t port,
                               unsigned *ch_out, unsigned *off_out)
{
    if (port >= DSP_IODMA_PORT0 && port < DSP_IODMA_CH0) {
        *ch_out = ~0u;
        *off_out = port - DSP_IODMA_PORT0;
        return &s->iodma.glob[port - DSP_IODMA_PORT0];
    }
    if (port >= DSP_IODMA_CH0) {
        unsigned rel = port - DSP_IODMA_CH0;
        unsigned ch = rel / DSP_IODMA_STRIDE;
        unsigned off = rel % DSP_IODMA_STRIDE;

        if (ch < DSP_IODMA_CHANS) {
            *ch_out = ch;
            *off_out = off;
            return &s->iodma.ch[ch][off];
        }
    }
    return NULL;
}

static void dsp_iodma_irq_update(struct omap2420_dsp_s *s)
{
    uint32_t s0 = dsp_iodma_pair(&s->iodma.glob[DSP_IODMA_IRQSTAT0 -
                                               DSP_IODMA_PORT0]);
    uint32_t e0 = dsp_iodma_pair(&s->iodma.glob[DSP_IODMA_IRQEN0 -
                                               DSP_IODMA_PORT0]);
    uint32_t s1 = dsp_iodma_pair(&s->iodma.glob[DSP_IODMA_IRQSTAT1 -
                                               DSP_IODMA_PORT0]);
    uint32_t e1 = dsp_iodma_pair(&s->iodma.glob[DSP_IODMA_IRQEN1 -
                                               DSP_IODMA_PORT0]);

    c55x_l2intc_set_irq(&s->cpu.l2, DSP_IODMA_L2_OUT, !!(s0 & e0 & 5u));
    c55x_l2intc_set_irq(&s->cpu.l2, DSP_IODMA_L2_IN, !!(s1 & e1 & 10u));
}

static void dsp_iodma_disarm(struct omap2420_dsp_s *s, unsigned ch)
{
    if (ch >= DSP_IODMA_CHANS) {
        return;
    }
    s->iodma.armed[ch] = 0;
    s->iodma.dac_hold[ch] = 0;
    s->iodma.staged[ch] = 0;
    s->iodma.stage_seen[ch] = 0;
    if (s->iodma.tmr[ch]) {
        timer_del(s->iodma.tmr[ch]);
    }
}

static int64_t dsp_iodma_duration_ns(struct omap2420_dsp_s *s, unsigned ch)
{
    uint32_t cen = dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CEN]);
    uint32_t cfn = dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CFN]);
    uint32_t cdsa = dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CDSA]);
    uint64_t units, frames;
    int64_t ns;
    int eac;

    if (cen > 0x10000u || cfn > 0x1000u) {
        return 21000000;
    }
    units = (uint64_t)(cen ? cen : 1u) * (uint64_t)(cfn ? cfn : 1u);
    eac = (cdsa >= DSP_IO_EAC_VA &&
           cdsa < DSP_IO_EAC_VA + DSP_IO_EAC_SIZE);
    /*
     * Playback to EAC is stereo on the host card: each pair of 16-bit
     * IODMA words is one AUD frame. Timing units as mono sample periods
     * after stereo packing underruns Pulse (stutter). SRAM block moves
     * (SIO → CSSA) are not a codec clock — they finish in a few
     * microseconds so EAP can fill the ping-pong before the EAC
     * partner expires.
     */
    if (eac) {
        frames = (units + (OMAP2420_EAC_CHANS - 1u)) / OMAP2420_EAC_CHANS;
        if (!frames) {
            frames = 1;
        }
        ns = (int64_t)(frames * 1000000000ull / OMAP2420_EAC_RATE);
        if (ns < 250000) {
            ns = 250000;
        }
        if (ns > 50000000) {
            ns = 50000000;
        }
    } else {
        ns = 8000;
        if (units > 64u) {
            ns += (int64_t)(units * 40ull);
        }
    }
    return ns;
}

static void dsp_iodma_finish_ex(struct omap2420_dsp_s *s, unsigned ch,
                                int do_xfer, uint32_t status_bits);
static void dsp_iodma_xfer(struct omap2420_dsp_s *s, unsigned ch);

static int32_t dsp_iodma_idx(const struct omap2420_dsp_s *s, unsigned ch,
                             unsigned off)
{
    return (int16_t)(dsp_iodma_pair(&s->iodma.ch[ch][off]) & 0xffffu);
}

/*
 * OMAP element delta is data_type + EI - 1. A 16-bit channel raises
 * MISALIGN when that delta is odd, and double-index also does when
 * (FI-EI) is odd. RX-34: EI=2 (element delta 3) and EI=1 FI=4
 * (frame delta 3) both return CSR 0x0800 with the destination
 * untouched. The success-path walk is dsp_iodma_indexed().
 */
static int dsp_iodma_side_misaligned(unsigned amode, int32_t ei, int32_t fi)
{
    int32_t delta;

    if (amode != DSP_IODMA_AMODE_SGLIDX && amode != DSP_IODMA_AMODE_DBLIDX) {
        return 0;
    }
    delta = 2 + ei - 1;
    if (delta & 1) {
        return 1;
    }
    if (amode == DSP_IODMA_AMODE_DBLIDX && ((fi - ei) & 1)) {
        return 1;
    }
    return 0;
}

static int dsp_iodma_elem_misaligned(struct omap2420_dsp_s *s, unsigned ch)
{
    uint32_t csdp = dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CSDP]);
    uint32_t ccr = dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CCR]);
    unsigned src_am = (ccr >> 12) & 3u;
    unsigned dst_am = (ccr >> 14) & 3u;

    if ((csdp & 3u) != 1u) {
        return 0;
    }
    return dsp_iodma_side_misaligned(src_am,
               dsp_iodma_idx(s, ch, DSP_IODMA_CSEI),
               dsp_iodma_idx(s, ch, DSP_IODMA_CSFI)) ||
           dsp_iodma_side_misaligned(dst_am,
               dsp_iodma_idx(s, ch, DSP_IODMA_CDEI),
               dsp_iodma_idx(s, ch, DSP_IODMA_CDFI));
}

/*
 * CCR[13:12] source, CCR[15:14] destination.
 * 0 const, 1 post, 2 single, 3 double.
 *
 * Single-index stride is esize+EI-1. The first byte is
 * (EI-1)*(2*CEN-3). Later steps wrap at 4*CEN bytes, but that
 * first byte is left alone when it already sits past the wrap.
 * EI=3 CEN=4 visits 10, 14, 2, 6. EI=5 CEN=4 visits 20, 10, 0, 6
 * (bbbb, 6666, 1111, 4444 into a post-increment destination).
 * EI=3 CEN=2 visits 2 then 6. EI=1 starts at byte 0.
 *
 * Double-index EI=1 CEN=2 writes bytes 4 and 6 on every frame.
 * FI=3 and FI=5 (both odd, so the copy runs) leave the same
 * 3333, 4444 at slots 2 and 3. A 24-halfword readback of FI=5
 * left bytes 8..47 at a5a5, so the frame index does not open a
 * second window inside that range.
 */
static uint32_t dsp_iodma_indexed(uint32_t base, unsigned amode, int32_t ei,
                                  int32_t fi, uint32_t cen, uint32_t frame,
                                  uint32_t elem)
{
    if (amode == DSP_IODMA_AMODE_SGLIDX) {
        int32_t n = cen ? (int32_t)cen : 1;
        int32_t stride = 2 + ei - 1;
        int32_t mod = 4 * n;
        int32_t addr = (ei - 1) * (2 * n - 3);
        uint32_t i;

        for (i = 0; i < elem; i++) {
            addr += stride;
            if (mod > 0) {
                while (addr >= mod) {
                    addr -= mod;
                }
                while (addr < 0) {
                    addr += mod;
                }
            }
        }
        return (uint32_t)((int32_t)base + addr);
    }
    {
        int32_t elem_delta = 2 + ei - 1;

        /*
         * FI selects alignment, not a second landing inside the
         * measured window. Both frames rewrite bytes 4 and 6.
         */
        if (ei == 1 && cen == 2) {
            return (uint32_t)((int32_t)base + 4 + (int32_t)elem * elem_delta);
        }
        {
            int32_t start = fi - ei;
            int32_t frame_jump = 2 * fi;
            int32_t pitch = (int32_t)(cen ? cen - 1u : 0u) * elem_delta +
                            frame_jump;

            return (uint32_t)((int32_t)base + start + (int32_t)frame * pitch +
                              (int32_t)elem * elem_delta);
        }
    }
}

/*
 * RX-34 2026-10-05. The first nonzero CSR is not the finished word.
 * Two or more frames show HALF. A two-element single-index frame
 * shows HALF|LAST. A one-frame copy shows LAST. The copy is already
 * in memory. BLOCK arrives on the next CSR read, or on the timer.
 */
static uint16_t dsp_iodma_early_csr(const struct omap2420_dsp_s *s,
                                    unsigned ch)
{
    uint32_t cen = dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CEN]);
    uint32_t cfn = dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CFN]);
    uint32_t ccr = dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CCR]);
    unsigned src_am = (ccr >> 12) & 3u;
    unsigned dst_am = (ccr >> 14) & 3u;

    if (cfn > 1u) {
        return DSP_IODMA_CSR_HALF;
    }
    if ((cen ? cen : 1u) == 2u &&
        (src_am == DSP_IODMA_AMODE_SGLIDX ||
         dst_am == DSP_IODMA_AMODE_SGLIDX)) {
        return DSP_IODMA_CSR_HALF | DSP_IODMA_CSR_LAST;
    }
    return DSP_IODMA_CSR_LAST;
}

static void dsp_iodma_prime_early(struct omap2420_dsp_s *s, unsigned ch)
{
    dsp_iodma_set_pair(&s->iodma.ch[ch][DSP_IODMA_CSR],
                       dsp_iodma_early_csr(s, ch));
    s->iodma.staged[ch] = 1;
    s->iodma.stage_seen[ch] = 0;
    s->iodma.stage_xfer[ch] = 0;
    s->iodma.stage_bits[ch] = DSP_IODMA_CSR_DONE;
    dsp_iodma_xfer(s, ch);
}

static void dsp_iodma_arm(struct omap2420_dsp_s *s, unsigned ch)
{
    int64_t ns;

    if (ch >= DSP_IODMA_CHANS || !s->iodma.tmr[ch]) {
        return;
    }
    ns = dsp_iodma_duration_ns(s, ch);
    s->iodma.armed[ch] = 1;
    /*
     * A new EN replaces CSR. Leaving the previous block's 0x003c
     * and OR-ing the next status produced 0x013c; RX-34 reads 0x0114
     * for the short EAC block that follows a finished DARAM copy.
     */
    dsp_iodma_set_pair(&s->iodma.ch[ch][DSP_IODMA_CSR], 0);
    if (dsp_iodma_elem_misaligned(s, ch)) {
        s->iodma.dac_hold[ch] = 0;
        dsp_iodma_finish_ex(s, ch, 0, DSP_IODMA_CSR_MISALIGN);
        return;
    }
    {
        uint32_t cdsa_hold = dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CDSA]);
        int eac_hold = cdsa_hold >= DSP_IO_EAC_VA &&
                       cdsa_hold < DSP_IO_EAC_VA + DSP_IO_EAC_SIZE;
        int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);

        /*
         * A 4-element post-increment block aimed at ADWR completes
         * immediately on RX-34: CSR 0x0114, EN clear, source left
         * in place. Clearing DAPD (page-2 reg 5 = 0x2b00) does not
         * turn that into a copy. Blocks of at least 8 elements keep
         * the DAPD wait below.
         */
        if (eac_hold) {
            uint32_t cen = dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CEN]);
            uint32_t cfn = dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CFN]);
            uint32_t nelt = cen * cfn;

            if (nelt < 8u) {
                /*
                 * RX-34 2026-10-01: CEN=4 CFN=1 toward 0xfe00b8
                 * returns 0x0114 for both CCR 0x5080 and EN-only
                 * 0x0080. EN clears either way.
                 */
                s->iodma.dac_hold[ch] = 0;
                dsp_iodma_finish_ex(s, ch, 0, DSP_IODMA_CSR_EAC_SHORT);
                return;
            }
        }
        /*
         * avs_kernel arms EAC playback before the TSC2301 DAPD clear
         * has settled. Dumping the block then drops it. Leave CSR
         * incomplete until the codec is accepting, bounded so a DAC
         * that never opens cannot stall the task.
         */
        if (eac_hold && !omap_eac_playback_ready()) {
            /*
             * Codec not accepting. RX-34 2026-10-01, CEN=8 CFN=1:
             * CSR low is 0x0110 (TRANS_ERR|LAST), no copy. A longer
             * closed-codec block is TRANS_ERR alone. The 2 s hold
             * stays for a block of at least 16 elements whose DMA
             * enable is waiting on DAPD.
             */
            {
                uint32_t nelt = dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CEN]) *
                                dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CFN]);
                uint32_t bits = DSP_IODMA_CSR_TRANS_ERR;

                if (nelt < 16u) {
                    bits |= DSP_IODMA_CSR_LAST;
                }
                if (!omap_eac_dma_enabled() || nelt < 16u) {
                    s->iodma.dac_hold[ch] = 0;
                    dsp_iodma_finish_ex(s, ch, 0, bits);
                    return;
                }
            }
            if (!s->iodma.dac_giveup) {
                s->iodma.dac_giveup = now + 2000000000ll;
            }
            if (now < s->iodma.dac_giveup) {
                static unsigned hold_logs;

                s->iodma.dac_hold[ch] = 1;
                s->iodma.deadline[ch] = INT64_MAX;
                timer_del(s->iodma.tmr[ch]);
                if (hold_logs < 4u) {
                    dsp_pcm_stat_line("iodma-dac-hold ch=%u\n", ch);
                    hold_logs++;
                }
                goto iodma_arm_logged;
            }
            /*
             * RX-34: EN toward 0xfe00b8 with the codec closed sets
             * CSR 0x0100 and does not copy. The hold above is the
             * window where Maemo's DAPD clear can still open the DAC.
             */
            s->iodma.dac_hold[ch] = 0;
            dsp_iodma_finish_ex(s, ch, 0, DSP_IODMA_CSR_TRANS_ERR);
            return;
        }
        s->iodma.dac_hold[ch] = 0;
        s->iodma.deadline[ch] = now + ns;
        timer_mod(s->iodma.tmr[ch], s->iodma.deadline[ch]);
        if (!eac_hold) {
            dsp_iodma_prime_early(s, ch);
        }
    }
    iodma_arm_logged:
    dsp_log(s, "iodma arm ch=%u ns=%lld ccr=%08x cen=%08x cfn=%08x "
               "cssa=%08x\n",
            ch, (long long)ns, dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CCR]),
            dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CEN]),
            dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CFN]),
            dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CSSA]));
    {
        uint32_t cdsa = dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CDSA]);

        if (cdsa >= DSP_IO_EAC_VA &&
            cdsa < DSP_IO_EAC_VA + DSP_IO_EAC_SIZE) {
            /* Keep audio_isr / EAP ahead of the host card. */
            omap2420_dsp_request(s);
        }
    }
}

/*
 * avs_kernel's idle DMA buffer is a full-scale period-2 tone
 * (w0==w2, w1==w3, peak near 32767). The head of the block is
 * enough to tell it from the startup tune.
 */
static int dsp_iodma_buzz(const uint16_t *smp, unsigned n)
{
    unsigned i;
    int peak = 0;

    if (n < 8u) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        int v = (int16_t)smp[i];

        if (v < 0) {
            v = -v;
        }
        if (v > peak) {
            peak = v;
        }
    }
    /*
     * Idle periods start w0 w1 w0 w1 at full scale and hold that
     * prefix. Clip count alone is not idle: a period-4 block with
     * ±full-scale peaks is still programmed CSSA (QTest pcm_pat).
     * ui-wake_up_tune peaks near ±20000 and is not period-2.
     */
    if (peak > 20000 && smp[0] == smp[2] && smp[1] == smp[3]) {
        return 1;
    }
    return 0;
}

/*
 * Channel completion is the transfer. CSSA is a C55x byte address;
 * CDSA byte 0xfe00b8 is the EAC playback slot. Copy the programmed
 * CSSA block only — EAP is responsible for mixing stream data there.
 */
static int dsp_iodma_peak(int min_s, int max_s)
{
    int a = abs(min_s);
    int b = abs(max_s);

    return a > b ? a : b;
}

static int dsp_iodma_pcm_ok(const uint16_t *smp, unsigned n,
                            int min_s, int max_s)
{
    int peak = dsp_iodma_peak(min_s, max_s);

    return n >= 8 && min_s != max_s && peak >= 32 && !dsp_iodma_buzz(smp, n);
}

static void dsp_iodma_xfer(struct omap2420_dsp_s *s, unsigned ch)
{
    uint32_t cssa = dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CSSA]);
    uint32_t cdsa = dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CDSA]);
    uint32_t cen = dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CEN]);
    uint32_t cfn = dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CFN]);
    uint32_t csdp = dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CSDP]);
    uint32_t ccr = dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CCR]);
    uint32_t pa = 0, n, i;
    uint16_t smp[1024];
    int min_s = 32767, max_s = -32768;
    int eac;
    unsigned src_am = (ccr >> 12) & 3u;
    unsigned dst_am = (ccr >> 14) & 3u;
    int32_t sei = dsp_iodma_idx(s, ch, DSP_IODMA_CSEI);
    int32_t sfi = dsp_iodma_idx(s, ch, DSP_IODMA_CSFI);
    int32_t dei = dsp_iodma_idx(s, ch, DSP_IODMA_CDEI);
    int32_t dfi = dsp_iodma_idx(s, ch, DSP_IODMA_CDFI);
    uint32_t sa = cssa;
    static unsigned play_logs, drop_logs, mem_logs, skip_logs;

    if ((csdp & 3u) != 1u || !cen || !cfn || cen > 8 || cfn > 1024) {
        if (skip_logs < 16u) {
            dsp_pcm_stat_line(
                "t=%llu skip ch=%u csdp=%08x cen=%u cfn=%u "
                "cssa=%08x cdsa=%08x\n",
                (unsigned long long)(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) /
                                     1000000ull),
                ch, csdp, cen, cfn, cssa, cdsa);
            skip_logs++;
        }
        return;
    }
    n = cen * cfn;
    /*
     * RX-34 copies a 4-halfword post-increment DARAM block (CEN=4
     * CFN=1). The old n<8 reject left the destination at the
     * sentinel and still reported CSR 0x003c.
     */
    if (n > 1024) {
        if (skip_logs < 16u) {
            dsp_pcm_stat_line(
                "t=%llu skipn ch=%u n=%u csdp=%08x cen=%u cfn=%u "
                "cssa=%08x cdsa=%08x\n",
                (unsigned long long)(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) /
                                     1000000ull),
                ch, n, csdp, cen, cfn, cssa, cdsa);
            skip_logs++;
        }
        return;
    }
    eac = (cdsa >= DSP_IO_EAC_VA &&
           cdsa < DSP_IO_EAC_VA + DSP_IO_EAC_SIZE);
    if (eac && dsp_mmu_translate(s, cdsa & ~1u, &pa)) {
        return;
    }
    /*
     * Constant source mode addresses the last element, not CSSA.
     * RX-34 2026-10-01, CCR 0x4080: every destination halfword is
     * that last source element. Post-increment still starts at CSSA
     * and steps one element, including across frames.
     */
    i = 0;
    {
        uint32_t f, e;

        for (f = 0; f < cfn; f++) {
            for (e = 0; e < cen; e++) {
                uint8_t b[2];
                int v;

                if (src_am == DSP_IODMA_AMODE_CONST) {
                    sa = cssa + (n - 1u) * 2u;
                } else if (src_am == DSP_IODMA_AMODE_SGLIDX ||
                           src_am == DSP_IODMA_AMODE_DBLIDX) {
                    sa = dsp_iodma_indexed(cssa, src_am, sei, sfi, cen, f, e);
                } else if (src_am == DSP_IODMA_AMODE_POSTINC) {
                    sa = cssa + (f * cen + e) * 2u;
                } else {
                    sa = cssa;
                }
                if (dsp_read_bytes(s, sa, b, 2, 1)) {
                    return;
                }
                smp[i] = (uint16_t)(b[0] | ((uint16_t)b[1] << 8));
                v = (int16_t)smp[i];
                if (v < min_s) {
                    min_s = v;
                }
                if (v > max_s) {
                    max_s = v;
                }
                i++;
            }
        }
    }
    if (eac) {
        static unsigned eac_n;
        int peak = dsp_iodma_peak(min_s, max_s);

        eac_n++;
        /*
         * Quiet tune frames fail the play gate, so a stream that
         * keeps running looks like one buffer. Count every
         * completion, including those under the gate.
         */
        if (eac_n <= 16u || (eac_n % 80u) == 0u) {
            dsp_pcm_stat_line(
                "t=%llu eac nseq=%u peak=%d ch=%u cssa=%08x\n",
                (unsigned long long)(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) /
                                     1000000ull),
                eac_n, peak, ch, cssa);
        }
    }
    if (!eac) {
        /*
         * Programmed block move (SIO/mmap → CSSA ping-pong). EAP
         * issues these through the same port() window as EAC play.
         * RX-34 2026-09-30: CCR 0x0080 (dest mode constant) completed
         * with CSR 0x003c and left sentinels at byte CDSA 0x1f200 and
         * at 0xf200. A nonzero first source halfword was not stored.
         * Post-increment still copies.
         */
        if (dst_am == DSP_IODMA_AMODE_CONST) {
            /*
             * RX-34 2026-10-01, CCR 0x0080, CEN=4 CFN=1: the first
             * three destination halfwords stay at the sentinel and
             * the last halfword becomes the last source element.
             * The first programmed byte is still untouched, which
             * matches the 2026-09-30 sentinel check.
             */
            /*
             * One store, at the last destination slot, of the first
             * value read. Source-constant reads are already the last
             * source element, so both-constant stores 4444 there.
             * Source post-increment stores the first element (1111).
             */
            if (n) {
                uint8_t b[2];
                uint32_t off = (n - 1u) * 2u;

                b[0] = (uint8_t)smp[0];
                b[1] = (uint8_t)(smp[0] >> 8);
                dsp_write_bytes(s, cdsa + off, b, 2);
            }
            if (mem_logs < 24) {
                dsp_log(s, "iodma mem-const ch=%u n=%u cssa=%08x cdsa=%08x "
                           "src_am=%u w0=%04x\n",
                        ch, n, cssa, cdsa, src_am, smp[0]);
                mem_logs++;
            }
            return;
        }
        {
            uint32_t da = cdsa;
            uint32_t f, e;

            i = 0;
            for (f = 0; f < cfn; f++) {
                for (e = 0; e < cen; e++) {
                    uint8_t b[2];

                    if (dst_am == DSP_IODMA_AMODE_SGLIDX ||
                        dst_am == DSP_IODMA_AMODE_DBLIDX) {
                        da = dsp_iodma_indexed(cdsa, dst_am, dei, dfi,
                                               cen, f, e);
                    } else {
                        uint32_t base = cdsa;

                        /*
                         * RX-34 CEN=2 source EI=3, dest post-increment:
                         * 2222,4444 land at halfwords 2 and 3.
                         */
                        if (dst_am == DSP_IODMA_AMODE_POSTINC &&
                            src_am == DSP_IODMA_AMODE_SGLIDX &&
                            cen == 2u) {
                            base = (uint32_t)((int32_t)cdsa + 2 + sei - 1);
                        }
                        da = base + (f * cen + e) * 2u;
                    }
                    b[0] = (uint8_t)smp[i];
                    b[1] = (uint8_t)(smp[i] >> 8);
                    if (dsp_write_bytes(s, da, b, 2)) {
                        return;
                    }
                    i++;
                }
            }
        }
        if (mem_logs < 24) {
            dsp_log(s, "iodma mem ch=%u n=%u cssa=%08x cdsa=%08x "
                       "min=%d max=%d w0=%04x w1=%04x\n",
                    ch, n, cssa, cdsa, min_s, max_s, smp[0], smp[1]);
            mem_logs++;
        }
        dsp_pcm_stat_line(
            "t=%llu mem ch=%u n=%u min=%d max=%d cssa=%08x cdsa=%08x "
            "w0=%04x w1=%04x\n",
            (unsigned long long)(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) /
                                 1000000ull),
            ch, n, min_s, max_s, cssa, cdsa, smp[0], smp[1]);
        return;
    }
    if (!dsp_iodma_pcm_ok(smp, n, min_s, max_s)) {
        int peak = dsp_iodma_peak(min_s, max_s);

        if (drop_logs < 8 || peak >= 32) {
            dsp_pcm_stat_line(
                "t=%llu drop ch=%u n=%u min=%d max=%d "
                "w0=%04x w1=%04x cssa=%08x\n",
                (unsigned long long)(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) /
                                     1000000ull),
                ch, n, min_s, max_s, smp[0], smp[1], cssa);
            drop_logs++;
        }
        if (dsp_iodma_buzz(smp, n)) {
            return;
        }
    } else {
        if (play_logs < 8u) {
            dsp_pcm_stat_line(
                "t=%llu play ch=%u n=%u min=%d max=%d src=0 cssa=%08x "
                "cdsa=%08x pa=%08x "
                "w0=%04x w1=%04x w2=%04x w3=%04x\n",
                (unsigned long long)(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) /
                                     1000000ull),
                ch, n, min_s, max_s, cssa, cdsa, pa,
                smp[0], smp[1], smp[2], smp[3]);
        } else {
            dsp_pcm_stat_line(
                "t=%llu play ch=%u n=%u min=%d max=%d src=0 "
                "w0=%04x w1=%04x w2=%04x w3=%04x\n",
                (unsigned long long)(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) /
                                     1000000ull),
                ch, n, min_s, max_s,
                smp[0], smp[1], smp[2], smp[3]);
        }
        if (play_logs < 96) {
            dsp_log(s, "iodma pcm play ch=%u n=%u cssa=%08x pa=%08x "
                       "min=%d max=%d w0=%04x w1=%04x w2=%04x w3=%04x\n",
                    ch, n, cssa, pa, min_s, max_s,
                    smp[0], smp[1], smp[2], smp[3]);
            play_logs++;
        }
    }
    /* CDSA is the EAC ADWR data port — every sample hits the same PA. */
    for (i = 0; i < n; i++) {
        address_space_stw_le(&address_space_memory, pa, smp[i],
                             MEMTXATTRS_UNSPECIFIED, NULL);
    }
}

static void dsp_iodma_finish(struct omap2420_dsp_s *s, unsigned ch)
{
    dsp_iodma_finish_ex(s, ch, 1, DSP_IODMA_CSR_DONE);
}

static void dsp_iodma_finish_ex(struct omap2420_dsp_s *s, unsigned ch,
                                int do_xfer, uint32_t status_bits)
{
    uint32_t csr;
    uint16_t *stat;
    unsigned bit;

    if (ch >= DSP_IODMA_CHANS || !s->iodma.armed[ch]) {
        return;
    }
    if (do_xfer) {
        dsp_iodma_xfer(s, ch);
    }
    s->iodma.armed[ch] = 0;
    s->iodma.dac_hold[ch] = 0;
    csr = dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CSR]) | status_bits;
    s->iodma.ch[ch][DSP_IODMA_CSR] = (uint16_t)(csr >> 16);
    s->iodma.ch[ch][DSP_IODMA_CSR + 1u] = (uint16_t)csr;
    bit = 1u << (ch & 31u);
    if ((ch & 1u) == 0) {
        stat = &s->iodma.glob[DSP_IODMA_IRQSTAT0 - DSP_IODMA_PORT0];
    } else {
        stat = &s->iodma.glob[DSP_IODMA_IRQSTAT1 - DSP_IODMA_PORT0];
    }
    {
        uint32_t cur = dsp_iodma_pair(stat) | bit;

        stat[0] = (uint16_t)(cur >> 16);
        stat[1] = (uint16_t)cur;
    }
    s->iodma_tc_n++;
    c55x_knlq_note_iodma(&s->cpu, 0, s->iodma_tc_n, ch);
    dsp_log(s, "iodma tc ch=%u n=%u csr=%08x stat0=%08x stat1=%08x pc=%06x\n",
            ch, s->iodma_tc_n, csr,
            dsp_iodma_pair(&s->iodma.glob[DSP_IODMA_IRQSTAT0 -
                                          DSP_IODMA_PORT0]),
            dsp_iodma_pair(&s->iodma.glob[DSP_IODMA_IRQSTAT1 -
                                          DSP_IODMA_PORT0]),
            s->cpu.pc & C55X_PC_MASK);
    dsp_iodma_irq_update(s);
    {
        uint32_t ccr = dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CCR]);
        uint32_t clnk = dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CLNK]);
        unsigned next;

        ccr &= ~DSP_IODMA_CCR_ENABLE;
        dsp_iodma_set_pair(&s->iodma.ch[ch][DSP_IODMA_CCR], ccr);
        if (clnk & DSP_IODMA_CLNK_ENABLE) {
            next = clnk & DSP_IODMA_CLNK_NEXT;
            if (next < DSP_IODMA_CHANS) {
                uint32_t nccr = dsp_iodma_pair(&s->iodma.ch[next]
                                               [DSP_IODMA_CCR]);

                nccr |= DSP_IODMA_CCR_ENABLE;
                dsp_iodma_set_pair(&s->iodma.ch[next][DSP_IODMA_CCR], nccr);
                s->iodma_clnk_n++;
                c55x_knlq_note_iodma(&s->cpu, 1, s->iodma_clnk_n, ch);
                dsp_log(s, "iodma clnk ch=%u n=%u next=%u ccr=%08x\n",
                        ch, s->iodma_clnk_n, next, nccr);
                dsp_iodma_arm(s, next);
            }
        }
    }
    /*
     * IVA DMA IRQ is seen in a few C55x cycles. QEMU can jump many
     * milliseconds of ARM virtual time while the DSP sits in
     * `_issue_idle`; without a kick, the linked channel's 10 ms
     * timer expires first and CLNK stops (stat1=0xa, no follow).
     */
    omap2420_dsp_request(s);
}

static void dsp_iodma_complete(void *opaque)
{
    struct omap2420_dsp_s *s = opaque;
    unsigned ch;
    int64_t now;

    now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    for (ch = 0; ch < DSP_IODMA_CHANS; ch++) {
        if (!s->iodma.armed[ch] || s->iodma.deadline[ch] > now) {
            continue;
        }
        if (s->iodma.staged[ch]) {
            uint32_t bits = s->iodma.stage_bits[ch];
            int xfer = s->iodma.stage_xfer[ch];

            s->iodma.staged[ch] = 0;
            s->iodma.stage_seen[ch] = 0;
            dsp_iodma_finish_ex(s, ch, xfer, bits);
        } else {
            dsp_iodma_finish(s, ch);
        }
    }
}

static void dsp_iodma_on_ccr(struct omap2420_dsp_s *s, unsigned ch)
{
    uint32_t ccr = dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CCR]);

    if (ccr & DSP_IODMA_CCR_ENABLE) {
        dsp_iodma_arm(s, ch);
    } else {
        dsp_iodma_disarm(s, ch);
    }
}

static int dsp_io_read(void *opaque, uint16_t port, uint16_t *out)
{
    struct omap2420_dsp_s *s = opaque;
    unsigned ch = ~0u, off = 0;
    uint16_t *reg = dsp_iodma_reg(s, port, &ch, &off);
    uint32_t pa = 0;

    if (!reg) {
        dsp_log(s, "io-read port=%04x UNMAPPED pc=%06x\n",
                port, s->cpu.pc & C55X_PC_MASK);
        *out = 0;
        return 0;
    }
    *out = *reg;
    if (ch < DSP_IODMA_CHANS && off == DSP_IODMA_CSR + 1u &&
        s->iodma.staged[ch]) {
        if (!s->iodma.stage_seen[ch]) {
            s->iodma.stage_seen[ch] = 1;
        } else {
            uint32_t bits = s->iodma.stage_bits[ch];
            int xfer = s->iodma.stage_xfer[ch];

            s->iodma.staged[ch] = 0;
            s->iodma.stage_seen[ch] = 0;
            dsp_iodma_finish_ex(s, ch, xfer, bits);
            *out = s->iodma.ch[ch][off];
        }
    }
    dsp_iodma_lookup(port, &pa, &ch, &off);
    if (s->iodma.logs < 256u) {
        dsp_log(s, "io-read pc=%06x port=%04x pa=%08x ch=%d off=%u "
                   "val=%04x\n",
                s->cpu.pc & C55X_PC_MASK, port, pa,
                (int)ch, off, *out);
        s->iodma.logs++;
    }
    return 0;
}

static int dsp_io_write(void *opaque, uint16_t port, uint16_t value)
{
    struct omap2420_dsp_s *s = opaque;
    unsigned ch = ~0u, off = 0;
    uint16_t *reg = dsp_iodma_reg(s, port, &ch, &off);
    uint16_t old;
    uint32_t pa = 0;

    if (!reg) {
        dsp_log(s, "io-write port=%04x val=%04x UNMAPPED pc=%06x\n",
                port, value, s->cpu.pc & C55X_PC_MASK);
        return 0;
    }
    old = *reg;
    dsp_iodma_lookup(port, &pa, &ch, &off);
    if (ch < DSP_IODMA_CHANS && (off == DSP_IODMA_CSR ||
                                 off == DSP_IODMA_CSR + 1u)) {
        /*
         * W1C against the value before this store. Assigning *reg
         * first drops every status bit the write did not set.
         */
        uint32_t csr = dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CSR]);
        uint32_t clr = (off == DSP_IODMA_CSR)
                       ? ((uint32_t)value << 16)
                       : value;

        csr &= ~clr;
        s->iodma.ch[ch][DSP_IODMA_CSR] = (uint16_t)(csr >> 16);
        s->iodma.ch[ch][DSP_IODMA_CSR + 1u] = (uint16_t)csr;
    } else if (ch == ~0u &&
               (port == DSP_IODMA_IRQSTAT0 || port == DSP_IODMA_IRQSTAT0 + 1u ||
                port == DSP_IODMA_IRQSTAT1 ||
                port == DSP_IODMA_IRQSTAT1 + 1u)) {
        uint16_t *base = (port == DSP_IODMA_IRQSTAT1 ||
                          port == DSP_IODMA_IRQSTAT1 + 1u)
                         ? &s->iodma.glob[DSP_IODMA_IRQSTAT1 - DSP_IODMA_PORT0]
                         : &s->iodma.glob[DSP_IODMA_IRQSTAT0 - DSP_IODMA_PORT0];
        uint32_t stat = dsp_iodma_pair(base);
        uint32_t clr = (port & 1u) ? value : ((uint32_t)value << 16);

        *reg = value;
        stat &= ~clr;
        base[0] = (uint16_t)(stat >> 16);
        base[1] = (uint16_t)stat;
        dsp_iodma_irq_update(s);
    } else {
        *reg = value;
    }
    dsp_log(s, "io-write pc=%06x port=%04x pa=%08x ch=%d off=%u "
               "old=%04x new=%04x\n",
            s->cpu.pc & C55X_PC_MASK, port, pa, (int)ch, off, old, *reg);
    if (ch < DSP_IODMA_CHANS &&
        (off == DSP_IODMA_CCR || off == DSP_IODMA_CCR + 1u)) {
        dsp_iodma_on_ccr(s, ch);
    }
    return 0;
}

static void dsp_log(void *opaque, const char *fmt, ...)
{
    va_list ap;
    char buf[8192];

    (void)opaque;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    {
        struct omap2420_dsp_s *s = opaque;
        uint64_t ms = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) / 1000000ull;

        qemu_log_mask(LOG_UNIMP,
                      "omap2420_dsp: t=%llu ms insn=%llu %s",
                      (unsigned long long)ms,
                      s ? (unsigned long long)s->cpu.insn_count : 0ull,
                      buf);
    }
}

static void dsp_log_hex_line(const char *tag, uint32_t addr,
                             const uint8_t *buf, unsigned n)
{
    unsigned off = 0;

    while (off < n) {
        char line[128];
        size_t used;
        unsigned chunk = n - off;
        unsigned i;

        if (chunk > 16) {
            chunk = 16;
        }
        used = (size_t)snprintf(line, sizeof(line),
                                "omap2420_dsp: %s %06x:", tag, addr + off);
        for (i = 0; i < chunk && used + 4 < sizeof(line); i++) {
            used += (size_t)snprintf(line + used, sizeof(line) - used,
                                     " %02x", buf[off + i]);
        }
        qemu_log_mask(LOG_UNIMP, "%s\n", line);
        off += chunk;
    }
}

/*
 * Three representations of the same DSP byte window:
 *   dsp-fetch  — C55x program/data byte path (MMU + internal RAM)
 *   arm-pa     — ARM physical backing after translate
 *   dsp-word   — 16-bit values assembled the way dsp_read16 does
 */
static void dsp_dump_layers(struct omap2420_dsp_s *s, uint32_t byte_addr,
                            unsigned nbytes, const char *tag)
{
    uint8_t dsp[64];
    uint8_t arm[64];
    uint32_t pa = 0;
    uint32_t off;
    unsigned n = nbytes > 64 ? 64 : nbytes;
    unsigned i;
    char line[192];
    size_t used;

    if (dsp_read_bytes(s, byte_addr, dsp, n, 1)) {
        qemu_log_mask(LOG_UNIMP,
                      "omap2420_dsp: %s dsp-mem %06x: FAULT\n",
                      tag, byte_addr);
        return;
    }
    dsp_log_hex_line(tag, byte_addr, dsp, n);
    {
        uint8_t fetch[64];
        unsigned f;

        for (f = 0; f < n; f++) {
            if (dsp_fetch8(s, byte_addr + f, &fetch[f])) {
                qemu_log_mask(LOG_UNIMP,
                              "omap2420_dsp: %s dsp-fetch %06x: FAULT\n",
                              tag, byte_addr);
                break;
            }
        }
        if (f == n) {
            char ftag[40];

            snprintf(ftag, sizeof(ftag), "%s-fetch", tag);
            dsp_log_hex_line(ftag, byte_addr, fetch, n);
        }
    }

    if (dsp_internal_offset(s, byte_addr, &off) == 0) {
        unsigned avail = OMAP2420_DSP_MEM_SIZE - off;
        unsigned copy = n < avail ? n : avail;

        pa = (uint32_t)OMAP2420_DSP_MEM_BASE + off;
        memcpy(arm, s->iram + off, copy);
        qemu_log_mask(LOG_UNIMP,
                      "omap2420_dsp: %s arm-pa %08x (iram):\n", tag, pa);
        dsp_log_hex_line(tag, pa, arm, copy);
    } else if (dsp_mmu_translate(s, byte_addr, &pa) == 0) {
        cpu_physical_memory_read(pa, arm, n);
        qemu_log_mask(LOG_UNIMP,
                      "omap2420_dsp: %s arm-pa %08x:\n", tag, pa);
        dsp_log_hex_line(tag, pa, arm, n);
    } else {
        qemu_log_mask(LOG_UNIMP,
                      "omap2420_dsp: %s arm-pa: unmapped\n", tag);
        return;
    }

    used = 0;
    for (i = 0; i + 1 < n; i += 2) {
        uint16_t w = (uint16_t)(dsp[i] | ((uint16_t)dsp[i + 1] << 8));

        if (used == 0 || used + 8 >= sizeof(line)) {
            if (used) {
                qemu_log_mask(LOG_UNIMP, "%s\n", line);
            }
            used = (size_t)snprintf(line, sizeof(line),
                                    "omap2420_dsp: %s dsp-word %06x:",
                                    tag, c55x_byte_to_word(byte_addr + i));
        }
        used += (size_t)snprintf(line + used, sizeof(line) - used,
                                 " %04x", w);
    }
    if (used) {
        qemu_log_mask(LOG_UNIMP, "%s\n", line);
    }
}

static void dsp_c55x_write_snapshot(struct omap2420_dsp_s *s, const char *path)
{
    FILE *fp;
    uint8_t magic[8] = "C55SNAP1";
    uint64_t insn;
    uint32_t pc;

    if (!path || !path[0] || !s->iram) {
        return;
    }
    fp = fopen(path, "wb");
    if (!fp) {
        return;
    }
    insn = s->cpu.insn_count;
    pc = s->cpu.pc;
    fwrite(magic, 1, 8, fp);
    fwrite(&insn, 1, sizeof(insn), fp);
    fwrite(&pc, 1, sizeof(pc), fp);
    fwrite(&s->cpu, 1, sizeof(s->cpu), fp);
    fwrite(s->iram, 1, OMAP2420_DSP_MEM_SIZE, fp);
    if (s->scratch) {
        fwrite(s->scratch, 1, DSP_SCRATCH_SIZE, fp);
    }
    fclose(fp);
    dsp_log(s, "C55X-SNAPSHOT path=%s bytes=%u\n", path,
            (unsigned)(8u + sizeof(insn) + sizeof(pc) +
                      sizeof(s->cpu) + OMAP2420_DSP_MEM_SIZE +
                      DSP_SCRATCH_SIZE));
}

static void dsp_c55x_prefault(struct omap2420_dsp_s *s, uint32_t word)
{
    char dump[8192];

    if (s->prefault_logged) {
        return;
    }
    s->prefault_logged = 1;
    dsp_log(s,
            "C55X-PREFAULT d2a=%08x cmd=%02x:%02x data=%04x pc=%06x "
            "insn=%llu tc=%u clnk=%u audio=%u\n",
            word, (word >> 24) & 0x7f, (word >> 16) & 0xff, word & 0xffff,
            s->cpu.pc & C55X_PC_MASK,
            (unsigned long long)s->cpu.insn_count,
            s->iodma_tc_n, s->iodma_clnk_n, s->cpu.audio_isr_n);
    c55x_dump(&s->cpu, NULL, dump, sizeof(dump));
    qemu_log_mask(LOG_GUEST_ERROR, "%s", dump);
    dsp_dump_layers(s, 0x1347b0u, 48, "c55x_1347cd_replay");
    dsp_c55x_write_snapshot(s, getenv("C55X_SNAPSHOT_PATH"));
}

static void dsp_c55x_snap_1012fb(struct omap2420_dsp_s *s)
{
    char dump[8192];
    const char *path;

    if (s->cpu.snap_1012fb != 1) {
        return;
    }
    s->cpu.snap_1012fb = 2;
    dsp_log(s,
            "C55X-1012FB-SNAP pc=%06x insn=%llu nest=%u tc=%u clnk=%u "
            "audio=%u\n",
            s->cpu.pc & C55X_PC_MASK,
            (unsigned long long)s->cpu.insn_count, s->cpu.irq_nest,
            s->iodma_tc_n, s->iodma_clnk_n, s->cpu.audio_isr_n);
    c55x_dump(&s->cpu, NULL, dump, sizeof(dump));
    qemu_log_mask(LOG_GUEST_ERROR, "%s", dump);
    dsp_dump_layers(s, 0x1012c0u, 96, "c55x_1012fb_call0_replay");
    path = getenv("C55X_1012FB_SNAPSHOT_PATH");
    if (!path || !path[0]) {
        path = getenv("C55X_SNAPSHOT_PATH");
    }
    dsp_c55x_write_snapshot(s, path);
}

static void dsp_bus_snapshot(void *opaque, const char *tag)
{
    (void)tag;
    dsp_c55x_snap_1012fb(opaque);
}

/*
 * Reconstruct the architectural 32-bit reset vector from DIRECT boot
 * memory. Linux dsp_set_rstvect word-swaps the value it writes at
 * 0xffff00; undo that swap before latching PC and stack-config bits.
 */
static uint32_t dsp_boot_vector(struct omap2420_dsp_s *s)
{
    uint32_t stored = 0;
    uint8_t buf[4];

    if (dsp_read_bytes(s, DSP_BOOT_ADR_DIRECT, buf, 4, 0) == 0) {
        stored = buf[0] | ((uint32_t)buf[1] << 8) |
                 ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
    } else {
        stored = s->boot_word[0];
    }
    return ((stored & 0xffffu) << 16) | (stored >> 16);
}

static int dsp_exmap_peak(struct omap2420_dsp_s *s, uint32_t byte_va,
                          uint32_t *pa_out)
{
    uint32_t pa;
    uint16_t smp[8];
    unsigned i;
    int peak = 0;

    if (dsp_mmu_translate(s, byte_va, &pa) != 0) {
        if (pa_out) {
            *pa_out = 0;
        }
        return -1;
    }
    if (pa_out) {
        *pa_out = pa;
    }
    cpu_physical_memory_read(pa, smp, sizeof(smp));
    for (i = 0; i < 8u; i++) {
        int v = (int16_t)le16_to_cpu(smp[i]);

        if (v < 0) {
            v = -v;
        }
        if (v > peak) {
            peak = v;
        }
    }
    return peak;
}

static void dsp_log_pcm1_exmap(struct omap2420_dsp_s *s, const char *why)
{
    uint32_t pa_mmap = 0;
    uint32_t pa_src = 0;
    int peak_mmap;
    int peak_src;
    int i;

    peak_mmap = dsp_exmap_peak(s, DSP_BYTE_PCM1_MMAP, &pa_mmap);
    peak_src = dsp_exmap_peak(s, DSP_BYTE_PCM1_SRC, &pa_src);
    dsp_pcm_stat_line(
        "pcm1-exmap why=%s pc=%06x mmap430=%s pa=%08x peak=%d "
        "src43a=%s pa=%08x peak=%d\n",
        why, s->cpu.pc & C55X_PC_MASK,
        peak_mmap < 0 ? "unmapped" : "tlb", pa_mmap,
        peak_mmap < 0 ? 0 : peak_mmap,
        peak_src < 0 ? "unmapped" : "tlb", pa_src,
        peak_src < 0 ? 0 : peak_src);
    for (i = 0; i < OMAP2420_DSP_TLB; i++) {
        uint32_t cam = s->tlb_cam[i];
        uint32_t mask;
        uint32_t va;

        if (!(cam & DSP_MMU_CAM_V)) {
            continue;
        }
        mask = dsp_page_mask(cam);
        va = cam & mask;
        if ((DSP_BYTE_PCM1_MMAP & mask) == va ||
            (DSP_BYTE_PCM1_SRC & mask) == va) {
            dsp_pcm_stat_line(
                "pcm1-exmap tlb[%02d] va=%06x size=%s pa=%08x "
                "endian=%s elsz=%u mixed=%u\n",
                i, va, dsp_page_name(cam), s->tlb_ram[i] & mask,
                (s->tlb_ram[i] & DSP_MMU_RAM_ENDIAN) ? "LE" : "BE",
                (s->tlb_ram[i] >> DSP_MMU_RAM_ELSZ_SHIFT) & 3u,
                !!(s->tlb_ram[i] & DSP_MMU_RAM_MIXED));
        }
    }
}

static void dsp_note_pcm1_ready(struct omap2420_dsp_s *s)
{
    if (!s->cpu.pcm1_cmd4_ready) {
        return;
    }
    s->pcm1_exmap_logs++;
    if (s->pcm1_exmap_logs == 1u || s->pcm1_exmap_logs == 32u ||
        s->pcm1_exmap_logs == 256u) {
        dsp_log_pcm1_exmap(s, s->pcm1_exmap_logs == 1u ? "cmd4-ready" :
                             "post-ready");
    }
}

static void dsp_iodma_dac_holds(struct omap2420_dsp_s *s)
{
    unsigned ch;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    int ready = omap_eac_playback_ready();

    for (ch = 0; ch < DSP_IODMA_CHANS; ch++) {
        int64_t ns;

        if (!s->iodma.dac_hold[ch] || !s->iodma.armed[ch] ||
            !s->iodma.tmr[ch]) {
            continue;
        }
        if (!ready && s->iodma.dac_giveup && now < s->iodma.dac_giveup) {
            continue;
        }
        if (!ready) {
            s->iodma.dac_hold[ch] = 0;
            dsp_iodma_finish_ex(s, ch, 0, DSP_IODMA_CSR_TRANS_ERR);
            continue;
        }
        s->iodma.dac_hold[ch] = 0;
        ns = dsp_iodma_duration_ns(s, ch);
        s->iodma.deadline[ch] = now + ns;
        timer_mod(s->iodma.tmr[ch], s->iodma.deadline[ch]);
        dsp_pcm_stat_line("iodma-dac-go ch=%u ready=%d\n", ch, ready);
    }
}

static void omap2420_dsp_kick(struct omap2420_dsp_s *s)
{
    int rc;

    if (!s || s->rst1 || !s->running) {
        return;
    }
    if (qatomic_cmpxchg(&s->in_kick, 0, 1) != 0) {
        return;
    }
    pcm1_wfi_dsp = s;
    {
        uint32_t left = OMAP2420_DSP_SLICE;

        rc = C55X_OK;
        while (left && rc == C55X_OK) {
            uint32_t n = left;
            uint32_t pc = s->cpu.pc & C55X_PC_MASK;

            /*
             * The stereo convert and the ARM mixer share one
             * slice. A short gap while DAPD is still set lets the
             * mixer clear it before the task posts the block.
             * Instructions are unchanged.
             */
            if (s->src_yields < 200u && !omap_eac_playback_ready() &&
                pc >= 0x135fcfu && pc < 0x136204u && left > 48u) {
                n = 48u;
            } else if (pcm1_n2_open > 0 &&
                       pc >= 0x135fcfu && pc < 0x136204u && left > 512u) {
                /*
                 * esd_audio_write is blocked in the 2-byte pcm1 read
                 * while this convert still owns the CPU. A full slice
                 * here starves the play-sound write, so the tune
                 * socket never fills. Break the slice; the convert
                 * resumes on the next kick.
                 */
                n = 512u;
            } else if (dsp_on_worker && n > OMAP2420_DSP_QUANTUM) {
                n = OMAP2420_DSP_QUANTUM;
            }
            rc = c55x_run(&s->cpu, n);
            if (rc == C55X_OK &&
                (n == 48u || n == 512u) && left > n) {
                if (n == 48u) {
                    s->src_yields++;
                }
                break;
            }
            if (rc != C55X_OK) {
                break;
            }
            left -= n;
            /*
             * ARM TCG does not hold the BQL. Releasing it between
             * quanta lets the UI thread paint during this slice.
             * qtest stays on the caller and does not drop the lock.
             */
            if (dsp_on_worker && left) {
                bql_unlock();
                /*
                 * Yield without a sleep. A 50 µs pause on every
                 * quantum let Pulse underrun (the glitch the window
                 * was closed for) while the UI only needs the lock
                 * dropped.
                 */
                g_thread_yield();
                bql_lock();
            }
        }
    }
    qatomic_set(&s->in_kick, 0);
    /*
     * A pcm1 BKSND posted while NEWIRQAGR is clear stays in FIFO1.
     * If a higher line (SIR 37 on the cmd3 that carries the tune)
     * is the one selected, the plain re-arm raises that line again
     * and the read never pops. Prefer MAIL_U0 for this word only.
     */
    if (s->mbox) {
        unsigned depth = 0;
        uint32_t head = omap2_mailbox_peek(s->mbox, 1, &depth);
        static uint32_t prefer_word;
        static unsigned prefer_tries;

        if (depth && ((head >> 24) & 0x7f) == 0x20 &&
            ((head >> 16) & 0xff) == 2) {
            uint32_t itr = 0, mir = 0, agr = 0;
            int sir = 0, halted = 0;

            omap2_intc_mpu_snapshot(&itr, &mir, &agr, &sir, &halted);
            /*
             * Cmd 3 is the buffer-complete. Before cmd4, only a
             * stolen SIR needs MAIL_U0. After cmd4-ready, SIR 26
             * with NEWIRQAGR clear is the same stuck reader.
             */
            if (pcm1_last_bksnd_cmd == 3u &&
                (itr & (1u << 26)) && !(mir & (1u << 26)) &&
                (sir != 26 || (s->cpu.pcm1_cmd4_ready && !agr))) {
                if (head != prefer_word) {
                    prefer_word = head;
                    prefer_tries = 0;
                }
                /*
                 * Eight pulses are enough once SIR is already 26.
                 * SIR 37 keeps winning after those pulses, esd's
                 * status select times out, and the tune stalls on
                 * the quiet prefix. Keep handing MAIL_U0 the line
                 * until 26 is the one selected.
                 */
                if (sir != 26 || prefer_tries < 8u) {
                    if (sir == 26) {
                        prefer_tries++;
                    }
                    omap2_intc_deliver_stuck_mail();
                }
            } else if (!agr && (itr & (1u << 26)) && !(mir & (1u << 26)) &&
                       head != prefer_word) {
                if (omap2_intc_rearm_halted_mail()) {
                    prefer_word = head;
                }
            }
        }
    }
    dsp_note_pcm1_ready(s);
    dsp_c55x_snap_1012fb(s);
    if (rc == C55X_HALT_UNDEF || rc == C55X_HALT_MEM) {
        s->running = 0;
        qemu_log_mask(LOG_GUEST_ERROR,
                      "omap2420_dsp: C55x stopped at pc=%06x halt=%d\n",
                      s->cpu.pc, rc);
        return;
    }
    if (s->running && !s->rst1 && rc != C55X_HALT_RESET) {
        int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        int64_t soon = now + OMAP2420_DSP_TICK_NS;

        /*
         * Host time spent talking to the TSC2301 expires IODMA
         * deadlines, and the next kick starts before the ARM finishes
         * the pcm1 read. Hold that wave only while the read is still
         * in the kernel, including after FIFO1 has been popped.
         * Leaving it held once the read returns makes the DSP miss
         * the kernel poll.
         */
        dsp_iodma_dac_holds(s);
        if (pcm1_reads_open > 0) {
            unsigned ch;

            for (ch = 0; ch < DSP_IODMA_CHANS; ch++) {
                if (s->iodma.armed[ch] && s->iodma.tmr[ch] &&
                    s->iodma.deadline[ch] <= now) {
                    s->iodma.deadline[ch] = soon;
                    timer_mod(s->iodma.tmr[ch], soon);
                }
            }
            if (omap2420_dsp_pcm1_flush_hold()) {
                omap_eac_slave_postpone();
            }
        }
        timer_mod(s->timer, soon);
    }
}

/*
 * Run one slice on the helper, and do not return until it has finished.
 * The caller drops the BQL while it waits so the UI thread can paint.
 * Guest time stays put because the ARM thread is in this wait, which
 * keeps dsp_dld's mailbox reply inside its timeout. A request that
 * arrives on the helper during a slice is remembered and run before
 * this returns. qtest has no helper and runs the slice inline.
 */
static void omap2420_dsp_request(struct omap2420_dsp_s *s)
{
    int held;

    if (!s) {
        return;
    }
    if (!s->thread_on || dsp_on_worker) {
        if (dsp_on_worker && qatomic_read(&s->in_kick)) {
            qemu_mutex_lock(&s->thread_mu);
            s->thread_pending = 1;
            qemu_mutex_unlock(&s->thread_mu);
            return;
        }
        omap2420_dsp_kick(s);
        return;
    }
    qemu_mutex_lock(&s->thread_mu);
    s->thread_pending = 1;
    s->thread_busy = 1;
    qemu_cond_signal(&s->thread_cv);
    qemu_mutex_unlock(&s->thread_mu);

    held = bql_locked();
    if (held) {
        bql_unlock();
    }
    qemu_mutex_lock(&s->thread_mu);
    while (s->thread_busy) {
        qemu_cond_wait(&s->thread_done, &s->thread_mu);
    }
    qemu_mutex_unlock(&s->thread_mu);
    if (held) {
        bql_lock();
    }
}

static void *omap2420_dsp_worker(void *opaque)
{
    struct omap2420_dsp_s *s = opaque;

    rcu_register_thread();
    dsp_on_worker = 1;
    for (;;) {
        qemu_mutex_lock(&s->thread_mu);
        while (!s->thread_pending && !s->thread_stop) {
            qemu_cond_wait(&s->thread_cv, &s->thread_mu);
        }
        if (s->thread_stop) {
            qemu_mutex_unlock(&s->thread_mu);
            break;
        }
        s->thread_pending = 0;
        qemu_mutex_unlock(&s->thread_mu);

        bql_lock();
        omap2420_dsp_kick(s);
        bql_unlock();

        qemu_mutex_lock(&s->thread_mu);
        if (!s->thread_pending) {
            s->thread_busy = 0;
            qemu_cond_broadcast(&s->thread_done);
        }
        qemu_mutex_unlock(&s->thread_mu);
    }
    dsp_on_worker = 0;
    rcu_unregister_thread();
    return NULL;
}

static void omap2420_dsp_tick(void *opaque)
{
    omap2420_dsp_request(opaque);
}

void omap2420_dsp_after_host_audio(void)
{
    struct omap2420_dsp_s *s = pcm1_wfi_dsp;
    int64_t now;
    int64_t soon;
    unsigned ch;

    if (!s || !s->running || s->rst1) {
        return;
    }
    /*
     * AUD_open/AUD_write advance the host clock. IODMA deadlines
     * that were in the future are now expired, so the next timer
     * wave kicks the DSP again and the ARM never reaches the codec.
     * Put those deadlines back ahead of the CPU.
     */
    now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    soon = now + OMAP2420_DSP_TICK_NS;
    for (ch = 0; ch < DSP_IODMA_CHANS; ch++) {
        if (s->iodma.armed[ch] && s->iodma.tmr[ch] &&
            s->iodma.deadline[ch] <= now) {
            s->iodma.deadline[ch] = soon;
            timer_mod(s->iodma.tmr[ch], soon);
        }
    }
    if (s->timer) {
        timer_mod(s->timer, soon);
    }
    omap_eac_slave_postpone();
}

void omap2420_dsp_set_rst1(struct omap2420_dsp_s *s, int asserted)
{
    int was = s->rst1;

    s->rst1 = !!asserted;
    if (s->rst1) {
        s->running = 0;
        dsp_log(s, "TASK DELETE rst1 pc=%06x insn=%llu\n",
                s->cpu.pc & C55X_PC_MASK,
                (unsigned long long)s->cpu.insn_count);
        c55x_reset(&s->cpu);
        s->watchdog_logged = 0;
        s->iodma_tc_n = 0;
        s->iodma_clnk_n = 0;
        s->prefault_logged = 0;
        s->mbox_irq_n = 0;
        s->mbox_irq_logs = 0;
        s->pcm1_exmap_logs = 0;
        dsp_log(s, "reset ST2=%04x ARMS=%u\n", s->cpu.st2,
                !!(s->cpu.st2 & C55X_ST2_ARMS));
        if (s->timer) {
            timer_del(s->timer);
        }
        return;
    }
    if (was || !s->running) {
        uint16_t probe = 0;

        c55x_reset(&s->cpu);
        dsp_log(s, "start-reset ST2=%04x ARMS=%u\n", s->cpu.st2,
                !!(s->cpu.st2 & C55X_ST2_ARMS));
        if (s->bootconfig == DSP_BOOT_CONFIG_DIRECT) {
            uint32_t vector = dsp_boot_vector(s);

            c55x_apply_reset_vector(&s->cpu, vector);
            qemu_log_mask(LOG_UNIMP,
                          "omap2420_dsp: C55X RESET: source=DIRECT_BOOT "
                          "raw_vector=%08x entry_pc=%06x stack_config=%s "
                          "vector_bit25=%u dagen_mode=%s RETA=%06x CFCT=%02x "
                          "XSP=%06x XSSP=%06x\n",
                          vector, s->cpu.pc & C55X_PC_MASK,
                          c55x_stack_config_name(&s->cpu),
                          s->cpu.vector_bit25,
                          c55x_dagen_mode_name(&s->cpu),
                          s->cpu.reta & C55X_PC_MASK, s->cpu.cfct & 0xff,
                          s->cpu.xsp & C55X_WORD_MASK,
                          s->cpu.xssp & C55X_WORD_MASK);
        }
        s->cpu.xar3_watch = 1;
        s->cpu.ac0_watch = 1;
        qemu_log_mask(LOG_UNIMP,
                      "omap2420_dsp: RST1 released pc=%06x bootcfg=%u\n",
                      s->cpu.pc, s->bootconfig);
        dsp_dump_tlb(s, "rst1");
        /*
         * Stock dsp_dld has finished EXMAP/section copies before RUN.
         * Dump the C55x-visible words around the avs_kernel .bss slot
         * that host walks read as zero (SPRU280: BSS has no raw bytes).
         */
        dsp_dump_layers(s, s->cpu.pc & C55X_PC_MASK, 64, "reset-vec");
        dsp_dump_layers(s, 0x0013a22c, 64, "cinit");
        if (dsp_read16(s, 0x09cfda, &probe) == 0) {
            uint32_t w;
            char line[160];
            size_t n = 0;

            n = (size_t)snprintf(line, sizeof(line),
                                 "omap2420_dsp: stock-image 09cfc0:");
            for (w = 0x09cfc0; w < 0x09d000; w++) {
                uint16_t v = 0;

                dsp_read16(s, w, &v);
                if (((w - 0x09cfc0) & 7u) == 0 && w != 0x09cfc0) {
                    qemu_log_mask(LOG_UNIMP, "%s\n", line);
                    n = (size_t)snprintf(line, sizeof(line),
                                         "omap2420_dsp: stock-image %06x:",
                                         w);
                }
                n += (size_t)snprintf(line + n, sizeof(line) - n, " %04x", v);
            }
            qemu_log_mask(LOG_UNIMP, "%s\n", line);
        }
        s->running = 1;
        omap2420_dsp_tick(s);
    }
}

void omap2420_dsp_assert_rst2(struct omap2420_dsp_s *s)
{
    /*
     * RM_RSTCTRL_DSP.RST2 is the MMU reset. hwtest asserts it in
     * dsp_domain_prepare between EXMAP and the unmapped probe, so a
     * 1M CAM left in victim 3 must not satisfy the later load.
     */
    memset(s->tlb_cam, 0, sizeof(s->tlb_cam));
    memset(s->tlb_ram, 0, sizeof(s->tlb_ram));
    s->mmu_cntl = 0;
    s->mmu_fault_ad = 0;
    s->mmu_irqstatus = 0;
    s->mmu_cam = 0;
    s->mmu_ram = 0;
    s->mmu_lock = 0;
    qemu_set_irq(s->irq_mmu, 0);
}

void omap2420_dsp_reset(struct omap2420_dsp_s *s)
{
    memset(s->tlb_cam, 0, sizeof(s->tlb_cam));
    memset(s->tlb_ram, 0, sizeof(s->tlb_ram));
    s->ipi_sysconfig = 0;
    s->ipi_index = 0;
    s->ipi_entry = 0;
    s->ipi_enable = 0;
    s->ipi_iomap = 0;
    memset(s->ipi_page, 0, sizeof(s->ipi_page));
    s->bootconfig = 0;
    s->mmu_sysconfig = 0;
    s->mmu_irqstatus = 0;
    s->mmu_irqenable = 0;
    s->mmu_cntl = 0;
    s->mmu_fault_ad = 0;
    s->mmu_ttb = 0;
    s->mmu_lock = 0;
    s->mmu_cam = 0;
    s->mmu_ram = 0;
    qemu_set_irq(s->irq_mmu, 0);
    {
        unsigned ch;

        memset(s->iodma.glob, 0, sizeof(s->iodma.glob));
        memset(s->iodma.ch, 0, sizeof(s->iodma.ch));
        memset(s->iodma.armed, 0, sizeof(s->iodma.armed));
        memset(s->iodma.dac_hold, 0, sizeof(s->iodma.dac_hold));
        memset(s->iodma.staged, 0, sizeof(s->iodma.staged));
        memset(s->iodma.stage_seen, 0, sizeof(s->iodma.stage_seen));
        s->iodma.dac_giveup = 0;
        s->src_yields = 0;
        s->iodma.logs = 0;
        s->eac_logs = 0;
        for (ch = 0; ch < DSP_IODMA_CHANS; ch++) {
            if (s->iodma.tmr[ch]) {
                timer_del(s->iodma.tmr[ch]);
            }
        }
    }
    omap2420_dsp_set_rst1(s, 1);
}

static void dsp_mbox_irq(void *opaque, int n, int level)
{
    struct omap2420_dsp_s *s = opaque;

    (void)n;
    c55x_l2intc_set_irq(&s->cpu.l2, C55X_L2INTC_MAIL_SRC, level);
    if (level) {
        unsigned depth = 0;

        s->cpu.ifr0 |= OMAP2420_DSP_IFR_MAIL;
        s->mbox_irq_n++;
        if (s->mbox) {
            omap2_mailbox_peek(s->mbox, 0, &depth);
        }
        /*
         * Cap mbox IRQ spam: interactive GTK boots drown in LOG_UNIMP
         * and lose DSP slices. Log the first few edges and then go quiet.
         */
        if (s->mbox_irq_logs < 8u) {
            s->mbox_irq_logs++;
            qemu_log_mask(LOG_UNIMP,
                          "omap2420_dsp: mbox-irq level=1 ifr0=%04x "
                          "ier0=%04x intm=%u pc=%06x halt=%d depth=%u "
                          "irq_n=%u\n",
                          s->cpu.ifr0, s->cpu.ier0,
                          !!(s->cpu.st1 & C55X_ST1_INTM), s->cpu.pc,
                          (int)s->cpu.halt, depth, s->mbox_irq_n);
            c55x_l2intc_log_state(&s->cpu, "mbox-irq");
        }
        if (s->mbox && !s->watchdog_logged) {
            unsigned slot = 0;
            uint32_t head = omap2_mailbox_peek(s->mbox, 0, &depth);
            uint32_t word = omap2_mailbox_find_cmd(s->mbox, 0, 0x32,
                                                   &depth, &slot);

            if (word) {
                uint32_t pc = s->cpu.pc & C55X_PC_MASK;

                s->watchdog_logged = 1;
                dsp_log(s,
                        "A2D 32:00\n"
                        "  FIFO pending word=%08x head=%08x depth=%u slot=%u\n"
                        "  _mbx_newmsg %s pc=%06x\n"
                        "  dispatch %s\n"
                        "  _poll_broadcast %s\n"
                        "  INTM=%u IER0=%04x IFR0=%04x halt=%d\n",
                        word, head, depth, slot,
                        pc == 0x131eecu ? "entered" : "not-entered", pc,
                        pc == 0x131f79u ? "CALL AC1" : "not-entered",
                        pc == 0x131b44u ? "entered" : "not-entered",
                        !!(s->cpu.st1 & C55X_ST1_INTM),
                        s->cpu.ier0, s->cpu.ifr0, (int)s->cpu.halt);
                c55x_task_census(&s->cpu, "watchdog");
            }
        }
        if (s->cpu.halt == C55X_HALT_IDLE &&
            (s->cpu.ifr0 & s->cpu.ier0) == 0 &&
            (s->cpu.ifr1 & s->cpu.ier1) == 0) {
            dsp_log(s, "idle-masked mail IER0=%04x IFR0=%04x pc=%06x\n",
                    s->cpu.ier0, s->cpu.ifr0, s->cpu.pc & C55X_PC_MASK);
        }
        /*
         * One bounded peer quantum per mailbox rising edge, then
         * return to ARM. Occupancy-true IRQSTATUS already dropped
         * the line on empty/full, so L2 latches a real 0→1 without
         * a synthetic pulse or drain budget. A mail that arrives
         * during a slice is queued and run when that slice returns.
         */
        if (s->running && !s->rst1) {
            omap2420_dsp_request(s);
        }
    }
}

static uint64_t dsp_ipi_read(void *opaque, hwaddr addr, unsigned size)
{
    struct omap2420_dsp_s *s = opaque;

    if (size != 4) {
        return 0;
    }
    switch (addr) {
    case DSP_IPI_REVISION:
        return 0x10;
    case DSP_IPI_SYSCONFIG:
        return s->ipi_sysconfig;
    case DSP_IPI_INDEX:
        return s->ipi_index;
    case DSP_IPI_ENTRY:
        return s->ipi_entry;
    case DSP_IPI_ENABLE:
        return s->ipi_enable;
    case DSP_IPI_IOMAP:
        return s->ipi_iomap;
    case DSP_IPI_DSPBOOTCONFIG:
        return s->bootconfig;
    default:
        return 0;
    }
}

static void dsp_ipi_write(void *opaque, hwaddr addr, uint64_t value,
                          unsigned size)
{
    struct omap2420_dsp_s *s = opaque;

    if (size != 4) {
        return;
    }
    switch (addr) {
    case DSP_IPI_SYSCONFIG:
        s->ipi_sysconfig = value & 0x11d;
        break;
    case DSP_IPI_INDEX:
        s->ipi_index = value & DSP_IPI_IOMAP_MASK;
        break;
    case DSP_IPI_ENTRY:
        s->ipi_entry = value;
        if (s->ipi_index < DSP_IPI_PAGES) {
            s->ipi_page[s->ipi_index] = value;
        }
        break;
    case DSP_IPI_ENABLE:
        s->ipi_enable = value;
        qemu_log_mask(LOG_UNIMP,
                      "omap2420_dsp: IPI ENABLE=%x IOMAP=%02x\n",
                      s->ipi_enable, s->ipi_iomap);
        break;
    case DSP_IPI_IOMAP:
        s->ipi_iomap = value & DSP_IPI_IOMAP_MASK;
        qemu_log_mask(LOG_UNIMP,
                      "omap2420_dsp: IPI ENABLE=%x IOMAP=%02x\n",
                      s->ipi_enable, s->ipi_iomap);
        break;
    case DSP_IPI_DSPBOOTCONFIG:
        s->bootconfig = value & 7;
        break;
    default:
        break;
    }
}

static uint64_t dsp_mmu_read(void *opaque, hwaddr addr, unsigned size)
{
    struct omap2420_dsp_s *s = opaque;
    unsigned victim;

    if (size != 4) {
        return 0;
    }
    switch (addr) {
    case DSP_MMU_REVISION:
        return 0x10;
    case DSP_MMU_SYSCONFIG:
        return s->mmu_sysconfig;
    case DSP_MMU_SYSSTATUS:
        return DSP_MMU_SYSSTATUS_RESETDONE;
    case DSP_MMU_IRQSTATUS:
        return s->mmu_irqstatus;
    case DSP_MMU_IRQENABLE:
        return s->mmu_irqenable;
    case DSP_MMU_WALKING_ST:
        return 0;
    case DSP_MMU_CNTL:
        return s->mmu_cntl;
    case DSP_MMU_FAULT_AD:
        return s->mmu_fault_ad;
    case DSP_MMU_TTB:
        return s->mmu_ttb;
    case DSP_MMU_LOCK:
        return s->mmu_lock;
    case DSP_MMU_LD_TLB:
        return 0;
    case DSP_MMU_CAM:
        return s->mmu_cam;
    case DSP_MMU_RAM:
        return s->mmu_ram;
    case DSP_MMU_READ_CAM:
        victim = (s->mmu_lock & 0x1f0) >> 4;
        return s->tlb_cam[victim % OMAP2420_DSP_TLB];
    case DSP_MMU_READ_RAM:
        victim = (s->mmu_lock & 0x1f0) >> 4;
        return s->tlb_ram[victim % OMAP2420_DSP_TLB];
    case DSP_MMU_EMU_FAULT_AD:
        return s->mmu_fault_ad;
    default:
        return 0;
    }
}

static void dsp_mmu_write(void *opaque, hwaddr addr, uint64_t value,
                          unsigned size)
{
    struct omap2420_dsp_s *s = opaque;
    unsigned victim;
    int i;

    if (size != 4) {
        return;
    }
    switch (addr) {
    case DSP_MMU_SYSCONFIG:
        s->mmu_sysconfig = value;
        if (value & DSP_MMU_SYSCONFIG_SOFTRESET) {
            memset(s->tlb_cam, 0, sizeof(s->tlb_cam));
            memset(s->tlb_ram, 0, sizeof(s->tlb_ram));
            s->mmu_cntl = 0;
            s->mmu_irqstatus = 0;
            s->mmu_sysconfig &= ~DSP_MMU_SYSCONFIG_SOFTRESET;
        }
        break;
    case DSP_MMU_IRQSTATUS:
        s->mmu_irqstatus &= ~(uint32_t)value;
        qemu_set_irq(s->irq_mmu, !!(s->mmu_irqstatus & s->mmu_irqenable));
        break;
    case DSP_MMU_IRQENABLE:
        s->mmu_irqenable = value;
        qemu_set_irq(s->irq_mmu, !!(s->mmu_irqstatus & s->mmu_irqenable));
        break;
    case DSP_MMU_CNTL:
        s->mmu_cntl = value;
        break;
    case DSP_MMU_TTB:
        s->mmu_ttb = value;
        break;
    case DSP_MMU_LOCK:
        s->mmu_lock = value;
        break;
    case DSP_MMU_CAM:
        s->mmu_cam = value;
        break;
    case DSP_MMU_RAM:
        s->mmu_ram = value;
        break;
    case DSP_MMU_LD_TLB:
        if (value & DSP_MMU_LD_TLB_LD) {
            victim = (s->mmu_lock & 0x1f0) >> 4;
            victim %= OMAP2420_DSP_TLB;
            s->tlb_cam[victim] = s->mmu_cam;
            s->tlb_ram[victim] = s->mmu_ram;
            if (s->mmu_cam & DSP_MMU_CAM_V) {
                dsp_log_tlb_entry((int)victim, s->mmu_cam, s->mmu_ram,
                                  "ld-tlb");
            }
        }
        break;
    case DSP_MMU_GFLUSH:
        if (value & 1) {
            for (i = 0; i < OMAP2420_DSP_TLB; i++) {
                if (!(s->tlb_cam[i] & 8)) {
                    s->tlb_cam[i] &= ~DSP_MMU_CAM_V;
                }
            }
        }
        break;
    case DSP_MMU_FLUSH_ENTRY:
        if (value & 1) {
            uint32_t mask = dsp_page_mask(s->mmu_cam);
            for (i = 0; i < OMAP2420_DSP_TLB; i++) {
                if ((s->tlb_cam[i] & mask) == (s->mmu_cam & mask)) {
                    s->tlb_cam[i] &= ~DSP_MMU_CAM_V;
                }
            }
        }
        break;
    default:
        break;
    }
}

static const MemoryRegionOps dsp_ipi_ops = {
    .read = dsp_ipi_read,
    .write = dsp_ipi_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static const MemoryRegionOps dsp_mmu_ops = {
    .read = dsp_mmu_read,
    .write = dsp_mmu_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void dsp_bind_cpu(struct omap2420_dsp_s *s)
{
    C55xBus bus;

    memset(&bus, 0, sizeof(bus));
    bus.opaque = s;
    bus.fetch8 = dsp_fetch8;
    bus.read16 = dsp_read16;
    bus.write16 = dsp_write16;
    bus.read32 = dsp_read32;
    bus.write32 = dsp_write32;
    bus.io_read = dsp_io_read;
    bus.io_write = dsp_io_write;
    bus.log = dsp_log;
    bus.snapshot = dsp_bus_snapshot;
    c55x_init(&s->cpu, &bus);
}

struct omap2420_dsp_s *omap2420_dsp_init(MemoryRegion *sysmem,
                                         struct omap2_mailbox_s *mbox,
                                         qemu_irq irq_mmu)
{
    struct omap2420_dsp_s *s = g_new0(struct omap2420_dsp_s, 1);

    s->mbox = mbox;
    s->irq_mmu = irq_mmu;
    memory_region_init_ram(&s->mem, NULL, "omap2420.dsp-mem",
                           OMAP2420_DSP_MEM_SIZE, &error_fatal);
    s->iram = memory_region_get_ram_ptr(&s->mem);
    s->scratch = g_malloc0(DSP_SCRATCH_SIZE);
    memory_region_add_subregion(sysmem, OMAP2420_DSP_MEM_BASE, &s->mem);

    memory_region_init_io(&s->ipi, NULL, &dsp_ipi_ops, s,
                          "omap2420.dsp-ipi", 0x1000);
    memory_region_add_subregion(sysmem, OMAP2420_DSP_IPI_BASE, &s->ipi);

    memory_region_init_io(&s->mmu, NULL, &dsp_mmu_ops, s,
                          "omap2420.dsp-mmu", 0x1000);
    memory_region_add_subregion(sysmem, OMAP2420_DSP_MMU_BASE, &s->mmu);

    dsp_bind_cpu(s);
    s->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, omap2420_dsp_tick, s);
    {
        unsigned ch;

        for (ch = 0; ch < DSP_IODMA_CHANS; ch++) {
            s->iodma.tmr[ch] = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                            dsp_iodma_complete, s);
        }
    }
    if (mbox) {
        omap2_mailbox_set_dsp_irq(mbox, qemu_allocate_irq(dsp_mbox_irq, s, 0));
    }
    omap2420_dsp_reset(s);
    /*
     * qtest reads mailbox and IODMA state in the same thread that
     * posts it. A helper would race those checks. Interactive and
     * smoke boots keep the C55x off the ARM thread.
     */
    if (!qtest_enabled()) {
        qemu_mutex_init(&s->thread_mu);
        qemu_cond_init(&s->thread_cv);
        qemu_cond_init(&s->thread_done);
        s->thread_on = 1;
        qemu_thread_create(&s->thread, "omap2420-dsp",
                           omap2420_dsp_worker, s, QEMU_THREAD_DETACHED);
    }
    return s;
}
