/*
 * OMAP2420 DSP subsystem: C55x interpreter, IPI, DSP MMU, internal RAM.
 *
 * This is not a qemu-system-c55x target. The ARM machine owns a bounded
 * C55x slice scheduled from a virtual-clock timer while RST1_DSP is clear.
 * Mailbox words are produced only by executed instructions.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/timer.h"
#include "qapi/error.h"
#include "exec/memory.h"
#include "exec/cpu-common.h"
#include "exec/address-spaces.h"
#include "hw/irq.h"
#include "hw/arm/omap.h"
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
#define DSP_IODMA_CSSA          14u
#define DSP_IODMA_CCR_ENABLE    (1u << 7)
#define DSP_IODMA_CLNK_ENABLE   (1u << 15)
#define DSP_IODMA_CLNK_NEXT     0x1fu
#define DSP_IODMA_CSR_DONE      0x38u
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
        int64_t deadline[DSP_IODMA_CHANS];
        QEMUTimer *tmr[DSP_IODMA_CHANS];
        unsigned logs;
    } iodma;
    unsigned eac_logs;
    unsigned watchdog_logged;
    unsigned iodma_tc_n;
    unsigned iodma_clnk_n;
    unsigned prefault_logged;
    uint16_t mbox_d2a_msw;
    C55xCPU cpu;
    int rst1;
    int running;
    int in_kick;
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

static void dsp_c55x_prefault(struct omap2420_dsp_s *s, uint32_t word);

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
    } else if (dsp_mbox_offset(va, &off0) == 0 &&
               dsp_mbox_offset((va + 1) & C55X_PC_MASK, &off1) == 0 &&
               off1 == off0 + 1) {
        if (off0 >= 0x40 && off0 < 0x80) {
            cpu_physical_memory_write(OMAP2420_MBOX_BASE + off0, buf, 2);
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
        /*
         * MESSAGE(1) reads pop the D2A FIFO. Reconstruct the word
         * from the two store16s; never address_space_ldl the slot.
         */
        if (off0 == 0x44) {
            s->mbox_d2a_msw = value;
        }
        if (off0 == 0x46) {
            uint32_t word = ((uint32_t)s->mbox_d2a_msw << 16) | value;

            if (((word >> 24) & 0x7f) == 0x20 &&
                ((word >> 16) & 0xff) == 0x03 &&
                (word & 0xffffu) == 0x000fu) {
                dsp_c55x_prefault(s, word);
            }
        }
        rc = 0;
    } else if (dsp_mmu_translate(s, va, &pa0) == 0 &&
               dsp_mmu_translate(s, (va + 1) & C55X_PC_MASK, &pa1) == 0 &&
               pa1 == pa0 + 1) {
        cpu_physical_memory_write(pa0, buf, 2);
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
static void omap2420_dsp_kick(struct omap2420_dsp_s *s);

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
    if (s->iodma.tmr[ch]) {
        timer_del(s->iodma.tmr[ch]);
    }
}

static int64_t dsp_iodma_duration_ns(struct omap2420_dsp_s *s, unsigned ch)
{
    uint32_t cen = dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CEN]);
    uint32_t cfn = dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CFN]);
    uint64_t units;
    int64_t ns;

    if (cen > 0x10000u || cfn > 0x1000u) {
        return 21000000;
    }
    units = (uint64_t)(cen ? cen : 1u) * (uint64_t)(cfn ? cfn : 1u);
    ns = (int64_t)(units * 1000000000ull / 48000ull);
    if (ns < 1000000) {
        ns = 1000000;
    }
    if (ns > 50000000) {
        ns = 50000000;
    }
    return ns;
}

static void dsp_iodma_arm(struct omap2420_dsp_s *s, unsigned ch)
{
    int64_t ns;

    if (ch >= DSP_IODMA_CHANS || !s->iodma.tmr[ch]) {
        return;
    }
    ns = dsp_iodma_duration_ns(s, ch);
    s->iodma.armed[ch] = 1;
    s->iodma.deadline[ch] = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + ns;
    timer_mod(s->iodma.tmr[ch], s->iodma.deadline[ch]);
    dsp_log(s, "iodma arm ch=%u ns=%lld ccr=%08x cen=%08x cfn=%08x "
               "cssa=%08x\n",
            ch, (long long)ns, dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CCR]),
            dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CEN]),
            dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CFN]),
            dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CSSA]));
}

static void dsp_iodma_finish(struct omap2420_dsp_s *s, unsigned ch)
{
    uint32_t csr;
    uint16_t *stat;
    unsigned bit;

    if (ch >= DSP_IODMA_CHANS || !s->iodma.armed[ch]) {
        return;
    }
    s->iodma.armed[ch] = 0;
    csr = dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CSR]) | DSP_IODMA_CSR_DONE;
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
    omap2420_dsp_kick(s);
}

static void dsp_iodma_complete(void *opaque)
{
    struct omap2420_dsp_s *s = opaque;
    unsigned ch;
    int64_t now;

    now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    for (ch = 0; ch < DSP_IODMA_CHANS; ch++) {
        if (s->iodma.armed[ch] && s->iodma.deadline[ch] <= now) {
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
        *reg = value;
        {
            uint32_t csr = dsp_iodma_pair(&s->iodma.ch[ch][DSP_IODMA_CSR]);
            uint32_t clr = (off == DSP_IODMA_CSR)
                           ? ((uint32_t)value << 16)
                           : value;

            csr &= ~clr;
            s->iodma.ch[ch][DSP_IODMA_CSR] = (uint16_t)(csr >> 16);
            s->iodma.ch[ch][DSP_IODMA_CSR + 1u] = (uint16_t)csr;
        }
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

        qemu_log_mask(LOG_GUEST_ERROR,
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

static void omap2420_dsp_kick(struct omap2420_dsp_s *s)
{
    int rc;

    if (!s || s->rst1 || !s->running || s->in_kick) {
        return;
    }
    s->in_kick = 1;
    rc = c55x_run(&s->cpu, OMAP2420_DSP_SLICE);
    s->in_kick = 0;
    dsp_c55x_snap_1012fb(s);
    if (rc == C55X_HALT_UNDEF || rc == C55X_HALT_MEM) {
        s->running = 0;
        qemu_log_mask(LOG_GUEST_ERROR,
                      "omap2420_dsp: C55x stopped at pc=%06x halt=%d\n",
                      s->cpu.pc, rc);
        return;
    }
    if (s->running && !s->rst1 && rc != C55X_HALT_RESET) {
        timer_mod(s->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                  1000000); /* 1 ms; ~4k insns per DSP clock slice */
    }
}

static void omap2420_dsp_tick(void *opaque)
{
    omap2420_dsp_kick(opaque);
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
        s->cpu.ifr0 |= OMAP2420_DSP_IFR_MAIL;
        qemu_log_mask(LOG_UNIMP,
                      "omap2420_dsp: mbox-irq level=1 ifr0=%04x "
                      "ier0=%04x intm=%u pc=%06x halt=%d\n",
                      s->cpu.ifr0, s->cpu.ier0,
                      !!(s->cpu.st1 & C55X_ST1_INTM), s->cpu.pc,
                      (int)s->cpu.halt);
        c55x_l2intc_log_state(&s->cpu, "mbox-irq");
        if (s->mbox && !s->watchdog_logged) {
            unsigned depth = 0;
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
         * Do not run a synchronous DSP slice here: early mailbox traffic
         * would starve the ARM guest. Arm the 1 ms timer so IDLE wakes
         * on the next tick if IFR & IER is set.
         */
        if (s->running && !s->rst1 && s->timer) {
            timer_mod(s->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
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
    return s;
}
