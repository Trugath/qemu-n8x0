/*
 * TI OMAP2420 ISP / camera subsystem (L4TA 11).
 *
 * Four functional regions at 0x48052000:
 *   Top  +0x000, core +0x400, DMA +0x800, MMU +0xc00
 *
 * Stock Maemo omap24xxcam soft-resets CAM_SYSCONFIG then polls
 * CAM_SYSSTATUS.RESETDONE (~10k reads of 0x48052014). Without a
 * mapped L4 agent those accesses are rejected and the poll burns
 * guest time. This stub accepts the OCP SYSCONFIG/SYSSTATUS dance
 * on every block and retains the few control registers the Diablo
 * probe writes; it does not model capture, CCP, or TCM825x.
 *
 * Register names follow Linux drivers/media/video/omap24xxcam.h.
 */

#include "qemu/osdep.h"
#include "hw/irq.h"
#include "hw/arm/omap.h"
#include "qemu/log.h"

#define CAM_REVISION            0x000
#define CAM_SYSCONFIG           0x010
#define CAM_SYSSTATUS           0x014
#define CAM_IRQSTATUS           0x018
#define CAM_GPO                 0x040
#define CAM_GPI                 0x050

#define CC_CTRL                 0x040
#define CC_CTRL_DMA             0x044
#define CC_CTRL_XCLK            0x048
#define CC_IRQENABLE            0x01c

#define CAMDMA_IRQENABLE_L0     0x018
#define CAMDMA_OCP_SYSCONFIG    0x02c
#define CAMDMA_GCR              0x078

#define CAM_SYSCONFIG_SOFTRESET (1u << 1)
#define CAM_SYSSTATUS_RESETDONE (1u << 0)

/* Untouched silicon value unknown; DSS Top uses 0x20. */
#define CAM_REV_VALUE           0x20

struct omap2_camera_s {
    MemoryRegion iomem_top;
    MemoryRegion iomem_core;
    MemoryRegion iomem_dma;
    MemoryRegion iomem_mmu;
    qemu_irq irq;

    uint32_t top_sysconfig;
    uint32_t top_irqstatus;
    uint32_t top_gpo;
    uint32_t top_gpi;

    uint32_t core_sysconfig;
    uint32_t core_irqstatus;
    uint32_t core_irqenable;
    uint32_t core_ctrl;
    uint32_t core_ctrl_dma;
    uint32_t core_ctrl_xclk;

    uint32_t dma_sysconfig;
    uint32_t dma_irqenable_l0;
    uint32_t dma_gcr;

    uint32_t mmu_sysconfig;
};

static void omap2_camera_softreset(struct omap2_camera_s *s)
{
    s->top_sysconfig &= ~CAM_SYSCONFIG_SOFTRESET;
    s->top_irqstatus = 0;
    s->top_gpo = 0;
    s->top_gpi = 0;

    s->core_sysconfig &= ~CAM_SYSCONFIG_SOFTRESET;
    s->core_irqstatus = 0;
    s->core_irqenable = 0;
    s->core_ctrl = 0;
    s->core_ctrl_dma = 0;
    s->core_ctrl_xclk = 0;

    s->dma_sysconfig &= ~CAM_SYSCONFIG_SOFTRESET;
    s->dma_irqenable_l0 = 0;
    s->dma_gcr = 0;

    s->mmu_sysconfig &= ~CAM_SYSCONFIG_SOFTRESET;
}

static uint64_t omap2_camera_ocp_read(uint32_t sysconfig, uint32_t rev,
                                      hwaddr addr)
{
    switch (addr) {
    case CAM_REVISION:
        return rev;
    case CAM_SYSCONFIG:
        return sysconfig;
    case CAM_SYSSTATUS:
        return CAM_SYSSTATUS_RESETDONE;
    default:
        return 0;
    }
}

static int omap2_camera_ocp_write(uint32_t *sysconfig, uint64_t value,
                                  hwaddr addr, struct omap2_camera_s *s)
{
    switch (addr) {
    case CAM_REVISION:
    case CAM_SYSSTATUS:
        return 1;
    case CAM_SYSCONFIG:
        *sysconfig = value & 0xffffu;
        if (value & CAM_SYSCONFIG_SOFTRESET) {
            omap2_camera_softreset(s);
        }
        return 1;
    default:
        return 0;
    }
}

static uint64_t omap2_camera_top_read(void *opaque, hwaddr addr, unsigned size)
{
    struct omap2_camera_s *s = opaque;

    if (size != 4) {
        return omap_badwidth_read32(opaque, addr);
    }
    switch (addr) {
    case CAM_REVISION:
    case CAM_SYSCONFIG:
    case CAM_SYSSTATUS:
        return omap2_camera_ocp_read(s->top_sysconfig, CAM_REV_VALUE, addr);
    case CAM_IRQSTATUS:
        return s->top_irqstatus;
    case CAM_GPO:
        return s->top_gpo;
    case CAM_GPI:
        return s->top_gpi;
    default:
        break;
    }
    OMAP_BAD_REG(addr);
    return 0;
}

static void omap2_camera_top_write(void *opaque, hwaddr addr,
                                   uint64_t value, unsigned size)
{
    struct omap2_camera_s *s = opaque;

    if (size != 4) {
        omap_badwidth_write32(opaque, addr, value);
        return;
    }
    if (omap2_camera_ocp_write(&s->top_sysconfig, value, addr, s)) {
        return;
    }
    switch (addr) {
    case CAM_IRQSTATUS:
        s->top_irqstatus &= ~(uint32_t)value;
        return;
    case CAM_GPO:
        s->top_gpo = value;
        return;
    case CAM_GPI:
        return;
    default:
        break;
    }
    OMAP_BAD_REG(addr);
}

static uint64_t omap2_camera_core_read(void *opaque, hwaddr addr, unsigned size)
{
    struct omap2_camera_s *s = opaque;

    if (size != 4) {
        return omap_badwidth_read32(opaque, addr);
    }
    switch (addr) {
    case CAM_REVISION:
    case CAM_SYSCONFIG:
    case CAM_SYSSTATUS:
        return omap2_camera_ocp_read(s->core_sysconfig, CAM_REV_VALUE, addr);
    case CAM_IRQSTATUS:
        return s->core_irqstatus;
    case CC_IRQENABLE:
        return s->core_irqenable;
    case CC_CTRL:
        return s->core_ctrl;
    case CC_CTRL_DMA:
        return s->core_ctrl_dma;
    case CC_CTRL_XCLK:
        return s->core_ctrl_xclk;
    default:
        break;
    }
    OMAP_BAD_REG(addr);
    return 0;
}

static void omap2_camera_core_write(void *opaque, hwaddr addr,
                                    uint64_t value, unsigned size)
{
    struct omap2_camera_s *s = opaque;

    if (size != 4) {
        omap_badwidth_write32(opaque, addr, value);
        return;
    }
    if (omap2_camera_ocp_write(&s->core_sysconfig, value, addr, s)) {
        return;
    }
    switch (addr) {
    case CAM_IRQSTATUS:
        s->core_irqstatus &= ~(uint32_t)value;
        return;
    case CC_IRQENABLE:
        s->core_irqenable = value;
        return;
    case CC_CTRL:
        s->core_ctrl = value;
        return;
    case CC_CTRL_DMA:
        s->core_ctrl_dma = value;
        return;
    case CC_CTRL_XCLK:
        s->core_ctrl_xclk = value;
        return;
    default:
        break;
    }
    OMAP_BAD_REG(addr);
}

static uint64_t omap2_camera_dma_read(void *opaque, hwaddr addr, unsigned size)
{
    struct omap2_camera_s *s = opaque;

    if (size != 4) {
        return omap_badwidth_read32(opaque, addr);
    }
    switch (addr) {
    case CAM_REVISION:
        return CAM_REV_VALUE;
    case CAMDMA_OCP_SYSCONFIG:
        return s->dma_sysconfig;
    case CAM_SYSSTATUS:
        return CAM_SYSSTATUS_RESETDONE;
    case CAMDMA_IRQENABLE_L0:
        return s->dma_irqenable_l0;
    case CAMDMA_GCR:
        return s->dma_gcr;
    default:
        break;
    }
    OMAP_BAD_REG(addr);
    return 0;
}

static void omap2_camera_dma_write(void *opaque, hwaddr addr,
                                   uint64_t value, unsigned size)
{
    struct omap2_camera_s *s = opaque;

    if (size != 4) {
        omap_badwidth_write32(opaque, addr, value);
        return;
    }
    switch (addr) {
    case CAM_REVISION:
    case CAM_SYSSTATUS:
        return;
    case CAMDMA_OCP_SYSCONFIG:
        s->dma_sysconfig = value & 0xffffu;
        if (value & CAM_SYSCONFIG_SOFTRESET) {
            omap2_camera_softreset(s);
        }
        return;
    case CAMDMA_IRQENABLE_L0:
        s->dma_irqenable_l0 = value;
        return;
    case CAMDMA_GCR:
        s->dma_gcr = value;
        return;
    default:
        break;
    }
    OMAP_BAD_REG(addr);
}

static uint64_t omap2_camera_mmu_read(void *opaque, hwaddr addr, unsigned size)
{
    struct omap2_camera_s *s = opaque;

    if (size != 4) {
        return omap_badwidth_read32(opaque, addr);
    }
    switch (addr) {
    case CAM_REVISION:
    case CAM_SYSCONFIG:
    case CAM_SYSSTATUS:
        return omap2_camera_ocp_read(s->mmu_sysconfig, CAM_REV_VALUE, addr);
    default:
        break;
    }
    OMAP_BAD_REG(addr);
    return 0;
}

static void omap2_camera_mmu_write(void *opaque, hwaddr addr,
                                   uint64_t value, unsigned size)
{
    struct omap2_camera_s *s = opaque;

    if (size != 4) {
        omap_badwidth_write32(opaque, addr, value);
        return;
    }
    if (omap2_camera_ocp_write(&s->mmu_sysconfig, value, addr, s)) {
        return;
    }
    OMAP_BAD_REG(addr);
}

static const MemoryRegionOps omap2_camera_top_ops = {
    .read = omap2_camera_top_read,
    .write = omap2_camera_top_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static const MemoryRegionOps omap2_camera_core_ops = {
    .read = omap2_camera_core_read,
    .write = omap2_camera_core_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static const MemoryRegionOps omap2_camera_dma_ops = {
    .read = omap2_camera_dma_read,
    .write = omap2_camera_dma_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static const MemoryRegionOps omap2_camera_mmu_ops = {
    .read = omap2_camera_mmu_read,
    .write = omap2_camera_mmu_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

struct omap2_camera_s *omap2_camera_init(struct omap_target_agent_s *ta,
                                         qemu_irq irq)
{
    struct omap2_camera_s *s = g_new0(struct omap2_camera_s, 1);

    s->irq = irq;
    omap2_camera_softreset(s);

    memory_region_init_io(&s->iomem_top, NULL, &omap2_camera_top_ops, s,
                          "omap2.camera.top", omap_l4_region_size(ta, 0));
    memory_region_init_io(&s->iomem_core, NULL, &omap2_camera_core_ops, s,
                          "omap2.camera.core", omap_l4_region_size(ta, 1));
    memory_region_init_io(&s->iomem_dma, NULL, &omap2_camera_dma_ops, s,
                          "omap2.camera.dma", omap_l4_region_size(ta, 2));
    memory_region_init_io(&s->iomem_mmu, NULL, &omap2_camera_mmu_ops, s,
                          "omap2.camera.mmu", omap_l4_region_size(ta, 3));
    omap_l4_attach(ta, 0, &s->iomem_top);
    omap_l4_attach(ta, 1, &s->iomem_core);
    omap_l4_attach(ta, 2, &s->iomem_dma);
    omap_l4_attach(ta, 3, &s->iomem_mmu);
    return s;
}
