/*
 * N8x0 EAC speaker-sink capture.
 *
 * N800 (RX-34): EAC frames reach the speaker only through the TSC2301
 * DAC, and that DAC stays silent for 100 ms after power-up.
 * N810 (RX-44): Diablo still clocks the EAC window; the AIC33 digital
 * path is not this sink. McBSP2 is not the stock path.
 *
 * The wav audiodev is the emulated speaker. Tests never open the host
 * sound card.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "libqtest.h"

#define EAC_BASE            0x48090000ull
#define DMA4_BASE           0x48056000ull
#define PRCM_BASE           0x48008000ull
#define CM_FCLKEN1_CORE     (PRCM_BASE + 0x200)
#define CM_ICLKEN1_CORE     (PRCM_BASE + 0x210)
#define RM_RSTCTRL_DSP      (PRCM_BASE + 0x850)

#define CM_EN_SDMA          (1u << 1)
#define CM_EN_EAC           (1u << 9)
#define DSP_RST1            (1u << 0)
#define DSP_RST2            (1u << 1)

#define EAC_CPTCTL          0x010
#define EAC_ADWR            0x0b4
#define EAC_AGCFR           0x0bc
#define EAC_AGCTR           0x0c0
#define EAC_AGCFR2          0x0c4
#define EAC_AGCFR3          0x0c8
#define EAC_VERSION         0x100
#define EAC_SYSCONFIG       0x104
#define EAC_SYSSTATUS       0x108

#define EAC_TXE             (1u << 5)
#define EAC_MN_ST           (1u << 10)
#define EAC_EACPWD          (1u << 0)
#define EAC_AUDEN           (1u << 1)
#define EAC_DMAWEN          (1u << 11)
#define EAC_SOFTRESET       (1u << 1)
#define EAC_RESETDONE       (1u << 0)
#define EAC_FS48K           (7u << 9)

#define DMA4_IRQSTATUS_L0   0x08
#define DMA4_IRQENABLE_L0   0x18
#define DMA4_CCR            0x80
#define DMA4_CICR           0x88
#define DMA4_CSR            0x8c
#define DMA4_CSDP           0x90
#define DMA4_CEN            0x94
#define DMA4_CFN            0x98
#define DMA4_CSSA           0x9c
#define DMA4_CDSA           0xa0

#define DMA4_CCR_EN         (1u << 7)
#define DMA4_CCR_SRC_POST   (1u << 12)
#define DMA4_END_BLOCK      (1u << 5)
#define OMAP24XX_DMA_EAC_AC_WR 18
#define DMA_SRC             0x80001000u

#define AUDIODEV_OPTS \
    "out.frequency=48000,out.channels=2,out.format=s16"

typedef struct {
    int16_t *pcm;
    size_t frames;
    uint32_t rate;
    uint16_t channels;
    uint16_t bits;
} WavPcm;

static char *make_wav_path(void)
{
    char *path = NULL;
    GError *err = NULL;
    int fd = g_file_open_tmp("n8x0-eac-XXXXXX", &path, &err);

    g_assert_no_error(err);
    g_assert_cmpint(fd, >=, 0);
    close(fd);
    return path;
}

static QTestState *eac_start(const char *machine, const char *wav)
{
    QTestState *qts;
    uint32_t fclk;
    uint32_t iclk;

    qts = qtest_initf("-machine %s,audiodev=snd0 -display none "
                      "-audiodev wav,id=snd0,path=%s,%s",
                      machine, wav, AUDIODEV_OPTS);

    fclk = qtest_readl(qts, CM_FCLKEN1_CORE);
    iclk = qtest_readl(qts, CM_ICLKEN1_CORE);
    qtest_writel(qts, CM_FCLKEN1_CORE, fclk | CM_EN_EAC | CM_EN_SDMA);
    qtest_writel(qts, CM_ICLKEN1_CORE, iclk | CM_EN_EAC | CM_EN_SDMA);
    return qts;
}

static void eac_write16(QTestState *qts, uint64_t off, uint16_t val)
{
    qtest_writew(qts, EAC_BASE + off, val);
}

static uint16_t eac_read16(QTestState *qts, uint64_t off)
{
    return qtest_readw(qts, EAC_BASE + off);
}

static void eac_soft_reset(QTestState *qts)
{
    eac_write16(qts, EAC_SYSCONFIG, EAC_SOFTRESET);
    g_assert_cmphex(eac_read16(qts, EAC_SYSSTATUS) & EAC_RESETDONE,
                    ==, EAC_RESETDONE);
}

static void eac_config_48k_stereo(QTestState *qts, uint16_t agctr)
{
    eac_write16(qts, EAC_AGCFR, eac_read16(qts, EAC_AGCFR) | EAC_MN_ST);
    eac_write16(qts, EAC_AGCFR3, EAC_FS48K);
    eac_write16(qts, EAC_AGCTR, agctr);
}

static void eac_wait_txe(QTestState *qts)
{
    int i;

    for (i = 0; i < 32; i++) {
        qtest_clock_step(qts, NANOSECONDS_PER_SECOND / 100);
        if (eac_read16(qts, EAC_CPTCTL) & EAC_TXE) {
            return;
        }
    }
    g_error("EAC TXE did not assert");
}

static void eac_write_stereo(QTestState *qts, int16_t left, int16_t right)
{
    eac_write16(qts, EAC_ADWR, (uint16_t)left);
    eac_write16(qts, EAC_ADWR, (uint16_t)right);
}

static void eac_drain(QTestState *qts, unsigned frames)
{
    int64_t ns = ((int64_t)frames * NANOSECONDS_PER_SECOND) / 48000 +
                 NANOSECONDS_PER_SECOND / 50;

    qtest_clock_step(qts, ns);
}

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
    WavPcm wav = {0};
    gchar *data = NULL;
    gsize len = 0;
    GError *err = NULL;
    const uint8_t *p;
    size_t n;
    uint16_t fmt = 0;
    uint32_t data_bytes = 0;
    bool have_fmt = false;

    g_file_get_contents(path, &data, &len, &err);
    g_assert_no_error(err);
    g_assert_cmpuint(len, >=, 12);

    p = (const uint8_t *)data;
    n = len;
    g_assert(memcmp(p, "RIFF", 4) == 0);
    g_assert(memcmp(p + 8, "WAVE", 4) == 0);
    p += 12;
    n -= 12;

    while (n >= 8) {
        uint32_t chunk_size;
        bool is_fmt = memcmp(p, "fmt ", 4) == 0;
        bool is_data = memcmp(p, "data", 4) == 0;

        g_assert(read_le32(p + 4, n - 4, &chunk_size));
        p += 8;
        n -= 8;
        g_assert_cmpuint(chunk_size, <=, n);

        if (is_fmt) {
            g_assert(read_le16(p, n, &fmt));
            g_assert(read_le16(p + 2, n - 2, &wav.channels));
            g_assert(read_le32(p + 4, n - 4, &wav.rate));
            g_assert(read_le16(p + 14, n - 14, &wav.bits));
            have_fmt = true;
        } else if (is_data) {
            data_bytes = chunk_size;
            g_assert(have_fmt);
            g_assert_cmphex(fmt, ==, 1);
            g_assert_cmpuint(wav.channels, ==, 2);
            g_assert_cmpuint(wav.bits, ==, 16);
            g_assert_cmpuint(wav.rate, ==, 48000);
            g_assert_cmpuint(data_bytes % 4, ==, 0);
            wav.frames = data_bytes / 4;
            wav.pcm = g_new(int16_t, wav.frames * 2);
            memcpy(wav.pcm, p, data_bytes);
            break;
        }

        p += chunk_size + (chunk_size & 1);
        n -= chunk_size + (chunk_size & 1);
    }

    g_assert_nonnull(wav.pcm);
    g_free(data);
    return wav;
}

static void wav_free(WavPcm *wav)
{
    g_free(wav->pcm);
    wav->pcm = NULL;
}

static void assert_prefix(const WavPcm *wav, const int16_t *want, size_t frames)
{
    size_t i;

    g_assert_cmpuint(wav->frames, >=, frames);
    for (i = 0; i < frames * 2; i++) {
        g_assert_cmpint(wav->pcm[i], ==, want[i]);
    }
}

static void fill_1khz_square(int16_t *pcm, size_t frames)
{
    size_t i;

    for (i = 0; i < frames; i++) {
        int16_t s = ((i % 48) < 24) ? 0x4000 : -0x4000;

        pcm[i * 2] = s;
        pcm[i * 2 + 1] = s;
    }
}

static void test_sample_format(void)
{
    char *wav_path = make_wav_path();
    QTestState *qts = eac_start("n810", wav_path);
    WavPcm wav;
    static const int16_t want[] = {
        0x0000, 0x7fff,
        (int16_t)0x8000, 0x1234,
    };

    eac_config_48k_stereo(qts, EAC_AUDEN | EAC_DMAWEN);
    eac_wait_txe(qts);
    eac_write_stereo(qts, 0x0000, 0x7fff);
    eac_write_stereo(qts, (int16_t)0x8000, 0x1234);
    eac_drain(qts, 8);

    qtest_quit(qts);
    wav = load_wav(wav_path);
    assert_prefix(&wav, want, 2);
    wav_free(&wav);
    unlink(wav_path);
    g_free(wav_path);
}

static void test_sink_capture(void)
{
    char *wav_path = make_wav_path();
    QTestState *qts = eac_start("n810", wav_path);
    int16_t want[480 * 2];
    WavPcm wav;
    size_t i;

    fill_1khz_square(want, 480);
    eac_config_48k_stereo(qts, EAC_AUDEN | EAC_DMAWEN);
    eac_wait_txe(qts);
    for (i = 0; i < 480; i++) {
        eac_write_stereo(qts, want[i * 2], want[i * 2 + 1]);
    }
    eac_drain(qts, 480);

    qtest_quit(qts);
    wav = load_wav(wav_path);
    g_assert_cmpuint(wav.frames, >=, 480);
    assert_prefix(&wav, want, 480);
    wav_free(&wav);
    unlink(wav_path);
    g_free(wav_path);
}

#define MCSPI1_BASE         0x48098000ull
#define MCSPI_CHCONF0       0x2c
#define MCSPI_CHCTRL0       0x34
#define MCSPI_TX0           0x38
#define MCSPI_RX0           0x3c
#define TSC_AUDIO_PAGE      2
#define TSC_DAC_POWER       5
/* Reset power bits with PWDNC and DAPWDN clear, reserved bits as 0x2aa0. */
#define TSC_DAC_POWER_UP    0x2be0

static uint16_t tsc2301_spi_xfer(QTestState *qts, uint16_t cmd, uint16_t data)
{
    qtest_writel(qts, MCSPI1_BASE + MCSPI_CHCONF0, 0x060000u | (15u << 7));
    qtest_writel(qts, MCSPI1_BASE + MCSPI_CHCTRL0, 1);
    qtest_writel(qts, MCSPI1_BASE + MCSPI_TX0, cmd);
    qtest_readl(qts, MCSPI1_BASE + MCSPI_RX0);
    qtest_writel(qts, MCSPI1_BASE + MCSPI_TX0, data);
    return qtest_readl(qts, MCSPI1_BASE + MCSPI_RX0) & 0xffff;
}

static void tsc2301_spi_write(QTestState *qts, uint16_t cmd, uint16_t data)
{
    tsc2301_spi_xfer(qts, cmd, data);
}

static uint16_t tsc2301_spi_read(QTestState *qts, int page, int reg)
{
    uint16_t cmd = 0x8000u | ((page & 0xf) << 11) | ((reg & 0x3f) << 5);

    return tsc2301_spi_xfer(qts, cmd, 0);
}

static void tsc2301_power_dac(QTestState *qts)
{
    tsc2301_spi_write(qts, (TSC_AUDIO_PAGE << 11) | (TSC_DAC_POWER << 5),
                      TSC_DAC_POWER_UP);
}

static bool wav_contains(const WavPcm *wav, int16_t sample)
{
    size_t i;

    for (i = 0; i < wav->frames * 2; i++) {
        if (wav->pcm[i] == sample) {
            return true;
        }
    }
    return false;
}

static void test_n800_state_machine(void)
{
    char *wav_path = make_wav_path();
    QTestState *qts = eac_start("n800", wav_path);
    WavPcm wav;

    g_assert_cmphex(eac_read16(qts, EAC_VERSION), ==, 0x0010);
    g_assert_cmphex(eac_read16(qts, EAC_AGCFR), ==, 0x0649);
    g_assert_cmphex(eac_read16(qts, EAC_AGCTR) & 0x780f, ==, 0x0000);

    eac_write16(qts, EAC_AGCFR, eac_read16(qts, EAC_AGCFR) | EAC_MN_ST);
    eac_write16(qts, EAC_AGCFR3, EAC_FS48K);
    eac_write16(qts, EAC_AGCTR, EAC_EACPWD);
    eac_write_stereo(qts, 0x1111, 0x2222);

    eac_write16(qts, EAC_AGCTR, EAC_AUDEN | EAC_DMAWEN);
    eac_wait_txe(qts);
    eac_write_stereo(qts, 0x3333, 0x4444);

    /* DAC still in reset power-down: EAC bits do not reach the speaker. */
    tsc2301_power_dac(qts);
    qtest_clock_step(qts, 50 * NANOSECONDS_PER_SECOND / 1000);
    eac_write_stereo(qts, 0x5555, 0x6666);

    qtest_clock_step(qts, 60 * NANOSECONDS_PER_SECOND / 1000);
    eac_write_stereo(qts, 0x7777, 0x8888);
    eac_drain(qts, 8);

    qtest_quit(qts);
    wav = load_wav(wav_path);
    g_assert(!wav_contains(&wav, 0x1111));
    g_assert(!wav_contains(&wav, 0x3333));
    g_assert(!wav_contains(&wav, 0x5555));
    g_assert(wav_contains(&wav, 0x7777));
    g_assert(wav_contains(&wav, 0x8888));
    wav_free(&wav);
    unlink(wav_path);
    g_free(wav_path);
}

/* Nokia polls PDSTS for 100 ms. APD-only clear must finish; DAC clear must not. */
static void test_n800_pdsts(void)
{
    QTestState *qts = qtest_init("-machine n800 -display none");
    uint16_t pwr;

    pwr = tsc2301_spi_read(qts, TSC_AUDIO_PAGE, TSC_DAC_POWER);
    g_assert(pwr & (1u << 15));
    g_assert(pwr & (1u << 10));
    g_assert(pwr & (1u << 7));

    tsc2301_spi_write(qts, (TSC_AUDIO_PAGE << 11) | (TSC_DAC_POWER << 5),
                      0x2c40);
    pwr = tsc2301_spi_read(qts, TSC_AUDIO_PAGE, TSC_DAC_POWER);
    g_assert(!(pwr & (1u << 15)));
    g_assert(pwr & (1u << 10));
    g_assert(pwr & (1u << 7));

    tsc2301_spi_write(qts, (TSC_AUDIO_PAGE << 11) | (TSC_DAC_POWER << 5),
                      0x2840);
    pwr = tsc2301_spi_read(qts, TSC_AUDIO_PAGE, TSC_DAC_POWER);
    g_assert(!(pwr & (1u << 10)));
    g_assert(!(pwr & (1u << 7)));
    qtest_clock_step(qts, 100 * NANOSECONDS_PER_SECOND / 1000);
    pwr = tsc2301_spi_read(qts, TSC_AUDIO_PAGE, TSC_DAC_POWER);
    g_assert(!(pwr & (1u << 7)));

    qtest_quit(qts);
}

static void test_n810_eac_stream(void)
{
    char *wav_path = make_wav_path();
    QTestState *qts = eac_start("n810", wav_path);
    WavPcm wav;
    static const int16_t want[] = {
        0x1111, 0x2222,
        0x1111, -0x2222,
        -0x1111, 0x2222,
        -0x1111, -0x2222,
    };

    g_assert_cmphex(qtest_readl(qts, RM_RSTCTRL_DSP) & DSP_RST1, ==, DSP_RST1);

    eac_config_48k_stereo(qts, EAC_AUDEN | EAC_DMAWEN);
    eac_wait_txe(qts);
    eac_write_stereo(qts, 0x1111, 0x2222);
    eac_write_stereo(qts, 0x1111, -0x2222);
    eac_write_stereo(qts, -0x1111, 0x2222);
    eac_write_stereo(qts, -0x1111, -0x2222);
    eac_drain(qts, 16);

    qtest_quit(qts);
    wav = load_wav(wav_path);
    assert_prefix(&wav, want, 4);
    wav_free(&wav);
    unlink(wav_path);
    g_free(wav_path);
}

static void test_audio_dma(void)
{
    char *wav_path = make_wav_path();
    QTestState *qts = eac_start("n810", wav_path);
    static const int16_t src[] = {
        0x0101, 0x0202,
        0x0303, 0x0404,
        0x7f00, (int16_t)0x80ff,
        0x1234, (int16_t)0xabcd,
    };
    uint8_t raw[sizeof(src)];
    WavPcm wav;
    uint32_t csr;
    size_t i;

    for (i = 0; i < G_N_ELEMENTS(src); i++) {
        raw[i * 2] = (uint8_t)src[i];
        raw[i * 2 + 1] = (uint8_t)((uint16_t)src[i] >> 8);
    }

    eac_config_48k_stereo(qts, EAC_AUDEN | EAC_DMAWEN);
    eac_wait_txe(qts);

    qtest_memwrite(qts, DMA_SRC, raw, sizeof(raw));
    qtest_writel(qts, DMA4_BASE + DMA4_IRQENABLE_L0, 1);
    qtest_writel(qts, DMA4_BASE + DMA4_CICR, DMA4_END_BLOCK);
    qtest_writel(qts, DMA4_BASE + DMA4_CSDP, 1); /* 16-bit */
    qtest_writel(qts, DMA4_BASE + DMA4_CEN, G_N_ELEMENTS(src));
    qtest_writel(qts, DMA4_BASE + DMA4_CFN, 1);
    qtest_writel(qts, DMA4_BASE + DMA4_CSSA, DMA_SRC);
    qtest_writel(qts, DMA4_BASE + DMA4_CDSA, (uint32_t)(EAC_BASE + EAC_ADWR));
    qtest_writel(qts, DMA4_BASE + DMA4_CCR,
                 DMA4_CCR_EN | DMA4_CCR_SRC_POST | OMAP24XX_DMA_EAC_AC_WR);

    eac_drain(qts, 16);
    csr = qtest_readl(qts, DMA4_BASE + DMA4_CSR);
    g_assert_cmphex(csr & DMA4_END_BLOCK, ==, DMA4_END_BLOCK);

    qtest_quit(qts);
    wav = load_wav(wav_path);
    assert_prefix(&wav, src, G_N_ELEMENTS(src) / 2);
    wav_free(&wav);
    unlink(wav_path);
    g_free(wav_path);
}

static void test_direct_pcm_no_dsp(void)
{
    char *wav_path = make_wav_path();
    QTestState *qts = eac_start("n810", wav_path);
    WavPcm wav;
    static const int16_t want[] = { 0x55aa, (int16_t)0xaa55 };

    qtest_writel(qts, RM_RSTCTRL_DSP, DSP_RST1 | DSP_RST2);
    g_assert_cmphex(qtest_readl(qts, RM_RSTCTRL_DSP) & DSP_RST1, ==, DSP_RST1);

    eac_config_48k_stereo(qts, EAC_AUDEN | EAC_DMAWEN);
    eac_wait_txe(qts);
    eac_write_stereo(qts, 0x55aa, (int16_t)0xaa55);
    eac_drain(qts, 8);

    qtest_quit(qts);
    wav = load_wav(wav_path);
    assert_prefix(&wav, want, 1);
    wav_free(&wav);
    unlink(wav_path);
    g_free(wav_path);
}

static void test_reset_replays(void)
{
    char *wav_path = make_wav_path();
    QTestState *qts = eac_start("n810", wav_path);
    WavPcm wav;
    static const int16_t want[] = { 0x4242, 0x4343 };

    eac_config_48k_stereo(qts, EAC_AUDEN | EAC_DMAWEN);
    eac_wait_txe(qts);
    eac_write_stereo(qts, 0x4242, 0x4343);
    eac_drain(qts, 8);

    eac_soft_reset(qts);
    g_assert_cmphex(eac_read16(qts, EAC_AGCFR), ==, 0x0649);
    g_assert_cmphex(eac_read16(qts, EAC_AGCTR) & 0x780f, ==, 0x0000);

    eac_config_48k_stereo(qts, EAC_AUDEN | EAC_DMAWEN);
    eac_wait_txe(qts);
    eac_write_stereo(qts, 0x4242, 0x4343);
    eac_drain(qts, 8);

    qtest_quit(qts);
    wav = load_wav(wav_path);
    /*
     * format_update closes the wav voice, so the file holds the second
     * play only. That is the reset contract: identical samples after
     * SOFTRESET without restarting QEMU.
     */
    assert_prefix(&wav, want, 1);
    wav_free(&wav);
    unlink(wav_path);
    g_free(wav_path);
}

static void test_mcbsp2_not_diablo(void)
{
    g_test_skip("Diablo N810 uses OMAP24xx EAC + AIC33, not mainline McBSP2. "
                "The stream contract is /n810/eac/stream.");
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    qtest_add_func("/n8x0/audio/sample-format", test_sample_format);
    qtest_add_func("/n8x0/audio/sink-capture", test_sink_capture);
    qtest_add_func("/n8x0/audio/dma", test_audio_dma);
    qtest_add_func("/n800/eac/state-machine", test_n800_state_machine);
    qtest_add_func("/n800/tsc2301/pdsts", test_n800_pdsts);
    qtest_add_func("/n810/eac/stream", test_n810_eac_stream);
    qtest_add_func("/n810/eac/direct-pcm-no-dsp", test_direct_pcm_no_dsp);
    qtest_add_func("/n810/eac/reset-replay", test_reset_replays);
    qtest_add_func("/n810/mcbsp2/stream", test_mcbsp2_not_diablo);
    return g_test_run();
}
