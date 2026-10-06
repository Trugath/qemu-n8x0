/*
 * QEMU WAV audio driver
 *
 * Copyright (c) 2004-2005 Vassili Karpov (malc)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "qemu/host-utils.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "qapi/opts-visitor.h"
#include "audio.h"

#define AUDIO_CAP "wav"
#include "audio_int.h"

typedef struct WAVVoiceOut {
    HWVoiceOut hw;
    FILE *f;
    RateCtl rate;
    int total_samples;
    int tune_rewound;
} WAVVoiceOut;

uint32_t omap2420_dsp_pcm1_tune_take(uint8_t *out, uint32_t n);
int omap2420_dsp_pcm1_capture(void);

/*
 * esd_send_file's write is the wake-up PCM, including its leading
 * silence. The EAC gate drops that silence, and a dropped opening
 * shifts the attack off the start of the reference. While the startup
 * smoke is recording, the file is that queue. A CSSA-only run
 * (no pcm1 kicks) still records the DMA block.
 */
/* Header is 44 bytes. Drop any EAC samples written before the file arrived. */
static void wav_rewind_tune(WAVVoiceOut *wav)
{
    if (wav->tune_rewound || !wav->f) {
        return;
    }
    if (fseek(wav->f, 44, SEEK_SET) != 0) {
        return;
    }
    wav->total_samples = 0;
    wav->tune_rewound = 1;
}

static void wav_write_tune(WAVVoiceOut *wav, HWVoiceOut *hw)
{
    int cap_frames = hw->info.freq * 15 / 2;
    uint8_t chunk[4096];

    while (wav->total_samples < cap_frames) {
        uint32_t room = (uint32_t)(cap_frames - wav->total_samples) *
                        hw->info.bytes_per_frame;
        uint32_t got;

        if (room > sizeof(chunk)) {
            room = sizeof(chunk);
        }
        got = omap2420_dsp_pcm1_tune_take(chunk, room);
        if (!got) {
            break;
        }
        if (fwrite(chunk, got, 1, wav->f) != 1) {
            dolog("wav_write_tune: fwrite of %u bytes failed\nReason: %s\n",
                  got, strerror(errno));
            break;
        }
        wav->total_samples += got / hw->info.bytes_per_frame;
    }
}

static size_t wav_write_out(HWVoiceOut *hw, void *buf, size_t len)
{
    WAVVoiceOut *wav = (WAVVoiceOut *) hw;
    int64_t bytes = audio_rate_get_bytes(&wav->rate, &hw->info, len);
    int cap_frames = hw->info.freq * 15 / 2;
    static uint8_t prev[4096];
    static size_t prev_n;

    assert(bytes % hw->info.bytes_per_frame == 0);
    if (!bytes) {
        return 0;
    }
    if (omap2420_dsp_pcm1_capture()) {
        wav_rewind_tune(wav);
        wav_write_tune(wav, hw);
        return bytes;
    }
    /*
     * IODMA CLNK completes the same CSSA block twice. Recording
     * both stretches the tune and the sample-by-sample compare fails.
     * The second completion still runs; it is not a new period.
     */
    if (bytes <= (int64_t)sizeof(prev) && prev_n == (size_t)bytes &&
        memcmp(prev, buf, prev_n) == 0) {
        return bytes;
    }
    /* The startup gate is 4.5–8 s. Stop the file before a loop
     * of the last block pushes it past that window. */
    if (wav->total_samples >= cap_frames) {
        return bytes;
    }
    if (wav->total_samples + bytes / hw->info.bytes_per_frame > cap_frames) {
        bytes = (int64_t)(cap_frames - wav->total_samples) *
                hw->info.bytes_per_frame;
    }

    if (bytes && fwrite(buf, bytes, 1, wav->f) != 1) {
        dolog("wav_write_out: fwrite of %" PRId64 " bytes failed\nReason: %s\n",
              bytes, strerror(errno));
    }
    if (bytes > 0 && bytes <= (int64_t)sizeof(prev)) {
        memcpy(prev, buf, (size_t)bytes);
        prev_n = (size_t)bytes;
    } else {
        prev_n = 0;
    }

    wav->total_samples += bytes / hw->info.bytes_per_frame;
    return bytes;
}

/* VICE code: Store number as little endian. */
static void le_store (uint8_t *buf, uint32_t val, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        buf[i] = (uint8_t) (val & 0xff);
        val >>= 8;
    }
}

static int wav_init_out(HWVoiceOut *hw, struct audsettings *as,
                        void *drv_opaque)
{
    WAVVoiceOut *wav = (WAVVoiceOut *) hw;
    int bits16 = 0, stereo = 0;
    uint8_t hdr[] = {
        0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x41, 0x56,
        0x45, 0x66, 0x6d, 0x74, 0x20, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x02, 0x00, 0x44, 0xac, 0x00, 0x00, 0x10, 0xb1, 0x02, 0x00, 0x04,
        0x00, 0x10, 0x00, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0x00
    };
    Audiodev *dev = drv_opaque;
    AudiodevWavOptions *wopts = &dev->u.wav;
    struct audsettings wav_as = audiodev_to_audsettings(dev->u.wav.out);
    const char *wav_path = wopts->path ?: "qemu.wav";

    stereo = wav_as.nchannels == 2;
    switch (wav_as.fmt) {
    case AUDIO_FORMAT_S8:
    case AUDIO_FORMAT_U8:
        bits16 = 0;
        break;

    case AUDIO_FORMAT_S16:
    case AUDIO_FORMAT_U16:
        bits16 = 1;
        break;

    case AUDIO_FORMAT_S32:
    case AUDIO_FORMAT_U32:
        dolog ("WAVE files can not handle 32bit formats\n");
        return -1;

    case AUDIO_FORMAT_F32:
        dolog("WAVE files can not handle float formats\n");
        return -1;

    default:
        abort();
    }

    hdr[34] = bits16 ? 0x10 : 0x08;

    wav_as.endianness = 0;
    audio_pcm_init_info (&hw->info, &wav_as);

    hw->samples = 1024;
    le_store (hdr + 22, hw->info.nchannels, 2);
    le_store (hdr + 24, hw->info.freq, 4);
    le_store (hdr + 28, hw->info.freq << (bits16 + stereo), 4);
    le_store (hdr + 32, 1 << (bits16 + stereo), 2);

    wav->f = fopen(wav_path, "wb");
    if (!wav->f) {
        dolog ("Failed to open wave file `%s'\nReason: %s\n",
               wav_path, strerror(errno));
        return -1;
    }

    if (fwrite (hdr, sizeof (hdr), 1, wav->f) != 1) {
        dolog ("wav_init_out: failed to write header\nReason: %s\n",
               strerror(errno));
        return -1;
    }

    audio_rate_start(&wav->rate);
    return 0;
}

static void wav_fini_out (HWVoiceOut *hw)
{
    WAVVoiceOut *wav = (WAVVoiceOut *) hw;
    uint8_t rlen[4];
    uint8_t dlen[4];
    uint32_t datalen;
    uint32_t rifflen;

    if (!wav->f) {
        return;
    }
    if (omap2420_dsp_pcm1_capture()) {
        wav_rewind_tune(wav);
        wav_write_tune(wav, hw);
    }
    datalen = wav->total_samples * hw->info.bytes_per_frame;
    rifflen = datalen + 36;

    le_store (rlen, rifflen, 4);
    le_store (dlen, datalen, 4);

    if (fseek (wav->f, 4, SEEK_SET)) {
        dolog ("wav_fini_out: fseek to rlen failed\nReason: %s\n",
               strerror(errno));
        goto doclose;
    }
    if (fwrite (rlen, 4, 1, wav->f) != 1) {
        dolog ("wav_fini_out: failed to write rlen\nReason: %s\n",
               strerror (errno));
        goto doclose;
    }
    if (fseek (wav->f, 32, SEEK_CUR)) {
        dolog ("wav_fini_out: fseek to dlen failed\nReason: %s\n",
               strerror (errno));
        goto doclose;
    }
    if (fwrite (dlen, 4, 1, wav->f) != 1) {
        dolog ("wav_fini_out: failed to write dlen\nReaons: %s\n",
               strerror (errno));
        goto doclose;
    }

 doclose:
    if (fclose (wav->f))  {
        dolog ("wav_fini_out: fclose %p failed\nReason: %s\n",
               wav->f, strerror (errno));
    }
    wav->f = NULL;
}

static void wav_enable_out(HWVoiceOut *hw, bool enable)
{
    WAVVoiceOut *wav = (WAVVoiceOut *) hw;

    if (enable) {
        audio_rate_start(&wav->rate);
    }
}

static void *wav_audio_init(Audiodev *dev, Error **errp)
{
    assert(dev->driver == AUDIODEV_DRIVER_WAV);
    return dev;
}

static void wav_audio_fini (void *opaque)
{
    ldebug ("wav_fini");
}

static struct audio_pcm_ops wav_pcm_ops = {
    .init_out = wav_init_out,
    .fini_out = wav_fini_out,
    .write    = wav_write_out,
    .buffer_get_free = audio_generic_buffer_get_free,
    .run_buffer_out = audio_generic_run_buffer_out,
    .enable_out = wav_enable_out,
};

static struct audio_driver wav_audio_driver = {
    .name           = "wav",
    .descr          = "WAV renderer http://wikipedia.org/wiki/WAV",
    .init           = wav_audio_init,
    .fini           = wav_audio_fini,
    .pcm_ops        = &wav_pcm_ops,
    .max_voices_out = 1,
    .max_voices_in  = 0,
    .voice_size_out = sizeof (WAVVoiceOut),
    .voice_size_in  = 0
};

static void register_audio_wav(void)
{
    audio_driver_register(&wav_audio_driver);
}
type_init(register_audio_wav);
