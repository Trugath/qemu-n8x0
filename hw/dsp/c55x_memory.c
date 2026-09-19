#include "c55x.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint16_t read_le16(const uint8_t *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t read_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int flat_in_range(const C55xFlat *flat, uint32_t byte_addr, unsigned n)
{
    return flat && flat->mem &&
           (uint64_t)byte_addr + n <= flat->size &&
           byte_addr < C55X_DSPSPACE_BYTES;
}

static int flat_fetch8(void *opaque, uint32_t byte_addr, uint8_t *out)
{
    C55xFlat *flat = opaque;

    byte_addr &= C55X_PC_MASK;
    if (!flat_in_range(flat, byte_addr, 1)) {
        return -1;
    }
    *out = flat->mem[byte_addr];
    return 0;
}

static C55xL2Intc *flat_l2(C55xFlat *flat)
{
    return (flat && flat->cpu) ? &flat->cpu->l2 : NULL;
}

static int flat_read16(void *opaque, uint32_t word_addr, uint16_t *out)
{
    C55xFlat *flat = opaque;
    C55xL2Intc *l2 = flat_l2(flat);
    uint32_t byte_addr = c55x_word_to_byte(word_addr);

    if (l2 && c55x_l2intc_owns(word_addr)) {
        int rc = c55x_l2intc_read16(l2, word_addr, out);

        if (rc <= 0) {
            return rc;
        }
    }
    if (!flat_in_range(flat, byte_addr, 2)) {
        return -1;
    }
    *out = read_le16(flat->mem + byte_addr);
    return 0;
}

static void flat_note_write(C55xFlat *flat, uint32_t word_addr,
                            uint16_t old_value, uint16_t new_value)
{
    if (flat->data_write && old_value != new_value) {
        flat->data_write(flat->data_write_opaque, word_addr,
                         old_value, new_value);
    }
}

static int flat_write16(void *opaque, uint32_t word_addr, uint16_t value)
{
    C55xFlat *flat = opaque;
    C55xL2Intc *l2 = flat_l2(flat);
    uint32_t byte_addr = c55x_word_to_byte(word_addr);
    uint16_t old_value;

    if (l2 && c55x_l2intc_owns(word_addr)) {
        int rc = c55x_l2intc_write16(l2, word_addr, value);

        if (rc < 0) {
            return -1;
        }
        if (rc == 0) {
            return 0;
        }
    }
    if (!flat_in_range(flat, byte_addr, 2)) {
        return -1;
    }
    old_value = read_le16(flat->mem + byte_addr);
    flat->mem[byte_addr] = (uint8_t)value;
    flat->mem[byte_addr + 1] = (uint8_t)(value >> 8);
    flat_note_write(flat, word_addr, old_value, value);
    return 0;
}

static int flat_read32(void *opaque, uint32_t word_addr, uint32_t *out)
{
    C55xFlat *flat = opaque;
    uint32_t byte_addr = c55x_word_to_byte(word_addr);

    if (!flat_in_range(flat, byte_addr, 4)) {
        return -1;
    }
    *out = read_le32(flat->mem + byte_addr);
    return 0;
}

static int flat_write32(void *opaque, uint32_t word_addr, uint32_t value)
{
    C55xFlat *flat = opaque;
    uint32_t byte_addr = c55x_word_to_byte(word_addr);
    uint16_t old0, old1;

    if (!flat_in_range(flat, byte_addr, 4)) {
        return -1;
    }
    old0 = read_le16(flat->mem + byte_addr);
    old1 = read_le16(flat->mem + byte_addr + 2);
    flat->mem[byte_addr] = (uint8_t)value;
    flat->mem[byte_addr + 1] = (uint8_t)(value >> 8);
    flat->mem[byte_addr + 2] = (uint8_t)(value >> 16);
    flat->mem[byte_addr + 3] = (uint8_t)(value >> 24);
    flat_note_write(flat, word_addr, old0, (uint16_t)value);
    flat_note_write(flat, word_addr + 1u, old1, (uint16_t)(value >> 16));
    return 0;
}

static int flat_io_read(void *opaque, uint16_t port, uint16_t *out)
{
    C55xFlat *flat = opaque;

    if (flat->io_read) {
        *out = flat->io_read(flat->io_opaque, port);
        return 0;
    }
    *out = 0;
    return 0;
}

static int flat_io_write(void *opaque, uint16_t port, uint16_t value)
{
    C55xFlat *flat = opaque;

    flat->last_io_port = port;
    flat->last_io_value = value;
    flat->last_io_writes++;
    if (flat->io_write) {
        flat->io_write(flat->io_opaque, port, value);
    }
    return 0;
}

static void flat_log(void *opaque, const char *fmt, ...)
    __attribute__((format(gnu_printf, 2, 3)));
static void flat_log(void *opaque, const char *fmt, ...)
{
    va_list ap;

    (void)opaque;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

void c55x_flat_init(C55xFlat *flat, uint8_t *mem, size_t size)
{
    memset(flat, 0, sizeof(*flat));
    flat->mem = mem;
    flat->size = size;
}

void c55x_flat_bind(C55xFlat *flat, C55xCPU *cpu)
{
    if (flat) {
        flat->cpu = cpu;
    }
}

C55xBus c55x_flat_bus(C55xFlat *flat)
{
    C55xBus bus;

    memset(&bus, 0, sizeof(bus));
    bus.opaque = flat;
    bus.fetch8 = flat_fetch8;
    bus.read16 = flat_read16;
    bus.write16 = flat_write16;
    bus.read32 = flat_read32;
    bus.write32 = flat_write32;
    bus.io_read = flat_io_read;
    bus.io_write = flat_io_write;
    bus.log = flat_log;
    return bus;
}

static void coff_name(const uint8_t *file, size_t file_size,
                      uint32_t strtab, const uint8_t *name8, char *out)
{
    uint32_t off;
    size_t n;

    out[0] = '\0';
    if (!name8[0] && !name8[1] && !name8[2] && !name8[3]) {
        off = read_le32(name8 + 4);
        if (!strtab || (uint64_t)strtab + off >= file_size) {
            snprintf(out, C55X_COFF_NAME_MAX, "?str+%u", off);
            return;
        }
        n = 0;
        while (strtab + off + n < file_size && file[strtab + off + n] &&
               n + 1 < C55X_COFF_NAME_MAX) {
            out[n] = (char)file[strtab + off + n];
            n++;
        }
        out[n] = '\0';
        return;
    }
    for (n = 0; n < 8 && name8[n]; n++) {
        out[n] = (char)name8[n];
    }
    out[n] = '\0';
}

void c55x_coff_image_free(C55xCoffImage *img)
{
    if (!img) {
        return;
    }
    free(img->sec);
    img->sec = NULL;
    img->nsections = 0;
}

int c55x_coff_should_load(const C55xCoffSection *s)
{
    if (!s || !s->size || !s->raw_ptr) {
        return 0;
    }
    if (s->flags & C55X_STYP_SKIP) {
        return 0;
    }
    return 1;
}

void c55x_coff_flags_str(uint32_t flags, char *buf, size_t len)
{
    static const struct {
        uint32_t bit;
        const char *name;
    } bits[] = {
        { C55X_STYP_DSECT, "DSECT" },
        { C55X_STYP_NOLOAD, "NOLOAD" },
        { C55X_STYP_GROUP, "GROUP" },
        { C55X_STYP_PAD, "PAD" },
        { C55X_STYP_COPY, "COPY" },
        { C55X_STYP_TEXT, "TEXT" },
        { C55X_STYP_DATA, "DATA" },
        { C55X_STYP_BSS, "BSS" },
        { C55X_STYP_BLOCK, "BLOCK" },
        { C55X_STYP_PASS, "PASS" },
        { C55X_STYP_CLINK, "CLINK" },
    };
    size_t used = 0;
    unsigned i;
    uint32_t extra;

    if (!buf || !len) {
        return;
    }
    buf[0] = '\0';
    if (!flags) {
        snprintf(buf, len, "REG");
        return;
    }
    extra = flags;
    for (i = 0; i < sizeof(bits) / sizeof(bits[0]); i++) {
        if (flags & bits[i].bit) {
            used += (size_t)snprintf(buf + used, len - used, "%s%s",
                                     used ? "+" : "", bits[i].name);
            extra &= ~bits[i].bit;
            if (used + 1 >= len) {
                return;
            }
        }
    }
    if (extra) {
        snprintf(buf + used, len - used, "%s%#x", used ? "+" : "", extra);
    }
}

const C55xCoffSection *c55x_coff_section_at(const C55xCoffImage *img,
                                            uint32_t byte_addr)
{
    unsigned i;

    if (!img || !img->sec) {
        return NULL;
    }
    for (i = 0; i < img->nsections; i++) {
        const C55xCoffSection *s = &img->sec[i];
        uint32_t base = s->paddr;

        if (s->size && base <= byte_addr && byte_addr - base < s->size) {
            return s;
        }
    }
    return NULL;
}

int c55x_coff_parse(const uint8_t *file, size_t file_size,
                    C55xCoffImage *out, char *err, size_t err_len)
{
    uint32_t strtab = 0;
    size_t off;
    unsigned i;

    if (err && err_len) {
        err[0] = '\0';
    }
    if (!out) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    if (file_size < C55X_COFF_FILEHDR) {
        snprintf(err, err_len, "COFF shorter than 22-byte filehdr");
        return -1;
    }
    out->magic = read_le16(file);
    out->nscns = read_le16(file + 2);
    out->symptr = read_le32(file + 8);
    out->nsyms = read_le32(file + 12);
    out->opthdr = read_le16(file + 16);
    out->flags = read_le16(file + 18);
    out->target = read_le16(file + 20);
    if (out->magic != C55X_COFF_MAGIC && out->magic != 0xc2) {
        snprintf(err, err_len, "unexpected COFF magic %04x", out->magic);
        return -1;
    }
    if (file_size < C55X_COFF_FILEHDR + out->opthdr) {
        snprintf(err, err_len, "optional header truncated");
        return -1;
    }
    if (out->opthdr >= C55X_COFF_OPTHDR) {
        out->tsize = read_le32(file + C55X_COFF_FILEHDR + 4);
        out->dsize = read_le32(file + C55X_COFF_FILEHDR + 8);
        out->bsize = read_le32(file + C55X_COFF_FILEHDR + 12);
        out->entry = read_le32(file + C55X_COFF_FILEHDR + 16);
        out->text_start = read_le32(file + C55X_COFF_FILEHDR + 20);
        out->data_start = read_le32(file + C55X_COFF_FILEHDR + 24);
    }
    if (out->symptr && out->nsyms) {
        uint64_t st = (uint64_t)out->symptr +
                      (uint64_t)out->nsyms * C55X_COFF_SYMESZ;

        if (st < file_size) {
            strtab = (uint32_t)st;
        }
    }
    off = C55X_COFF_FILEHDR + out->opthdr;
    if ((uint64_t)off + (uint64_t)out->nscns * C55X_COFF_SECHDR > file_size) {
        snprintf(err, err_len, "section table truncated");
        return -1;
    }
    out->sec = calloc(out->nscns ? out->nscns : 1, sizeof(*out->sec));
    if (!out->sec) {
        snprintf(err, err_len, "out of memory");
        return -1;
    }
    out->nsections = out->nscns;
    for (i = 0; i < out->nscns; i++) {
        const uint8_t *sh = file + off;
        C55xCoffSection *s = &out->sec[i];

        coff_name(file, file_size, strtab, sh, s->name);
        s->paddr = read_le32(sh + 8);
        s->vaddr = read_le32(sh + 12);
        s->size = read_le32(sh + 16);
        s->raw_ptr = read_le32(sh + 20);
        s->reloc_ptr = read_le32(sh + 24);
        s->reloc_count = read_le32(sh + 32);
        s->flags = read_le32(sh + 40);
        s->page = read_le16(sh + 46);
        off += C55X_COFF_SECHDR;
    }
    return 0;
}

static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

const C55xCoffSection *c55x_coff_section_named(const C55xCoffImage *img,
                                               const char *name)
{
    unsigned i;

    if (!img || !img->sec || !name) {
        return NULL;
    }
    for (i = 0; i < img->nsections; i++) {
        if (!strcmp(img->sec[i].name, name)) {
            return &img->sec[i];
        }
    }
    return NULL;
}

int c55x_cinit_parse(const uint8_t *sec, size_t sec_size,
                     C55xCinitRecord **out, unsigned *n_out,
                     char *err, size_t err_len)
{
    unsigned count = 0;
    size_t pos = 0;
    C55xCinitRecord *recs;
    unsigned i;

    if (err && err_len) {
        err[0] = '\0';
    }
    if (!sec || !out || !n_out) {
        return -1;
    }
    *out = NULL;
    *n_out = 0;
    while (pos + 2 <= sec_size) {
        uint16_t raw = read_be16(sec + pos);
        uint16_t nwords = (uint16_t)(raw & C55X_CINIT_MAX_WORDS);
        size_t rec_bytes;

        if (nwords == 0) {
            break;
        }
        rec_bytes = 6u + (size_t)nwords * 2u;
        if (pos + rec_bytes > sec_size) {
            snprintf(err, err_len, ".cinit record truncated at %#zx", pos);
            return -1;
        }
        count++;
        pos += rec_bytes;
    }
    if (pos + 2 > sec_size || (read_be16(sec + pos) & C55X_CINIT_MAX_WORDS)) {
        snprintf(err, err_len, ".cinit missing zero-size terminator");
        return -1;
    }
    recs = calloc(count ? count : 1, sizeof(*recs));
    if (!recs) {
        snprintf(err, err_len, "out of memory");
        return -1;
    }
    pos = 0;
    for (i = 0; i < count; i++) {
        uint16_t nwords = (uint16_t)(read_be16(sec + pos) & C55X_CINIT_MAX_WORDS);
        uint32_t packed = ((uint32_t)sec[pos + 2] << 24) |
                          ((uint32_t)sec[pos + 3] << 16) |
                          ((uint32_t)sec[pos + 4] << 8) |
                          (uint32_t)sec[pos + 5];

        recs[i].nwords = nwords;
        recs[i].dest = packed >> 8;
        recs[i].space = (uint8_t)(packed & 0xffu);
        recs[i].rec_off = (uint32_t)pos;
        recs[i].data_off = (uint32_t)(pos + 6);
        pos += 6u + (size_t)nwords * 2u;
    }
    *out = recs;
    *n_out = count;
    return 0;
}

void c55x_cinit_free(C55xCinitRecord *recs)
{
    free(recs);
}

uint16_t c55x_cinit_word(const uint8_t *sec, const C55xCinitRecord *r,
                         unsigned i)
{
    if (!sec || !r || i >= r->nwords) {
        return 0;
    }
    return read_be16(sec + r->data_off + (size_t)i * 2u);
}

int c55x_cinit_find(const C55xCinitRecord *recs, unsigned n,
                    uint32_t word_addr)
{
    unsigned i;

    if (!recs) {
        return -1;
    }
    word_addr &= C55X_WORD_MASK;
    for (i = 0; i < n; i++) {
        if (recs[i].dest <= word_addr &&
            word_addr - recs[i].dest < recs[i].nwords) {
            return (int)i;
        }
    }
    return -1;
}

static int coff_sym_keep(unsigned sclass)
{
    return sclass == C55X_C_EXT || sclass == C55X_C_STAT ||
           sclass == C55X_C_LABEL || sclass == C55X_C_USTATIC;
}

int c55x_coff_parse_syms(const uint8_t *file, size_t file_size,
                         const C55xCoffImage *img,
                         C55xCoffSymbol **out, unsigned *n_out,
                         char *err, size_t err_len)
{
    uint32_t strtab = 0;
    uint32_t i;
    unsigned count = 0;
    C55xCoffSymbol *syms;

    if (err && err_len) {
        err[0] = '\0';
    }
    if (!file || !img || !out || !n_out) {
        return -1;
    }
    *out = NULL;
    *n_out = 0;
    if (!img->symptr || !img->nsyms) {
        return 0;
    }
    if ((uint64_t)img->symptr + (uint64_t)img->nsyms * C55X_COFF_SYMESZ >
        file_size) {
        snprintf(err, err_len, "symbol table truncated");
        return -1;
    }
    strtab = img->symptr + img->nsyms * C55X_COFF_SYMESZ;
    for (i = 0; i < img->nsyms; ) {
        const uint8_t *e = file + img->symptr + i * C55X_COFF_SYMESZ;
        uint8_t naux = e[17];

        count++;
        i += 1u + naux;
        if (i > img->nsyms) {
            snprintf(err, err_len, "symbol aux count overrun");
            return -1;
        }
    }
    syms = calloc(count ? count : 1, sizeof(*syms));
    if (!syms) {
        snprintf(err, err_len, "out of memory");
        return -1;
    }
    count = 0;
    for (i = 0; i < img->nsyms; ) {
        const uint8_t *e = file + img->symptr + i * C55X_COFF_SYMESZ;
        C55xCoffSymbol *s = &syms[count++];

        coff_name(file, file_size, strtab, e, s->name);
        s->value = read_le32(e + 8);
        s->scnum = (int16_t)read_le16(e + 12);
        s->type = read_le16(e + 14);
        s->sclass = e[16];
        s->naux = e[17];
        i += 1u + s->naux;
    }
    *out = syms;
    *n_out = count;
    return 0;
}

void c55x_coff_syms_free(C55xCoffSymbol *syms)
{
    free(syms);
}

const char *c55x_coff_sclass_str(unsigned sclass)
{
    switch (sclass) {
    case C55X_C_EXT:
        return "EXT";
    case C55X_C_STAT:
        return "STAT";
    case C55X_C_LABEL:
        return "LABEL";
    case C55X_C_USTATIC:
        return "USTATIC";
    case C55X_C_BLOCK:
        return "BLOCK";
    case C55X_C_FCN:
        return "FCN";
    case C55X_C_FILE:
        return "FILE";
    default:
        return "OTHER";
    }
}

static int coff_sym_better(const C55xCoffSymbol *a, const C55xCoffSymbol *b)
{
    int a_dot, b_dot;

    if (!b) {
        return 1;
    }
    if (a->sclass == C55X_C_EXT && b->sclass != C55X_C_EXT) {
        return 1;
    }
    if (a->sclass != C55X_C_EXT && b->sclass == C55X_C_EXT) {
        return 0;
    }
    a_dot = a->name[0] == '.';
    b_dot = b->name[0] == '.';
    if (a_dot != b_dot) {
        return !a_dot;
    }
    return 0;
}

const C55xCoffSymbol *c55x_coff_sym_at(const C55xCoffSymbol *syms, unsigned n,
                                       uint32_t byte_addr)
{
    const C55xCoffSymbol *best = NULL;
    unsigned i;

    if (!syms) {
        return NULL;
    }
    for (i = 0; i < n; i++) {
        if (syms[i].value == byte_addr && coff_sym_keep(syms[i].sclass) &&
            coff_sym_better(&syms[i], best)) {
            best = &syms[i];
        }
    }
    return best;
}

const C55xCoffSymbol *c55x_coff_sym_nearest(const C55xCoffSymbol *syms,
                                            unsigned n, uint32_t byte_addr)
{
    const C55xCoffSymbol *best = NULL;
    unsigned i;

    if (!syms) {
        return NULL;
    }
    for (i = 0; i < n; i++) {
        if (!coff_sym_keep(syms[i].sclass) || syms[i].value > byte_addr) {
            continue;
        }
        if (!best || syms[i].value > best->value ||
            (syms[i].value == best->value &&
             coff_sym_better(&syms[i], best))) {
            best = &syms[i];
        }
    }
    return best;
}

int c55x_coff_load(uint8_t *image, size_t image_size,
                   const uint8_t *file, size_t file_size,
                   uint32_t *entry_out, char *err, size_t err_len)
{
    C55xCoffImage img;
    unsigned i;

    if (c55x_coff_parse(file, file_size, &img, err, err_len)) {
        return -1;
    }
    for (i = 0; i < img.nsections; i++) {
        const C55xCoffSection *s = &img.sec[i];

        if (!c55x_coff_should_load(s)) {
            continue;
        }
        if ((uint64_t)s->raw_ptr + s->size > file_size) {
            snprintf(err, err_len, "section %s data truncated", s->name);
            c55x_coff_image_free(&img);
            return -1;
        }
        if ((uint64_t)s->paddr + s->size > image_size) {
            snprintf(err, err_len,
                     "section %s load %#x size %u out of image",
                     s->name, s->paddr, s->size);
            c55x_coff_image_free(&img);
            return -1;
        }
        if ((s->flags & C55X_STYP_DATA) &&
            !(s->flags & C55X_STYP_TEXT)) {
            uint32_t j;

            /*
             * TI C55x COFF serializes 16-bit data words most-significant
             * byte first.  The flat DSP bus stores native data words
             * least-significant byte first; instruction bytes must remain
             * in their original order because fetch is byte addressed.
             */
            for (j = 0; j + 1 < s->size; j += 2) {
                image[s->paddr + j] = file[s->raw_ptr + j + 1];
                image[s->paddr + j + 1] = file[s->raw_ptr + j];
            }
            if (j < s->size) {
                image[s->paddr + j] = file[s->raw_ptr + j];
            }
        } else {
            memcpy(image + s->paddr, file + s->raw_ptr, s->size);
        }
    }
    if (entry_out) {
        *entry_out = img.entry & C55X_PC_MASK;
    }
    c55x_coff_image_free(&img);
    return 0;
}
