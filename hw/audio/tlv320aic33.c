/*
 * TLV320AIC33 stereo codec — I2C control plane only.
 *
 * N810: 7-bit address 0x18 (MFP1:MFP0 = 00), RESETB on GPIO 118
 * active-low. Page-select at register 0, software reset page0[1] bit 7.
 * Digital audio / speaker datapath is not modelled.
 *
 * Reset defaults follow the Linux tlv320aic3x cache (what the stock
 * driver reads back after probe).
 */

#include "qemu/osdep.h"
#include "hw/i2c/i2c.h"
#include "hw/irq.h"
#include "hw/audio/tlv320aic33.h"
#include "migration/vmstate.h"
#include "qapi/error.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qom/object.h"
#include "trace.h"

#define TLV320AIC33_PAGES       2
#define TLV320AIC33_REGS        128
#define TLV320AIC33_SOFT_RESET  0x80

OBJECT_DECLARE_SIMPLE_TYPE(TLV320AIC33State, TLV320AIC33)

struct TLV320AIC33State {
    I2CSlave parent_obj;

    uint8_t page;
    uint8_t pointer;
    int i2c_len;
    int reset_asserted;
    uint8_t regs[TLV320AIC33_PAGES][TLV320AIC33_REGS];
};

/*
 * Linux sound/soc/codecs/tlv320aic3x.c aic3x_reg[] reset cache,
 * registers 0..109. Remaining page-0 / page-1 bytes stay 0.
 */
static const uint8_t tlv320aic33_page0_reset[] = {
    0x00, 0x00, 0x00, 0x10, 0x04, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x80,
    0x80, 0xff, 0xff, 0x78, 0x78, 0x78, 0x78, 0x78,
    0x78, 0x00, 0x00, 0xfe, 0x00, 0x00, 0xfe, 0x00,
    0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x80, 0x80, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static void tlv320aic33_apply_defaults(TLV320AIC33State *s)
{
    memset(s->regs, 0, sizeof(s->regs));
    memcpy(s->regs[0], tlv320aic33_page0_reset, sizeof(tlv320aic33_page0_reset));
    s->page = 0;
    s->pointer = 0;
    s->regs[0][0] = 0;
}

static uint8_t tlv320aic33_read_reg(TLV320AIC33State *s, uint8_t reg)
{
    uint8_t page = s->page & 1;
    uint8_t val;

    if (reg == 0) {
        val = page;
    } else {
        val = s->regs[page][reg];
    }
    qemu_log_mask(LOG_GUEST_ERROR,
                  "  AIC33 page%u[0x%02x] -> 0x%02x\n", page, reg, val);
    trace_tlv320aic33_i2c("R", page, reg, val);
    return val;
}

static void tlv320aic33_write_reg(TLV320AIC33State *s, uint8_t reg, uint8_t val)
{
    uint8_t page = s->page & 1;

    qemu_log_mask(LOG_GUEST_ERROR,
                  "  AIC33 page%u[0x%02x] <- 0x%02x\n", page, reg, val);
    trace_tlv320aic33_i2c("W", page, reg, val);

    if (reg == 0) {
        s->page = val & 1;
        s->regs[0][0] = s->page;
        s->regs[1][0] = s->page;
        return;
    }
    if (page == 0 && reg == 1 && (val & TLV320AIC33_SOFT_RESET)) {
        qemu_log_mask(LOG_GUEST_ERROR, "  AIC33 software reset\n");
        tlv320aic33_apply_defaults(s);
        return;
    }
    s->regs[page][reg] = val;
}

static void tlv320aic33_gpio_reset(void *opaque, int line, int level)
{
    TLV320AIC33State *s = opaque;
    int asserted = !level;

    (void)line;
    if (asserted == s->reset_asserted) {
        return;
    }
    s->reset_asserted = asserted;
    qemu_log_mask(LOG_GUEST_ERROR, "  AIC33 reset %s\n",
                  asserted ? "asserted" : "deasserted");
    trace_tlv320aic33_reset(asserted);
    if (asserted) {
        tlv320aic33_apply_defaults(s);
        s->i2c_len = 0;
    }
}

static int tlv320aic33_event(I2CSlave *i2c, enum i2c_event event)
{
    TLV320AIC33State *s = TLV320AIC33(i2c);

    if (s->reset_asserted &&
        (event == I2C_START_SEND || event == I2C_START_RECV ||
         event == I2C_START_SEND_ASYNC)) {
        return 1;
    }
    switch (event) {
    case I2C_START_SEND:
    case I2C_START_SEND_ASYNC:
        s->i2c_len = 0;
        return 0;
    case I2C_START_RECV:
    case I2C_FINISH:
    case I2C_NACK:
        return 0;
    }
    return 0;
}

static int tlv320aic33_tx(I2CSlave *i2c, uint8_t data)
{
    TLV320AIC33State *s = TLV320AIC33(i2c);

    if (s->reset_asserted) {
        return 1;
    }
    if (s->i2c_len == 0) {
        s->pointer = data & (TLV320AIC33_REGS - 1);
        s->i2c_len = 1;
        return 0;
    }
    tlv320aic33_write_reg(s, s->pointer, data);
    s->pointer = (s->pointer + 1) & (TLV320AIC33_REGS - 1);
    return 0;
}

static uint8_t tlv320aic33_rx(I2CSlave *i2c)
{
    TLV320AIC33State *s = TLV320AIC33(i2c);
    uint8_t val;

    if (s->reset_asserted) {
        return 0xff;
    }
    val = tlv320aic33_read_reg(s, s->pointer);
    s->pointer = (s->pointer + 1) & (TLV320AIC33_REGS - 1);
    return val;
}

static void tlv320aic33_reset(DeviceState *dev)
{
    TLV320AIC33State *s = TLV320AIC33(dev);

    s->reset_asserted = 0;
    s->i2c_len = 0;
    tlv320aic33_apply_defaults(s);
}

static void tlv320aic33_realize(DeviceState *dev, Error **errp)
{
    (void)errp;
    qdev_init_gpio_in(dev, tlv320aic33_gpio_reset, 1);
    tlv320aic33_reset(dev);
}

static const VMStateDescription vmstate_tlv320aic33 = {
    .name = "tlv320aic33",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_I2C_SLAVE(parent_obj, TLV320AIC33State),
        VMSTATE_UINT8(page, TLV320AIC33State),
        VMSTATE_UINT8(pointer, TLV320AIC33State),
        VMSTATE_INT32(i2c_len, TLV320AIC33State),
        VMSTATE_INT32(reset_asserted, TLV320AIC33State),
        VMSTATE_UINT8_2DARRAY(regs, TLV320AIC33State,
                               TLV320AIC33_PAGES, TLV320AIC33_REGS),
        VMSTATE_END_OF_LIST()
    }
};

static void tlv320aic33_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    I2CSlaveClass *sc = I2C_SLAVE_CLASS(klass);

    (void)data;
    dc->realize = tlv320aic33_realize;
    dc->reset = tlv320aic33_reset;
    sc->event = tlv320aic33_event;
    sc->recv = tlv320aic33_rx;
    sc->send = tlv320aic33_tx;
    dc->vmsd = &vmstate_tlv320aic33;
    dc->desc = "TLV320AIC33 I2C audio codec (control)";
}

static const TypeInfo tlv320aic33_info = {
    .name = TYPE_TLV320AIC33,
    .parent = TYPE_I2C_SLAVE,
    .instance_size = sizeof(TLV320AIC33State),
    .class_init = tlv320aic33_class_init,
};

static void tlv320aic33_register_types(void)
{
    type_register_static(&tlv320aic33_info);
}

type_init(tlv320aic33_register_types)
