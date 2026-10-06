/*
 * Toshiba TCM825x camera sensor — I2C probe responder.
 *
 * N800/N810: 7-bit address 0x29 on I2C1 (omap i2c[0]). Stock
 * omap24xxcam treats a NACK as -EBUSY and logs
 * "Failed to detect TCM825x sensor chip". Any acknowledged read of a
 * non-negative byte clears that. Capture is not modelled.
 */

#include "qemu/osdep.h"
#include "hw/i2c/i2c.h"
#include "migration/vmstate.h"
#include "qemu/module.h"
#include "qom/object.h"

#define TYPE_TCM825X "tcm825x"
OBJECT_DECLARE_SIMPLE_TYPE(TCM825xState, TCM825X)

struct TCM825xState {
    I2CSlave parent_obj;

    uint8_t pointer;
    int i2c_len;
};

static int tcm825x_event(I2CSlave *i2c, enum i2c_event event)
{
    TCM825xState *s = TCM825X(i2c);

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

static int tcm825x_tx(I2CSlave *i2c, uint8_t data)
{
    TCM825xState *s = TCM825X(i2c);

    /* First byte selects the register; further bytes are ignored. */
    if (s->i2c_len == 0) {
        s->pointer = data;
    }
    s->i2c_len++;
    return 0;
}

static uint8_t tcm825x_rx(I2CSlave *i2c)
{
    /*
     * Diablo reads register 1 and treats 0 as "device not detected".
     * Any non-zero byte is a successful probe.
     */
    (void)i2c;
    return 0x01;
}

static void tcm825x_reset(DeviceState *dev)
{
    TCM825xState *s = TCM825X(dev);

    s->pointer = 0;
    s->i2c_len = 0;
}

static const VMStateDescription vmstate_tcm825x = {
    .name = "tcm825x",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_I2C_SLAVE(parent_obj, TCM825xState),
        VMSTATE_UINT8(pointer, TCM825xState),
        VMSTATE_INT32(i2c_len, TCM825xState),
        VMSTATE_END_OF_LIST()
    }
};

static void tcm825x_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    I2CSlaveClass *sc = I2C_SLAVE_CLASS(klass);

    (void)data;
    dc->reset = tcm825x_reset;
    sc->event = tcm825x_event;
    sc->recv = tcm825x_rx;
    sc->send = tcm825x_tx;
    dc->vmsd = &vmstate_tcm825x;
    dc->desc = "Toshiba TCM825x camera sensor (I2C probe)";
}

static const TypeInfo tcm825x_info = {
    .name = TYPE_TCM825X,
    .parent = TYPE_I2C_SLAVE,
    .instance_size = sizeof(TCM825xState),
    .class_init = tcm825x_class_init,
};

static void tcm825x_register_types(void)
{
    type_register_static(&tcm825x_info);
}

type_init(tcm825x_register_types)
