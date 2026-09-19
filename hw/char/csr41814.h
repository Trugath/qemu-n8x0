#ifndef HW_CHAR_CSR41814_H
#define HW_CHAR_CSR41814_H

#include "chardev/char.h"
#include "hw/irq.h"

/*
 * CSR41814 H4+ pins, matching the historical n8x0 wiring.
 * Reset is active-low: both reset and wakeup high enables the chip.
 * A falling edge on reset clears the UART parser.
 */
#define CSR41814_PIN_RESET  0
#define CSR41814_PIN_WAKEUP 1
#define CSR41814_NPINS      2

Chardev *uart_csr41814_init(void);
qemu_irq *csr41814_pins_get(Chardev *chr);

#endif
