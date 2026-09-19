#ifndef HW_SSI_CX3110X_H
#define HW_SSI_CX3110X_H

#include "hw/irq.h"

struct cx3110x_s;

struct cx3110x_s *cx3110x_init(qemu_irq irq);
uint32_t cx3110x_txrx(void *opaque, uint32_t tx, int len);
void cx3110x_setcs(void *opaque, int selected);

#endif
