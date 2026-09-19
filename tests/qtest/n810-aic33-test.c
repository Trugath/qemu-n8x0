/*
 * N810 TLV320AIC33 I2C control-plane and GPIO 118 reset.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "libqtest.h"

#define I2C1_BASE           0x48070000ull
#define I2C2_BASE           0x48072000ull
#define GPIO4_BASE          0x4801e000ull
#define CM_FCLKEN1_CORE    0x48008200ull
#define CM_ICLKEN1_CORE    0x48008210ull
#define CM_FCLKEN_WKUP     0x48008400ull
#define CM_ICLKEN_WKUP     0x48008410ull

#define I2C_REV   0x00
#define I2C_STAT  0x08
#define I2C_CNT   0x18
#define I2C_DATA  0x1c
#define I2C_CON   0x24
#define I2C_SA    0x2c

#define I2C_STAT_NACK  (1u << 1)
#define I2C_STAT_XRDY  (1u << 4)
#define I2C_STAT_RRDY  (1u << 3)
#define I2C_STAT_SBD   (1u << 15)

#define I2C_CON_STT     (1u << 0)
#define I2C_CON_STP     (1u << 1)
#define I2C_CON_TRX     (1u << 9)
#define I2C_CON_MST     (1u << 10)
#define I2C_CON_I2C_EN  (1u << 15)

#define GPIO_OE            0x34
#define GPIO_CLEARDATAOUT  0x90
#define GPIO_SETDATAOUT    0x94
#define AIC33_GPIO_BIT     (1u << 22)

#define AIC33_ADDR         0x18
#define AIC33_PLL_PROGA    3
#define AIC33_PLL_RESET    0x10
#define AIC33_SOFT_RESET   0x80

static void n810_clocks(QTestState *qts)
{
    uint32_t fclk = qtest_readl(qts, CM_FCLKEN1_CORE);
    uint32_t iclk = qtest_readl(qts, CM_ICLKEN1_CORE);

    qtest_writel(qts, CM_FCLKEN1_CORE, fclk | (1u << 19) | (1u << 20));
    qtest_writel(qts, CM_ICLKEN1_CORE, iclk | (1u << 19) | (1u << 20));
    qtest_writel(qts, CM_FCLKEN_WKUP,
                 qtest_readl(qts, CM_FCLKEN_WKUP) | (1u << 2));
    qtest_writel(qts, CM_ICLKEN_WKUP,
                 qtest_readl(qts, CM_ICLKEN_WKUP) | (1u << 2));
}

static void i2c_enable(QTestState *qts, uint64_t base)
{
    g_assert_cmphex(qtest_readw(qts, base + I2C_REV), ==, 0x34);
    qtest_writew(qts, base + I2C_CON, I2C_CON_I2C_EN);
}

static void i2c_clear_stat(QTestState *qts, uint64_t base)
{
    qtest_writew(qts, base + I2C_STAT, 0x27);
}

static bool i2c_start_nack(QTestState *qts, uint64_t base, uint8_t addr,
                           bool recv)
{
    uint16_t con;
    uint16_t stat;

    qtest_writew(qts, base + I2C_SA, addr);
    qtest_writew(qts, base + I2C_CNT, 1);
    con = I2C_CON_I2C_EN | I2C_CON_MST | I2C_CON_STT | I2C_CON_STP;
    if (!recv) {
        con |= I2C_CON_TRX;
    }
    qtest_writew(qts, base + I2C_CON, con);
    stat = qtest_readw(qts, base + I2C_STAT);
    i2c_clear_stat(qts, base);
    return (stat & I2C_STAT_NACK) != 0;
}

static void i2c_send(QTestState *qts, uint64_t base, uint8_t addr,
                     const uint8_t *buf, uint16_t len)
{
    uint16_t data;

    qtest_writew(qts, base + I2C_SA, addr);
    qtest_writew(qts, base + I2C_CNT, len);
    qtest_writew(qts, base + I2C_CON,
                 I2C_CON_I2C_EN | I2C_CON_TRX | I2C_CON_MST |
                 I2C_CON_STT | I2C_CON_STP);
    data = qtest_readw(qts, base + I2C_STAT);
    g_assert((data & I2C_STAT_NACK) == 0);

    while (len > 1) {
        data = qtest_readw(qts, base + I2C_STAT);
        g_assert((data & I2C_STAT_XRDY) != 0);
        data = buf[0] | ((uint16_t)buf[1] << 8);
        qtest_writew(qts, base + I2C_DATA, data);
        buf += 2;
        len -= 2;
    }
    if (len == 1) {
        data = qtest_readw(qts, base + I2C_STAT);
        g_assert((data & I2C_STAT_XRDY) != 0);
        qtest_writew(qts, base + I2C_DATA, buf[0]);
    }
    data = qtest_readw(qts, base + I2C_CON);
    g_assert((data & I2C_CON_STP) == 0);
}

static void i2c_recv(QTestState *qts, uint64_t base, uint8_t addr,
                     uint8_t *buf, uint16_t len)
{
    uint16_t data;
    uint16_t stat;
    uint16_t orig_len = len;

    qtest_writew(qts, base + I2C_SA, addr);
    qtest_writew(qts, base + I2C_CNT, len);
    qtest_writew(qts, base + I2C_CON,
                 I2C_CON_I2C_EN | I2C_CON_MST | I2C_CON_STT | I2C_CON_STP);
    data = qtest_readw(qts, base + I2C_STAT);
    g_assert((data & I2C_STAT_NACK) == 0);

    while (len > 0) {
        data = qtest_readw(qts, base + I2C_CON);
        if (len <= 4) {
            g_assert((data & I2C_CON_STP) == 0);
            data = qtest_readw(qts, base + I2C_CNT);
            g_assert_cmpuint(data, ==, orig_len);
        } else {
            g_assert((data & I2C_CON_STP) != 0);
        }

        data = qtest_readw(qts, base + I2C_STAT);
        g_assert((data & I2C_STAT_RRDY) != 0);

        data = qtest_readw(qts, base + I2C_DATA);
        stat = qtest_readw(qts, base + I2C_STAT);
        if (len == 1) {
            g_assert((stat & I2C_STAT_SBD) != 0);
            buf[0] = data & 0xff;
            buf++;
            len--;
        } else {
            buf[0] = data & 0xff;
            buf[1] = data >> 8;
            buf += 2;
            len -= 2;
        }
    }
}

static uint8_t aic33_read(QTestState *qts, uint8_t reg)
{
    uint8_t val = 0;

    i2c_send(qts, I2C2_BASE, AIC33_ADDR, &reg, 1);
    i2c_recv(qts, I2C2_BASE, AIC33_ADDR, &val, 1);
    return val;
}

static void aic33_write(QTestState *qts, uint8_t reg, uint8_t val)
{
    uint8_t buf[2] = { reg, val };

    i2c_send(qts, I2C2_BASE, AIC33_ADDR, buf, 2);
}

static QTestState *n810_start(void)
{
    QTestState *qts = qtest_init("-machine n810 -display none");

    n810_clocks(qts);
    i2c_enable(qts, I2C1_BASE);
    i2c_enable(qts, I2C2_BASE);
    return qts;
}

static void test_probe(void)
{
    QTestState *qts = n810_start();

    g_assert_false(i2c_start_nack(qts, I2C2_BASE, AIC33_ADDR, false));
    g_assert_true(i2c_start_nack(qts, I2C1_BASE, AIC33_ADDR, false));
    g_assert_cmphex(aic33_read(qts, AIC33_PLL_PROGA), ==, AIC33_PLL_RESET);

    aic33_write(qts, 2, 0x55);
    g_assert_cmphex(aic33_read(qts, 2), ==, 0x55);

    aic33_write(qts, 1, AIC33_SOFT_RESET);
    g_assert_cmphex(aic33_read(qts, 2), ==, 0x00);
    g_assert_cmphex(aic33_read(qts, AIC33_PLL_PROGA), ==, AIC33_PLL_RESET);

    aic33_write(qts, 0, 1);
    aic33_write(qts, 0x10, 0xab);
    aic33_write(qts, 0, 0);
    aic33_write(qts, 0, 1);
    g_assert_cmphex(aic33_read(qts, 0x10), ==, 0xab);

    qtest_quit(qts);
}

static void test_reset_gpio(void)
{
    QTestState *qts = n810_start();
    uint32_t oe;

    g_assert_false(i2c_start_nack(qts, I2C2_BASE, AIC33_ADDR, false));

    qtest_writel(qts, GPIO4_BASE + GPIO_SETDATAOUT, AIC33_GPIO_BIT);
    oe = qtest_readl(qts, GPIO4_BASE + GPIO_OE);
    qtest_writel(qts, GPIO4_BASE + GPIO_OE, oe & ~AIC33_GPIO_BIT);
    g_assert_false(i2c_start_nack(qts, I2C2_BASE, AIC33_ADDR, false));

    qtest_writel(qts, GPIO4_BASE + GPIO_CLEARDATAOUT, AIC33_GPIO_BIT);
    g_assert_true(i2c_start_nack(qts, I2C2_BASE, AIC33_ADDR, false));

    qtest_writel(qts, GPIO4_BASE + GPIO_SETDATAOUT, AIC33_GPIO_BIT);
    g_assert_false(i2c_start_nack(qts, I2C2_BASE, AIC33_ADDR, false));
    g_assert_cmphex(aic33_read(qts, AIC33_PLL_PROGA), ==, AIC33_PLL_RESET);

    qtest_quit(qts);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    qtest_add_func("/n810/aic33/probe", test_probe);
    qtest_add_func("/n810/aic33/reset", test_reset_gpio);
    return g_test_run();
}
