#define KNLQ_EV 512
#define KNLQ_WIN 64

#define KNLQ_EV_INT5_ENT 1
#define KNLQ_EV_INT5_XIT 2
#define KNLQ_EV_INT2_ENT 3
#define KNLQ_EV_INT2_XIT 4
#define KNLQ_EV_IPOST 5
#define KNLQ_EV_ATM 6
#define KNLQ_EV_SKIP 7
#define KNLQ_EV_PUT 8
#define KNLQ_EV_GET 9
#define KNLQ_EV_LINK 10
#define KNLQ_EV_WORK 11
#define KNLQ_EV_RUN 12
#define KNLQ_EV_CB 13
#define KNLQ_EV_BEGIN 14
#define KNLQ_EV_COMMIT 15
#define KNLQ_EV_ABORT 16
#define KNLQ_EV_INTM 17
#define KNLQ_EV_IRQ 18
#define KNLQ_EV_HOLD 19
#define KNLQ_EV_WIN 20
#define KNLQ_EV_ISR 21
#define KNLQ_EV_TC 22
#define KNLQ_EV_CLNK 23
#define KNLQ_EV_SENT 24

static uint8_t knlq_inited;
static uint8_t knlq_delay_int5;
static uint8_t knlq_no_nest;
static uint8_t knlq_trace_que;
static uint8_t knlq_suppress_put;
static uint8_t knlq_hold_logged;
static uint8_t knlq_nest_logged;
static uint8_t knlq_skip_put;
static uint8_t knlq_in_get;
static uint8_t knlq_in_put;
static uint8_t knlq_in_ipost;
static uint8_t knlq_pub_open;
static uint8_t knlq_pub_linked;
static uint8_t knlq_pub_aborted;
static uint8_t knlq_ready_empty;
static uint8_t knlq_win_left;
static uint8_t knlq_intm_prev;
static uint8_t knlq_cb_n;
static uint8_t knlq_cb_good;
static uint8_t knlq_null_get_logged;
static unsigned knlq_ev_w;
static unsigned knlq_ev_n;
static uint32_t knlq_arg_handle;
static uint32_t knlq_arg_elem;
static uint32_t knlq_pre_next;
static uint32_t knlq_pre_prev;
static uint32_t knlq_elem;
static uint32_t knlq_atm_t0;
static uint16_t knlq_atm_count;
static uint32_t knlq_good_pub;
static uint32_t knlq_skip_pub;
static struct {
    uint64_t insn;
    uint32_t pc;
    uint32_t a;
    uint32_t b;
    uint8_t event;
    uint8_t intm;
    uint8_t nest;
} knlq_ev[KNLQ_EV];

static int knlq_env_on(const char *name)
{
    const char *e = getenv(name);

    return e && e[0] && e[0] != '0';
}

static void knlq_init(void)
{
    if (knlq_inited) {
        return;
    }
    knlq_inited = 1;
    knlq_delay_int5 = knlq_env_on("C55X_DELAY_INT5");
    knlq_no_nest = knlq_env_on("C55X_NO_EXTRA_NESTING");
    knlq_trace_que = knlq_env_on("C55X_TRACE_BIOS_QUE");
    knlq_suppress_put = knlq_env_on("C55X_SUPPRESS_KNLQ_PUT");
}

static void knlq_reset_ring(void)
{
    knlq_ev_w = 0;
    knlq_ev_n = 0;
    knlq_cb_n = 0;
    knlq_cb_good = 0;
    knlq_in_get = 0;
    knlq_in_put = 0;
    knlq_in_ipost = 0;
    knlq_skip_put = 0;
    knlq_hold_logged = 0;
    knlq_nest_logged = 0;
    knlq_pub_open = 0;
    knlq_pub_linked = 0;
    knlq_pub_aborted = 0;
    knlq_ready_empty = 0;
    knlq_win_left = 0;
    knlq_elem = 0;
    knlq_atm_t0 = 0;
    knlq_atm_count = 0;
    knlq_good_pub = 0;
    knlq_skip_pub = 0;
    knlq_null_get_logged = 0;
    memset(knlq_ev, 0, sizeof(knlq_ev));
}

static uint32_t knlq_handle(C55xCPU *cpu)
{
    return peek_dbl_ram(cpu, BIOS_WORD_KNL_WORKQ) & C55X_WORD_MASK;
}

static uint32_t knlq_next(C55xCPU *cpu, uint32_t q)
{
    return peek_dbl_ram(cpu, q) & C55X_WORD_MASK;
}

static uint32_t knlq_prev(C55xCPU *cpu, uint32_t q)
{
    return peek_dbl_ram(cpu, (q + 2u) & C55X_WORD_MASK) & C55X_WORD_MASK;
}

static uint32_t knlq_fxn(C55xCPU *cpu, uint32_t e)
{
    return peek_dbl(cpu, (e + 6u) & C55X_WORD_MASK) & C55X_WORD_MASK;
}

static int knlq_in_rptb(uint32_t pc)
{
    pc &= C55X_PC_MASK;
    return pc >= BIOS_PC_SRC_RPTB0 && pc < BIOS_PC_SRC_RPTB1;
}

static int knlq_in_cs(uint32_t pc)
{
    pc &= C55X_PC_MASK;
    if (pc >= BIOS_PC_KNL_IPOST && pc <= BIOS_PC_KNL_IPOST_RET) {
        return 1;
    }
    if (pc >= BIOS_PC_ATM_INCU && pc <= BIOS_PC_ATM_INCU_RET) {
        return 1;
    }
    if (pc >= BIOS_PC_QUE_GET && pc <= BIOS_PC_QUE_PUT_RET) {
        return 1;
    }
    return 0;
}

static const char *knlq_ev_name(uint8_t event)
{
    switch (event) {
    case KNLQ_EV_INT5_ENT:
        return "INT5-ENT";
    case KNLQ_EV_INT5_XIT:
        return "INT5-XIT";
    case KNLQ_EV_INT2_ENT:
        return "INT2-ENT";
    case KNLQ_EV_INT2_XIT:
        return "INT2-XIT";
    case KNLQ_EV_IPOST:
        return "IPOST";
    case KNLQ_EV_ATM:
        return "ATM";
    case KNLQ_EV_SKIP:
        return "SKIP-PUT";
    case KNLQ_EV_PUT:
        return "PUT";
    case KNLQ_EV_GET:
        return "GET";
    case KNLQ_EV_LINK:
        return "LINK";
    case KNLQ_EV_WORK:
        return "WORK";
    case KNLQ_EV_RUN:
        return "KNL_run";
    case KNLQ_EV_CB:
        return "CB";
    case KNLQ_EV_BEGIN:
        return "PUB-BEGIN";
    case KNLQ_EV_COMMIT:
        return "PUB-COMMIT";
    case KNLQ_EV_ABORT:
        return "PUB-ABORT";
    case KNLQ_EV_INTM:
        return "INTM";
    case KNLQ_EV_IRQ:
        return "IRQ";
    case KNLQ_EV_HOLD:
        return "HOLD";
    case KNLQ_EV_WIN:
        return "WIN";
    case KNLQ_EV_ISR:
        return "audio_isr";
    case KNLQ_EV_TC:
        return "TC";
    case KNLQ_EV_CLNK:
        return "CLNK";
    case KNLQ_EV_SENT:
        return "SENTINEL";
    default:
        return "?";
    }
}

static void knlq_ev_push(C55xCPU *cpu, uint8_t event, uint32_t pc,
                          uint32_t a, uint32_t b)
{
    unsigned slot;

    slot = knlq_ev_w % KNLQ_EV;
    knlq_ev[slot].insn = cpu->insn_count;
    knlq_ev[slot].pc = pc & C55X_PC_MASK;
    knlq_ev[slot].a = a;
    knlq_ev[slot].b = b;
    knlq_ev[slot].event = event;
    knlq_ev[slot].intm = !!(cpu->st1 & C55X_ST1_INTM);
    knlq_ev[slot].nest = cpu->irq_nest;
    knlq_ev_w++;
    if (knlq_ev_n < KNLQ_EV) {
        knlq_ev_n++;
    }
}

static void knlq_dump_ring(C55xCPU *cpu)
{
    unsigned i;
    unsigned start;

    if (!knlq_ev_n) {
        return;
    }
    start = (knlq_ev_w + KNLQ_EV - knlq_ev_n) % KNLQ_EV;
    c55x_log(cpu, "KNLQ-RING n=%u good_pub=%u skip_pub=%u\n",
             knlq_ev_n, knlq_good_pub, knlq_skip_pub);
    for (i = 0; i < knlq_ev_n; i++) {
        unsigned slot = (start + i) % KNLQ_EV;

        c55x_log(cpu,
                 "  t%u %s pc=%06x a=%06x b=%06x INTM=%u nest=%u insn=%llu\n",
                 i, knlq_ev_name(knlq_ev[slot].event), knlq_ev[slot].pc,
                 knlq_ev[slot].a, knlq_ev[slot].b, knlq_ev[slot].intm,
                 knlq_ev[slot].nest,
                 (unsigned long long)knlq_ev[slot].insn);
    }
}

static void knlq_flush(C55xCPU *cpu, const char *why)
{
    uint32_t q = knlq_handle(cpu);
    uint32_t next = knlq_next(cpu, q);
    uint32_t prev = knlq_prev(cpu, q);

    c55x_log(cpu,
             "KNLQ-FLUSH why=%s q=%06x next=%06x prev=%06x work=%u "
             "elem=%06x count=%04x T0=%04x linked=%u open=%u "
             "IFR0=%04x INTM=%u nest=%u insn=%llu\n",
             why ? why : "?", q, next, prev,
             peek16(cpu, BIOS_WORD_KNL_WORK), knlq_elem, knlq_atm_count,
             knlq_atm_t0, knlq_pub_linked, knlq_pub_open, cpu->ifr0,
             !!(cpu->st1 & C55X_ST1_INTM), cpu->irq_nest,
             (unsigned long long)cpu->insn_count);
    knlq_dump_ring(cpu);
}

void c55x_knlq_flush(C55xCPU *cpu, const char *why)
{
    knlq_init();
    knlq_flush(cpu, why);
}

static int knlq_q_empty(C55xCPU *cpu)
{
    uint32_t q = knlq_handle(cpu);

    return q && knlq_next(cpu, q) == q;
}

static void knlq_mark_linked(C55xCPU *cpu)
{
    uint32_t next;

    if (knlq_q_empty(cpu)) {
        return;
    }
    knlq_pub_linked = 1;
    if (!knlq_pub_open) {
        return;
    }
    next = knlq_next(cpu, knlq_handle(cpu));
    knlq_ev_push(cpu, KNLQ_EV_COMMIT, cpu->pc, knlq_elem, next);
    knlq_good_pub++;
    knlq_pub_open = 0;
    c55x_log(cpu,
             "KNL-PUBLISH-COMMIT pc=%06x elem=%06x next=%06x "
             "T0=%04x nest=%u INTM=%u insn=%llu\n",
             cpu->pc & C55X_PC_MASK, knlq_elem, next, knlq_atm_t0,
             cpu->irq_nest, !!(cpu->st1 & C55X_ST1_INTM),
             (unsigned long long)cpu->insn_count);
}

static int knlq_ready_empty_note(C55xCPU *cpu, uint32_t pc, const char *why)
{
    uint32_t q;
    uint16_t work;

    q = knlq_handle(cpu);
    work = peek16(cpu, BIOS_WORD_KNL_WORK);
    if (!q || !work || knlq_next(cpu, q) != q) {
        return 0;
    }
    if (knlq_ready_empty) {
        return 0;
    }
    knlq_ready_empty = 1;
    c55x_log(cpu,
             "QUE-READY-EMPTY q=%06x work=%u pc=%06x why=%s elem=%06x "
             "T0=%04x nest=%u INTM=%u IFR0=%04x insn=%llu\n",
             q, work, pc & C55X_PC_MASK, why ? why : "?",
             knlq_elem, knlq_atm_t0, cpu->irq_nest,
             !!(cpu->st1 & C55X_ST1_INTM), cpu->ifr0,
             (unsigned long long)cpu->insn_count);
    return 1;
}

static void knlq_abort(C55xCPU *cpu, const char *why, uint32_t pc)
{
    if (knlq_pub_aborted || !knlq_pub_open) {
        return;
    }
    knlq_pub_aborted = 1;
    knlq_pub_open = 0;
    knlq_ev_push(cpu, KNLQ_EV_ABORT, pc, knlq_elem, knlq_atm_t0);
    c55x_log(cpu,
             "KNL-PUBLISH-ABORT why=%s pc=%06x elem=%06x count=%04x "
             "T0=%04x q=%06x next=%06x nest=%u INTM=%u IFR0=%04x "
             "insn=%llu\n",
             why, pc & C55X_PC_MASK, knlq_elem, knlq_atm_count,
             knlq_atm_t0, knlq_handle(cpu),
             knlq_next(cpu, knlq_handle(cpu)), cpu->irq_nest,
             !!(cpu->st1 & C55X_ST1_INTM), cpu->ifr0,
             (unsigned long long)cpu->insn_count);
    knlq_ready_empty_note(cpu, pc, why);
    knlq_flush(cpu, why);
}

static void knlq_log_state(C55xCPU *cpu, const char *tag)
{
    uint32_t q;
    uint16_t work;
    uint32_t next;
    uint32_t prev;
    int empty;

    if (!knlq_trace_que) {
        return;
    }
    q = knlq_handle(cpu);
    work = peek16(cpu, BIOS_WORD_KNL_WORK);
    next = knlq_next(cpu, q);
    prev = knlq_prev(cpu, q);
    empty = q && next == q;
    c55x_log(cpu,
             "%s q=%06x next=%06x prev=%06x work=%u empty=%u "
             "set=%04x nest=%u INTM=%u IER0=%04x IFR0=%04x "
             "RETA=%06x CFCT=%02x XSP=%06x XSSP=%06x "
             "last_irq=%u from=%06x audio=%u tc=%u clnk=%u insn=%llu\n",
             tag, q, next, prev, work, empty,
             peek16(cpu, BIOS_WORD_KNL_SET), cpu->irq_nest,
             !!(cpu->st1 & C55X_ST1_INTM), cpu->ier0, cpu->ifr0,
             cpu->reta & C55X_PC_MASK, cpu->cfct & 0xffu,
             cpu->xsp & C55X_WORD_MASK, cpu->xssp & C55X_WORD_MASK,
             cpu->last_irq_bit, cpu->last_irq_from & C55X_PC_MASK,
             cpu->audio_isr_n, cpu->host_tc_n, cpu->host_clnk_n,
             (unsigned long long)cpu->insn_count);
}

static int knlq_hold_int5(C55xCPU *cpu, unsigned bit, uint32_t from)
{
    knlq_init();
    if (!knlq_delay_int5 || bit != 5 ||
        (!knlq_in_rptb(from) && !knlq_pub_open)) {
        knlq_hold_logged = 0;
        return 0;
    }
    if (!knlq_hold_logged) {
        knlq_hold_logged = 1;
        knlq_ev_push(cpu, KNLQ_EV_HOLD, from, knlq_handle(cpu),
                     peek16(cpu, BIOS_WORD_KNL_WORK));
    }
    return 1;
}

static int knlq_hold_nest(C55xCPU *cpu, unsigned bit, uint32_t from)
{
    knlq_init();
    if (!knlq_no_nest || cpu->irq_nest < 1 ||
        (!knlq_in_cs(from) && !knlq_pub_open)) {
        knlq_nest_logged = 0;
        return 0;
    }
    if (!knlq_nest_logged) {
        knlq_nest_logged = 1;
        knlq_ev_push(cpu, KNLQ_EV_HOLD, from, bit, cpu->ifr0);
    }
    return 1;
}

static int knlq_arm_snap(C55xCPU *cpu, unsigned bit, uint32_t from)
{
    knlq_init();
    if (bit != 5 || !knlq_in_rptb(from) || cpu->snap_1012fb) {
        return 0;
    }
    cpu->snap_1012fb = 1;
    c55x_log(cpu, "C55X-1012FB-SNAP from=%06x nest=%u insn=%llu\n",
             from & C55X_PC_MASK, cpu->irq_nest,
             (unsigned long long)cpu->insn_count);
    knlq_flush(cpu, "snap");
    return 1;
}

static void knlq_note_accept(C55xCPU *cpu)
{
    uint8_t intm = !!(cpu->st1 & C55X_ST1_INTM);
    uint16_t pending;

    knlq_init();
    pending = (uint16_t)(cpu->ifr0 & cpu->ier0);
    if (intm != knlq_intm_prev) {
        knlq_ev_push(cpu, KNLQ_EV_INTM, cpu->pc, knlq_intm_prev, intm);
        if (knlq_win_left || knlq_pub_open || knlq_in_ipost) {
            c55x_log(cpu,
                     "KNL-INTM pc=%06x %u->%u IFR0=%04x IER0=%04x "
                     "pending=%04x nest=%u rpt=%u/%u insn=%llu\n",
                     cpu->pc & C55X_PC_MASK, knlq_intm_prev, intm,
                     cpu->ifr0, cpu->ier0, pending, cpu->irq_nest,
                     cpu->rpt_armed, cpu->rpt_active,
                     (unsigned long long)cpu->insn_count);
        }
        knlq_intm_prev = intm;
    }
    if (knlq_win_left && !intm && pending) {
        knlq_ev_push(cpu, KNLQ_EV_IRQ, cpu->pc, pending, cpu->rpt_active);
    }
}

static void knlq_note_irq(C55xCPU *cpu, unsigned bit, uint32_t from)
{
    knlq_init();
    knlq_ev_push(cpu, KNLQ_EV_IRQ, from, bit, cpu->ifr0);
    if (bit == 5) {
        knlq_ev_push(cpu, KNLQ_EV_INT5_ENT, from, knlq_handle(cpu),
                     peek16(cpu, BIOS_WORD_KNL_WORK));
        knlq_log_state(cpu, "INT5-ENTRY");
    } else if (bit == 2) {
        knlq_ev_push(cpu, KNLQ_EV_INT2_ENT, from, knlq_handle(cpu),
                     peek16(cpu, BIOS_WORD_KNL_WORK));
        knlq_log_state(cpu, "INT2-ENTRY");
    }
}

static void knlq_note_reti(C55xCPU *cpu)
{
    uint8_t bit = cpu->last_irq_bit;

    if (bit == 5) {
        knlq_ev_push(cpu, KNLQ_EV_INT5_XIT, cpu->pc, knlq_handle(cpu),
                     peek16(cpu, BIOS_WORD_KNL_WORK));
        knlq_log_state(cpu, "INT5-EXIT");
    } else if (bit == 2) {
        knlq_ev_push(cpu, KNLQ_EV_INT2_XIT, cpu->pc, knlq_handle(cpu),
                     peek16(cpu, BIOS_WORD_KNL_WORK));
        knlq_log_state(cpu, "INT2-EXIT");
    }
    if (knlq_pub_open && (bit == 5 || bit == 2)) {
        knlq_abort(cpu, "reti-uncommitted", cpu->pc);
    } else if (knlq_ready_empty_note(cpu, cpu->pc, "reti")) {
        knlq_flush(cpu, "QUE-READY-EMPTY");
    }
}

static void knlq_note_work_store(C55xCPU *cpu, uint16_t old, uint16_t value)
{
    uint32_t q;
    uint32_t next;

    knlq_init();
    q = knlq_handle(cpu);
    next = knlq_next(cpu, q);
    knlq_ev_push(cpu, KNLQ_EV_WORK, cpu->pc, old, value);
    c55x_log(cpu,
             "KNL-WORK pc=%06x %u->%u q=%06x next=%06x elem=%06x "
             "T0=%04x nest=%u INTM=%u IFR0=%04x insn=%llu\n",
             cpu->pc & C55X_PC_MASK, old, value, q, next, knlq_elem,
             knlq_atm_t0, cpu->irq_nest, !!(cpu->st1 & C55X_ST1_INTM),
             cpu->ifr0, (unsigned long long)cpu->insn_count);
    if (old == 0 && value != 0) {
        knlq_pub_open = 1;
        knlq_pub_aborted = 0;
        knlq_ev_push(cpu, KNLQ_EV_BEGIN, cpu->pc, knlq_elem, next);
        c55x_log(cpu,
                 "KNL-PUBLISH-BEGIN pc=%06x elem=%06x next=%06x "
                 "T0=%04x nest=%u INTM=%u insn=%llu\n",
                 cpu->pc & C55X_PC_MASK, knlq_elem, next, knlq_atm_t0,
                 cpu->irq_nest, !!(cpu->st1 & C55X_ST1_INTM),
                 (unsigned long long)cpu->insn_count);
        if (q && next != q) {
            knlq_mark_linked(cpu);
        }
    } else if (old != 0 && value == 0 && knlq_pub_open) {
        knlq_abort(cpu, "knl_run-uncommitted", cpu->pc);
    }
}

static void knlq_note_link(C55xCPU *cpu, uint32_t word, uint16_t old,
                           uint16_t value)
{
    knlq_init();
    knlq_ev_push(cpu, KNLQ_EV_LINK, cpu->pc, word,
                 ((uint32_t)old << 16) | value);
    knlq_mark_linked(cpu);
}

static void knlq_log_get_after(C55xCPU *cpu, uint32_t from_pc)
{
    uint32_t ar0 = cpu->xar[0] & C55X_WORD_MASK;
    uint32_t fxn = knlq_fxn(cpu, ar0);
    uint32_t q = knlq_handle(cpu);
    int sentinel = knlq_arg_handle && ar0 == knlq_arg_handle;
    int stream_q = knlq_arg_handle && knlq_arg_handle != q;

    knlq_ev_push(cpu, sentinel ? KNLQ_EV_SENT : KNLQ_EV_GET, from_pc, ar0,
                 fxn);
    if (knlq_trace_que || stream_q) {
        c55x_log(cpu,
                 "QUEUE %06x GET pc=%06x elem=%06x fxn=%06x "
                 "empty_sentinel=%u next=%06x prev=%06x work=%u nest=%u "
                 "knl=%u insn=%llu\n",
                 knlq_arg_handle, from_pc, ar0, fxn, sentinel,
                 knlq_next(cpu, knlq_arg_handle),
                 knlq_prev(cpu, knlq_arg_handle),
                 peek16(cpu, BIOS_WORD_KNL_WORK), cpu->irq_nest,
                 knlq_arg_handle == q,
                 (unsigned long long)cpu->insn_count);
    }
}

static void knlq_log_put_after(C55xCPU *cpu, uint32_t from_pc)
{
    uint32_t fxn = knlq_fxn(cpu, knlq_arg_elem);
    uint32_t q = knlq_handle(cpu);
    int stream_q = knlq_arg_handle && knlq_arg_handle != q;

    knlq_ev_push(cpu, KNLQ_EV_PUT, from_pc, knlq_arg_elem, fxn);
    if (knlq_arg_handle == q) {
        knlq_mark_linked(cpu);
    }
    if (knlq_trace_que || stream_q) {
        c55x_log(cpu,
                 "QUEUE %06x PUT pc=%06x elem=%06x fxn=%06x "
                 "next %06x->%06x work=%u nest=%u knl=%u insn=%llu\n",
                 knlq_arg_handle, from_pc, knlq_arg_elem, fxn,
                 knlq_pre_next, knlq_next(cpu, knlq_arg_handle),
                 peek16(cpu, BIOS_WORD_KNL_WORK), cpu->irq_nest,
                 knlq_arg_handle == q, (unsigned long long)cpu->insn_count);
    }
}

static void knlq_note_before(C55xCPU *cpu)
{
    uint32_t pc = cpu->pc & C55X_PC_MASK;
    uint32_t q;
    uint32_t ar0;
    uint32_t ar1;
    uint32_t ar5;
    uint32_t fxn;
    uint16_t work;
    int sentinel;

    knlq_init();
    if (cpu->insn_count == 0) {
        knlq_reset_ring();
        knlq_intm_prev = !!(cpu->st1 & C55X_ST1_INTM);
    }
    if (knlq_win_left) {
        knlq_ev_push(cpu, KNLQ_EV_WIN, pc, cpu->ifr0,
                     ((uint32_t)cpu->rpt_active << 16) | cpu->ier0);
        knlq_win_left--;
    }
    if (pc != BIOS_PC_AUDIO_ISR && pc != BIOS_PC_KNL_RUN &&
        pc != BIOS_PC_KNL_IPOST && pc != BIOS_PC_KNL_CALL0 &&
        pc != BIOS_PC_QUE_GET && pc != BIOS_PC_QUE_PUT &&
        pc != BIOS_PC_KNL_IPOST_BCC && pc != BIOS_PC_ATM_INCU &&
        pc != BIOS_PC_KNL_CLEAR_WORK) {
        return;
    }
    q = knlq_handle(cpu);
    ar0 = cpu->xar[0] & C55X_WORD_MASK;
    ar1 = cpu->xar[1] & C55X_WORD_MASK;
    ar5 = cpu->xar[5] & C55X_WORD_MASK;

    if (pc == BIOS_PC_AUDIO_ISR) {
        knlq_ev_push(cpu, KNLQ_EV_ISR, pc, cpu->audio_isr_n + 1u,
                     cpu->host_tc_n);
        return;
    }
    if (pc == BIOS_PC_KNL_RUN) {
        knlq_ev_push(cpu, KNLQ_EV_RUN, pc, q,
                     peek16(cpu, BIOS_WORD_KNL_WORK));
        knlq_log_state(cpu, "KNL-RUN");
        return;
    }
    if (pc == BIOS_PC_KNL_CLEAR_WORK && knlq_pub_open) {
        knlq_abort(cpu, "knl_run-consume", pc);
        return;
    }
    if (pc == BIOS_PC_KNL_IPOST) {
        knlq_in_ipost = 1;
        knlq_pub_linked = 0;
        knlq_pub_aborted = 0;
        knlq_ready_empty = 0;
        knlq_elem = ar0;
        knlq_atm_count = peek_word_safe(ar0 + 4u) ?
                        peek16_ram(cpu, ar0 + 4u) : 0;
        knlq_win_left = KNLQ_WIN;
        knlq_ev_push(cpu, KNLQ_EV_IPOST, pc, ar0, knlq_atm_count);
        knlq_log_state(cpu, "KNL-IPOST");
        return;
    }
    if (pc == BIOS_PC_ATM_INCU) {
        knlq_ev_push(cpu, KNLQ_EV_ATM, pc, ar0,
                     peek_word_safe(ar0) ? peek16_ram(cpu, ar0) : 0);
        return;
    }
    if (pc == BIOS_PC_KNL_IPOST_BCC) {
        knlq_atm_t0 = cpu->t[0];
        knlq_atm_count = peek_word_safe(knlq_elem + 4u) ?
                        peek16_ram(cpu, knlq_elem + 4u) : knlq_atm_count;
        knlq_ev_push(cpu, KNLQ_EV_ATM, pc, knlq_elem, knlq_atm_t0);
        return;
    }
    if (pc == BIOS_PC_KNL_CALL0) {
        work = peek16(cpu, BIOS_WORD_KNL_WORK);
        sentinel = q && ar5 == q;
        fxn = knlq_fxn(cpu, ar5);
        knlq_cb_n++;
        if (!sentinel && (cpu->ac[0] & 0xffffffu) != 0) {
            knlq_cb_good++;
        }
        knlq_ev_push(cpu, sentinel ? KNLQ_EV_SENT : KNLQ_EV_CB, pc, ar5,
                     (uint32_t)(cpu->ac[0] & 0xffffffu));
        c55x_log(cpu,
                 "KNL-CB ar5=%06x AC0=%06x sentinel=%u nest=%u "
                 "from=%06x insn=%llu\n",
                 ar5, (uint32_t)(cpu->ac[0] & 0xffffffu), sentinel,
                 cpu->irq_nest, cpu->last_irq_from & C55X_PC_MASK,
                 (unsigned long long)cpu->insn_count);
        if (knlq_trace_que || sentinel) {
            c55x_log(cpu,
                     "CALLBACK-GET caller=%06x queue_handle=%06x "
                     "before next=%06x prev=%06x QUE_get return=%06x "
                     "empty_sentinel=%u +0=%04x +1=%04x +2=%04x +3=%04x "
                     "+4=%04x +5=%04x +6=%06x AC0=%010llx work=%u "
                     "work_set=%04x nest=%u INTM=%u IER0=%04x IFR0=%04x "
                     "last_irq=%u from=%06x audio=%u tc=%u clnk=%u "
                     "good=%u/%u insn=%llu\n",
                     cpu->reta & C55X_PC_MASK, q, knlq_next(cpu, q),
                     knlq_prev(cpu, q), ar5, sentinel,
                     peek16(cpu, ar5), peek16(cpu, ar5 + 1u),
                     peek16(cpu, ar5 + 2u), peek16(cpu, ar5 + 3u),
                     peek16(cpu, ar5 + 4u), peek16(cpu, ar5 + 5u),
                     fxn, (unsigned long long)cpu->ac[0], work,
                     peek16(cpu, BIOS_WORD_KNL_SET), cpu->irq_nest,
                     !!(cpu->st1 & C55X_ST1_INTM), cpu->ier0, cpu->ifr0,
                     cpu->last_irq_bit, cpu->last_irq_from & C55X_PC_MASK,
                     cpu->audio_isr_n, cpu->host_tc_n, cpu->host_clnk_n,
                     knlq_cb_good, knlq_cb_n,
                     (unsigned long long)cpu->insn_count);
        }
        if (sentinel) {
            c55x_log(cpu,
                     "CALLBACK-GET-SENTINEL queue=%06x AR5=%06x "
                     "AC0=%010llx work=%u nest=%u last_irq=%u from=%06x "
                     "insn=%llu\n",
                     q, ar5, (unsigned long long)cpu->ac[0], work,
                     cpu->irq_nest, cpu->last_irq_bit,
                     cpu->last_irq_from & C55X_PC_MASK,
                     (unsigned long long)cpu->insn_count);
            knlq_flush(cpu, "callback-sentinel");
        }
        return;
    }
    if (pc == BIOS_PC_QUE_GET) {
        uint32_t xar5 = cpu->xar[5] & C55X_WORD_MASK;
        uint32_t xar7 = cpu->xar[7] & C55X_WORD_MASK;
        uint32_t stream16 = 0;
        uint32_t ier_as_link = ((uint32_t)cpu->ier0 << 16) | cpu->ifr0;
        int null_handle;

        knlq_arg_handle = ar0;
        knlq_pre_next = ar0 ? knlq_next(cpu, ar0) : 0;
        knlq_pre_prev = ar0 ? knlq_prev(cpu, ar0) : 0;
        knlq_in_get = 1;
        null_handle = (ar0 == 0) ||
                      (ar0 && knlq_pre_next == ier_as_link);
        if (xar7) {
            stream16 = peek_dbl_ram(cpu, (xar7 + 0x16u) & C55X_WORD_MASK) &
                       C55X_WORD_MASK;
        }
        knlq_ev_push(cpu, KNLQ_EV_GET, pc, ar0, cpu->reta & C55X_PC_MASK);
        /*
         * Always-on for null / postStream / non-KNL stream queues. Full
         * KNL traffic stays on the ring unless C55X_TRACE_BIOS_QUE.
         */
        if (null_handle || (cpu->reta & C55X_PC_MASK) == 0x12a266u ||
            (ar0 && ar0 != q) || knlq_trace_que) {
            c55x_log(cpu,
                     "QUE-GET handle=%06x pre_next=%06x pre_prev=%06x "
                     "RETA=%06x knl=%u insn=%llu\n",
                     ar0, knlq_pre_next, knlq_pre_prev,
                     cpu->reta & C55X_PC_MASK,
                     ar0 && ar0 == q, (unsigned long long)cpu->insn_count);
        }
        if (null_handle && !knlq_null_get_logged) {
            knlq_null_get_logged = 1;
            c55x_log(cpu,
                     "QUE-GET-NULL handle=%06x pre_next=%06x pre_prev=%06x "
                     "RETA=%06x XAR5=%06x XAR7=%06x stream+16=%06x "
                     "*XAR5=%06x IER0=%04x IFR0=%04x nest=%u insn=%llu\n",
                     ar0, knlq_pre_next, knlq_pre_prev,
                     cpu->reta & C55X_PC_MASK, xar5, xar7, stream16,
                     xar5 ? (peek_dbl_ram(cpu, xar5) & C55X_WORD_MASK) : 0,
                     cpu->ier0, cpu->ifr0, cpu->irq_nest,
                     (unsigned long long)cpu->insn_count);
            knlq_flush(cpu, "QUE-GET-NULL");
        }
        return;
    }
    if (pc == BIOS_PC_QUE_PUT) {
        knlq_arg_handle = ar0;
        knlq_arg_elem = ar1;
        knlq_pre_next = ar0 ? knlq_next(cpu, ar0) : 0;
        knlq_pre_prev = ar0 ? knlq_prev(cpu, ar0) : 0;
        knlq_in_put = 1;
        if (knlq_suppress_put && q && ar0 == q && cpu->irq_nest >= 2) {
            knlq_skip_put = 1;
        }
        return;
    }
}

static void knlq_note_after(C55xCPU *cpu, uint32_t from, uint32_t next)
{
    uint32_t from_pc = from & C55X_PC_MASK;
    uint32_t next_pc = next & C55X_PC_MASK;

    knlq_init();
    if (knlq_in_ipost && from_pc == BIOS_PC_KNL_IPOST_BCC &&
        next_pc == 0x1022ddu) {
        knlq_skip_pub++;
        knlq_ev_push(cpu, KNLQ_EV_SKIP, from_pc, knlq_elem, knlq_atm_t0);
        c55x_log(cpu,
                 "KNL-SKIP-PUT elem=%06x T0=%04x count=%04x nest=%u "
                 "INTM=%u IFR0=%04x insn=%llu\n",
                 knlq_elem, knlq_atm_t0, knlq_atm_count, cpu->irq_nest,
                 !!(cpu->st1 & C55X_ST1_INTM), cpu->ifr0,
                 (unsigned long long)cpu->insn_count);
    }
    if (knlq_in_ipost && from_pc == BIOS_PC_KNL_IPOST_RET) {
        knlq_in_ipost = 0;
        if (knlq_pub_open) {
            knlq_abort(cpu, "ipost-ret-uncommitted", from_pc);
        }
    }
    if (knlq_in_get && from_pc >= BIOS_PC_QUE_GET &&
        from_pc < BIOS_PC_QUE_PUT &&
        (next_pc < BIOS_PC_QUE_GET || next_pc >= BIOS_PC_QUE_PUT)) {
        knlq_in_get = 0;
        knlq_log_get_after(cpu, from_pc);
        return;
    }
    if (knlq_in_put && from_pc >= BIOS_PC_QUE_PUT &&
        from_pc < BIOS_PC_SWI_OR &&
        (next_pc < BIOS_PC_QUE_PUT || next_pc >= BIOS_PC_SWI_OR)) {
        knlq_in_put = 0;
        knlq_log_put_after(cpu, from_pc);
    }
}

static int knlq_take_skip(C55xCPU *cpu)
{
    if (!knlq_skip_put) {
        return 0;
    }
    knlq_skip_put = 0;
    knlq_in_put = 0;
    (void)cpu;
    return 1;
}

static void knlq_note_call0(C55xCPU *cpu)
{
    knlq_init();
    c55x_log(cpu,
             "CALL-0 queue_handle=%06x AR5=%06x AC0=%010llx "
             "empty_sentinel=%u nest=%u insn=%llu\n",
             knlq_handle(cpu), cpu->xar[5] & C55X_WORD_MASK,
             (unsigned long long)cpu->ac[0],
             knlq_handle(cpu) &&
                 ((cpu->xar[5] & C55X_WORD_MASK) == knlq_handle(cpu)),
             cpu->irq_nest, (unsigned long long)cpu->insn_count);
    knlq_flush(cpu, "call0");
}

void c55x_knlq_note_iodma(C55xCPU *cpu, int clnk, unsigned n, unsigned ch)
{
    knlq_init();
    if (clnk) {
        cpu->host_clnk_n = n;
        knlq_ev_push(cpu, KNLQ_EV_CLNK, cpu->pc, ch, n);
    } else {
        cpu->host_tc_n = n;
        knlq_ev_push(cpu, KNLQ_EV_TC, cpu->pc, ch, n);
    }
}
