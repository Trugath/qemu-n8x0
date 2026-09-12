/*
 * Generic guest virtual-PC tracing and a rolling hardware-event ring.
 *
 * Host-side debugging only: no guest-visible device or ABI.
 */

#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qemu/timer.h"
#include "qemu/user-trace-pc.h"

typedef struct {
    int64_t ns;
    char text[192];
} HwEvent;

typedef struct {
    const char *name;
    uint32_t nr;
} UserTraceSyscall;

static const UserTraceSyscall user_trace_syscall_table[] = {
    { "brk", 45 },
    { "mmap", 90 },
    { "munmap", 91 },
    { "mmap2", 192 },
};

static uint64_t user_trace_pcs[USER_TRACE_PC_MAX];
static uint64_t user_trace_ring_pcs[USER_TRACE_PC_MAX];
static uint64_t user_trace_learn_pcs[USER_TRACE_PC_MAX];
static uint64_t user_trace_code_pcs[USER_TRACE_PC_MAX];
static uint32_t user_trace_syscalls[USER_TRACE_PC_MAX];
static uint64_t user_trace_mem_secs[USER_TRACE_PC_MAX];
static bool user_trace_mem_fired[USER_TRACE_PC_MAX];
static int user_trace_pc_count;
static int user_trace_ring_pc_count;
static int user_trace_learn_pc_count;
static int user_trace_code_pc_count;
static int user_trace_syscall_count;
static int user_trace_mem_count;
static unsigned user_trace_stack_word_count = USER_TRACE_STACK_WORDS_DEFAULT;
static unsigned user_trace_code_word_count = USER_TRACE_CODE_WORDS_DEFAULT;
static HwEvent hw_event_ring[HW_EVENT_RING_SIZE];
static unsigned hw_event_ring_head;
static unsigned hw_event_ring_count;
static bool user_trace_learned;
static uint64_t user_trace_learned_ttbr0;
static uint32_t user_trace_learned_asid;
static bool user_trace_have_brk;
static uint32_t user_trace_brk;
static bool user_trace_have_svc_ret;
static uint32_t user_trace_svc_ret_pc;
static uint32_t user_trace_svc_nr;
static uint32_t user_trace_svc_r0;
static uint32_t user_trace_svc_r1;
static uint32_t user_trace_svc_r2;
static uint32_t user_trace_svc_r3;
static uint32_t user_trace_svc_r4;
static uint32_t user_trace_svc_r5;

static bool list_match(const uint64_t *pcs, int count, uint64_t pc)
{
    int i;

    for (i = 0; i < count; i++) {
        if (pcs[i] == pc) {
            return true;
        }
    }
    return false;
}

static void parse_u64_list(const char *list, uint64_t *out, int *count,
                           int max, const char *optname)
{
    const char *p = list;

    while (*p) {
        uint64_t value;
        const char *end = NULL;
        int err;

        while (*p == ',' || g_ascii_isspace(*p)) {
            p++;
        }
        if (!*p) {
            break;
        }
        err = qemu_strtou64(p, &end, 0, &value);
        if (err || end == p ||
            (*end != '\0' && *end != ',' && !g_ascii_isspace(*end))) {
            error_report("invalid %s value near '%s'", optname, p);
            exit(1);
        }
        if (*count >= max) {
            error_report("%s accepts at most %d values", optname, max);
            exit(1);
        }
        out[(*count)++] = value;
        p = end;
    }
}

void user_trace_pc_parse(const char *list)
{
    parse_u64_list(list, user_trace_pcs, &user_trace_pc_count,
                   USER_TRACE_PC_MAX, "-user-trace-pc");
}

void user_trace_ring_pc_parse(const char *list)
{
    parse_u64_list(list, user_trace_ring_pcs, &user_trace_ring_pc_count,
                   USER_TRACE_PC_MAX, "-user-trace-ring-pc");
}

void user_trace_learn_pc_parse(const char *list)
{
    parse_u64_list(list, user_trace_learn_pcs, &user_trace_learn_pc_count,
                   USER_TRACE_PC_MAX, "-user-trace-learn-pc");
}

void user_trace_code_pc_parse(const char *list)
{
    parse_u64_list(list, user_trace_code_pcs, &user_trace_code_pc_count,
                   USER_TRACE_PC_MAX, "-user-trace-code-pc");
}

void user_trace_syscall_parse(const char *list)
{
    const char *p = list;

    while (*p) {
        const char *end;
        uint64_t nr;
        bool found = false;
        int i;

        while (*p == ',' || g_ascii_isspace(*p)) {
            p++;
        }
        if (!*p) {
            break;
        }
        end = p;
        while (*end && *end != ',' && !g_ascii_isspace(*end)) {
            end++;
        }
        for (i = 0; i < (int)G_N_ELEMENTS(user_trace_syscall_table); i++) {
            if ((size_t)(end - p) == strlen(user_trace_syscall_table[i].name) &&
                g_ascii_strncasecmp(p, user_trace_syscall_table[i].name,
                                    end - p) == 0) {
                nr = user_trace_syscall_table[i].nr;
                found = true;
                break;
            }
        }
        if (!found) {
            const char *num_end = NULL;

            if (qemu_strtou64(p, &num_end, 0, &nr) || num_end != end) {
                error_report("invalid -user-trace-syscall value near '%s'", p);
                exit(1);
            }
        }
        if (user_trace_syscall_count >= USER_TRACE_PC_MAX) {
            error_report("-user-trace-syscall accepts at most %d values",
                         USER_TRACE_PC_MAX);
            exit(1);
        }
        user_trace_syscalls[user_trace_syscall_count++] = (uint32_t)nr;
        p = end;
    }
}

void user_trace_mem_times_parse(const char *list)
{
    parse_u64_list(list, user_trace_mem_secs, &user_trace_mem_count,
                   USER_TRACE_PC_MAX, "-user-trace-mem-times");
}

void user_trace_pc_set_stack_words(unsigned words)
{
    if (words > 64) {
        error_report("-user-trace-stack-words accepts at most 64");
        exit(1);
    }
    user_trace_stack_word_count = words;
}

void user_trace_pc_set_code_words(unsigned words)
{
    if (words > 64) {
        error_report("-user-trace-code-words accepts at most 64");
        exit(1);
    }
    user_trace_code_word_count = words;
}

unsigned user_trace_pc_stack_words(void)
{
    return user_trace_stack_word_count;
}

unsigned user_trace_pc_code_words(void)
{
    return user_trace_code_word_count;
}

bool user_trace_pc_enabled(void)
{
    return user_trace_pc_count > 0;
}

bool user_trace_pc_match(uint64_t pc)
{
    return list_match(user_trace_pcs, user_trace_pc_count, pc);
}

bool user_trace_ring_pc_match(uint64_t pc)
{
    return list_match(user_trace_ring_pcs, user_trace_ring_pc_count, pc);
}

bool user_trace_learn_pc_match(uint64_t pc)
{
    return list_match(user_trace_learn_pcs, user_trace_learn_pc_count, pc);
}

bool user_trace_code_pc_match(uint64_t pc)
{
    return list_match(user_trace_code_pcs, user_trace_code_pc_count, pc);
}

bool user_trace_syscall_enabled(void)
{
    return user_trace_syscall_count > 0;
}

bool user_trace_syscall_match(uint32_t nr)
{
    int i;

    for (i = 0; i < user_trace_syscall_count; i++) {
        if (user_trace_syscalls[i] == nr) {
            return true;
        }
    }
    return false;
}

const char *user_trace_syscall_name(uint32_t nr)
{
    int i;

    for (i = 0; i < (int)G_N_ELEMENTS(user_trace_syscall_table); i++) {
        if (user_trace_syscall_table[i].nr == nr) {
            return user_trace_syscall_table[i].name;
        }
    }
    return "unknown";
}

bool user_trace_svc_ret_pending(uint32_t pc)
{
    return user_trace_have_svc_ret && user_trace_svc_ret_pc == pc;
}

void user_trace_svc_arm_enter(uint32_t pc, uint32_t retpc, uint32_t nr,
                              uint32_t r0, uint32_t r1, uint32_t r2,
                              uint32_t r3, uint32_t r4, uint32_t r5,
                              uint64_t ttbr0, uint32_t asid)
{
    int64_t ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);

    user_trace_have_svc_ret = true;
    user_trace_svc_ret_pc = retpc;
    user_trace_svc_nr = nr;
    user_trace_svc_r0 = r0;
    user_trace_svc_r1 = r1;
    user_trace_svc_r2 = r2;
    user_trace_svc_r3 = r3;
    user_trace_svc_r4 = r4;
    user_trace_svc_r5 = r5;
    qemu_log("user-trace-svc ns=%" PRId64 " nr=%u name=%s pc=0x%" PRIx32
             " retpc=0x%" PRIx32 " ttbr0=0x%" PRIx64 " asid=0x%" PRIx32
             " r0=0x%" PRIx32 " r1=0x%" PRIx32 " r2=0x%" PRIx32
             " r3=0x%" PRIx32 " r4=0x%" PRIx32 " r5=0x%" PRIx32 "\n",
             ns, nr, user_trace_syscall_name(nr), pc, retpc, ttbr0, asid,
             r0, r1, r2, r3, r4, r5);
}

void user_trace_svc_arm_leave(uint32_t pc, uint32_t r0)
{
    int64_t ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    int32_t signed_r0 = (int32_t)r0;
    int err = 0;

    if (signed_r0 < 0 && signed_r0 > -4096) {
        err = -signed_r0;
    }
    qemu_log("user-trace-svc-ret ns=%" PRId64 " nr=%u name=%s pc=0x%" PRIx32
             " r0=0x%" PRIx32 " errno=%d"
             " arg0=0x%" PRIx32 " arg1=0x%" PRIx32 " arg2=0x%" PRIx32
             " arg3=0x%" PRIx32 " arg4=0x%" PRIx32 " arg5=0x%" PRIx32 "\n",
             ns, user_trace_svc_nr, user_trace_syscall_name(user_trace_svc_nr),
             pc, r0, err, user_trace_svc_r0, user_trace_svc_r1,
             user_trace_svc_r2, user_trace_svc_r3, user_trace_svc_r4,
             user_trace_svc_r5);
    if (user_trace_svc_nr == 45 && err == 0) {
        user_trace_note_brk(r0);
    }
    user_trace_have_svc_ret = false;
}

void user_trace_note_brk(uint32_t value)
{
    user_trace_brk = value;
    user_trace_have_brk = true;
}

bool user_trace_last_brk(uint32_t *out)
{
    if (!user_trace_have_brk) {
        return false;
    }
    *out = user_trace_brk;
    return true;
}

void user_trace_learn_from_hit(uint32_t pc, uint64_t ttbr0, uint32_t asid)
{
    if (user_trace_learned) {
        return;
    }
    user_trace_learned = true;
    user_trace_learned_ttbr0 = ttbr0;
    user_trace_learned_asid = asid;
    qemu_log("user-trace-learn ns=%" PRId64 " pc=0x%" PRIx32
             " ttbr0=0x%" PRIx64 " asid=0x%" PRIx32 "\n",
             qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), pc, ttbr0, asid);
}

bool user_trace_as_learned(void)
{
    return user_trace_learned;
}

bool user_trace_as_matches(uint64_t ttbr0, uint32_t asid)
{
    /*
     * Linux can reassign CONTEXTIDR.ASID while keeping the same TTBR0.
     * Treat the page-table base as the process identity.
     */
    if (!user_trace_learned || user_trace_learned_ttbr0 != ttbr0) {
        return false;
    }
    user_trace_learned_asid = asid;
    return true;
}

bool user_trace_allow_as(uint32_t pc, uint64_t ttbr0, uint32_t asid)
{
    if (user_trace_learn_pc_count == 0) {
        return true;
    }
    if (!user_trace_learned) {
        if (user_trace_learn_pc_match(pc)) {
            user_trace_learn_from_hit(pc, ttbr0, asid);
            return true;
        }
        return false;
    }
    return user_trace_as_matches(ttbr0, asid);
}

int user_trace_mem_due(int64_t sec)
{
    int i;

    for (i = 0; i < user_trace_mem_count; i++) {
        if (!user_trace_mem_fired[i] && sec >= 0 &&
            (uint64_t)sec >= user_trace_mem_secs[i]) {
            return i;
        }
    }
    return -1;
}

void user_trace_mem_mark(int index)
{
    if (index >= 0 && index < user_trace_mem_count) {
        user_trace_mem_fired[index] = true;
    }
}

void user_trace_pc_log(const char *line)
{
    qemu_log("%s\n", line);
}

void hw_event_ring_record(const char *fmt, ...)
{
    HwEvent *event;
    va_list ap;

    event = &hw_event_ring[hw_event_ring_head];
    event->ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    va_start(ap, fmt);
    g_vsnprintf(event->text, sizeof(event->text), fmt, ap);
    va_end(ap);
    hw_event_ring_head = (hw_event_ring_head + 1) % HW_EVENT_RING_SIZE;
    if (hw_event_ring_count < HW_EVENT_RING_SIZE) {
        hw_event_ring_count++;
    }
}

void hw_event_ring_dump(void)
{
    unsigned start;
    unsigned i;

    if (!hw_event_ring_count) {
        qemu_log("hw-event-ring empty\n");
        return;
    }
    start = (hw_event_ring_head + HW_EVENT_RING_SIZE - hw_event_ring_count) %
            HW_EVENT_RING_SIZE;
    qemu_log("hw-event-ring count=%u\n", hw_event_ring_count);
    for (i = 0; i < hw_event_ring_count; i++) {
        unsigned idx = (start + i) % HW_EVENT_RING_SIZE;

        qemu_log("hw-event-ring [%u] ns=%" PRId64 " %s\n",
                 i, hw_event_ring[idx].ns, hw_event_ring[idx].text);
    }
}

void hw_event_ring_dump_unique(uint64_t ttbr0, uint32_t asid, uint32_t pc)
{
    static uint64_t keys[32];
    static unsigned used;
    uint64_t key = ttbr0 ^ ((uint64_t)asid << 48) ^ ((uint64_t)pc << 16);
    unsigned i;

    for (i = 0; i < used; i++) {
        if (keys[i] == key) {
            return;
        }
    }
    if (used < G_N_ELEMENTS(keys)) {
        keys[used++] = key;
    }
    hw_event_ring_dump();
}
