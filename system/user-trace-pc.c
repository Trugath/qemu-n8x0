/*
 * Generic guest virtual-PC tracing and a rolling hardware-event ring.
 *
 * Host-side debugging only: no guest-visible device or ABI.
 *
 * Syscall numbers are ARM EABI values with __NR_SYSCALL_BASE == 0, matching
 * Linux 2.6.21 (Diablo) unistd-common.h. rt_tgsigqueueinfo (363) arrived in
 * 2.6.31 and is listed only so a later guest cannot hide a send.
 */

#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qemu/timer.h"
#include "qemu/user-trace-pc.h"
#include "hw/core/cpu.h"
#include "exec/cpu-common.h"
#include "sysemu/runstate.h"

void omap2420_dsp_pcm1_read_entered(uint32_t nbytes);
void omap2420_dsp_pcm1_read_result(uint32_t nbytes, uint32_t got,
                                   const uint8_t *buf, uint32_t n);
void omap2420_dsp_pcm1_read_finished(void);
void omap2420_dsp_pcm1_n2_finished(void);

#define LINUX_O_NONBLOCK 0x800
#define USER_TRACE_NOSMQ_MAX 256
#define USER_TRACE_NOSMQ_MSG 16

#define USER_TRACE_PROC_MAX 256
#define USER_TRACE_NAME_MAX 48
#define USER_TRACE_PENDING_MAX 64
#define USER_TRACE_RETPC_MAX 64
#define USER_TRACE_SOCK_MAX 64
#define USER_TRACE_PATH_MAX 96
#define USER_TRACE_THREAD_MAX 16
#define USER_TRACE_NEST_MAX 8
#define USER_TRACE_FD_MAX 256

typedef struct {
    int64_t ns;
    char text[192];
} HwEvent;

typedef struct {
    const char *name;
    uint32_t nr;
} UserTraceSyscall;

typedef struct {
    bool used;
    uint64_t ttbr0;
    uint32_t pid;
    uint32_t ppid;
    uint32_t tid;
    char name[USER_TRACE_NAME_MAX];
} UserTraceProc;

typedef struct {
    bool used;
    uint32_t retpc;
    uint32_t nr;
    uint32_t pc;
    uint32_t lr;
    uint32_t r[7];
    uint64_t ttbr0;
    uint32_t asid;
    int64_t enter_ns;
    uint32_t io_fd;
    uint32_t buf_addr;
    uint32_t buf_len;
    bool is_read;
    bool has_io;
    uint8_t payload[USER_TRACE_SOCK_BYTES_DEFAULT];
    uint32_t payload_len;
    uint32_t msg_prio;
    bool have_msg_prio;
    int nest;
    uint32_t tls;
    int restarts;
    char path[USER_TRACE_PATH_MAX];
} UserTracePending;

typedef struct {
    uint32_t prio;
    uint8_t payload[USER_TRACE_NOSMQ_MSG];
    uint32_t payload_len;
    int64_t insert_ns;
} UserTraceNosmqSlot;

typedef struct {
    uint32_t nr;
    uint32_t r[7];
    uint32_t pc;
    int64_t enter_ns;
    int restarts;
    int interrupts;
} UserTraceNest;

typedef struct {
    bool used;
    uint64_t ttbr0;
    uint32_t tls;
    uint32_t tid;
    uint32_t pid;
    int nest;
    int clones;
    UserTraceNest stack[USER_TRACE_NEST_MAX];
} UserTraceThread;

typedef struct {
    bool used;
    uint64_t ttbr0;
    uint32_t fd;
    char path[USER_TRACE_PATH_MAX];
    char how[16];
    int64_t ns;
} UserTraceFd;

typedef struct {
    bool used;
    uint64_t ttbr0;
    uint32_t fd;
    uint32_t pid;
    char role[12];
    char name[USER_TRACE_NAME_MAX];
    char path[USER_TRACE_PATH_MAX];
    int64_t ns;
    bool paired;
} UserTraceSock;

/*
 * ARM EABI / Linux 2.6.21 (Diablo). Numbers from asm-arm/unistd-common.h
 * with __NR_SYSCALL_BASE 0.
 */
static const UserTraceSyscall user_trace_syscall_table[] = {
    { "restart_syscall", 0 },
    { "exit", 1 },
    { "fork", 2 },
    { "read", 3 },
    { "write", 4 },
    { "open", 5 },
    { "close", 6 },
    { "execve", 11 },
    { "lseek", 19 },
    { "getpid", 20 },
    { "getppid", 64 },
    { "pause", 29 },
    { "kill", 37 },
    { "dup", 41 },
    { "brk", 45 },
    { "ioctl", 54 },
    { "fcntl", 55 },
    { "dup2", 63 },
    { "sigsuspend", 72 },
    { "wait4", 114 },
    { "_llseek", 140 },
    { "mmap", 90 },
    { "munmap", 91 },
    { "sigreturn", 119 },
    { "clone", 120 },
    { "select", 142 },
    { "readv", 145 },
    { "writev", 146 },
    { "nanosleep", 162 },
    { "poll", 168 },
    { "rt_sigreturn", 173 },
    { "rt_sigaction", 174 },
    { "rt_sigprocmask", 175 },
    { "rt_sigtimedwait", 177 },
    { "rt_sigqueueinfo", 178 },
    { "rt_sigsuspend", 179 },
    { "pread64", 180 },
    { "vfork", 190 },
    { "mmap2", 192 },
    { "gettid", 224 },
    { "tkill", 238 },
    { "futex", 240 },
    { "exit_group", 248 },
    { "set_tid_address", 256 },
    { "timer_create", 257 },
    { "timer_settime", 258 },
    { "clock_gettime", 263 },
    { "clock_nanosleep", 265 },
    { "tgkill", 268 },
    { "mq_open", 274 },
    { "mq_unlink", 275 },
    { "mq_timedsend", 276 },
    { "mq_timedreceive", 277 },
    { "mq_getsetattr", 279 },
    { "socket", 281 },
    { "bind", 282 },
    { "connect", 283 },
    { "listen", 284 },
    { "accept", 285 },
    { "send", 289 },
    { "sendto", 290 },
    { "recv", 291 },
    { "recvfrom", 292 },
    { "sendmsg", 296 },
    { "recvmsg", 297 },
    { "openat", 322 },
    { "rt_tgsigqueueinfo", 363 },
    { "set_tls", 0xf0005 },
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
static bool user_trace_syscall_global;
static bool user_trace_proc_enabled;
static bool user_trace_dsmesock;
static bool user_trace_bme_syscalls;
static bool user_trace_have_sock_window;
static int64_t user_trace_sock_window_start;
static int64_t user_trace_sock_window_end;
static unsigned user_trace_sock_byte_count = USER_TRACE_SOCK_BYTES_DEFAULT;
static int64_t user_trace_sample_period;
static int64_t user_trace_quit_sec;
static int64_t user_trace_dump_sec;
static bool user_trace_dumped_state;
static bool user_trace_quit_requested;
static QEMUTimer *user_trace_quit_timer;
static QEMUTimer *user_trace_dump_timer;
static UserTraceThread user_trace_threads[USER_TRACE_THREAD_MAX];
static UserTraceFd user_trace_fds[USER_TRACE_FD_MAX];
static uint32_t user_trace_retpcs[USER_TRACE_RETPC_MAX];
static int user_trace_retpc_count;
static uint64_t user_trace_watched_bme_ttbr0;
static bool user_trace_have_bme_ttbr0;
static int user_trace_bme_syscall_depth;
static char user_trace_ret_extra[512];
static struct {
    bool have;
    uint64_t ttbr0;
    uint32_t fd;
    uint32_t flags;
    bool o_nonblock;
    bool have_attr;
    int32_t mq_flags;
    int32_t mq_maxmsg;
    int32_t mq_msgsize;
    int32_t mq_curmsgs;
    int depth;
    int mismatches;
    int send30;
    int send15;
    int recv30;
    int recv15;
    int recv_other;
    bool saw_fill;
    int64_t fill_ns;
    uint32_t fill_prio;
    UserTraceNosmqSlot slots[USER_TRACE_NOSMQ_MAX];
    char name[USER_TRACE_PATH_MAX];
} user_trace_nosmq;
static char nosmq_open_name[USER_TRACE_PATH_MAX];
static uint32_t nosmq_open_flags;
static int32_t nosmq_open_mq_flags;
static int32_t nosmq_open_maxmsg;
static int32_t nosmq_open_msgsize;
static int32_t nosmq_open_curmsgs;
static bool nosmq_open_have_attr;
static UserTraceSock user_trace_socks[USER_TRACE_SOCK_MAX];
static char user_trace_pending_unix_path[USER_TRACE_PATH_MAX];
static uint64_t user_trace_pending_unix_ttbr0;
static uint32_t user_trace_pending_unix_fd;
static bool user_trace_pending_unix_is_bind;
static bool user_trace_have_window;
static int64_t user_trace_window_start;
static int64_t user_trace_window_end;
static bool user_trace_have_write_window;
static int64_t user_trace_write_window_start;
static int64_t user_trace_write_window_end;
#define USER_TRACE_WRITE_NAME_MAX 256
static char user_trace_write_name[USER_TRACE_WRITE_NAME_MAX];
static UserTraceProc user_trace_procs[USER_TRACE_PROC_MAX];
static UserTracePending user_trace_pending[USER_TRACE_PENDING_MAX];
static char user_trace_last_exec_name[USER_TRACE_NAME_MAX];
static uint32_t user_trace_last_exec_pid;
static uint64_t user_trace_last_exec_ttbr0;
static int64_t user_trace_last_exec_ns;
static uint32_t user_trace_last_fork_child;
static uint32_t user_trace_last_fork_ppid;
static struct {
    uint32_t pid;
    char name[USER_TRACE_NAME_MAX];
} user_trace_pid_names[USER_TRACE_PROC_MAX];

static UserTraceProc *proc_find(uint64_t ttbr0);
static void bme_note_ttbr0(uint64_t ttbr0);
static void nosmq_dump(const char *why);
static void nosmq_bind(uint64_t ttbr0, uint32_t fd, const char *path);
static bool nosmq_is_fd(uint64_t ttbr0, uint32_t fd);
static void nosmq_send(const UserTracePending *pending, int64_t now);
static void nosmq_recv(const UserTracePending *pending, int64_t now);
static void fill_eret_extra(UserTracePending *pending, uint32_t r0);
static bool svc_verbose(uint32_t nr);

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

static void parse_sec_window(const char *list, int64_t *start, int64_t *end,
                             bool *have, const char *optname)
{
    uint64_t values[2];
    int count = 0;

    parse_u64_list(list, values, &count, 2, optname);
    if (count != 2 || values[1] < values[0]) {
        error_report("%s expects start,end virtual seconds", optname);
        exit(1);
    }
    *start = (int64_t)values[0];
    *end = (int64_t)values[1];
    *have = true;
}

static bool name_matches(const char *haystack, const char *needle)
{
    const char *p;

    if (!haystack || !needle || !needle[0]) {
        return false;
    }
    for (p = haystack; *p; p++) {
        const char *h = p;
        const char *n = needle;

        while (*h && *n &&
               g_ascii_tolower(*h) == g_ascii_tolower(*n)) {
            h++;
            n++;
        }
        if (!*n) {
            return true;
        }
    }
    return false;
}

static bool csv_name_matches(const char *haystack, const char *csv)
{
    const char *start = csv;
    const char *end;

    if (!haystack || !haystack[0] || !csv || !csv[0]) {
        return false;
    }
    while (*start) {
        char needle[64];
        size_t n;

        while (*start == ',' || *start == ' ') {
            start++;
        }
        if (!*start) {
            break;
        }
        end = start;
        while (*end && *end != ',') {
            end++;
        }
        n = (size_t)(end - start);
        if (n >= sizeof(needle)) {
            n = sizeof(needle) - 1;
        }
        memcpy(needle, start, n);
        needle[n] = 0;
        while (n && needle[n - 1] == ' ') {
            needle[--n] = 0;
        }
        if (needle[0] && name_matches(haystack, needle)) {
            return true;
        }
        start = *end ? end + 1 : end;
    }
    return false;
}

static bool watch_matches_ttbr0(uint64_t ttbr0)
{
    const UserTraceProc *slot;

    if (!user_trace_write_name[0]) {
        return false;
    }
    slot = proc_find(ttbr0);
    if (slot && slot->name[0] &&
        csv_name_matches(slot->name, user_trace_write_name)) {
        return true;
    }
    return csv_name_matches(user_trace_last_exec_name, user_trace_write_name);
}

static const char *basename_of(const char *path)
{
    const char *slash;

    if (!path) {
        return "";
    }
    slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static UserTraceProc *proc_find(uint64_t ttbr0)
{
    int i;

    for (i = 0; i < USER_TRACE_PROC_MAX; i++) {
        if (user_trace_procs[i].used && user_trace_procs[i].ttbr0 == ttbr0) {
            return &user_trace_procs[i];
        }
    }
    return NULL;
}

static UserTraceProc *proc_find_pid(uint32_t pid)
{
    int i;

    if (!pid) {
        return NULL;
    }
    for (i = 0; i < USER_TRACE_PROC_MAX; i++) {
        if (user_trace_procs[i].used && user_trace_procs[i].pid == pid) {
            return &user_trace_procs[i];
        }
    }
    return NULL;
}

static UserTraceProc *proc_ensure(uint64_t ttbr0)
{
    UserTraceProc *slot = proc_find(ttbr0);
    int i;

    if (slot) {
        return slot;
    }
    for (i = 0; i < USER_TRACE_PROC_MAX; i++) {
        if (!user_trace_procs[i].used) {
            slot = &user_trace_procs[i];
            memset(slot, 0, sizeof(*slot));
            slot->used = true;
            slot->ttbr0 = ttbr0;
            return slot;
        }
    }
    return NULL;
}

static void proc_log(const char *why, const UserTraceProc *slot)
{
    if (!slot) {
        return;
    }
    qemu_log("user-trace-proc ns=%" PRId64 " why=%s ttbr0=0x%" PRIx64
             " pid=%u ppid=%u tid=%u name=%s\n",
             qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), why, slot->ttbr0,
             slot->pid, slot->ppid, slot->tid,
             slot->name[0] ? slot->name : "?");
}

static void pid_name_store(uint32_t pid, const char *name)
{
    const char *base;
    int i;
    int empty = -1;

    if (!pid || !name || !name[0]) {
        return;
    }
    base = basename_of(name);
    for (i = 0; i < USER_TRACE_PROC_MAX; i++) {
        if (user_trace_pid_names[i].pid == pid) {
            g_strlcpy(user_trace_pid_names[i].name, base,
                      sizeof(user_trace_pid_names[i].name));
            return;
        }
        if (empty < 0 && !user_trace_pid_names[i].pid) {
            empty = i;
        }
    }
    if (empty >= 0) {
        user_trace_pid_names[empty].pid = pid;
        g_strlcpy(user_trace_pid_names[empty].name, base,
                  sizeof(user_trace_pid_names[empty].name));
    }
}

static const char *pid_name_lookup(uint32_t pid)
{
    int i;

    if (!pid) {
        return NULL;
    }
    for (i = 0; i < USER_TRACE_PROC_MAX; i++) {
        if (user_trace_pid_names[i].pid == pid &&
            user_trace_pid_names[i].name[0]) {
            return user_trace_pid_names[i].name;
        }
    }
    return NULL;
}

static void proc_set_name(UserTraceProc *slot, const char *name)
{
    const char *base;

    if (!slot || !name || !name[0]) {
        return;
    }
    base = basename_of(name);
    if (!base[0]) {
        return;
    }
    if (g_strcmp0(slot->name, base) == 0) {
        return;
    }
    g_strlcpy(slot->name, base, sizeof(slot->name));
    if (slot->pid) {
        pid_name_store(slot->pid, base);
    }
    proc_log("name", slot);
}

static void proc_note_execve(uint64_t ttbr0, const char *path)
{
    UserTraceProc *slot = proc_ensure(ttbr0);
    char stripped[USER_TRACE_PATH_MAX];
    const char *use = path;
    const char *space;
    const char *base;

    if (path) {
        g_strlcpy(stripped, path, sizeof(stripped));
        space = strchr(stripped, ' ');
        if (space) {
            stripped[space - stripped] = 0;
            use = stripped;
        }
    }
    base = basename_of(use);

    g_strlcpy(user_trace_last_exec_name, base,
              sizeof(user_trace_last_exec_name));
    user_trace_last_exec_ttbr0 = ttbr0;
    user_trace_last_exec_ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    if (slot && !slot->pid && user_trace_last_fork_child) {
        slot->pid = user_trace_last_fork_child;
    }
    user_trace_last_exec_pid = slot && slot->pid ? slot->pid : 0;
    if (user_trace_last_exec_pid) {
        pid_name_store(user_trace_last_exec_pid, use);
    }
    if (slot) {
        proc_set_name(slot, use);
        if (slot->pid) {
            UserTraceProc *by_pid = proc_find_pid(slot->pid);
            if (by_pid && by_pid != slot) {
                proc_set_name(by_pid, use);
            }
        }
    }
    if (g_strrstr(base, "bme_RX")) {
        bme_note_ttbr0(ttbr0);
    }
}

static void proc_maybe_inherit_exec(UserTraceProc *slot)
{
    int64_t now;

    if (!slot || slot->name[0] || !user_trace_last_exec_name[0]) {
        return;
    }
    now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    if (now - user_trace_last_exec_ns > 1000000000LL) {
        return;
    }
    if (slot->ttbr0 != user_trace_last_exec_ttbr0 &&
        !(user_trace_last_exec_pid && slot->pid &&
          slot->pid == user_trace_last_exec_pid)) {
        return;
    }
    proc_set_name(slot, user_trace_last_exec_name);
}

static void proc_note_pid(uint64_t ttbr0, uint32_t pid)
{
    UserTraceProc *slot;
    UserTraceProc *by_pid;

    if (!pid || (int32_t)pid < 0) {
        return;
    }
    slot = proc_ensure(ttbr0);
    if (!slot) {
        return;
    }
    if (slot->pid != pid) {
        slot->pid = pid;
        proc_log("pid", slot);
    }
    if (!slot->name[0] && pid_name_lookup(pid)) {
        proc_set_name(slot, pid_name_lookup(pid));
    }
    by_pid = proc_find_pid(pid);
    if (by_pid && by_pid != slot && by_pid->name[0] && !slot->name[0]) {
        proc_set_name(slot, by_pid->name);
    }
    if (user_trace_last_exec_pid == pid && user_trace_last_exec_name[0]) {
        proc_set_name(slot, user_trace_last_exec_name);
    }
    proc_maybe_inherit_exec(slot);
}

static void proc_note_tid(uint64_t ttbr0, uint32_t tid)
{
    UserTraceProc *slot;

    if (!tid || (int32_t)tid < 0) {
        return;
    }
    slot = proc_ensure(ttbr0);
    if (!slot) {
        return;
    }
    if (slot->tid != tid) {
        slot->tid = tid;
        proc_log("tid", slot);
    }
    proc_maybe_inherit_exec(slot);
}

static const UserTraceProc *proc_lookup(uint64_t ttbr0)
{
    UserTraceProc *slot = proc_find(ttbr0);

    if (slot) {
        proc_maybe_inherit_exec(slot);
    }
    return slot;
}

static bool in_sec_window(bool have, int64_t start, int64_t end)
{
    int64_t sec;

    if (!have) {
        return true;
    }
    sec = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) / 1000000000LL;
    return sec >= start && sec <= end;
}

static bool is_identity_nr(uint32_t nr)
{
    return nr == 1 || nr == 2 || nr == 11 || nr == 114 || nr == 120 ||
           nr == 190 || nr == 224 || nr == 248 || nr == 256;
}

static bool is_bme_lifetime_nr(uint32_t nr)
{
    return nr == 0 || nr == 1 || nr == 5 || nr == 6 || nr == 29 ||
           nr == 41 || nr == 63 || nr == 72 || nr == 119 || nr == 120 ||
           nr == 173 || nr == 177 || nr == 179 || nr == 224 || nr == 248 ||
           nr == 256 || nr == 257 || nr == 258 || nr == 274 || nr == 275 ||
           nr == 276 || nr == 277 || nr == 279 || nr == 281 ||
           nr == 282 || nr == 283 || nr == 322 || nr == 0xf0005;
}

static bool is_sigreturn_nr(uint32_t nr)
{
    return nr == 119 || nr == 173;
}

static bool is_noreturn_nr(uint32_t nr)
{
    return nr == 1 || nr == 11 || nr == 119 || nr == 173 || nr == 248;
}

static void bme_note_ttbr0(uint64_t ttbr0)
{
    UserTraceProc *slot;

    if (!ttbr0) {
        return;
    }
    if (user_trace_have_bme_ttbr0 && user_trace_watched_bme_ttbr0 == ttbr0) {
        return;
    }
    user_trace_watched_bme_ttbr0 = ttbr0;
    user_trace_have_bme_ttbr0 = true;
    slot = proc_ensure(ttbr0);
    if (slot && user_trace_last_exec_name[0]) {
        proc_set_name(slot, user_trace_last_exec_name);
    }
    qemu_log("user-trace-proc ns=%" PRId64 " why=bme-as ttbr0=0x%" PRIx64
             " name=%s\n",
             qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), ttbr0,
             user_trace_last_exec_name[0] ? user_trace_last_exec_name : "bme_RX-44");
}

static const char *erestart_name(int32_t r0)
{
    switch (-r0) {
    case 512:
        return "ERESTARTSYS";
    case 513:
        return "ERESTARTNOINTR";
    case 514:
        return "ERESTARTNOHAND";
    case 516:
        return "ERESTART_RESTARTBLOCK";
    default:
        return NULL;
    }
}

static UserTraceThread *thread_find(uint64_t ttbr0, uint32_t tls)
{
    int i;

    for (i = 0; i < USER_TRACE_THREAD_MAX; i++) {
        if (user_trace_threads[i].used &&
            user_trace_threads[i].ttbr0 == ttbr0 &&
            user_trace_threads[i].tls == tls) {
            return &user_trace_threads[i];
        }
    }
    return NULL;
}

static UserTraceThread *thread_ensure(uint64_t ttbr0, uint32_t tls)
{
    UserTraceThread *slot = thread_find(ttbr0, tls);
    int i;

    if (slot) {
        return slot;
    }
    for (i = 0; i < USER_TRACE_THREAD_MAX; i++) {
        if (!user_trace_threads[i].used) {
            slot = &user_trace_threads[i];
            memset(slot, 0, sizeof(*slot));
            slot->used = true;
            slot->ttbr0 = ttbr0;
            slot->tls = tls;
            return slot;
        }
    }
    return NULL;
}

static void thread_log_new(const char *why, const UserTraceThread *th,
                           uint32_t extra)
{
    if (!th) {
        return;
    }
    qemu_log("user-trace-thread ns=%" PRId64 " why=%s ttbr0=0x%" PRIx64
             " tls=0x%" PRIx32 " tid=%u pid=%u extra=%u nest=%d\n",
             qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), why, th->ttbr0, th->tls,
             th->tid, th->pid, extra, th->nest);
}

static void thread_enter(uint64_t ttbr0, uint32_t tls, uint32_t nr,
                         const uint32_t *r, uint32_t pc, uint32_t *tid_out,
                         int *nest_out, uint32_t *out_nr)
{
    UserTraceThread *th;
    const UserTraceProc *proc = proc_lookup(ttbr0);

    *tid_out = proc ? proc->tid : 0;
    *nest_out = 0;
    *out_nr = 0;
    if (!user_trace_is_bme_as(ttbr0)) {
        return;
    }
    if (is_noreturn_nr(nr) && nr != 120) {
        *tid_out = 0;
        return;
    }
    th = thread_ensure(ttbr0, tls);
    if (!th) {
        return;
    }
    if (proc) {
        th->pid = proc->pid;
        if (!th->tid && proc->tid) {
            th->tid = proc->tid;
        }
    }
    if (th->nest > 0 && th->stack[th->nest - 1].nr == nr &&
        th->stack[th->nest - 1].pc == pc) {
        th->stack[th->nest - 1].restarts++;
        memcpy(th->stack[th->nest - 1].r, r, sizeof(th->stack[th->nest - 1].r));
        *tid_out = th->tid;
        *nest_out = th->nest;
        *out_nr = nr;
        return;
    }
    if (th->nest > 0 && !is_sigreturn_nr(nr) && nr != 0) {
        th->stack[th->nest - 1].interrupts++;
        *out_nr = th->stack[th->nest - 1].nr;
    }
    if (th->nest < USER_TRACE_NEST_MAX) {
        UserTraceNest *nest = &th->stack[th->nest];

        nest->nr = nr;
        memcpy(nest->r, r, sizeof(nest->r));
        nest->pc = pc;
        nest->enter_ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        nest->restarts = 0;
        nest->interrupts = 0;
        th->nest++;
    }
    *tid_out = th->tid;
    *nest_out = th->nest;
}

static void thread_leave(uint64_t ttbr0, uint32_t tls, uint32_t nr,
                         uint32_t r0)
{
    UserTraceThread *th = thread_find(ttbr0, tls);
    const char *erestart;
    UserTraceNest *nest;

    if (!th || th->nest <= 0) {
        return;
    }
    nest = &th->stack[th->nest - 1];
    if (nest->nr != nr && th->nest > 1) {
        int i;

        for (i = th->nest - 1; i >= 0; i--) {
            if (th->stack[i].nr == nr) {
                nest = &th->stack[i];
                break;
            }
        }
    }
    if (nr == 224 && (int32_t)r0 > 0) {
        th->tid = r0;
        thread_log_new("gettid", th, r0);
    }
    if (nr == 120 && (int32_t)r0 > 0) {
        th->clones++;
        thread_log_new("clone-parent", th, r0);
    }
    if (nr == 120 && r0 == 0) {
        thread_log_new("clone-child", th, 0);
    }
    if ((nr == 1 || nr == 248) && th->nest > 0) {
        thread_log_new(nr == 248 ? "exit_group" : "exit", th, r0);
    }
    erestart = erestart_name((int32_t)r0);
    if (erestart) {
        nest->restarts++;
        qemu_log("user-trace-erestart ns=%" PRId64 " tls=0x%" PRIx32
                 " tid=%u nr=%u name=%s %s r0=0x%" PRIx32 "\n",
                 qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), th->tls, th->tid, nr,
                 user_trace_syscall_name(nr), erestart, r0);
        return;
    }
    if (th->nest > 0 && th->stack[th->nest - 1].nr == nr) {
        th->nest--;
    } else if (th->nest > 0) {
        th->nest--;
    }
}

static UserTraceFd *trace_fd_find(uint64_t ttbr0, uint32_t fd)
{
    int i;

    for (i = 0; i < USER_TRACE_FD_MAX; i++) {
        if (user_trace_fds[i].used && user_trace_fds[i].ttbr0 == ttbr0 &&
            user_trace_fds[i].fd == fd) {
            return &user_trace_fds[i];
        }
    }
    return NULL;
}

static bool path_is_pcm1(const char *path)
{
    return path && path[0] && g_strrstr(path, "dsptask/pcm1");
}

static bool pcm1_fd_match(uint64_t ttbr0, uint32_t fd)
{
    const UserTraceFd *slot = trace_fd_find(ttbr0, fd);

    return slot && path_is_pcm1(slot->path);
}

static bool pcm1_opened_on_as(uint64_t ttbr0)
{
    int i;

    for (i = 0; i < USER_TRACE_FD_MAX; i++) {
        if (user_trace_fds[i].used && user_trace_fds[i].ttbr0 == ttbr0 &&
            path_is_pcm1(user_trace_fds[i].path)) {
            return true;
        }
    }
    return false;
}

const char *user_trace_fd_path(uint64_t ttbr0, uint32_t fd)
{
    const UserTraceFd *slot = trace_fd_find(ttbr0, fd);

    return slot && slot->path[0] ? slot->path : "";
}

static void trace_fd_log(const char *why, const UserTraceFd *slot)
{
    const UserTraceProc *proc;

    if (!slot) {
        return;
    }
    proc = proc_lookup(slot->ttbr0);
    qemu_log("user-trace-fd ns=%" PRId64 " why=%s ttbr0=0x%" PRIx64
             " fd=%u path=%s how=%s pid=%u name=%s\n",
             qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), why, slot->ttbr0, slot->fd,
             slot->path[0] ? slot->path : "?", slot->how,
             proc && proc->pid ? proc->pid : 0,
             proc && proc->name[0] ? proc->name : "?");
}

static UserTraceFd *trace_fd_bind(uint64_t ttbr0, uint32_t fd, const char *path,
                                  const char *how)
{
    UserTraceFd *slot = trace_fd_find(ttbr0, fd);
    int i;

    if ((int32_t)fd < 0) {
        return NULL;
    }
    if (!slot) {
        int evict = -1;

        for (i = 0; i < USER_TRACE_FD_MAX; i++) {
            if (!user_trace_fds[i].used) {
                slot = &user_trace_fds[i];
                memset(slot, 0, sizeof(*slot));
                slot->used = true;
                break;
            }
            if (evict < 0 && !user_trace_is_bme_as(user_trace_fds[i].ttbr0)) {
                evict = i;
            }
        }
        if (!slot && evict >= 0) {
            slot = &user_trace_fds[evict];
            memset(slot, 0, sizeof(*slot));
            slot->used = true;
        } else if (!slot) {
            slot = &user_trace_fds[0];
            memset(slot, 0, sizeof(*slot));
            slot->used = true;
        }
    }
    if (!slot) {
        return NULL;
    }
    slot->ttbr0 = ttbr0;
    slot->fd = fd;
    slot->ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    if (path && path[0]) {
        g_strlcpy(slot->path, path, sizeof(slot->path));
    }
    if (how && how[0]) {
        g_strlcpy(slot->how, how, sizeof(slot->how));
    }
    trace_fd_log("set", slot);
    return slot;
}

static void trace_fd_close(uint64_t ttbr0, uint32_t fd)
{
    UserTraceFd *slot = trace_fd_find(ttbr0, fd);

    if (!slot) {
        return;
    }
    trace_fd_log("close", slot);
    slot->used = false;
}

static void trace_fd_dup(uint64_t ttbr0, uint32_t oldfd, uint32_t newfd,
                         const char *how)
{
    UserTraceFd *old = trace_fd_find(ttbr0, oldfd);
    const char *path = old && old->path[0] ? old->path : "?";

    if ((int32_t)newfd < 0) {
        return;
    }
    trace_fd_bind(ttbr0, newfd, path, how);
}

static void fd_apply_return(UserTracePending *pending, uint32_t r0, int err)
{
    uint32_t nr = pending->nr;
    uint64_t ttbr0 = pending->ttbr0;
    const uint32_t *args = pending->r;
    char tmp[USER_TRACE_PATH_MAX];

    if (err) {
        if ((nr == 5 || nr == 322 || nr == 274) && pending->path[0]) {
            const UserTraceProc *proc = proc_lookup(ttbr0);

            qemu_log("user-trace-fd ns=%" PRId64 " why=open-fail ttbr0=0x%"
                     PRIx64 " fd=-1 path=%s how=%s errno=%d pid=%u name=%s\n",
                     qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), ttbr0,
                     pending->path, user_trace_syscall_name(nr), err,
                     proc && proc->pid ? proc->pid : 0,
                     proc && proc->name[0] ? proc->name : "?");
        }
        return;
    }
    if ((nr == 5 || nr == 322 || nr == 274) && (int32_t)r0 >= 0) {
        trace_fd_bind(ttbr0, r0, pending->path[0] ? pending->path : "?",
                      user_trace_syscall_name(nr));
        if (nr == 274) {
            nosmq_bind(ttbr0, r0, pending->path);
        }
        if (pending->path[0] &&
            (g_strrstr(pending->path, "retu") ||
             g_strrstr(pending->path, "bme"))) {
            bme_note_ttbr0(ttbr0);
        }
    } else if (nr == 281 && (int32_t)r0 >= 0) {
        g_snprintf(tmp, sizeof(tmp), "socket:domain=%u:type=%u:proto=%u",
                   args[0], args[1], args[2]);
        trace_fd_bind(ttbr0, r0, tmp, "socket");
    } else if (nr == 283 && (int32_t)r0 >= 0) {
        UserTraceFd *slot = trace_fd_find(ttbr0, args[0]);

        if (pending->path[0]) {
            trace_fd_bind(ttbr0, args[0], pending->path, "connect");
        } else if (slot) {
            trace_fd_log("connect", slot);
        }
    } else if (nr == 41 && (int32_t)r0 >= 0) {
        trace_fd_dup(ttbr0, args[0], r0, "dup");
    } else if (nr == 63 && (int32_t)r0 >= 0) {
        trace_fd_dup(ttbr0, args[0], args[1], "dup2");
    } else if (nr == 6) {
        trace_fd_close(ttbr0, args[0]);
    }
}

static void user_trace_dump_pending_slots(const char *why)
{
    int i;
    int newest[USER_TRACE_PENDING_MAX];
    int n = 0;

    for (i = 0; i < USER_TRACE_PENDING_MAX; i++) {
        const UserTracePending *p = &user_trace_pending[i];
        int j;
        int replace = -1;

        if (!p->used || !user_trace_is_bme_as(p->ttbr0)) {
            continue;
        }
        for (j = 0; j < n; j++) {
            const UserTracePending *o = &user_trace_pending[newest[j]];

            if (o->tls == p->tls && o->ttbr0 == p->ttbr0) {
                replace = j;
                break;
            }
        }
        if (replace >= 0) {
            if (p->enter_ns >= user_trace_pending[newest[replace]].enter_ns) {
                newest[replace] = i;
            }
        } else {
            newest[n++] = i;
        }
    }
    for (i = 0; i < n; i++) {
        const UserTracePending *p = &user_trace_pending[newest[i]];

        qemu_log("user-trace-blocked ns=%" PRId64 " why=%s src=pending "
                 "tls=0x%" PRIx32 " tid=0 nr=%u name=%s pc=0x%" PRIx32
                 " entered_ns=%" PRId64
                 " arg0=0x%" PRIx32 " arg1=0x%" PRIx32 " arg2=0x%" PRIx32
                 " arg3=0x%" PRIx32 " retpc=0x%" PRIx32
                 " ttbr0=0x%" PRIx64 " restarts=%d interrupts=0\n",
                 qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), why, p->tls, p->nr,
                 user_trace_syscall_name(p->nr), p->pc, p->enter_ns,
                 p->r[0], p->r[1], p->r[2], p->r[3], p->retpc, p->ttbr0,
                 p->restarts);
    }
}

void user_trace_dump_bme_state(const char *why)
{
    int i;
    int j;

    qemu_log("user-trace-dump ns=%" PRId64 " why=%s\n",
             qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), why ? why : "?");
    for (i = 0; i < USER_TRACE_THREAD_MAX; i++) {
        const UserTraceThread *th = &user_trace_threads[i];

        if (!th->used || !user_trace_is_bme_as(th->ttbr0)) {
            continue;
        }
        qemu_log("user-trace-thread ns=%" PRId64 " why=dump ttbr0=0x%" PRIx64
                 " tls=0x%" PRIx32 " tid=%u pid=%u extra=%d nest=%d\n",
                 qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), th->ttbr0, th->tls,
                 th->tid, th->pid, th->clones, th->nest);
        for (j = 0; j < th->nest; j++) {
            const UserTraceNest *nest = &th->stack[j];

            qemu_log("user-trace-blocked ns=%" PRId64 " why=%s src=thread "
                     "tls=0x%" PRIx32 " tid=%u nr=%u name=%s pc=0x%" PRIx32
                     " entered_ns=%" PRId64
                     " arg0=0x%" PRIx32 " arg1=0x%" PRIx32 " arg2=0x%" PRIx32
                     " arg3=0x%" PRIx32 " retpc=0 nest=%d"
                     " ttbr0=0x%" PRIx64 " restarts=%d interrupts=%d\n",
                     qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), why, th->tls,
                     th->tid, nest->nr, user_trace_syscall_name(nest->nr),
                     nest->pc, nest->enter_ns, nest->r[0], nest->r[1],
                     nest->r[2], nest->r[3], j, th->ttbr0, nest->restarts,
                     nest->interrupts);
        }
        if (!th->nest) {
            qemu_log("user-trace-blocked ns=%" PRId64 " why=%s src=thread "
                     "tls=0x%" PRIx32 " tid=%u nr=0 name=none pc=0x0 "
                     "entered_ns=0 arg0=0x0 arg1=0x0 arg2=0x0 arg3=0x0 "
                     "retpc=0 nest=0 ttbr0=0x%" PRIx64
                     " restarts=0 interrupts=0\n",
                     qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), why, th->tls,
                     th->tid, th->ttbr0);
        }
    }
    user_trace_dump_pending_slots(why);
    nosmq_dump(why);
    for (i = 0; i < USER_TRACE_FD_MAX; i++) {
        if (user_trace_fds[i].used &&
            user_trace_is_bme_as(user_trace_fds[i].ttbr0)) {
            trace_fd_log("dump", &user_trace_fds[i]);
        }
    }
}

static void user_trace_dump_cb(void *opaque)
{
    (void)opaque;
    if (!user_trace_dumped_state) {
        user_trace_dumped_state = true;
        user_trace_dump_bme_state("t131");
    }
}

static void user_trace_quit_cb(void *opaque)
{
    (void)opaque;
    if (user_trace_quit_requested) {
        return;
    }
    user_trace_quit_requested = true;
    user_trace_dump_bme_state("quit");
    qemu_system_shutdown_request(SHUTDOWN_CAUSE_HOST_QMP_QUIT);
}

static void user_trace_quit_ensure(void)
{
    int64_t now;

    if (user_trace_quit_sec <= 0 || user_trace_quit_timer) {
        return;
    }
    now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    user_trace_quit_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                         user_trace_quit_cb, NULL);
    timer_mod(user_trace_quit_timer, user_trace_quit_sec * 1000000000LL);
    if (user_trace_dump_sec > 0 &&
        user_trace_dump_sec * 1000000000LL > now) {
        user_trace_dump_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                             user_trace_dump_cb, NULL);
        timer_mod(user_trace_dump_timer, user_trace_dump_sec * 1000000000LL);
    }
}

static bool is_write_nr(uint32_t nr)
{
    return nr == 4 || nr == 146 || nr == 289 || nr == 290 || nr == 296;
}

static bool is_read_nr(uint32_t nr)
{
    return nr == 3 || nr == 145 || nr == 291 || nr == 292 || nr == 297;
}

static bool is_sock_setup_nr(uint32_t nr)
{
    return nr == 6 || nr == 281 || nr == 282 || nr == 283 || nr == 284 ||
           nr == 285;
}

static bool is_io_nr(uint32_t nr)
{
    return is_read_nr(nr) || is_write_nr(nr);
}

static bool is_signal_send_nr(uint32_t nr)
{
    return nr == 37 || nr == 178 || nr == 238 || nr == 268 || nr == 363;
}

static bool path_is_dsmesock(const char *path)
{
    return path && (g_strrstr(path, "dsmesock") ||
                    g_strrstr(path, "dsme.socket"));
}

static bool sock_has_ttbr0(uint64_t ttbr0)
{
    int i;

    for (i = 0; i < USER_TRACE_SOCK_MAX; i++) {
        if (user_trace_socks[i].used && user_trace_socks[i].ttbr0 == ttbr0) {
            return true;
        }
    }
    return false;
}

static UserTraceSock *sock_find(uint64_t ttbr0, uint32_t fd)
{
    int i;

    for (i = 0; i < USER_TRACE_SOCK_MAX; i++) {
        if (user_trace_socks[i].used &&
            user_trace_socks[i].ttbr0 == ttbr0 &&
            user_trace_socks[i].fd == fd) {
            return &user_trace_socks[i];
        }
    }
    return NULL;
}

static UserTraceSock *sock_alloc(uint64_t ttbr0, uint32_t fd)
{
    UserTraceSock *slot = sock_find(ttbr0, fd);
    int i;

    if (slot) {
        return slot;
    }
    for (i = 0; i < USER_TRACE_SOCK_MAX; i++) {
        if (!user_trace_socks[i].used) {
            slot = &user_trace_socks[i];
            memset(slot, 0, sizeof(*slot));
            slot->used = true;
            slot->ttbr0 = ttbr0;
            slot->fd = fd;
            slot->ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
            return slot;
        }
    }
    return NULL;
}

static void sock_log(const char *op, const UserTraceSock *slot, uint32_t extra)
{
    const UserTraceProc *proc = proc_lookup(slot->ttbr0);

    qemu_log("user-trace-sock ns=%" PRId64 " op=%s fd=%u newfd=%u"
             " role=%s ttbr0=0x%" PRIx64 " pid=%u name=%s path=%s\n",
             qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), op, slot->fd, extra,
             slot->role[0] ? slot->role : "?", slot->ttbr0,
             proc && proc->pid ? proc->pid : slot->pid,
             proc && proc->name[0] ? proc->name :
                 (slot->name[0] ? slot->name : "?"),
             slot->path[0] ? slot->path : "?");
}

static void sock_remember_unix(uint64_t ttbr0, uint32_t fd, const char *path,
                               bool is_bind)
{
    g_strlcpy(user_trace_pending_unix_path, path,
              sizeof(user_trace_pending_unix_path));
    user_trace_pending_unix_ttbr0 = ttbr0;
    user_trace_pending_unix_fd = fd;
    user_trace_pending_unix_is_bind = is_bind;
}

static uint32_t le32_at(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void format_hex(char *out, size_t outsz, const uint8_t *buf, uint32_t len)
{
    uint32_t i;
    size_t pos = 0;

    if (!outsz) {
        return;
    }
    out[0] = 0;
    for (i = 0; i < len && pos + 2 < outsz; i++) {
        g_snprintf(out + pos, outsz - pos, "%02x", buf[i]);
        pos += 2;
    }
}

static bool svc_verbose(uint32_t nr)
{
    if (nr != 276 && nr != 277) {
        return true;
    }
    return in_sec_window(user_trace_have_window, user_trace_window_start,
                         user_trace_window_end);
}

/*
 * target/arm supplies a strong definition. The debug walker misses some
 * pages the short-descriptor fallback can still read.
 */
uint32_t __attribute__((weak))
user_trace_arch_copy(uint32_t addr, void *buf, uint32_t len)
{
    (void)addr;
    (void)buf;
    (void)len;
    return 0;
}

static uint32_t guest_copy(uint32_t addr, void *buf, uint32_t len)
{
    uint8_t *out = buf;
    uint32_t i;
    uint32_t n;

    CPUState *cs = current_cpu ? current_cpu : first_cpu;

    if (!cs || !addr || !len) {
        return 0;
    }
    for (i = 0; i < len; i++) {
        if (cpu_memory_rw_debug(cs, addr + i, &out[i], 1, false) != 0) {
            break;
        }
    }
    if (i == len) {
        return len;
    }
    n = user_trace_arch_copy(addr + i, out + i, len - i);
    return i + n;
}

static void fill_poll_mask(GString *buf, uint16_t mask)
{
    static const struct {
        uint16_t bit;
        const char *name;
    } bits[] = {
        { 0x0001, "IN" },
        { 0x0002, "PRI" },
        { 0x0004, "OUT" },
        { 0x0008, "ERR" },
        { 0x0010, "HUP" },
        { 0x0020, "NVAL" },
    };
    unsigned i;
    bool any = false;

    g_string_append_printf(buf, "0x%x", mask);
    if (!mask) {
        return;
    }
    g_string_append_c(buf, '(');
    for (i = 0; i < G_N_ELEMENTS(bits); i++) {
        if (mask & bits[i].bit) {
            g_string_append_printf(buf, "%s%s", any ? "|" : "", bits[i].name);
            any = true;
        }
    }
    g_string_append_c(buf, ')');
}

static void fill_eret_extra(UserTracePending *pending, uint32_t r0)
{
    int32_t ret = (int32_t)r0;
    GString *buf;
    uint8_t raw[64];
    uint32_t n;
    uint32_t i;

    if (pending->nr == 168 && pending->buf_addr && pending->buf_len) {
        uint32_t nfds = pending->buf_len;
        uint32_t shown = nfds > 8 ? 8 : nfds;

        buf = g_string_new(NULL);
        g_string_append_printf(buf, "nfds=%u timeout=0", nfds);
        for (i = 0; i < shown; i++) {
            uint8_t slot[8];

            if (guest_copy(pending->buf_addr + i * 8, slot, 8) != 8) {
                break;
            }
            g_string_append_printf(buf, " fd%u=%d ev=", i,
                                   (int32_t)ldl_le_p(slot));
            fill_poll_mask(buf, lduw_le_p(slot + 4));
            g_string_append(buf, " rev=");
            fill_poll_mask(buf, lduw_le_p(slot + 6));
        }
        user_trace_set_ret_extra(buf->str);
        g_string_free(buf, TRUE);
        return;
    }
    if (pending->nr == 277 && ret > 0 && pending->buf_addr) {
        uint32_t want = (uint32_t)ret;
        uint32_t prio = 0;
        uint8_t pr[4];

        if (want > USER_TRACE_NOSMQ_MSG) {
            want = USER_TRACE_NOSMQ_MSG;
        }
        n = guest_copy(pending->buf_addr, raw, want);
        if (n > sizeof(pending->payload)) {
            n = sizeof(pending->payload);
        }
        memcpy(pending->payload, raw, n);
        pending->payload_len = n;
        if (pending->r[3] >= 0x1000 && guest_copy(pending->r[3], pr, 4) == 4) {
            prio = ldl_le_p(pr);
            pending->msg_prio = prio;
            pending->have_msg_prio = true;
        }
        buf = g_string_new(NULL);
        g_string_append_printf(buf, "buflen=%u cap=%u hex=", (uint32_t)ret, n);
        for (i = 0; i < n; i++) {
            g_string_append_printf(buf, "%02x", raw[i]);
        }
        if (pending->have_msg_prio) {
            g_string_append_printf(buf, " prio=%u", prio);
        } else {
            g_string_append_printf(buf, " prio=unset prio_ptr=0x%" PRIx32,
                                   pending->r[3]);
        }
        user_trace_set_ret_extra(buf->str);
        g_string_free(buf, TRUE);
        return;
    }
    if (pending->nr == 54 && pending->r[2] >= 0x1000 &&
        (pending->r[1] == 0x6004 || pending->r[1] == 0x6005)) {
        uint32_t field;
        uint16_t value;

        n = guest_copy(pending->r[2], raw, 16);
        buf = g_string_new(NULL);
        g_string_append_printf(buf, "fd=%u req=0x%" PRIx32 " retmem=",
                               pending->r[0], pending->r[1]);
        for (i = 0; i < n; i++) {
            g_string_append_printf(buf, "%02x", raw[i]);
        }
        if (n >= 7) {
            field = ldl_le_p(raw);
            value = lduw_le_p(raw + 4);
            g_string_append_printf(buf,
                " field=0x%" PRIx32 " reg=%u mask=0x%x value=0x%x result=%u",
                field, (field >> 16) & 0x3f, field & 0xffff, value, raw[6]);
        }
        user_trace_set_ret_extra(buf->str);
        g_string_free(buf, TRUE);
        return;
    }
    if (pending->nr == 114) {
        uint32_t status = 0;
        bool have_status = false;

        if (pending->r[1] >= 0x1000 && guest_copy(pending->r[1], raw, 4) == 4) {
            status = ldl_le_p(raw);
            have_status = true;
        }
        buf = g_string_new(NULL);
        g_string_append_printf(buf, "wait_pid=%d options=0x%" PRIx32,
                               ret, pending->r[2]);
        if (have_status) {
            g_string_append_printf(buf, " status=0x%" PRIx32, status);
            if ((status & 0x7f) == 0) {
                g_string_append_printf(buf, " exited=%u", (status >> 8) & 0xff);
            } else if ((status & 0x7f) != 0x7f) {
                g_string_append_printf(buf, " signaled=%u", status & 0x7f);
            }
        }
        user_trace_set_ret_extra(buf->str);
        g_string_free(buf, TRUE);
        return;
    }
    if (pending->nr == 279 && ret >= 0 && pending->r[2] >= 0x1000) {
        n = guest_copy(pending->r[2], raw, 16);
        if (n == 16) {
            buf = g_string_new(NULL);
            g_string_append_printf(buf,
                "mq_flags=%d mq_maxmsg=%d mq_msgsize=%d mq_curmsgs=%d",
                (int32_t)ldl_le_p(raw), (int32_t)ldl_le_p(raw + 4),
                (int32_t)ldl_le_p(raw + 8), (int32_t)ldl_le_p(raw + 12));
            user_trace_set_ret_extra(buf->str);
            g_string_free(buf, TRUE);
        }
        return;
    }
    if (ret > 0 && pending->is_read && pending->buf_addr) {
        uint32_t want = (uint32_t)ret;

        if (want > user_trace_sock_byte_count) {
            want = user_trace_sock_byte_count;
        }
        n = guest_copy(pending->buf_addr, raw, want);
        /*
         * The SVC-return helper already copied this buffer with the
         * live CPU. first_cpu's debug walk can miss that page and
         * would otherwise replace a real payload with cap=0.
         */
        if (n == 0 && pending->payload_len > 0) {
            n = pending->payload_len;
            if (n > sizeof(raw)) {
                n = sizeof(raw);
            }
            memcpy(raw, pending->payload, n);
        } else {
            if (n > sizeof(pending->payload)) {
                n = sizeof(pending->payload);
            }
            memcpy(pending->payload, raw, n);
            pending->payload_len = n;
        }
        buf = g_string_new(NULL);
        g_string_append_printf(buf, "buflen=%u cap=%u hex=", (uint32_t)ret, n);
        for (i = 0; i < n; i++) {
            g_string_append_printf(buf, "%02x", raw[i]);
        }
        user_trace_set_ret_extra(buf->str);
        g_string_free(buf, TRUE);
    }
}

static const char *nosmq_class(const uint8_t *p, uint32_t n)
{
    static const uint8_t loop[12] = {
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    static const uint8_t timer[12] = {
        0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    if (n >= 12 && memcmp(p, loop, 12) == 0) {
        return "loop";
    }
    if (n >= 12 && memcmp(p, timer, 12) == 0) {
        return "timer";
    }
    return "other";
}

static bool nosmq_is_fd(uint64_t ttbr0, uint32_t fd)
{
    const UserTraceFd *slot;

    if (user_trace_nosmq.have && user_trace_nosmq.ttbr0 == ttbr0 &&
        user_trace_nosmq.fd == fd) {
        return true;
    }
    slot = trace_fd_find(ttbr0, fd);
    return slot && slot->path[0] && g_strrstr(slot->path, "nosmq");
}

static int nosmq_highest(void)
{
    int i;
    int best = -1;

    for (i = 0; i < user_trace_nosmq.depth; i++) {
        if (best < 0 ||
            user_trace_nosmq.slots[i].prio > user_trace_nosmq.slots[best].prio) {
            best = i;
        }
    }
    return best;
}

static void nosmq_dump(const char *why)
{
    char hex[USER_TRACE_NOSMQ_MSG * 2 + 1];
    int i;

    qemu_log("user-trace-nosmq-dump ns=%" PRId64 " why=%s have=%d fd=%u"
             " name=%s flags=0x%" PRIx32 " o_nonblock=%d have_attr=%d"
             " mq_flags=%d mq_maxmsg=%d mq_msgsize=%d mq_curmsgs=%d"
             " depth=%d mismatches=%d send30=%d send15=%d recv30=%d"
             " recv15=%d recv_other=%d filled=%d fill_ns=%" PRId64
             " fill_prio=%u\n",
             qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), why ? why : "?",
             user_trace_nosmq.have, user_trace_nosmq.fd,
             user_trace_nosmq.name[0] ? user_trace_nosmq.name : "?",
             user_trace_nosmq.flags, user_trace_nosmq.o_nonblock,
             user_trace_nosmq.have_attr, user_trace_nosmq.mq_flags,
             user_trace_nosmq.mq_maxmsg, user_trace_nosmq.mq_msgsize,
             user_trace_nosmq.mq_curmsgs, user_trace_nosmq.depth,
             user_trace_nosmq.mismatches, user_trace_nosmq.send30,
             user_trace_nosmq.send15, user_trace_nosmq.recv30,
             user_trace_nosmq.recv15, user_trace_nosmq.recv_other,
             user_trace_nosmq.saw_fill, user_trace_nosmq.fill_ns,
             user_trace_nosmq.fill_prio);
    for (i = 0; i < user_trace_nosmq.depth; i++) {
        format_hex(hex, sizeof(hex), user_trace_nosmq.slots[i].payload,
                   user_trace_nosmq.slots[i].payload_len);
        qemu_log("user-trace-nosmq-slot ns=%" PRId64 " why=%s i=%d prio=%u"
                 " hex=%s class=%s insert_ns=%" PRId64 "\n",
                 qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), why ? why : "?",
                 i, user_trace_nosmq.slots[i].prio, hex[0] ? hex : "-",
                 nosmq_class(user_trace_nosmq.slots[i].payload,
                             user_trace_nosmq.slots[i].payload_len),
                 user_trace_nosmq.slots[i].insert_ns);
    }
    for (i = 0; i < USER_TRACE_PENDING_MAX; i++) {
        const UserTracePending *p = &user_trace_pending[i];

        if (!p->used || p->nr != 276 || !nosmq_is_fd(p->ttbr0, p->r[0])) {
            continue;
        }
        format_hex(hex, sizeof(hex), p->payload, p->payload_len);
        qemu_log("user-trace-nosmq ns=%" PRId64
                 " op=send-block prio=%u hex=%s depth=%d maxmsg=%d"
                 " class=%s timeout=%s entered_ns=%" PRId64 "\n",
                 qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), p->r[3],
                 hex[0] ? hex : "-", user_trace_nosmq.depth,
                 user_trace_nosmq.mq_maxmsg,
                 nosmq_class(p->payload, p->payload_len),
                 p->r[4] ? "ptr" : "NULL", p->enter_ns);
    }
}

static void nosmq_bind(uint64_t ttbr0, uint32_t fd, const char *path)
{
    if (!path || !g_strrstr(path, "nosmq")) {
        return;
    }
    user_trace_nosmq.have = true;
    user_trace_nosmq.ttbr0 = ttbr0;
    user_trace_nosmq.fd = fd;
    g_strlcpy(user_trace_nosmq.name, path, sizeof(user_trace_nosmq.name));
    if (nosmq_open_name[0] && g_strrstr(nosmq_open_name, "nosmq")) {
        user_trace_nosmq.flags = nosmq_open_flags;
        user_trace_nosmq.o_nonblock = !!(nosmq_open_flags & LINUX_O_NONBLOCK);
        user_trace_nosmq.have_attr = nosmq_open_have_attr;
        user_trace_nosmq.mq_flags = nosmq_open_mq_flags;
        user_trace_nosmq.mq_maxmsg = nosmq_open_maxmsg;
        user_trace_nosmq.mq_msgsize = nosmq_open_msgsize;
        user_trace_nosmq.mq_curmsgs = nosmq_open_curmsgs;
    }
    qemu_log("user-trace-nosmq ns=%" PRId64
             " op=open fd=%u name=%s flags=0x%" PRIx32
             " o_nonblock=%d have_attr=%d mq_flags=%d mq_maxmsg=%d"
             " mq_msgsize=%d mq_curmsgs=%d\n",
             qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), fd,
             user_trace_nosmq.name, user_trace_nosmq.flags,
             user_trace_nosmq.o_nonblock, user_trace_nosmq.have_attr,
             user_trace_nosmq.mq_flags, user_trace_nosmq.mq_maxmsg,
             user_trace_nosmq.mq_msgsize, user_trace_nosmq.mq_curmsgs);
}

static void nosmq_send(const UserTracePending *pending, int64_t now)
{
    char hex[USER_TRACE_NOSMQ_MSG * 2 + 1];
    uint32_t prio = pending->r[3];
    uint32_t n = pending->payload_len;
    int before = user_trace_nosmq.depth;
    UserTraceNosmqSlot *slot;

    if (n > USER_TRACE_NOSMQ_MSG) {
        n = USER_TRACE_NOSMQ_MSG;
    }
    format_hex(hex, sizeof(hex), pending->payload, n);
    if (user_trace_nosmq.depth >= USER_TRACE_NOSMQ_MAX) {
        qemu_log("user-trace-nosmq ns=%" PRId64
                 " op=send prio=%u hex=%s ok=0 depth=%d->%d maxmsg=%d"
                 " class=%s overflow=1\n",
                 now, prio, hex[0] ? hex : "-", before, before,
                 user_trace_nosmq.mq_maxmsg,
                 nosmq_class(pending->payload, n));
        return;
    }
    slot = &user_trace_nosmq.slots[user_trace_nosmq.depth++];
    slot->prio = prio;
    slot->payload_len = n;
    slot->insert_ns = now;
    memcpy(slot->payload, pending->payload, n);
    if (prio == 0x1e) {
        user_trace_nosmq.send30++;
    } else if (prio == 0x0f) {
        user_trace_nosmq.send15++;
    }
    if (user_trace_nosmq.have_attr && user_trace_nosmq.mq_maxmsg > 0 &&
        before == user_trace_nosmq.mq_maxmsg - 1 &&
        user_trace_nosmq.depth == user_trace_nosmq.mq_maxmsg) {
        user_trace_nosmq.saw_fill = true;
        user_trace_nosmq.fill_ns = now;
        user_trace_nosmq.fill_prio = prio;
    }
    qemu_log("user-trace-nosmq ns=%" PRId64
             " op=send prio=%u hex=%s ok=1 depth=%d->%d maxmsg=%d class=%s"
             " filled=%d timeout=%s\n",
             now, prio, hex[0] ? hex : "-", before, user_trace_nosmq.depth,
             user_trace_nosmq.mq_maxmsg, nosmq_class(pending->payload, n),
             user_trace_nosmq.saw_fill && user_trace_nosmq.fill_ns == now,
             pending->r[4] ? "ptr" : "NULL");
}

static void nosmq_recv(const UserTracePending *pending, int64_t now)
{
    char got_hex[USER_TRACE_NOSMQ_MSG * 2 + 1];
    char exp_hex[USER_TRACE_NOSMQ_MSG * 2 + 1];
    int best = nosmq_highest();
    int before = user_trace_nosmq.depth;
    uint32_t prio = pending->have_msg_prio ? pending->msg_prio : 0;
    uint32_t n = pending->payload_len;
    uint32_t expected_prio = 0;
    int match = 1;

    if (n > USER_TRACE_NOSMQ_MSG) {
        n = USER_TRACE_NOSMQ_MSG;
    }
    format_hex(got_hex, sizeof(got_hex), pending->payload, n);
    if (best < 0) {
        user_trace_nosmq.mismatches++;
        qemu_log("user-trace-nosmq ns=%" PRId64
                 " op=recv prio=%u hex=%s expected_prio=0 expected_hex=-"
                 " match=0 depth=%d->%d maxmsg=%d class=%s empty=1\n",
                 now, prio, got_hex[0] ? got_hex : "-", before, before,
                 user_trace_nosmq.mq_maxmsg,
                 nosmq_class(pending->payload, n));
        return;
    }
    expected_prio = user_trace_nosmq.slots[best].prio;
    format_hex(exp_hex, sizeof(exp_hex), user_trace_nosmq.slots[best].payload,
               user_trace_nosmq.slots[best].payload_len);
    if (pending->have_msg_prio && prio != expected_prio) {
        match = 0;
    }
    if (n && (n != user_trace_nosmq.slots[best].payload_len ||
              memcmp(pending->payload, user_trace_nosmq.slots[best].payload,
                     n) != 0)) {
        match = 0;
    }
    if (!match) {
        user_trace_nosmq.mismatches++;
    }
    if (expected_prio == 0x1e) {
        user_trace_nosmq.recv30++;
    } else if (expected_prio == 0x0f) {
        user_trace_nosmq.recv15++;
    } else {
        user_trace_nosmq.recv_other++;
    }
    if (best + 1 < user_trace_nosmq.depth) {
        memmove(&user_trace_nosmq.slots[best],
                &user_trace_nosmq.slots[best + 1],
                (user_trace_nosmq.depth - best - 1) *
                    sizeof(user_trace_nosmq.slots[0]));
    }
    user_trace_nosmq.depth--;
    qemu_log("user-trace-nosmq ns=%" PRId64
             " op=recv prio=%u hex=%s expected_prio=%u expected_hex=%s"
             " match=%d depth=%d->%d maxmsg=%d class=%s\n",
             now, prio, got_hex[0] ? got_hex : "-", expected_prio,
             exp_hex[0] ? exp_hex : "-", match, before,
             user_trace_nosmq.depth, user_trace_nosmq.mq_maxmsg,
             nosmq_class(pending->payload, n));
}

void user_trace_nosmq_note_open(const char *name, uint32_t flags,
                                int32_t mq_flags, int32_t mq_maxmsg,
                                int32_t mq_msgsize, int32_t mq_curmsgs,
                                bool have_attr)
{
    if (!name) {
        return;
    }
    g_strlcpy(nosmq_open_name, name, sizeof(nosmq_open_name));
    nosmq_open_flags = flags;
    nosmq_open_mq_flags = mq_flags;
    nosmq_open_maxmsg = mq_maxmsg;
    nosmq_open_msgsize = mq_msgsize;
    nosmq_open_curmsgs = mq_curmsgs;
    nosmq_open_have_attr = have_attr;
}

static void sock_register(uint64_t ttbr0, uint32_t fd, const char *path,
                          const char *role)
{
    UserTraceSock *slot;
    const UserTraceProc *proc;

    if (!user_trace_dsmesock || !path_is_dsmesock(path)) {
        return;
    }
    slot = sock_alloc(ttbr0, fd);
    if (!slot) {
        return;
    }
    g_strlcpy(slot->role, role, sizeof(slot->role));
    g_strlcpy(slot->path, path, sizeof(slot->path));
    proc = proc_lookup(ttbr0);
    if (proc) {
        slot->pid = proc->pid;
        if (proc->name[0]) {
            g_strlcpy(slot->name, proc->name, sizeof(slot->name));
        }
    }
    sock_log(role, slot, 0);
}

/* Low attribute bits differ across a syscall; the L1 base does not. */
static bool pending_ttbr_match(uint64_t pending_ttbr, uint64_t live_ttbr)
{
    return ((uint32_t)pending_ttbr & 0xffffc000u) ==
           ((uint32_t)live_ttbr & 0xffffc000u);
}

static UserTracePending *pending_find(uint32_t retpc, uint64_t ttbr0)
{
    int i;
    UserTracePending *best = NULL;

    for (i = 0; i < USER_TRACE_PENDING_MAX; i++) {
        if (!user_trace_pending[i].used ||
            user_trace_pending[i].retpc != retpc ||
            !pending_ttbr_match(user_trace_pending[i].ttbr0, ttbr0)) {
            continue;
        }
        if (!best || user_trace_pending[i].enter_ns >= best->enter_ns) {
            best = &user_trace_pending[i];
        }
    }
    return best;
}

static void retpc_remember(uint32_t retpc)
{
    int i;

    for (i = 0; i < user_trace_retpc_count; i++) {
        if (user_trace_retpcs[i] == retpc) {
            return;
        }
    }
    if (user_trace_retpc_count >= USER_TRACE_RETPC_MAX) {
        return;
    }
    user_trace_retpcs[user_trace_retpc_count++] = retpc;
}

static int pending_reuse_slot(uint32_t retpc, uint32_t nr, uint32_t pc,
                              uint64_t ttbr0, uint32_t tls, int nest)
{
    int i;

    for (i = 0; i < USER_TRACE_PENDING_MAX; i++) {
        const UserTracePending *p = &user_trace_pending[i];

        if (!p->used || p->ttbr0 != ttbr0 || p->nr != nr) {
            continue;
        }
        if (p->tls != tls) {
            continue;
        }
        if (p->nest != nest) {
            continue;
        }
        if (p->pc == pc || p->retpc == retpc) {
            return i;
        }
    }
    return -1;
}

static void pending_store(uint32_t retpc, uint32_t nr, uint32_t pc,
                          uint32_t lr, const uint32_t *r, uint64_t ttbr0,
                          uint32_t asid, uint32_t tls, int nest,
                          const char *path)
{
    int i;
    int slot = -1;
    int evict = -1;
    int oldest = -1;
    bool reused = false;

    slot = pending_reuse_slot(retpc, nr, pc, ttbr0, tls, nest);
    if (slot >= 0) {
        reused = true;
        user_trace_pending[slot].restarts++;
        qemu_log("user-trace-restart ns=%" PRId64 " nr=%u name=%s ttbr0=0x%"
                 PRIx64 " tls=0x%" PRIx32 " pc=0x%" PRIx32 " retpc=0x%" PRIx32
                 " restarts=%d\n",
                 qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), nr,
                 user_trace_syscall_name(nr), ttbr0, tls, pc, retpc,
                 user_trace_pending[slot].restarts);
    } else {
        for (i = 0; i < USER_TRACE_PENDING_MAX; i++) {
            if (!user_trace_pending[i].used) {
                slot = i;
                break;
            }
            if (evict < 0 &&
                !user_trace_is_bme_as(user_trace_pending[i].ttbr0)) {
                evict = i;
            }
            if (oldest < 0 ||
                user_trace_pending[i].enter_ns <
                    user_trace_pending[oldest].enter_ns) {
                oldest = i;
            }
        }
        if (slot < 0) {
            slot = evict >= 0 ? evict : oldest;
        }
        if (slot < 0) {
            qemu_log("user-trace-pending-full ns=%" PRId64 " nr=%u ttbr0=0x%"
                     PRIx64 " tls=0x%" PRIx32 "\n",
                     qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), nr, ttbr0, tls);
            user_trace_have_svc_ret = true;
            user_trace_svc_ret_pc = retpc;
            return;
        }
        memset(&user_trace_pending[slot], 0, sizeof(user_trace_pending[slot]));
        user_trace_pending[slot].enter_ns =
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    }
    user_trace_pending[slot].used = true;
    user_trace_pending[slot].retpc = retpc;
    user_trace_pending[slot].nr = nr;
    user_trace_pending[slot].pc = pc;
    user_trace_pending[slot].lr = lr;
    memcpy(user_trace_pending[slot].r, r, sizeof(user_trace_pending[slot].r));
    user_trace_pending[slot].ttbr0 = ttbr0;
    user_trace_pending[slot].asid = asid;
    user_trace_pending[slot].tls = tls;
    user_trace_pending[slot].nest = nest;
    if (!reused) {
        user_trace_pending[slot].enter_ns =
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        user_trace_pending[slot].restarts = 0;
    }
    user_trace_pending[slot].io_fd = r[0];
    if (path && path[0]) {
        g_strlcpy(user_trace_pending[slot].path, path,
                  sizeof(user_trace_pending[slot].path));
    }
    user_trace_have_svc_ret = true;
    user_trace_svc_ret_pc = retpc;
    retpc_remember(retpc);
    user_trace_svc_nr = nr;
    user_trace_svc_r0 = r[0];
    user_trace_svc_r1 = r[1];
    user_trace_svc_r2 = r[2];
    user_trace_svc_r3 = r[3];
    user_trace_svc_r4 = r[4];
    user_trace_svc_r5 = r[5];
}

static UserTracePending *pending_take(uint32_t pc, uint64_t ttbr0)
{
    int i;
    UserTracePending *best = NULL;

    for (i = 0; i < USER_TRACE_PENDING_MAX; i++) {
        if (!user_trace_pending[i].used ||
            user_trace_pending[i].retpc != pc ||
            !pending_ttbr_match(user_trace_pending[i].ttbr0, ttbr0)) {
            continue;
        }
        if (!best || user_trace_pending[i].enter_ns >= best->enter_ns) {
            best = &user_trace_pending[i];
        }
    }
    return best;
}

static void decode_signal(uint32_t nr, const uint32_t *r,
                          uint32_t *target_pid, uint32_t *target_tid,
                          uint32_t *sig)
{
    *target_pid = 0;
    *target_tid = 0;
    *sig = 0;
    switch (nr) {
    case 37: /* kill */
        *target_pid = r[0];
        *sig = r[1];
        break;
    case 238: /* tkill */
        *target_tid = r[0];
        *sig = r[1];
        break;
    case 268: /* tgkill */
        *target_pid = r[0];
        *target_tid = r[1];
        *sig = r[2];
        break;
    case 178: /* rt_sigqueueinfo */
        *target_pid = r[0];
        *sig = r[1];
        break;
    case 363: /* rt_tgsigqueueinfo */
        *target_pid = r[0];
        *target_tid = r[1];
        *sig = r[2];
        break;
    default:
        break;
    }
}

static void log_signal_send(uint32_t nr, uint32_t pc, uint32_t lr,
                            const uint32_t *r, uint64_t ttbr0, uint32_t asid)
{
    const UserTraceProc *sender = proc_lookup(ttbr0);
    const UserTraceProc *target;
    uint32_t target_pid, target_tid, sig;
    const char *sender_name = sender && sender->name[0] ? sender->name : "?";
    const char *target_name = "?";

    decode_signal(nr, r, &target_pid, &target_tid, &sig);
    target = proc_find_pid(target_pid);
    if (target && target->name[0]) {
        target_name = target->name;
    }
    qemu_log("user-trace-sig ns=%" PRId64 " nr=%u name=%s pc=0x%" PRIx32
             " lr=0x%" PRIx32 " ttbr0=0x%" PRIx64 " asid=0x%" PRIx32
             " r0=0x%" PRIx32 " r1=0x%" PRIx32 " r2=0x%" PRIx32
             " r3=0x%" PRIx32 " r4=0x%" PRIx32 " r5=0x%" PRIx32
             " r6=0x%" PRIx32
             " sender_pid=%u sender_tid=%u sender_name=%s"
             " target_pid=%u target_tid=%u target_name=%s sig=%u\n",
             qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), nr,
             user_trace_syscall_name(nr), pc, lr, ttbr0, asid,
             r[0], r[1], r[2], r[3], r[4], r[5], r[6],
             sender ? sender->pid : 0, sender ? sender->tid : 0, sender_name,
             target_pid, target_tid, target_name, sig);
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

void user_trace_syscall_window_parse(const char *list)
{
    parse_sec_window(list, &user_trace_window_start, &user_trace_window_end,
                     &user_trace_have_window, "-user-trace-syscall-window");
}

void user_trace_write_window_parse(const char *list)
{
    parse_sec_window(list, &user_trace_write_window_start,
                     &user_trace_write_window_end,
                     &user_trace_have_write_window,
                     "-user-trace-write-window");
}

void user_trace_write_name_parse(const char *name)
{
    g_strlcpy(user_trace_write_name, name, sizeof(user_trace_write_name));
}

void user_trace_syscall_global_set(bool enabled)
{
    user_trace_syscall_global = enabled;
}

void user_trace_proc_set(bool enabled)
{
    user_trace_proc_enabled = enabled;
}

void user_trace_dsmesock_set(bool enabled)
{
    user_trace_dsmesock = enabled;
}

void user_trace_bme_syscalls_set(bool enabled)
{
    user_trace_bme_syscalls = enabled;
}

void user_trace_sock_window_parse(const char *list)
{
    parse_sec_window(list, &user_trace_sock_window_start,
                     &user_trace_sock_window_end,
                     &user_trace_have_sock_window, "-user-trace-sock-window");
}

void user_trace_sock_bytes_parse(const char *value)
{
    uint64_t n;

    if (qemu_strtou64(value, NULL, 0, &n) || n == 0 ||
        n > USER_TRACE_SOCK_BYTES_DEFAULT) {
        error_report("invalid -user-trace-sock-bytes '%s' (1-%d)",
                     value, USER_TRACE_SOCK_BYTES_DEFAULT);
        exit(1);
    }
    user_trace_sock_byte_count = (unsigned)n;
}

void user_trace_sample_ms_parse(const char *value)
{
    uint64_t n;

    if (qemu_strtou64(value, NULL, 0, &n) || n > 1000) {
        error_report("invalid -user-trace-sample-ms '%s'", value);
        exit(1);
    }
    user_trace_sample_period = (int64_t)n * 1000000LL;
}

void user_trace_quit_sec_parse(const char *value)
{
    uint64_t n;

    if (qemu_strtou64(value, NULL, 0, &n) || n == 0 || n > 3600) {
        error_report("invalid -user-trace-quit-sec '%s'", value);
        exit(1);
    }
    user_trace_quit_sec = (int64_t)n;
    user_trace_dump_sec = n > 1 ? (int64_t)n - 1 : (int64_t)n;
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
    /*
     * esd_send_file's write. r1 is the file PCM and r2 its length,
     * before the daemon mixes the stream.
     */
    if (pc == 0x41e9c85cu && user_trace_syscall_enabled()) {
        return true;
    }
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
    return user_trace_syscall_count > 0 || user_trace_proc_enabled ||
           user_trace_dsmesock || user_trace_bme_syscalls;
}

bool user_trace_syscall_match(uint32_t nr)
{
    int i;

    if (user_trace_proc_enabled && is_identity_nr(nr)) {
        return true;
    }
    for (i = 0; i < user_trace_syscall_count; i++) {
        if (user_trace_syscalls[i] == nr) {
            return true;
        }
    }
    return false;
}

bool user_trace_syscall_is_write(uint32_t nr)
{
    return is_write_nr(nr);
}

bool user_trace_syscall_is_read(uint32_t nr)
{
    return is_read_nr(nr);
}

bool user_trace_dsmesock_enabled(void)
{
    return user_trace_dsmesock;
}

bool user_trace_in_sock_window(void)
{
    return in_sec_window(user_trace_have_sock_window,
                         user_trace_sock_window_start,
                         user_trace_sock_window_end);
}

unsigned user_trace_sock_bytes(void)
{
    return user_trace_sock_byte_count;
}

bool user_trace_sock_fd(uint64_t ttbr0, uint32_t fd)
{
    return sock_find(ttbr0, fd) != NULL;
}

bool user_trace_is_bme_as(uint64_t ttbr0)
{
    const UserTraceProc *slot;
    int i;

    if (user_trace_have_bme_ttbr0 && ttbr0 == user_trace_watched_bme_ttbr0) {
        return true;
    }
    slot = proc_lookup(ttbr0);
    if (slot && slot->name[0] && g_strrstr(slot->name, "bme_RX")) {
        return true;
    }
    if (!user_trace_bme_syscalls) {
        return false;
    }
    for (i = 0; i < USER_TRACE_SOCK_MAX; i++) {
        if (user_trace_socks[i].used &&
            user_trace_socks[i].ttbr0 == ttbr0 &&
            strcmp(user_trace_socks[i].role, "client") == 0) {
            return true;
        }
    }
    return false;
}

bool user_trace_bme_in_syscall(void)
{
    return user_trace_bme_syscall_depth > 0;
}

void user_trace_bme_syscall_enter(uint64_t ttbr0)
{
    if (user_trace_is_bme_as(ttbr0)) {
        user_trace_bme_syscall_depth++;
    }
}

void user_trace_bme_syscall_leave(uint64_t ttbr0)
{
    if (user_trace_is_bme_as(ttbr0) && user_trace_bme_syscall_depth > 0) {
        user_trace_bme_syscall_depth--;
    }
}

bool user_trace_bme_ttbr0(uint64_t *out)
{
    if (!user_trace_have_bme_ttbr0) {
        return false;
    }
    *out = user_trace_watched_bme_ttbr0;
    return true;
}

bool user_trace_sample_enabled(void)
{
    return user_trace_sample_period > 0 && user_trace_have_bme_ttbr0;
}

int64_t user_trace_sample_period_ns(void)
{
    return user_trace_sample_period;
}

void user_trace_note_unix_connect(uint64_t ttbr0, uint32_t fd,
                                  const char *path)
{
    sock_remember_unix(ttbr0, fd, path, false);
}

void user_trace_note_unix_bind(uint64_t ttbr0, uint32_t fd, const char *path)
{
    sock_remember_unix(ttbr0, fd, path, true);
}

void user_trace_note_listen(uint64_t ttbr0, uint32_t fd)
{
    UserTraceSock *slot = sock_find(ttbr0, fd);

    if (!slot) {
        return;
    }
    g_strlcpy(slot->role, "listen", sizeof(slot->role));
    sock_log("listen", slot, 0);
}

void user_trace_note_accept(uint64_t ttbr0, uint32_t listen_fd, uint32_t newfd)
{
    UserTraceSock *listen = sock_find(ttbr0, listen_fd);
    UserTraceSock *peer;
    int i;
    UserTraceSock *client = NULL;

    if (!listen || (int32_t)newfd < 0) {
        return;
    }
    peer = sock_alloc(ttbr0, newfd);
    if (!peer) {
        return;
    }
    g_strlcpy(peer->role, "peer", sizeof(peer->role));
    g_strlcpy(peer->path, listen->path, sizeof(peer->path));
    for (i = 0; i < USER_TRACE_SOCK_MAX; i++) {
        if (user_trace_socks[i].used &&
            strcmp(user_trace_socks[i].role, "client") == 0 &&
            !user_trace_socks[i].paired &&
            strcmp(user_trace_socks[i].path, peer->path) == 0) {
            if (!client || user_trace_socks[i].ns >= client->ns) {
                client = &user_trace_socks[i];
            }
        }
    }
    if (client) {
        const UserTraceProc *proc = proc_lookup(client->ttbr0);

        client->paired = true;
        peer->paired = true;
        peer->pid = proc && proc->pid ? proc->pid : client->pid;
        g_strlcpy(peer->name,
                  proc && proc->name[0] ? proc->name : client->name,
                  sizeof(peer->name));
    }
    sock_log("accept", peer, newfd);
}

void user_trace_note_close(uint64_t ttbr0, uint32_t fd)
{
    UserTraceSock *slot = sock_find(ttbr0, fd);

    if (!slot) {
        return;
    }
    sock_log("close", slot, 0);
    slot->used = false;
}

void user_trace_pending_set_io(uint32_t retpc, uint64_t ttbr0, uint32_t fd,
                               uint32_t addr, uint32_t len, bool is_read)
{
    UserTracePending *pending = pending_find(retpc, ttbr0);

    if (!pending) {
        return;
    }
    pending->has_io = true;
    pending->io_fd = fd;
    pending->buf_addr = addr;
    pending->buf_len = len;
    pending->is_read = is_read;
}

void user_trace_pending_set_payload(uint32_t retpc, uint64_t ttbr0,
                                    const uint8_t *buf, uint32_t len)
{
    UserTracePending *pending = pending_find(retpc, ttbr0);

    if (!pending || !buf) {
        return;
    }
    if (len > user_trace_sock_byte_count) {
        len = user_trace_sock_byte_count;
    }
    if (len > sizeof(pending->payload)) {
        len = sizeof(pending->payload);
    }
    memcpy(pending->payload, buf, len);
    pending->payload_len = len;
}

void user_trace_pending_set_path(uint32_t retpc, uint64_t ttbr0,
                                 const char *path)
{
    UserTracePending *pending = pending_find(retpc, ttbr0);

    if (!pending || !path) {
        return;
    }
    g_strlcpy(pending->path, path, sizeof(pending->path));
}

bool user_trace_pending_read(uint32_t pc, uint64_t ttbr0, uint32_t *addr,
                             uint32_t *len)
{
    UserTracePending *pending = pending_find(pc, ttbr0);

    if (!pending || !pending->is_read || !pending->buf_addr) {
        return false;
    }
    *addr = pending->buf_addr;
    *len = pending->buf_len;
    return true;
}

bool user_trace_pending_info(uint32_t pc, uint64_t ttbr0, uint32_t *nr,
                             uint32_t *addr, uint32_t *len)
{
    UserTracePending *pending = pending_find(pc, ttbr0);

    if (!pending) {
        return false;
    }
    *nr = pending->nr;
    *addr = pending->buf_addr;
    *len = pending->buf_len;
    return true;
}

void user_trace_set_ret_extra(const char *extra)
{
    if (!extra) {
        user_trace_ret_extra[0] = 0;
        return;
    }
    g_strlcpy(user_trace_ret_extra, extra, sizeof(user_trace_ret_extra));
}

bool user_trace_syscall_should_log(uint32_t nr, uint64_t ttbr0, uint32_t asid,
                                   uint32_t r0)
{
    bool identity = user_trace_proc_enabled && is_identity_nr(nr);
    bool listed = false;
    bool bme = user_trace_bme_syscalls && user_trace_is_bme_as(ttbr0);
    bool lifetime = bme && is_bme_lifetime_nr(nr);
    bool fd_life = user_trace_proc_enabled &&
                   (nr == 5 || nr == 41 || nr == 63 || nr == 274 || nr == 322);
    bool sock_setup = user_trace_dsmesock && is_sock_setup_nr(nr);
    bool sock_io = user_trace_dsmesock && is_io_nr(nr) &&
                   user_trace_in_sock_window() && sock_find(ttbr0, r0);
    bool sock_wait = user_trace_dsmesock && user_trace_in_sock_window() &&
                     (nr == 142 || nr == 168) && sock_has_ttbr0(ttbr0);
    int i;

    for (i = 0; i < user_trace_syscall_count; i++) {
        if (user_trace_syscalls[i] == nr) {
            listed = true;
            break;
        }
    }
    if (!identity && !listed && !bme && !lifetime && !fd_life && !sock_setup &&
        !sock_io && !sock_wait) {
        return false;
    }
    /*
     * Global read floods delay esd past startup. Even with
     * -user-trace-syscall-global, log read/readv only on the pcm1 fd
     * or the AS that opened pcm1. That AS must stay traced after the
     * 8–40 s window: mmap/cmd2 often land near quit-sec 45, and esd
     * may still be unnamed right after execve.
     */
    if (listed && pcm1_opened_on_as(ttbr0)) {
        return true;
    }
    if (listed && is_read_nr(nr) && !sock_io) {
        return pcm1_fd_match(ttbr0, r0);
    }
    if (!user_trace_syscall_global && user_trace_learn_pc_count > 0 &&
        !bme && !lifetime && !fd_life && !sock_setup && !sock_io &&
        !sock_wait) {
        if (!user_trace_learned || !user_trace_as_matches(ttbr0, asid)) {
            return false;
        }
    }
    if (identity || sock_setup || lifetime || fd_life) {
        return true;
    }
    if (listed && watch_matches_ttbr0(ttbr0)) {
        return true;
    }
    if (sock_io || sock_wait) {
        return true;
    }
    if (bme) {
        return in_sec_window(user_trace_have_window, user_trace_window_start,
                             user_trace_window_end);
    }
    if (is_write_nr(nr) && !sock_io) {
        return in_sec_window(user_trace_have_write_window,
                             user_trace_write_window_start,
                             user_trace_write_window_end);
    }
    return in_sec_window(user_trace_have_window, user_trace_window_start,
                         user_trace_window_end);
}

bool user_trace_write_interesting(uint64_t ttbr0, uint32_t fd,
                                  const uint8_t *buf, uint32_t len)
{
    const UserTraceProc *slot = proc_lookup(ttbr0);
    const char *name = slot && slot->name[0] ? slot->name : "";
    uint32_t i;

    if (user_trace_dsmesock && sock_find(ttbr0, fd)) {
        return true;
    }
    if (user_trace_write_name[0] && csv_name_matches(name, user_trace_write_name)) {
        return true;
    }
    if (name_matches(name, "bme")) {
        return true;
    }
    if (buf && len) {
        for (i = 0; i + 2 < len; i++) {
            if (buf[i] == '*' && buf[i + 1] == '*' && buf[i + 2] == '*') {
                return true;
            }
        }
        if (g_strstr_len((const char *)buf, len, "malloc") ||
            g_strstr_len((const char *)buf, len, "double free") ||
            g_strstr_len((const char *)buf, len, "corrupted") ||
            g_strstr_len((const char *)buf, len, "stack smashing") ||
            g_strstr_len((const char *)buf, len, "assertion") ||
            g_strstr_len((const char *)buf, len, "Aborted") ||
            g_strstr_len((const char *)buf, len, "status =") ||
            g_strstr_len((const char *)buf, len, "exitting") ||
            g_strstr_len((const char *)buf, len, "releasing external")) {
            return true;
        }
    }
    if (user_trace_write_name[0] && name[0] &&
        !csv_name_matches(name, user_trace_write_name)) {
        return false;
    }
    return fd == 2 && !name[0];
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
    int i;

    for (i = 0; i < user_trace_retpc_count; i++) {
        if (user_trace_retpcs[i] == pc) {
            return true;
        }
    }
    for (i = 0; i < USER_TRACE_PENDING_MAX; i++) {
        if (user_trace_pending[i].used &&
            user_trace_pending[i].retpc == pc) {
            return true;
        }
    }
    return user_trace_have_svc_ret && user_trace_svc_ret_pc == pc;
}

static const char *io_op_name(uint32_t nr, bool is_read)
{
    switch (nr) {
    case 3:
        return "read";
    case 4:
        return "write";
    case 145:
        return "readv";
    case 146:
        return "writev";
    case 289:
        return "send";
    case 290:
        return "sendto";
    case 291:
        return "recv";
    case 292:
        return "recvfrom";
    case 296:
        return "sendmsg";
    case 297:
        return "recvmsg";
    default:
        return is_read ? "read" : "write";
    }
}

static void log_sock_io(const UserTracePending *pending, uint32_t r0, int err,
                        int64_t dur_ns)
{
    const UserTraceSock *slot;
    const UserTraceProc *proc;
    char hex[USER_TRACE_SOCK_BYTES_DEFAULT * 2 + 1];
    uint32_t line_size = 0;
    uint32_t size = 0;
    uint32_t type = 0;
    uint32_t req = pending->buf_len;

    if (!pending->has_io && !is_io_nr(pending->nr)) {
        return;
    }
    slot = sock_find(pending->ttbr0, pending->io_fd);
    if (!slot || !user_trace_in_sock_window()) {
        return;
    }
    proc = proc_lookup(pending->ttbr0);
    format_hex(hex, sizeof(hex), pending->payload, pending->payload_len);
    if (pending->payload_len >= 12) {
        line_size = le32_at(pending->payload);
        size = le32_at(pending->payload + 4);
        type = le32_at(pending->payload + 8);
    }
    qemu_log("user-trace-sock ns=%" PRId64 " op=%s fd=%u role=%s"
             " ttbr0=0x%" PRIx64 " pid=%u name=%s path=%s"
             " ret=%d req=%u errno=%d dur_ns=%" PRId64
             " hex=%s line_size=%u size=%u type=0x%" PRIx32 "\n",
             qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
             io_op_name(pending->nr, pending->is_read), pending->io_fd,
             slot->role[0] ? slot->role : "?", pending->ttbr0,
             proc && proc->pid ? proc->pid : slot->pid,
             proc && proc->name[0] ? proc->name :
                 (slot->name[0] ? slot->name : "?"),
             slot->path[0] ? slot->path : "?",
             (int32_t)r0, req, err, dur_ns, hex[0] ? hex : "-",
             line_size, size, type);
}

static void finish_svc(UserTracePending *pending, uint32_t r0)
{
    uint32_t nr = pending->nr;
    uint32_t pc = pending->retpc;
    const uint32_t *args = pending->r;
    uint64_t ttbr0 = pending->ttbr0;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    int64_t dur_ns = now - pending->enter_ns;
    int32_t signed_r0 = (int32_t)r0;
    int err = 0;

    if (signed_r0 < 0 && signed_r0 > -4096) {
        err = -signed_r0;
    }
    if (nr == 276 && err == 0 && nosmq_is_fd(ttbr0, args[0])) {
        nosmq_send(pending, now);
    } else if (nr == 277 && err == 0 && signed_r0 > 0 &&
               nosmq_is_fd(ttbr0, args[0])) {
        nosmq_recv(pending, now);
    } else if (nr == 279 && err == 0 && nosmq_is_fd(ttbr0, args[0]) &&
               user_trace_ret_extra[0]) {
        qemu_log("user-trace-nosmq ns=%" PRId64 " op=getsetattr fd=%u"
                 " new_ptr=0x%" PRIx32 " extra=%s\n",
                 now, args[0], args[1], user_trace_ret_extra);
    }
    if (svc_verbose(nr)) {
        qemu_log("user-trace-svc-ret ns=%" PRId64 " nr=%u name=%s pc=0x%" PRIx32
                 " r0=0x%" PRIx32 " errno=%d dur_ns=%" PRId64
                 " arg0=0x%" PRIx32 " arg1=0x%" PRIx32 " arg2=0x%" PRIx32
                 " arg3=0x%" PRIx32 " arg4=0x%" PRIx32 " arg5=0x%" PRIx32
                 " arg6=0x%" PRIx32 " ttbr0=0x%" PRIx64
                 " tls=0x%" PRIx32 "%s%s%s%s\n",
                 now, nr, user_trace_syscall_name(nr), pc, r0, err, dur_ns,
                 args[0], args[1], args[2], args[3], args[4], args[5], args[6],
                 ttbr0, pending->tls,
                 erestart_name(signed_r0) ? " erestart=" : "",
                 erestart_name(signed_r0) ? erestart_name(signed_r0) : "",
                 user_trace_ret_extra[0] ? " extra=" : "",
                 user_trace_ret_extra[0] ? user_trace_ret_extra : "");
    }
    user_trace_ret_extra[0] = 0;
    fd_apply_return(pending, r0, err);
    thread_leave(ttbr0, pending->tls, nr, r0);
    log_sock_io(pending, r0, err, dur_ns);
    if ((nr == 282 || nr == 283) &&
        user_trace_pending_unix_ttbr0 == ttbr0 &&
        user_trace_pending_unix_fd == args[0] &&
        user_trace_pending_unix_path[0]) {
        if (nr == 282 && err == 0) {
            sock_register(ttbr0, args[0], user_trace_pending_unix_path, "bound");
        }
        if (nr == 283 && (err == 0 || err == 115)) {
            sock_register(ttbr0, args[0], user_trace_pending_unix_path,
                          "client");
            if (path_is_dsmesock(user_trace_pending_unix_path) &&
                user_trace_bme_syscalls) {
                bme_note_ttbr0(ttbr0);
            }
        }
        user_trace_pending_unix_path[0] = 0;
    }
    if (nr == 284 && err == 0) {
        user_trace_note_listen(ttbr0, args[0]);
    }
    if (nr == 285 && err == 0) {
        user_trace_note_accept(ttbr0, args[0], r0);
    }
    if (nr == 6 && err == 0) {
        user_trace_note_close(ttbr0, args[0]);
    }
    if (nr == 45 && err == 0) {
        user_trace_note_brk(r0);
    }
    if (nr == 20 && err == 0) {
        proc_note_pid(ttbr0, r0);
    }
    if (nr == 224 && err == 0) {
        proc_note_tid(ttbr0, r0);
    }
    if ((nr == 2 || nr == 120 || nr == 190) && err == 0) {
        if (r0 == 0) {
            UserTraceProc *child = proc_ensure(ttbr0);
            if (user_trace_last_fork_child) {
                proc_note_pid(ttbr0, user_trace_last_fork_child);
            }
            if (child && user_trace_last_fork_ppid) {
                child->ppid = user_trace_last_fork_ppid;
            }
            proc_maybe_inherit_exec(child);
            proc_log("child", child);
        } else if ((int32_t)r0 > 0) {
            user_trace_last_fork_child = r0;
            UserTraceProc *parent = proc_ensure(ttbr0);
            user_trace_last_fork_ppid = parent && parent->pid ? parent->pid : 0;
            qemu_log("user-trace-proc ns=%" PRId64
                     " why=fork-parent ttbr0=0x%" PRIx64
                     " parent_pid=%u child_pid=%u name=%s\n",
                     now, ttbr0,
                     parent && parent->pid ? parent->pid : 0, r0,
                     parent && parent->name[0] ? parent->name : "?");
        }
    }
}

void user_trace_svc_arm_enter(uint32_t pc, uint32_t retpc, uint32_t lr,
                              uint32_t nr,
                              uint32_t r0, uint32_t r1, uint32_t r2,
                              uint32_t r3, uint32_t r4, uint32_t r5,
                              uint32_t r6,
                              uint64_t ttbr0, uint32_t asid, uint32_t tls,
                              const char *extra)
{
    uint32_t r[7] = { r0, r1, r2, r3, r4, r5, r6 };
    const UserTraceProc *slot = proc_lookup(ttbr0);
    int64_t ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    uint32_t tid = 0;
    int nest = 0;
    uint32_t out_nr = 0;

    if (nr == 11 && extra && extra[0]) {
        proc_note_execve(ttbr0, extra);
        slot = proc_lookup(ttbr0);
    } else {
        proc_maybe_inherit_exec(proc_ensure(ttbr0));
        slot = proc_lookup(ttbr0);
    }
    thread_enter(ttbr0, tls, nr, r, pc, &tid, &nest, &out_nr);
    if (!is_noreturn_nr(nr)) {
        pending_store(retpc, nr, pc, lr, r, ttbr0, asid, tls, nest, extra);
    }
    if (!is_noreturn_nr(nr)) {
        user_trace_bme_syscall_enter(ttbr0);
    }
    user_trace_quit_ensure();
    if (nr == 3 && extra && strstr(extra, "dsptask/pcm1")) {
        omap2420_dsp_pcm1_read_entered(r2);
    }
    if (svc_verbose(nr)) {
        qemu_log("user-trace-svc ns=%" PRId64 " nr=%u name=%s pc=0x%" PRIx32
                 " lr=0x%" PRIx32 " retpc=0x%" PRIx32 " ttbr0=0x%" PRIx64
                 " asid=0x%" PRIx32 " tls=0x%" PRIx32 " nest=%d out_nr=%u"
                 " r0=0x%" PRIx32 " r1=0x%" PRIx32 " r2=0x%" PRIx32
                 " r3=0x%" PRIx32 " r4=0x%" PRIx32 " r5=0x%" PRIx32
                 " r6=0x%" PRIx32
                 " sender_pid=%u sender_ppid=%u sender_tid=%u sender_name=%s%s%s\n",
                 ns, nr, user_trace_syscall_name(nr), pc, lr, retpc, ttbr0, asid,
                 tls, nest, out_nr, r0, r1, r2, r3, r4, r5, r6,
                 slot ? slot->pid : 0,
                 slot ? slot->ppid : 0,
                 tid ? tid : (slot ? slot->tid : 0),
                 slot && slot->name[0] ? slot->name : "?",
                 extra && extra[0] ? " extra=" : "",
                 extra && extra[0] ? extra : "");
    }
    if (is_sigreturn_nr(nr)) {
        qemu_log("user-trace-sigreturn ns=%" PRId64 " nr=%u tls=0x%" PRIx32
                 " tid=%u pc=0x%" PRIx32 " out_nr=%u ttbr0=0x%" PRIx64 "\n",
                 ns, nr, tls, tid, pc, out_nr, ttbr0);
    }
    if (is_signal_send_nr(nr)) {
        log_signal_send(nr, pc, lr, r, ttbr0, asid);
    }
}

void user_trace_svc_arm_leave(uint32_t pc, uint32_t r0)
{
    UserTracePending fake = {
        .used = true,
        .retpc = pc,
        .nr = user_trace_svc_nr,
        .r = {
            user_trace_svc_r0, user_trace_svc_r1, user_trace_svc_r2,
            user_trace_svc_r3, user_trace_svc_r4, user_trace_svc_r5, 0
        },
        .enter_ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
    };

    finish_svc(&fake, r0);
    user_trace_have_svc_ret = false;
}

void user_trace_svc_arm_eret(uint32_t pc, uint32_t r0, uint64_t ttbr0,
                             uint32_t asid)
{
    UserTracePending *pending = pending_take(pc, ttbr0);

    (void)asid;
    if (!pending) {
        return;
    }
    fill_eret_extra(pending, r0);
    if (pending->nr == 3 && pcm1_fd_match(ttbr0, pending->r[0]) &&
        pending->r[2] == 2) {
        omap2420_dsp_pcm1_n2_finished();
    }
    if (pending->nr == 3 && pcm1_fd_match(ttbr0, pending->r[0]) &&
        (pending->r[2] == 4 || pending->r[2] == 10 || pending->r[2] == 40)) {
        uint8_t bytes[16];
        uint32_t n = pending->r[2] < sizeof(bytes) ? pending->r[2] : sizeof(bytes);

        if ((int32_t)r0 > 0) {
            n = guest_copy(pending->r[1], bytes, n < (uint32_t)r0 ? n :
                           (uint32_t)r0);
        } else {
            n = 0;
        }
        omap2420_dsp_pcm1_read_result(pending->r[2], r0, bytes, n);
        omap2420_dsp_pcm1_read_finished();
    }
    finish_svc(pending, r0);
    user_trace_bme_syscall_leave(ttbr0);
    pending->used = false;
    if (user_trace_have_svc_ret && user_trace_svc_ret_pc == pc) {
        user_trace_have_svc_ret = false;
    }
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
