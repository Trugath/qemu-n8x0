#ifndef QEMU_USER_TRACE_PC_H
#define QEMU_USER_TRACE_PC_H

#define USER_TRACE_PC_MAX 128
#define USER_TRACE_STACK_WORDS_DEFAULT 16
#define USER_TRACE_CODE_WORDS_DEFAULT 0
#define USER_TRACE_WRITE_BYTES 256
#define USER_TRACE_SOCK_BYTES_DEFAULT 64
#define HW_EVENT_RING_SIZE 1024

void user_trace_pc_parse(const char *list);
void user_trace_ring_pc_parse(const char *list);
void user_trace_learn_pc_parse(const char *list);
void user_trace_code_pc_parse(const char *list);
void user_trace_syscall_parse(const char *list);
void user_trace_syscall_window_parse(const char *list);
void user_trace_write_window_parse(const char *list);
void user_trace_write_name_parse(const char *name);
void user_trace_syscall_global_set(bool enabled);
void user_trace_proc_set(bool enabled);
void user_trace_dsmesock_set(bool enabled);
void user_trace_bme_syscalls_set(bool enabled);
void user_trace_sock_window_parse(const char *list);
void user_trace_sock_bytes_parse(const char *value);
void user_trace_sample_ms_parse(const char *value);
void user_trace_quit_sec_parse(const char *value);
void user_trace_mem_times_parse(const char *list);
void user_trace_pc_set_stack_words(unsigned words);
void user_trace_pc_set_code_words(unsigned words);
unsigned user_trace_pc_stack_words(void);
unsigned user_trace_pc_code_words(void);
bool user_trace_pc_enabled(void);
bool user_trace_pc_match(uint64_t pc);
bool user_trace_ring_pc_match(uint64_t pc);
bool user_trace_learn_pc_match(uint64_t pc);
bool user_trace_code_pc_match(uint64_t pc);
bool user_trace_syscall_enabled(void);
bool user_trace_syscall_match(uint32_t nr);
bool user_trace_syscall_should_log(uint32_t nr, uint64_t ttbr0, uint32_t asid,
                                   uint32_t r0);
bool user_trace_syscall_is_write(uint32_t nr);
bool user_trace_syscall_is_read(uint32_t nr);
bool user_trace_dsmesock_enabled(void);
bool user_trace_in_sock_window(void);
unsigned user_trace_sock_bytes(void);
bool user_trace_sock_fd(uint64_t ttbr0, uint32_t fd);
bool user_trace_is_bme_as(uint64_t ttbr0);
bool user_trace_bme_in_syscall(void);
void user_trace_bme_syscall_enter(uint64_t ttbr0);
void user_trace_bme_syscall_leave(uint64_t ttbr0);
bool user_trace_bme_ttbr0(uint64_t *out);
bool user_trace_sample_enabled(void);
int64_t user_trace_sample_period_ns(void);
void user_trace_note_unix_connect(uint64_t ttbr0, uint32_t fd,
                                  const char *path);
void user_trace_note_unix_bind(uint64_t ttbr0, uint32_t fd, const char *path);
void user_trace_note_listen(uint64_t ttbr0, uint32_t fd);
void user_trace_note_accept(uint64_t ttbr0, uint32_t listen_fd,
                            uint32_t newfd);
void user_trace_note_close(uint64_t ttbr0, uint32_t fd);
void user_trace_pending_set_io(uint32_t retpc, uint64_t ttbr0, uint32_t fd,
                               uint32_t addr, uint32_t len, bool is_read);
void user_trace_pending_set_payload(uint32_t retpc, uint64_t ttbr0,
                                    const uint8_t *buf, uint32_t len);
void user_trace_pending_set_path(uint32_t retpc, uint64_t ttbr0,
                                 const char *path);
bool user_trace_pending_read(uint32_t pc, uint64_t ttbr0, uint32_t *addr,
                             uint32_t *len);
bool user_trace_pending_info(uint32_t pc, uint64_t ttbr0, uint32_t *nr,
                             uint32_t *addr, uint32_t *len);
void user_trace_set_ret_extra(const char *extra);
void user_trace_nosmq_note_open(const char *name, uint32_t flags,
                                int32_t mq_flags, int32_t mq_maxmsg,
                                int32_t mq_msgsize, int32_t mq_curmsgs,
                                bool have_attr);
void user_trace_dump_bme_state(const char *why);
bool user_trace_write_interesting(uint64_t ttbr0, uint32_t fd,
                                  const uint8_t *buf, uint32_t len);
const char *user_trace_syscall_name(uint32_t nr);
bool user_trace_svc_ret_pending(uint32_t pc);
void user_trace_svc_arm_enter(uint32_t pc, uint32_t retpc, uint32_t lr,
                              uint32_t nr,
                              uint32_t r0, uint32_t r1, uint32_t r2,
                              uint32_t r3, uint32_t r4, uint32_t r5,
                              uint32_t r6,
                              uint64_t ttbr0, uint32_t asid, uint32_t tls,
                              const char *extra);
void user_trace_svc_arm_leave(uint32_t pc, uint32_t r0);
void user_trace_svc_arm_eret(uint32_t pc, uint32_t r0, uint64_t ttbr0,
                             uint32_t asid);
void user_trace_note_brk(uint32_t value);
bool user_trace_last_brk(uint32_t *out);
void user_trace_learn_from_hit(uint32_t pc, uint64_t ttbr0, uint32_t asid);
bool user_trace_as_learned(void);
bool user_trace_as_matches(uint64_t ttbr0, uint32_t asid);
bool user_trace_allow_as(uint32_t pc, uint64_t ttbr0, uint32_t asid);
int user_trace_mem_due(int64_t sec);
void user_trace_mem_mark(int index);
void user_trace_pc_log(const char *line);

void hw_event_ring_record(const char *fmt, ...) G_GNUC_PRINTF(1, 2);
void hw_event_ring_dump(void);
void hw_event_ring_dump_unique(uint64_t ttbr0, uint32_t asid, uint32_t pc);

#endif
