#ifndef QEMU_USER_TRACE_PC_H
#define QEMU_USER_TRACE_PC_H

#define USER_TRACE_PC_MAX 128
#define USER_TRACE_STACK_WORDS_DEFAULT 16
#define USER_TRACE_CODE_WORDS_DEFAULT 0
#define HW_EVENT_RING_SIZE 1024

void user_trace_pc_parse(const char *list);
void user_trace_ring_pc_parse(const char *list);
void user_trace_learn_pc_parse(const char *list);
void user_trace_code_pc_parse(const char *list);
void user_trace_syscall_parse(const char *list);
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
const char *user_trace_syscall_name(uint32_t nr);
bool user_trace_svc_ret_pending(uint32_t pc);
void user_trace_svc_arm_enter(uint32_t pc, uint32_t retpc, uint32_t nr,
                              uint32_t r0, uint32_t r1, uint32_t r2,
                              uint32_t r3, uint32_t r4, uint32_t r5,
                              uint64_t ttbr0, uint32_t asid);
void user_trace_svc_arm_leave(uint32_t pc, uint32_t r0);
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
