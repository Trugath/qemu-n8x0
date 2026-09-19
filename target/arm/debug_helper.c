/*
 * ARM debug helpers.
 *
 * This code is licensed under the GNU GPL v2 or later.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include <string.h>
#include "qemu/log.h"
#include "cpu.h"
#include "internals.h"
#include "cpu-features.h"
#include "cpregs.h"
#include "exec/exec-all.h"
#include "exec/tb-flush.h"
#include "exec/helper-proto.h"
#include "sysemu/tcg.h"
#ifndef CONFIG_USER_ONLY
#include "qemu/timer.h"
#include "qemu/user-trace-pc.h"
#include "exec/cpu-common.h"
#include "hw/boards.h"
#endif

#ifdef CONFIG_TCG
/* Return the Exception Level targeted by debug exceptions. */
static int arm_debug_target_el(CPUARMState *env)
{
    bool secure = arm_is_secure(env);
    bool route_to_el2 = false;

    if (arm_feature(env, ARM_FEATURE_M)) {
        return 1;
    }

    if (arm_is_el2_enabled(env)) {
        route_to_el2 = env->cp15.hcr_el2 & HCR_TGE ||
                       env->cp15.mdcr_el2 & MDCR_TDE;
    }

    if (route_to_el2) {
        return 2;
    } else if (arm_feature(env, ARM_FEATURE_EL3) &&
               !arm_el_is_aa64(env, 3) && secure) {
        return 3;
    } else {
        return 1;
    }
}

/*
 * Raise an exception to the debug target el.
 * Modify syndrome to indicate when origin and target EL are the same.
 */
G_NORETURN static void
raise_exception_debug(CPUARMState *env, uint32_t excp, uint32_t syndrome)
{
    int debug_el = arm_debug_target_el(env);
    int cur_el = arm_current_el(env);

    /*
     * If singlestep is targeting a lower EL than the current one, then
     * DisasContext.ss_active must be false and we can never get here.
     * Similarly for watchpoint and breakpoint matches.
     */
    assert(debug_el >= cur_el);
    syndrome |= (debug_el == cur_el) << ARM_EL_EC_SHIFT;
    raise_exception(env, excp, syndrome, debug_el);
}

/* See AArch64.GenerateDebugExceptionsFrom() in ARM ARM pseudocode */
static bool aa64_generate_debug_exceptions(CPUARMState *env)
{
    int cur_el = arm_current_el(env);
    int debug_el;

    if (cur_el == 3) {
        return false;
    }

    /* MDCR_EL3.SDD disables debug events from Secure state */
    if (arm_is_secure_below_el3(env)
        && extract32(env->cp15.mdcr_el3, 16, 1)) {
        return false;
    }

    /*
     * Same EL to same EL debug exceptions need MDSCR_KDE enabled
     * while not masking the (D)ebug bit in DAIF.
     */
    debug_el = arm_debug_target_el(env);

    if (cur_el == debug_el) {
        return extract32(env->cp15.mdscr_el1, 13, 1)
            && !(env->daif & PSTATE_D);
    }

    /* Otherwise the debug target needs to be a higher EL */
    return debug_el > cur_el;
}

static bool aa32_generate_debug_exceptions(CPUARMState *env)
{
    int el = arm_current_el(env);

    if (el == 0 && arm_el_is_aa64(env, 1)) {
        return aa64_generate_debug_exceptions(env);
    }

    if (arm_is_secure(env)) {
        int spd;

        if (el == 0 && (env->cp15.sder & 1)) {
            /*
             * SDER.SUIDEN means debug exceptions from Secure EL0
             * are always enabled. Otherwise they are controlled by
             * SDCR.SPD like those from other Secure ELs.
             */
            return true;
        }

        spd = extract32(env->cp15.mdcr_el3, 14, 2);
        switch (spd) {
        case 1:
            /* SPD == 0b01 is reserved, but behaves as 0b00. */
        case 0:
            /*
             * For 0b00 we return true if external secure invasive debug
             * is enabled. On real hardware this is controlled by external
             * signals to the core. QEMU always permits debug, and behaves
             * as if DBGEN, SPIDEN, NIDEN and SPNIDEN are all tied high.
             */
            return true;
        case 2:
            return false;
        case 3:
            return true;
        }
    }

    return el != 2;
}

/*
 * Return true if debugging exceptions are currently enabled.
 * This corresponds to what in ARM ARM pseudocode would be
 *    if UsingAArch32() then
 *        return AArch32.GenerateDebugExceptions()
 *    else
 *        return AArch64.GenerateDebugExceptions()
 * We choose to push the if() down into this function for clarity,
 * since the pseudocode has it at all callsites except for the one in
 * CheckSoftwareStep(), where it is elided because both branches would
 * always return the same value.
 */
bool arm_generate_debug_exceptions(CPUARMState *env)
{
    if ((env->cp15.oslsr_el1 & 1) || (env->cp15.osdlr_el1 & 1)) {
        return false;
    }
    if (is_a64(env)) {
        return aa64_generate_debug_exceptions(env);
    } else {
        return aa32_generate_debug_exceptions(env);
    }
}

/*
 * Is single-stepping active? (Note that the "is EL_D AArch64?" check
 * implicitly means this always returns false in pre-v8 CPUs.)
 */
bool arm_singlestep_active(CPUARMState *env)
{
    return extract32(env->cp15.mdscr_el1, 0, 1)
        && arm_el_is_aa64(env, arm_debug_target_el(env))
        && arm_generate_debug_exceptions(env);
}

/* Return true if the linked breakpoint entry lbn passes its checks */
static bool linked_bp_matches(ARMCPU *cpu, int lbn)
{
    CPUARMState *env = &cpu->env;
    uint64_t bcr = env->cp15.dbgbcr[lbn];
    int brps = arm_num_brps(cpu);
    int ctx_cmps = arm_num_ctx_cmps(cpu);
    int bt;
    uint32_t contextidr;
    uint64_t hcr_el2;

    /*
     * Links to unimplemented or non-context aware breakpoints are
     * CONSTRAINED UNPREDICTABLE: either behave as if disabled, or
     * as if linked to an UNKNOWN context-aware breakpoint (in which
     * case DBGWCR<n>_EL1.LBN must indicate that breakpoint).
     * We choose the former.
     */
    if (lbn >= brps || lbn < (brps - ctx_cmps)) {
        return false;
    }

    bcr = env->cp15.dbgbcr[lbn];

    if (extract64(bcr, 0, 1) == 0) {
        /* Linked breakpoint disabled : generate no events */
        return false;
    }

    bt = extract64(bcr, 20, 4);
    hcr_el2 = arm_hcr_el2_eff(env);

    switch (bt) {
    case 3: /* linked context ID match */
        switch (arm_current_el(env)) {
        default:
            /* Context matches never fire in AArch64 EL3 */
            return false;
        case 2:
            if (!(hcr_el2 & HCR_E2H)) {
                /* Context matches never fire in EL2 without E2H enabled. */
                return false;
            }
            contextidr = env->cp15.contextidr_el[2];
            break;
        case 1:
            contextidr = env->cp15.contextidr_el[1];
            break;
        case 0:
            if ((hcr_el2 & (HCR_E2H | HCR_TGE)) == (HCR_E2H | HCR_TGE)) {
                contextidr = env->cp15.contextidr_el[2];
            } else {
                contextidr = env->cp15.contextidr_el[1];
            }
            break;
        }
        break;

    case 7:  /* linked contextidr_el1 match */
        contextidr = env->cp15.contextidr_el[1];
        break;
    case 13: /* linked contextidr_el2 match */
        contextidr = env->cp15.contextidr_el[2];
        break;

    case 9: /* linked VMID match (reserved if no EL2) */
    case 11: /* linked context ID and VMID match (reserved if no EL2) */
    case 15: /* linked full context ID match */
    default:
        /*
         * Links to Unlinked context breakpoints must generate no
         * events; we choose to do the same for reserved values too.
         */
        return false;
    }

    /*
     * We match the whole register even if this is AArch32 using the
     * short descriptor format (in which case it holds both PROCID and ASID),
     * since we don't implement the optional v7 context ID masking.
     */
    return contextidr == (uint32_t)env->cp15.dbgbvr[lbn];
}

static bool bp_wp_matches(ARMCPU *cpu, int n, bool is_wp)
{
    CPUARMState *env = &cpu->env;
    uint64_t cr;
    int pac, hmc, ssc, wt, lbn;
    /*
     * Note that for watchpoints the check is against the CPU security
     * state, not the S/NS attribute on the offending data access.
     */
    bool is_secure = arm_is_secure(env);
    int access_el = arm_current_el(env);

    if (is_wp) {
        CPUWatchpoint *wp = env->cpu_watchpoint[n];

        if (!wp || !(wp->flags & BP_WATCHPOINT_HIT)) {
            return false;
        }
        cr = env->cp15.dbgwcr[n];
        if (wp->hitattrs.user) {
            /*
             * The LDRT/STRT/LDT/STT "unprivileged access" instructions should
             * match watchpoints as if they were accesses done at EL0, even if
             * the CPU is at EL1 or higher.
             */
            access_el = 0;
        }
    } else {
        uint64_t pc = is_a64(env) ? env->pc : env->regs[15];

        if (!env->cpu_breakpoint[n] || env->cpu_breakpoint[n]->pc != pc) {
            return false;
        }
        cr = env->cp15.dbgbcr[n];
    }
    /*
     * The WATCHPOINT_HIT flag guarantees us that the watchpoint is
     * enabled and that the address and access type match; for breakpoints
     * we know the address matched; check the remaining fields, including
     * linked breakpoints. We rely on WCR and BCR having the same layout
     * for the LBN, SSC, HMC, PAC/PMC and is-linked fields.
     * Note that some combinations of {PAC, HMC, SSC} are reserved and
     * must act either like some valid combination or as if the watchpoint
     * were disabled. We choose the former, and use this together with
     * the fact that EL3 must always be Secure and EL2 must always be
     * Non-Secure to simplify the code slightly compared to the full
     * table in the ARM ARM.
     */
    pac = FIELD_EX64(cr, DBGWCR, PAC);
    hmc = FIELD_EX64(cr, DBGWCR, HMC);
    ssc = FIELD_EX64(cr, DBGWCR, SSC);

    switch (ssc) {
    case 0:
        break;
    case 1:
    case 3:
        if (is_secure) {
            return false;
        }
        break;
    case 2:
        if (!is_secure) {
            return false;
        }
        break;
    }

    switch (access_el) {
    case 3:
    case 2:
        if (!hmc) {
            return false;
        }
        break;
    case 1:
        if (extract32(pac, 0, 1) == 0) {
            return false;
        }
        break;
    case 0:
        if (extract32(pac, 1, 1) == 0) {
            return false;
        }
        break;
    default:
        g_assert_not_reached();
    }

    wt = FIELD_EX64(cr, DBGWCR, WT);
    lbn = FIELD_EX64(cr, DBGWCR, LBN);

    if (wt && !linked_bp_matches(cpu, lbn)) {
        return false;
    }

    return true;
}

static bool check_watchpoints(ARMCPU *cpu)
{
    CPUARMState *env = &cpu->env;
    int n;

    /*
     * If watchpoints are disabled globally or we can't take debug
     * exceptions here then watchpoint firings are ignored.
     */
    if (extract32(env->cp15.mdscr_el1, 15, 1) == 0
        || !arm_generate_debug_exceptions(env)) {
        return false;
    }

    for (n = 0; n < ARRAY_SIZE(env->cpu_watchpoint); n++) {
        if (bp_wp_matches(cpu, n, true)) {
            return true;
        }
    }
    return false;
}

bool arm_debug_check_breakpoint(CPUState *cs)
{
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;
    target_ulong pc;
    int n;

    /*
     * If breakpoints are disabled globally or we can't take debug
     * exceptions here then breakpoint firings are ignored.
     */
    if (extract32(env->cp15.mdscr_el1, 15, 1) == 0
        || !arm_generate_debug_exceptions(env)) {
        return false;
    }

    /*
     * Single-step exceptions have priority over breakpoint exceptions.
     * If single-step state is active-pending, suppress the bp.
     */
    if (arm_singlestep_active(env) && !(env->pstate & PSTATE_SS)) {
        return false;
    }

    /*
     * PC alignment faults have priority over breakpoint exceptions.
     */
    pc = is_a64(env) ? env->pc : env->regs[15];
    if ((is_a64(env) || !env->thumb) && (pc & 3) != 0) {
        return false;
    }

    /*
     * Instruction aborts have priority over breakpoint exceptions.
     * TODO: We would need to look up the page for PC and verify that
     * it is present and executable.
     */

    for (n = 0; n < ARRAY_SIZE(env->cpu_breakpoint); n++) {
        if (bp_wp_matches(cpu, n, false)) {
            return true;
        }
    }
    return false;
}

bool arm_debug_check_watchpoint(CPUState *cs, CPUWatchpoint *wp)
{
    /*
     * Called by core code when a CPU watchpoint fires; need to check if this
     * is also an architectural watchpoint match.
     */
    ARMCPU *cpu = ARM_CPU(cs);

    return check_watchpoints(cpu);
}

/*
 * Return the FSR value for a debug exception (watchpoint, hardware
 * breakpoint or BKPT insn) targeting the specified exception level.
 */
static uint32_t arm_debug_exception_fsr(CPUARMState *env)
{
    ARMMMUFaultInfo fi = { .type = ARMFault_Debug };
    int target_el = arm_debug_target_el(env);
    bool using_lpae;

    if (arm_feature(env, ARM_FEATURE_M)) {
        using_lpae = false;
    } else if (target_el == 2 || arm_el_is_aa64(env, target_el)) {
        using_lpae = true;
    } else if (arm_feature(env, ARM_FEATURE_PMSA) &&
               arm_feature(env, ARM_FEATURE_V8)) {
        using_lpae = true;
    } else if (arm_feature(env, ARM_FEATURE_LPAE) &&
               (env->cp15.tcr_el[target_el] & TTBCR_EAE)) {
        using_lpae = true;
    } else {
        using_lpae = false;
    }

    if (using_lpae) {
        return arm_fi_to_lfsc(&fi);
    } else {
        return arm_fi_to_sfsc(&fi);
    }
}

void arm_debug_excp_handler(CPUState *cs)
{
    /*
     * Called by core code when a watchpoint or breakpoint fires;
     * need to check which one and raise the appropriate exception.
     */
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;
    CPUWatchpoint *wp_hit = cs->watchpoint_hit;

    if (wp_hit) {
        if (wp_hit->flags & BP_CPU) {
            bool wnr = (wp_hit->flags & BP_WATCHPOINT_HIT_WRITE) != 0;

            cs->watchpoint_hit = NULL;

            env->exception.fsr = arm_debug_exception_fsr(env);
            env->exception.vaddress = wp_hit->hitaddr;
            raise_exception_debug(env, EXCP_DATA_ABORT,
                                  syn_watchpoint(0, 0, wnr));
        }
    } else {
        uint64_t pc = is_a64(env) ? env->pc : env->regs[15];

        /*
         * (1) GDB breakpoints should be handled first.
         * (2) Do not raise a CPU exception if no CPU breakpoint has fired,
         * since singlestep is also done by generating a debug internal
         * exception.
         */
        if (cpu_breakpoint_test(cs, pc, BP_GDB)
            || !cpu_breakpoint_test(cs, pc, BP_CPU)) {
            return;
        }

        env->exception.fsr = arm_debug_exception_fsr(env);
        /*
         * FAR is UNKNOWN: clear vaddress to avoid potentially exposing
         * values to the guest that it shouldn't be able to see at its
         * exception/security level.
         */
        env->exception.vaddress = 0;
        raise_exception_debug(env, EXCP_PREFETCH_ABORT, syn_breakpoint(0));
    }
}

/*
 * Raise an EXCP_BKPT with the specified syndrome register value,
 * targeting the correct exception level for debug exceptions.
 */
void HELPER(exception_bkpt_insn)(CPUARMState *env, uint32_t syndrome)
{
    int debug_el = arm_debug_target_el(env);
    int cur_el = arm_current_el(env);

    /* FSR will only be used if the debug target EL is AArch32. */
    env->exception.fsr = arm_debug_exception_fsr(env);
    /*
     * FAR is UNKNOWN: clear vaddress to avoid potentially exposing
     * values to the guest that it shouldn't be able to see at its
     * exception/security level.
     */
    env->exception.vaddress = 0;
    /*
     * Other kinds of architectural debug exception are ignored if
     * they target an exception level below the current one (in QEMU
     * this is checked by arm_generate_debug_exceptions()). Breakpoint
     * instructions are special because they always generate an exception
     * to somewhere: if they can't go to the configured debug exception
     * level they are taken to the current exception level.
     */
    if (debug_el < cur_el) {
        debug_el = cur_el;
    }
    raise_exception(env, EXCP_BKPT, syndrome, debug_el);
}

void HELPER(exception_swstep)(CPUARMState *env, uint32_t syndrome)
{
    raise_exception_debug(env, EXCP_UDEF, syndrome);
}

void hw_watchpoint_update(ARMCPU *cpu, int n)
{
    CPUARMState *env = &cpu->env;
    vaddr len = 0;
    vaddr wvr = env->cp15.dbgwvr[n];
    uint64_t wcr = env->cp15.dbgwcr[n];
    int mask;
    int flags = BP_CPU | BP_STOP_BEFORE_ACCESS;

    if (env->cpu_watchpoint[n]) {
        cpu_watchpoint_remove_by_ref(CPU(cpu), env->cpu_watchpoint[n]);
        env->cpu_watchpoint[n] = NULL;
    }

    if (!FIELD_EX64(wcr, DBGWCR, E)) {
        /* E bit clear : watchpoint disabled */
        return;
    }

    switch (FIELD_EX64(wcr, DBGWCR, LSC)) {
    case 0:
        /* LSC 00 is reserved and must behave as if the wp is disabled */
        return;
    case 1:
        flags |= BP_MEM_READ;
        break;
    case 2:
        flags |= BP_MEM_WRITE;
        break;
    case 3:
        flags |= BP_MEM_ACCESS;
        break;
    }

    /*
     * Attempts to use both MASK and BAS fields simultaneously are
     * CONSTRAINED UNPREDICTABLE; we opt to ignore BAS in this case,
     * thus generating a watchpoint for every byte in the masked region.
     */
    mask = FIELD_EX64(wcr, DBGWCR, MASK);
    if (mask == 1 || mask == 2) {
        /*
         * Reserved values of MASK; we must act as if the mask value was
         * some non-reserved value, or as if the watchpoint were disabled.
         * We choose the latter.
         */
        return;
    } else if (mask) {
        /* Watchpoint covers an aligned area up to 2GB in size */
        len = 1ULL << mask;
        /*
         * If masked bits in WVR are not zero it's CONSTRAINED UNPREDICTABLE
         * whether the watchpoint fires when the unmasked bits match; we opt
         * to generate the exceptions.
         */
        wvr &= ~(len - 1);
    } else {
        /* Watchpoint covers bytes defined by the byte address select bits */
        int bas = FIELD_EX64(wcr, DBGWCR, BAS);
        int basstart;

        if (extract64(wvr, 2, 1)) {
            /*
             * Deprecated case of an only 4-aligned address. BAS[7:4] are
             * ignored, and BAS[3:0] define which bytes to watch.
             */
            bas &= 0xf;
        }

        if (bas == 0) {
            /* This must act as if the watchpoint is disabled */
            return;
        }

        /*
         * The BAS bits are supposed to be programmed to indicate a contiguous
         * range of bytes. Otherwise it is CONSTRAINED UNPREDICTABLE whether
         * we fire for each byte in the word/doubleword addressed by the WVR.
         * We choose to ignore any non-zero bits after the first range of 1s.
         */
        basstart = ctz32(bas);
        len = cto32(bas >> basstart);
        wvr += basstart;
    }

    cpu_watchpoint_insert(CPU(cpu), wvr, len, flags,
                          &env->cpu_watchpoint[n]);
}

void hw_watchpoint_update_all(ARMCPU *cpu)
{
    int i;
    CPUARMState *env = &cpu->env;

    /*
     * Completely clear out existing QEMU watchpoints and our array, to
     * avoid possible stale entries following migration load.
     */
    cpu_watchpoint_remove_all(CPU(cpu), BP_CPU);
    memset(env->cpu_watchpoint, 0, sizeof(env->cpu_watchpoint));

    for (i = 0; i < ARRAY_SIZE(cpu->env.cpu_watchpoint); i++) {
        hw_watchpoint_update(cpu, i);
    }
}

void hw_breakpoint_update(ARMCPU *cpu, int n)
{
    CPUARMState *env = &cpu->env;
    uint64_t bvr = env->cp15.dbgbvr[n];
    uint64_t bcr = env->cp15.dbgbcr[n];
    vaddr addr;
    int bt;
    int flags = BP_CPU;

    if (env->cpu_breakpoint[n]) {
        cpu_breakpoint_remove_by_ref(CPU(cpu), env->cpu_breakpoint[n]);
        env->cpu_breakpoint[n] = NULL;
    }

    if (!extract64(bcr, 0, 1)) {
        /* E bit clear : watchpoint disabled */
        return;
    }

    bt = extract64(bcr, 20, 4);

    switch (bt) {
    case 4: /* unlinked address mismatch (reserved if AArch64) */
    case 5: /* linked address mismatch (reserved if AArch64) */
        qemu_log_mask(LOG_UNIMP,
                      "arm: address mismatch breakpoint types not implemented\n");
        return;
    case 0: /* unlinked address match */
    case 1: /* linked address match */
    {
        /*
         * Bits [1:0] are RES0.
         *
         * It is IMPLEMENTATION DEFINED whether bits [63:49]
         * ([63:53] for FEAT_LVA) are hardwired to a copy of the sign bit
         * of the VA field ([48] or [52] for FEAT_LVA), or whether the
         * value is read as written.  It is CONSTRAINED UNPREDICTABLE
         * whether the RESS bits are ignored when comparing an address.
         * Therefore we are allowed to compare the entire register, which
         * lets us avoid considering whether FEAT_LVA is actually enabled.
         *
         * The BAS field is used to allow setting breakpoints on 16-bit
         * wide instructions; it is CONSTRAINED UNPREDICTABLE whether
         * a bp will fire if the addresses covered by the bp and the addresses
         * covered by the insn overlap but the insn doesn't start at the
         * start of the bp address range. We choose to require the insn and
         * the bp to have the same address. The constraints on writing to
         * BAS enforced in dbgbcr_write mean we have only four cases:
         *  0b0000  => no breakpoint
         *  0b0011  => breakpoint on addr
         *  0b1100  => breakpoint on addr + 2
         *  0b1111  => breakpoint on addr
         * See also figure D2-3 in the v8 ARM ARM (DDI0487A.c).
         */
        int bas = extract64(bcr, 5, 4);
        addr = bvr & ~3ULL;
        if (bas == 0) {
            return;
        }
        if (bas == 0xc) {
            addr += 2;
        }
        break;
    }
    case 2: /* unlinked context ID match */
    case 8: /* unlinked VMID match (reserved if no EL2) */
    case 10: /* unlinked context ID and VMID match (reserved if no EL2) */
        qemu_log_mask(LOG_UNIMP,
                      "arm: unlinked context breakpoint types not implemented\n");
        return;
    case 9: /* linked VMID match (reserved if no EL2) */
    case 11: /* linked context ID and VMID match (reserved if no EL2) */
    case 3: /* linked context ID match */
    default:
        /*
         * We must generate no events for Linked context matches (unless
         * they are linked to by some other bp/wp, which is handled in
         * updates for the linking bp/wp). We choose to also generate no events
         * for reserved values.
         */
        return;
    }

    cpu_breakpoint_insert(CPU(cpu), addr, flags, &env->cpu_breakpoint[n]);
}

void hw_breakpoint_update_all(ARMCPU *cpu)
{
    int i;
    CPUARMState *env = &cpu->env;

    /*
     * Completely clear out existing QEMU breakpoints and our array, to
     * avoid possible stale entries following migration load.
     */
    cpu_breakpoint_remove_all(CPU(cpu), BP_CPU);
    memset(env->cpu_breakpoint, 0, sizeof(env->cpu_breakpoint));

    for (i = 0; i < ARRAY_SIZE(cpu->env.cpu_breakpoint); i++) {
        hw_breakpoint_update(cpu, i);
    }
}

#if !defined(CONFIG_USER_ONLY)

vaddr arm_adjust_watchpoint_address(CPUState *cs, vaddr addr, int len)
{
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;

    /*
     * In BE32 system mode, target memory is stored byteswapped (on a
     * little-endian host system), and by the time we reach here (via an
     * opcode helper) the addresses of subword accesses have been adjusted
     * to account for that, which means that watchpoints will not match.
     * Undo the adjustment here.
     */
    if (arm_sctlr_b(env)) {
        if (len == 1) {
            addr ^= 3;
        } else if (len == 2) {
            addr ^= 2;
        }
    }

    return addr;
}

#endif /* !CONFIG_USER_ONLY */
#endif /* CONFIG_TCG */

/*
 * Check for traps to "powerdown debug" registers, which are controlled
 * by MDCR.TDOSA
 */
static CPAccessResult access_tdosa(CPUARMState *env, const ARMCPRegInfo *ri,
                                   bool isread)
{
    int el = arm_current_el(env);
    uint64_t mdcr_el2 = arm_mdcr_el2_eff(env);
    bool mdcr_el2_tdosa = (mdcr_el2 & MDCR_TDOSA) || (mdcr_el2 & MDCR_TDE) ||
        (arm_hcr_el2_eff(env) & HCR_TGE);

    if (el < 2 && mdcr_el2_tdosa) {
        return CP_ACCESS_TRAP_EL2;
    }
    if (el < 3 && (env->cp15.mdcr_el3 & MDCR_TDOSA)) {
        return CP_ACCESS_TRAP_EL3;
    }
    return CP_ACCESS_OK;
}

/*
 * Check for traps to "debug ROM" registers, which are controlled
 * by MDCR_EL2.TDRA for EL2 but by the more general MDCR_EL3.TDA for EL3.
 */
static CPAccessResult access_tdra(CPUARMState *env, const ARMCPRegInfo *ri,
                                  bool isread)
{
    int el = arm_current_el(env);
    uint64_t mdcr_el2 = arm_mdcr_el2_eff(env);
    bool mdcr_el2_tdra = (mdcr_el2 & MDCR_TDRA) || (mdcr_el2 & MDCR_TDE) ||
        (arm_hcr_el2_eff(env) & HCR_TGE);

    if (el < 2 && mdcr_el2_tdra) {
        return CP_ACCESS_TRAP_EL2;
    }
    if (el < 3 && (env->cp15.mdcr_el3 & MDCR_TDA)) {
        return CP_ACCESS_TRAP_EL3;
    }
    return CP_ACCESS_OK;
}

/*
 * Check for traps to general debug registers, which are controlled
 * by MDCR_EL2.TDA for EL2 and MDCR_EL3.TDA for EL3.
 */
static CPAccessResult access_tda(CPUARMState *env, const ARMCPRegInfo *ri,
                                  bool isread)
{
    int el = arm_current_el(env);
    uint64_t mdcr_el2 = arm_mdcr_el2_eff(env);
    bool mdcr_el2_tda = (mdcr_el2 & MDCR_TDA) || (mdcr_el2 & MDCR_TDE) ||
        (arm_hcr_el2_eff(env) & HCR_TGE);

    if (el < 2 && mdcr_el2_tda) {
        return CP_ACCESS_TRAP_EL2;
    }
    if (el < 3 && (env->cp15.mdcr_el3 & MDCR_TDA)) {
        return CP_ACCESS_TRAP_EL3;
    }
    return CP_ACCESS_OK;
}

static CPAccessResult access_dbgvcr32(CPUARMState *env, const ARMCPRegInfo *ri,
                                      bool isread)
{
    /* MCDR_EL3.TDMA doesn't apply for FEAT_NV traps */
    if (arm_current_el(env) == 2 && (env->cp15.mdcr_el3 & MDCR_TDA)) {
        return CP_ACCESS_TRAP_EL3;
    }
    return CP_ACCESS_OK;
}

/*
 * Check for traps to Debug Comms Channel registers. If FEAT_FGT
 * is implemented then these are controlled by MDCR_EL2.TDCC for
 * EL2 and MDCR_EL3.TDCC for EL3. They are also controlled by
 * the general debug access trap bits MDCR_EL2.TDA and MDCR_EL3.TDA.
 * For EL0, they are also controlled by MDSCR_EL1.TDCC.
 */
static CPAccessResult access_tdcc(CPUARMState *env, const ARMCPRegInfo *ri,
                                  bool isread)
{
    int el = arm_current_el(env);
    uint64_t mdcr_el2 = arm_mdcr_el2_eff(env);
    bool mdscr_el1_tdcc = extract32(env->cp15.mdscr_el1, 12, 1);
    bool mdcr_el2_tda = (mdcr_el2 & MDCR_TDA) || (mdcr_el2 & MDCR_TDE) ||
        (arm_hcr_el2_eff(env) & HCR_TGE);
    bool mdcr_el2_tdcc = cpu_isar_feature(aa64_fgt, env_archcpu(env)) &&
                                          (mdcr_el2 & MDCR_TDCC);
    bool mdcr_el3_tdcc = cpu_isar_feature(aa64_fgt, env_archcpu(env)) &&
                                          (env->cp15.mdcr_el3 & MDCR_TDCC);

    if (el < 1 && mdscr_el1_tdcc) {
        return CP_ACCESS_TRAP;
    }
    if (el < 2 && (mdcr_el2_tda || mdcr_el2_tdcc)) {
        return CP_ACCESS_TRAP_EL2;
    }
    if (el < 3 && ((env->cp15.mdcr_el3 & MDCR_TDA) || mdcr_el3_tdcc)) {
        return CP_ACCESS_TRAP_EL3;
    }
    return CP_ACCESS_OK;
}

static void oslar_write(CPUARMState *env, const ARMCPRegInfo *ri,
                        uint64_t value)
{
    /*
     * Writes to OSLAR_EL1 may update the OS lock status, which can be
     * read via a bit in OSLSR_EL1.
     */
    int oslock;

    if (ri->state == ARM_CP_STATE_AA32) {
        oslock = (value == 0xC5ACCE55);
    } else {
        oslock = value & 1;
    }

    env->cp15.oslsr_el1 = deposit32(env->cp15.oslsr_el1, 1, 1, oslock);
}

static void osdlr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                        uint64_t value)
{
    ARMCPU *cpu = env_archcpu(env);
    /*
     * Only defined bit is bit 0 (DLK); if Feat_DoubleLock is not
     * implemented this is RAZ/WI.
     */
    if(arm_feature(env, ARM_FEATURE_AARCH64)
       ? cpu_isar_feature(aa64_doublelock, cpu)
       : cpu_isar_feature(aa32_doublelock, cpu)) {
        env->cp15.osdlr_el1 = value & 1;
    }
}

static void dbgclaimset_write(CPUARMState *env, const ARMCPRegInfo *ri,
                              uint64_t value)
{
    env->cp15.dbgclaim |= (value & 0xFF);
}

static uint64_t dbgclaimset_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    /* CLAIM bits are RAO */
    return 0xFF;
}

static void dbgclaimclr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                              uint64_t value)
{
    env->cp15.dbgclaim &= ~(value & 0xFF);
}

static const ARMCPRegInfo debug_cp_reginfo[] = {
    /*
     * DBGDRAR, DBGDSAR: always RAZ since we don't implement memory mapped
     * debug components. The AArch64 version of DBGDRAR is named MDRAR_EL1;
     * unlike DBGDRAR it is never accessible from EL0.
     * DBGDSAR is deprecated and must RAZ from v8 anyway, so it has no AArch64
     * accessor.
     */
    { .name = "DBGDRAR", .cp = 14, .crn = 1, .crm = 0, .opc1 = 0, .opc2 = 0,
      .access = PL0_R, .accessfn = access_tdra,
      .type = ARM_CP_CONST | ARM_CP_NO_GDB, .resetvalue = 0 },
    { .name = "MDRAR_EL1", .state = ARM_CP_STATE_AA64,
      .opc0 = 2, .opc1 = 0, .crn = 1, .crm = 0, .opc2 = 0,
      .access = PL1_R, .accessfn = access_tdra,
      .type = ARM_CP_CONST, .resetvalue = 0 },
    { .name = "DBGDSAR", .cp = 14, .crn = 2, .crm = 0, .opc1 = 0, .opc2 = 0,
      .access = PL0_R, .accessfn = access_tdra,
      .type = ARM_CP_CONST | ARM_CP_NO_GDB, .resetvalue = 0 },
    /* Monitor debug system control register; the 32-bit alias is DBGDSCRext. */
    { .name = "MDSCR_EL1", .state = ARM_CP_STATE_BOTH,
      .cp = 14, .opc0 = 2, .opc1 = 0, .crn = 0, .crm = 2, .opc2 = 2,
      .access = PL1_RW, .accessfn = access_tda,
      .fgt = FGT_MDSCR_EL1,
      .nv2_redirect_offset = 0x158,
      .fieldoffset = offsetof(CPUARMState, cp15.mdscr_el1),
      .resetvalue = 0 },
    /*
     * MDCCSR_EL0[30:29] map to EDSCR[30:29].  Simply RAZ as the external
     * Debug Communication Channel is not implemented.
     */
    { .name = "MDCCSR_EL0", .state = ARM_CP_STATE_AA64,
      .opc0 = 2, .opc1 = 3, .crn = 0, .crm = 1, .opc2 = 0,
      .access = PL0_R, .accessfn = access_tdcc,
      .type = ARM_CP_CONST, .resetvalue = 0 },
    /*
     * These registers belong to the Debug Communications Channel,
     * which is not implemented. However we implement RAZ/WI behaviour
     * with trapping to prevent spurious SIGILLs if the guest OS does
     * access them as the support cannot be probed for.
     */
    { .name = "OSDTRRX_EL1", .state = ARM_CP_STATE_BOTH, .cp = 14,
      .opc0 = 2, .opc1 = 0, .crn = 0, .crm = 0, .opc2 = 2,
      .access = PL1_RW, .accessfn = access_tdcc,
      .type = ARM_CP_CONST, .resetvalue = 0 },
    { .name = "OSDTRTX_EL1", .state = ARM_CP_STATE_BOTH, .cp = 14,
      .opc0 = 2, .opc1 = 0, .crn = 0, .crm = 3, .opc2 = 2,
      .access = PL1_RW, .accessfn = access_tdcc,
      .type = ARM_CP_CONST, .resetvalue = 0 },
    /* DBGDTRTX_EL0/DBGDTRRX_EL0 depend on direction */
    { .name = "DBGDTR_EL0", .state = ARM_CP_STATE_BOTH, .cp = 14,
      .opc0 = 2, .opc1 = 3, .crn = 0, .crm = 5, .opc2 = 0,
      .access = PL0_RW, .accessfn = access_tdcc,
      .type = ARM_CP_CONST, .resetvalue = 0 },
    /*
     * OSECCR_EL1 provides a mechanism for an operating system
     * to access the contents of EDECCR. EDECCR is not implemented though,
     * as is the rest of external device mechanism.
     */
    { .name = "OSECCR_EL1", .state = ARM_CP_STATE_BOTH, .cp = 14,
      .opc0 = 2, .opc1 = 0, .crn = 0, .crm = 6, .opc2 = 2,
      .access = PL1_RW, .accessfn = access_tda,
      .fgt = FGT_OSECCR_EL1,
      .type = ARM_CP_CONST, .resetvalue = 0 },
    /*
     * DBGDSCRint[15,12,5:2] map to MDSCR_EL1[15,12,5:2].  Map all bits as
     * it is unlikely a guest will care.
     * We don't implement the configurable EL0 access.
     */
    { .name = "DBGDSCRint", .state = ARM_CP_STATE_AA32,
      .cp = 14, .opc1 = 0, .crn = 0, .crm = 1, .opc2 = 0,
      .type = ARM_CP_ALIAS,
      .access = PL1_R, .accessfn = access_tda,
      .fieldoffset = offsetof(CPUARMState, cp15.mdscr_el1), },
    { .name = "OSLAR_EL1", .state = ARM_CP_STATE_BOTH,
      .cp = 14, .opc0 = 2, .opc1 = 0, .crn = 1, .crm = 0, .opc2 = 4,
      .access = PL1_W, .type = ARM_CP_NO_RAW,
      .accessfn = access_tdosa,
      .fgt = FGT_OSLAR_EL1,
      .writefn = oslar_write },
    { .name = "OSLSR_EL1", .state = ARM_CP_STATE_BOTH,
      .cp = 14, .opc0 = 2, .opc1 = 0, .crn = 1, .crm = 1, .opc2 = 4,
      .access = PL1_R, .resetvalue = 10,
      .accessfn = access_tdosa,
      .fgt = FGT_OSLSR_EL1,
      .fieldoffset = offsetof(CPUARMState, cp15.oslsr_el1) },
    /* Dummy OSDLR_EL1: 32-bit Linux will read this */
    { .name = "OSDLR_EL1", .state = ARM_CP_STATE_BOTH,
      .cp = 14, .opc0 = 2, .opc1 = 0, .crn = 1, .crm = 3, .opc2 = 4,
      .access = PL1_RW, .accessfn = access_tdosa,
      .fgt = FGT_OSDLR_EL1,
      .writefn = osdlr_write,
      .fieldoffset = offsetof(CPUARMState, cp15.osdlr_el1) },
    /*
     * Dummy DBGVCR: Linux wants to clear this on startup, but we don't
     * implement vector catch debug events yet.
     */
    { .name = "DBGVCR",
      .cp = 14, .opc1 = 0, .crn = 0, .crm = 7, .opc2 = 0,
      .access = PL1_RW, .accessfn = access_tda,
      .type = ARM_CP_NOP },
    /*
     * Dummy MDCCINT_EL1, since we don't implement the Debug Communications
     * Channel but Linux may try to access this register. The 32-bit
     * alias is DBGDCCINT.
     */
    { .name = "MDCCINT_EL1", .state = ARM_CP_STATE_BOTH,
      .cp = 14, .opc0 = 2, .opc1 = 0, .crn = 0, .crm = 2, .opc2 = 0,
      .access = PL1_RW, .accessfn = access_tdcc,
      .type = ARM_CP_NOP },
    /*
     * Dummy DBGCLAIM registers.
     * "The architecture does not define any functionality for the CLAIM tag bits.",
     * so we only keep the raw bits
     */
    { .name = "DBGCLAIMSET_EL1", .state = ARM_CP_STATE_BOTH,
      .cp = 14, .opc0 = 2, .opc1 = 0, .crn = 7, .crm = 8, .opc2 = 6,
      .type = ARM_CP_ALIAS,
      .access = PL1_RW, .accessfn = access_tda,
      .fgt = FGT_DBGCLAIM,
      .writefn = dbgclaimset_write, .readfn = dbgclaimset_read },
    { .name = "DBGCLAIMCLR_EL1", .state = ARM_CP_STATE_BOTH,
      .cp = 14, .opc0 = 2, .opc1 = 0, .crn = 7, .crm = 9, .opc2 = 6,
      .access = PL1_RW, .accessfn = access_tda,
      .fgt = FGT_DBGCLAIM,
      .writefn = dbgclaimclr_write, .raw_writefn = raw_write,
      .fieldoffset = offsetof(CPUARMState, cp15.dbgclaim) },
};

/* These are present only when EL1 supports AArch32 */
static const ARMCPRegInfo debug_aa32_el1_reginfo[] = {
    /*
     * Dummy DBGVCR32_EL2 (which is only for a 64-bit hypervisor
     * to save and restore a 32-bit guest's DBGVCR)
     */
    { .name = "DBGVCR32_EL2", .state = ARM_CP_STATE_AA64,
      .opc0 = 2, .opc1 = 4, .crn = 0, .crm = 7, .opc2 = 0,
      .access = PL2_RW, .accessfn = access_dbgvcr32,
      .type = ARM_CP_NOP | ARM_CP_EL3_NO_EL2_KEEP },
};

static const ARMCPRegInfo debug_lpae_cp_reginfo[] = {
    /* 64 bit access versions of the (dummy) debug registers */
    { .name = "DBGDRAR", .cp = 14, .crm = 1, .opc1 = 0,
      .access = PL0_R, .type = ARM_CP_CONST | ARM_CP_64BIT | ARM_CP_NO_GDB,
      .resetvalue = 0 },
    { .name = "DBGDSAR", .cp = 14, .crm = 2, .opc1 = 0,
      .access = PL0_R, .type = ARM_CP_CONST | ARM_CP_64BIT | ARM_CP_NO_GDB,
      .resetvalue = 0 },
};

static void dbgwvr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                         uint64_t value)
{
    ARMCPU *cpu = env_archcpu(env);
    int i = ri->crm;

    /*
     * Bits [1:0] are RES0.
     *
     * It is IMPLEMENTATION DEFINED whether [63:49] ([63:53] with FEAT_LVA)
     * are hardwired to the value of bit [48] ([52] with FEAT_LVA), or if
     * they contain the value written.  It is CONSTRAINED UNPREDICTABLE
     * whether the RESS bits are ignored when comparing an address.
     *
     * Therefore we are allowed to compare the entire register, which lets
     * us avoid considering whether or not FEAT_LVA is actually enabled.
     */
    value &= ~3ULL;

    raw_write(env, ri, value);
    if (tcg_enabled()) {
        hw_watchpoint_update(cpu, i);
    }
}

static void dbgwcr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                         uint64_t value)
{
    ARMCPU *cpu = env_archcpu(env);
    int i = ri->crm;

    raw_write(env, ri, value);
    if (tcg_enabled()) {
        hw_watchpoint_update(cpu, i);
    }
}

static void dbgbvr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                         uint64_t value)
{
    ARMCPU *cpu = env_archcpu(env);
    int i = ri->crm;

    raw_write(env, ri, value);
    if (tcg_enabled()) {
        hw_breakpoint_update(cpu, i);
    }
}

static void dbgbcr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                         uint64_t value)
{
    ARMCPU *cpu = env_archcpu(env);
    int i = ri->crm;

    /*
     * BAS[3] is a read-only copy of BAS[2], and BAS[1] a read-only
     * copy of BAS[0].
     */
    value = deposit64(value, 6, 1, extract64(value, 5, 1));
    value = deposit64(value, 8, 1, extract64(value, 7, 1));

    raw_write(env, ri, value);
    if (tcg_enabled()) {
        hw_breakpoint_update(cpu, i);
    }
}

void define_debug_regs(ARMCPU *cpu)
{
    /*
     * Define v7 and v8 architectural debug registers.
     * These are just dummy implementations for now.
     */
    int i;
    int wrps, brps, ctx_cmps;

    /*
     * The Arm ARM says DBGDIDR is optional and deprecated if EL1 cannot
     * use AArch32.  Given that bit 15 is RES1, if the value is 0 then
     * the register must not exist for this cpu.
     */
    if (cpu->isar.dbgdidr != 0) {
        ARMCPRegInfo dbgdidr = {
            .name = "DBGDIDR", .cp = 14, .crn = 0, .crm = 0,
            .opc1 = 0, .opc2 = 0,
            .access = PL0_R, .accessfn = access_tda,
            .type = ARM_CP_CONST, .resetvalue = cpu->isar.dbgdidr,
        };
        define_one_arm_cp_reg(cpu, &dbgdidr);
    }

    /*
     * DBGDEVID is present in the v7 debug architecture if
     * DBGDIDR.DEVID_imp is 1 (bit 15); from v7.1 and on it is
     * mandatory (and bit 15 is RES1). DBGDEVID1 and DBGDEVID2 exist
     * from v7.1 of the debug architecture. Because no fields have yet
     * been defined in DBGDEVID2 (and quite possibly none will ever
     * be) we don't define an ARMISARegisters field for it.
     * These registers exist only if EL1 can use AArch32, but that
     * happens naturally because they are only PL1 accessible anyway.
     */
    if (extract32(cpu->isar.dbgdidr, 15, 1)) {
        ARMCPRegInfo dbgdevid = {
            .name = "DBGDEVID",
            .cp = 14, .opc1 = 0, .crn = 7, .opc2 = 2, .crn = 7,
            .access = PL1_R, .accessfn = access_tda,
            .type = ARM_CP_CONST, .resetvalue = cpu->isar.dbgdevid,
        };
        define_one_arm_cp_reg(cpu, &dbgdevid);
    }
    if (cpu_isar_feature(aa32_debugv7p1, cpu)) {
        ARMCPRegInfo dbgdevid12[] = {
            {
                .name = "DBGDEVID1",
                .cp = 14, .opc1 = 0, .crn = 7, .opc2 = 1, .crn = 7,
                .access = PL1_R, .accessfn = access_tda,
                .type = ARM_CP_CONST, .resetvalue = cpu->isar.dbgdevid1,
            }, {
                .name = "DBGDEVID2",
                .cp = 14, .opc1 = 0, .crn = 7, .opc2 = 0, .crn = 7,
                .access = PL1_R, .accessfn = access_tda,
                .type = ARM_CP_CONST, .resetvalue = 0,
            },
        };
        define_arm_cp_regs(cpu, dbgdevid12);
    }

    brps = arm_num_brps(cpu);
    wrps = arm_num_wrps(cpu);
    ctx_cmps = arm_num_ctx_cmps(cpu);

    assert(ctx_cmps <= brps);

    define_arm_cp_regs(cpu, debug_cp_reginfo);
    if (cpu_isar_feature(aa64_aa32_el1, cpu)) {
        define_arm_cp_regs(cpu, debug_aa32_el1_reginfo);
    }

    if (arm_feature(&cpu->env, ARM_FEATURE_LPAE)) {
        define_arm_cp_regs(cpu, debug_lpae_cp_reginfo);
    }

    for (i = 0; i < brps; i++) {
        char *dbgbvr_el1_name = g_strdup_printf("DBGBVR%d_EL1", i);
        char *dbgbcr_el1_name = g_strdup_printf("DBGBCR%d_EL1", i);
        ARMCPRegInfo dbgregs[] = {
            { .name = dbgbvr_el1_name, .state = ARM_CP_STATE_BOTH,
              .cp = 14, .opc0 = 2, .opc1 = 0, .crn = 0, .crm = i, .opc2 = 4,
              .access = PL1_RW, .accessfn = access_tda,
              .fgt = FGT_DBGBVRN_EL1,
              .fieldoffset = offsetof(CPUARMState, cp15.dbgbvr[i]),
              .writefn = dbgbvr_write, .raw_writefn = raw_write
            },
            { .name = dbgbcr_el1_name, .state = ARM_CP_STATE_BOTH,
              .cp = 14, .opc0 = 2, .opc1 = 0, .crn = 0, .crm = i, .opc2 = 5,
              .access = PL1_RW, .accessfn = access_tda,
              .fgt = FGT_DBGBCRN_EL1,
              .fieldoffset = offsetof(CPUARMState, cp15.dbgbcr[i]),
              .writefn = dbgbcr_write, .raw_writefn = raw_write
            },
        };
        define_arm_cp_regs(cpu, dbgregs);
        g_free(dbgbvr_el1_name);
        g_free(dbgbcr_el1_name);
    }

    for (i = 0; i < wrps; i++) {
        char *dbgwvr_el1_name = g_strdup_printf("DBGWVR%d_EL1", i);
        char *dbgwcr_el1_name = g_strdup_printf("DBGWCR%d_EL1", i);
        ARMCPRegInfo dbgregs[] = {
            { .name = dbgwvr_el1_name, .state = ARM_CP_STATE_BOTH,
              .cp = 14, .opc0 = 2, .opc1 = 0, .crn = 0, .crm = i, .opc2 = 6,
              .access = PL1_RW, .accessfn = access_tda,
              .fgt = FGT_DBGWVRN_EL1,
              .fieldoffset = offsetof(CPUARMState, cp15.dbgwvr[i]),
              .writefn = dbgwvr_write, .raw_writefn = raw_write
            },
            { .name = dbgwcr_el1_name, .state = ARM_CP_STATE_BOTH,
              .cp = 14, .opc0 = 2, .opc1 = 0, .crn = 0, .crm = i, .opc2 = 7,
              .access = PL1_RW, .accessfn = access_tda,
              .fgt = FGT_DBGWCRN_EL1,
              .fieldoffset = offsetof(CPUARMState, cp15.dbgwcr[i]),
              .writefn = dbgwcr_write, .raw_writefn = raw_write
            },
        };
        define_arm_cp_regs(cpu, dbgregs);
        g_free(dbgwvr_el1_name);
        g_free(dbgwcr_el1_name);
    }
}

#if defined(CONFIG_TCG) && !defined(CONFIG_USER_ONLY)
static uint32_t user_trace_phys_ldl(hwaddr addr)
{
    uint32_t value = 0;

    cpu_physical_memory_read(addr, &value, sizeof(value));
    return le32_to_cpu(value);
}

static void user_trace_append_string(CPUState *cs, GString *msg,
                                     uint32_t addr, const char *tag)
{
    uint8_t buf[64];
    unsigned n;
    unsigned hex;

    if (addr < 0x1000) {
        return;
    }
    g_string_append_printf(msg, " %shex=", tag);
    for (hex = 0; hex < 16; hex++) {
        if (cpu_memory_rw_debug(cs, addr + hex, &buf[hex], 1, false) != 0) {
            g_string_append(msg, "??");
            return;
        }
        g_string_append_printf(msg, "%02x", buf[hex]);
    }
    for (n = 0; n < sizeof(buf) - 1; n++) {
        if (cpu_memory_rw_debug(cs, addr + n, &buf[n], 1, false) != 0) {
            return;
        }
        if (buf[n] == 0) {
            break;
        }
        if (buf[n] < 0x20 || buf[n] > 0x7e) {
            return;
        }
    }
    if (n < 1 || n >= sizeof(buf) - 1 || buf[n] != 0) {
        return;
    }
    buf[n] = 0;
    g_string_append_printf(msg, " %s=\"%s\"", tag, buf);
}

static void user_trace_append_words(CPUState *cs, GString *msg,
                                    uint32_t addr, unsigned words,
                                    const char *tag)
{
    unsigned i;

    if (!words) {
        return;
    }
    g_string_append_printf(msg, " %s@0x%" PRIx32 "=", tag, addr);
    for (i = 0; i < words; i++) {
        uint8_t raw[4];

        if (cpu_memory_rw_debug(cs, (vaddr)addr + (vaddr)i * 4, raw, 4,
                                false) == 0) {
            g_string_append_printf(msg, "%s0x%08" PRIx32,
                                   i ? "," : "", ldl_le_p(raw));
        } else {
            g_string_append_printf(msg, "%s????????", i ? "," : "");
        }
    }
}

static void user_trace_dump_guest_map(CPUARMState *env, const char *why)
{
    uint64_t ttbr0 = env->cp15.ttbr0_el[1];
    uint32_t asid = extract32(env->cp15.contextidr_el[1], 0, 8);
    uint32_t ttbcr = (uint32_t)env->cp15.tcr_el[1];
    unsigned n = extract32(ttbcr, 0, 3);
    unsigned shift = 14 - n;
    hwaddr ttb = (hwaddr)ttbr0 & ~((1ull << shift) - 1);
    uint32_t va;
    uint32_t range_start = 0;
    bool in_range = false;
    uint64_t mapped = 0;
    uint64_t low = 0;
    uint64_t high = 0;
    uint64_t heap = 0;
    unsigned ranges = 0;
    unsigned printed = 0;
    uint32_t brk = 0;
    uint64_t ram = current_machine ? (uint64_t)current_machine->ram_size : 0;
    uint32_t dram_pages = 0;
    uint8_t dram_seen[4096];
    int64_t ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);

    memset(dram_seen, 0, sizeof(dram_seen));
    qemu_log("user-trace-mem ns=%" PRId64 " why=%s ttbr0=0x%" PRIx64
             " asid=0x%" PRIx32 " ttbcr=0x%" PRIx32 " ttb=0x%" HWADDR_PRIx
             " ram=%" PRIu64 "\n",
             ns, why, ttbr0, asid, ttbcr, ttb, ram);
    if (!ttb) {
        qemu_log("user-trace-mem-summary why=%s mapped=0\n", why);
        return;
    }

    for (va = 0; va < 0xc0000000; ) {
        uint32_t l1 = user_trace_phys_ldl(ttb + (hwaddr)(va >> 20) * 4);
        uint32_t type = l1 & 3;
        uint32_t chunk = 0x100000;
        bool present = false;
        hwaddr phys = 0;

        if (type == 2) {
            present = true;
            if (l1 & (1u << 18)) {
                chunk = 0x1000000;
                phys = l1 & 0xff000000;
            } else {
                phys = l1 & 0xfff00000;
            }
        } else if (type == 1) {
            hwaddr l2 = l1 & 0xfffffc00;
            uint32_t j;

            chunk = 0x1000;
            for (j = 0; j < 256; j++) {
                uint32_t d2 = user_trace_phys_ldl(l2 + j * 4);
                uint32_t t2 = d2 & 3;
                uint32_t psz = 0x1000;
                bool p2 = false;
                hwaddr p2phys = 0;

                if (t2 == 1) {
                    psz = 0x10000;
                    p2 = true;
                    p2phys = d2 & 0xffff0000;
                } else if (t2 & 2) {
                    p2 = true;
                    p2phys = d2 & 0xfffff000;
                }
                if (p2 != in_range) {
                    if (in_range) {
                        if (printed < 256) {
                            qemu_log("user-trace-map va=0x%08" PRIx32
                                     "-0x%08" PRIx32 " size=0x%" PRIx32 "\n",
                                     range_start, va, va - range_start);
                            printed++;
                        }
                        ranges++;
                    }
                    in_range = p2;
                    range_start = va;
                }
                if (p2) {
                    uint32_t off;

                    mapped += psz;
                    if (va < 0x40000000) {
                        low += psz;
                        if (va >= 0x2a000) {
                            heap += psz;
                        }
                    } else {
                        high += psz;
                    }
                    for (off = 0; off < psz; off += 0x1000) {
                        uint64_t dram = (uint64_t)p2phys + off;

                        if (dram >= 0x80000000ull &&
                            dram < 0x80000000ull + ram) {
                            uint32_t page = (uint32_t)((dram - 0x80000000ull) >> 12);
                            unsigned byte = page / 8;
                            unsigned bit = page % 8;

                            if (byte < sizeof(dram_seen) &&
                                !(dram_seen[byte] & (1u << bit))) {
                                dram_seen[byte] |= 1u << bit;
                                dram_pages++;
                            }
                        }
                    }
                }
                va += psz;
                if (psz > 0x1000) {
                    j += (psz / 0x1000) - 1;
                }
            }
            continue;
        }

        if (present != in_range) {
            if (in_range) {
                if (printed < 256) {
                    qemu_log("user-trace-map va=0x%08" PRIx32 "-0x%08" PRIx32
                             " size=0x%" PRIx32 "\n",
                             range_start, va, va - range_start);
                    printed++;
                }
                ranges++;
            }
            in_range = present;
            range_start = va;
        }
        if (present) {
            uint32_t off;

            mapped += chunk;
            if (va < 0x40000000) {
                low += chunk;
                if (va >= 0x2a000) {
                    heap += chunk;
                }
            } else {
                high += chunk;
            }
            for (off = 0; off < chunk; off += 0x1000) {
                uint64_t dram = (uint64_t)phys + off;

                if (dram >= 0x80000000ull && dram < 0x80000000ull + ram) {
                    uint32_t page = (uint32_t)((dram - 0x80000000ull) >> 12);
                    unsigned byte = page / 8;
                    unsigned bit = page % 8;

                    if (byte < sizeof(dram_seen) &&
                        !(dram_seen[byte] & (1u << bit))) {
                        dram_seen[byte] |= 1u << bit;
                        dram_pages++;
                    }
                }
            }
        }
        va += chunk;
    }
    if (in_range) {
        if (printed < 256) {
            qemu_log("user-trace-map va=0x%08" PRIx32 "-0x%08" PRIx32
                     " size=0x%" PRIx32 "\n",
                     range_start, va, va - range_start);
        }
        ranges++;
    }
    qemu_log("user-trace-mem-summary ns=%" PRId64 " why=%s mapped=0x%" PRIx64
             " low=0x%" PRIx64 " heapish=0x%" PRIx64 " mmap=0x%" PRIx64
             " ranges=%u dram_pages=%u dram_bytes=0x%" PRIx64
             " guest_ram=0x%" PRIx64,
             ns, why, mapped, low, heap, high, ranges, dram_pages,
             (uint64_t)dram_pages << 12, ram);
    if (user_trace_last_brk(&brk)) {
        qemu_log(" brk=0x%" PRIx32, brk);
    }
    qemu_log("\n");
}

static void user_trace_maybe_mem(CPUARMState *env, const char *why, bool force)
{
    int64_t sec = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) / 1000000000LL;
    int due;

    if (force) {
        user_trace_dump_guest_map(env, why);
    }
    while ((due = user_trace_mem_due(sec)) >= 0) {
        user_trace_mem_mark(due);
        user_trace_dump_guest_map(env, why);
    }
}

void HELPER(user_trace_pc)(CPUARMState *env, uint32_t pc)
{
    CPUState *cs = env_cpu(env);
    uint32_t cpsr = cpsr_read(env);
    uint64_t ttbr0 = env->cp15.ttbr0_el[1];
    uint32_t asid = extract32(env->cp15.contextidr_el[1], 0, 8);
    int64_t ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    GString *msg = g_string_new(NULL);
    unsigned words = user_trace_pc_stack_words();
    unsigned code_words = user_trace_pc_code_words();
    unsigned i;

    if (!user_trace_allow_as(pc, ttbr0, asid)) {
        g_string_free(msg, TRUE);
        return;
    }

    g_string_append_printf(msg,
        "user-trace-pc ns=%" PRId64 " pc=0x%" PRIx32 " lr=0x%" PRIx32
        " sp=0x%" PRIx32 " cpsr=0x%" PRIx32 " ttbr0=0x%" PRIx64
        " asid=0x%" PRIx32 " el=%d",
        ns, pc, env->regs[14], env->regs[13], cpsr, ttbr0, asid,
        arm_current_el(env));
    for (i = 0; i <= 12; i++) {
        g_string_append_printf(msg, " r%u=0x%" PRIx32, i, env->regs[i]);
    }
    if (words) {
        g_string_append(msg, " stack=");
        for (i = 0; i < words; i++) {
            uint8_t raw[4];
            vaddr addr = (vaddr)env->regs[13] + (vaddr)i * 4;

            if (cpu_memory_rw_debug(cs, addr, raw, 4, false) == 0) {
                g_string_append_printf(msg, "%s0x%08" PRIx32,
                                       i ? "," : "", ldl_le_p(raw));
            } else {
                g_string_append_printf(msg, "%s????????", i ? "," : "");
            }
        }
    }
    if (user_trace_code_pc_match(pc) || user_trace_ring_pc_match(pc)) {
        for (i = 0; i < 4; i++) {
            char tag[8];

            g_snprintf(tag, sizeof(tag), "str%u", i);
            user_trace_append_string(cs, msg, env->regs[i], tag);
        }
    }
    if (code_words && user_trace_code_pc_match(pc)) {
        uint32_t code_addr = env->regs[14] & ~3u;

        if (code_addr >= 64) {
            code_addr -= 64;
        }
        user_trace_append_words(cs, msg, code_addr, code_words, "lrcode");
    }
    user_trace_pc_log(msg->str);
    g_string_free(msg, TRUE);
    user_trace_maybe_mem(env, "pc", false);
    if (user_trace_ring_pc_match(pc)) {
        user_trace_maybe_mem(env, "abort", true);
        hw_event_ring_dump();
    }
}

#ifndef CONFIG_USER_ONLY
static QEMUTimer *user_trace_sample_timer;

static void user_trace_sample_cb(void *opaque)
{
    CPUState *cs = first_cpu;
    ARMCPU *cpu;
    CPUARMState *env;
    uint64_t ttbr0;
    uint32_t asid;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    int64_t period = user_trace_sample_period_ns();
    int el;

    (void)opaque;
    if (cs && period > 0) {
        cpu = ARM_CPU(cs);
        env = &cpu->env;
        ttbr0 = env->cp15.ttbr0_el[1];
        asid = extract32(env->cp15.contextidr_el[1], 0, 8);
        el = arm_current_el(env);
        if (user_trace_in_sock_window() && user_trace_sample_enabled()) {
            if (user_trace_is_bme_as(ttbr0) && user_trace_bme_in_syscall()) {
                qemu_log("user-trace-sample ns=%" PRId64
                         " why=syscall el=%d ttbr0=0x%" PRIx64
                         " asid=0x%" PRIx32 " pc=0x%" PRIx32
                         " lr=0x%" PRIx32 " r0=0x%" PRIx32 "\n",
                         now, el, ttbr0, asid, env->regs[15], env->regs[14],
                         env->regs[0]);
            } else if (el != 0) {
                qemu_log("user-trace-sample ns=%" PRId64
                         " why=kernel el=%d ttbr0=0x%" PRIx64
                         " asid=0x%" PRIx32 " pc=0x%" PRIx32 "\n",
                         now, el, ttbr0, asid, env->regs[15]);
            } else if (!user_trace_is_bme_as(ttbr0)) {
                qemu_log("user-trace-sample ns=%" PRId64
                         " why=other-as el=%d ttbr0=0x%" PRIx64
                         " asid=0x%" PRIx32 " pc=0x%" PRIx32
                         " lr=0x%" PRIx32 "\n",
                         now, el, ttbr0, asid, env->regs[15], env->regs[14]);
            } else {
                qemu_log("user-trace-sample ns=%" PRId64
                         " why=userspace el=%d ttbr0=0x%" PRIx64
                         " asid=0x%" PRIx32 " pc=0x%" PRIx32
                         " lr=0x%" PRIx32 " r0=0x%" PRIx32
                         " r1=0x%" PRIx32 " r2=0x%" PRIx32 "\n",
                         now, el, ttbr0, asid, env->regs[15], env->regs[14],
                         env->regs[0], env->regs[1], env->regs[2]);
            }
        }
    }
    if (user_trace_sample_timer && period > 0) {
        timer_mod(user_trace_sample_timer, now + period);
    }
}

static void user_trace_sample_ensure(void)
{
    if (user_trace_sample_timer || !user_trace_sample_enabled()) {
        return;
    }
    user_trace_sample_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                           user_trace_sample_cb, NULL);
    timer_mod(user_trace_sample_timer,
              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
              user_trace_sample_period_ns());
}

static void user_trace_read_unix_path(CPUState *cs, uint32_t addr, uint32_t len,
                                      char *out, size_t outsz)
{
    uint8_t raw[110];
    uint32_t n = len > sizeof(raw) ? sizeof(raw) : len;
    uint16_t family;

    if (!outsz) {
        return;
    }
    out[0] = 0;
    if (!addr || n < 3) {
        return;
    }
    memset(raw, 0, sizeof(raw));
    if (cpu_memory_rw_debug(cs, addr, raw, n, false) != 0) {
        return;
    }
    family = (uint16_t)(raw[0] | (raw[1] << 8));
    if (family != 1) {
        return;
    }
    if (raw[2] == 0 && n > 3) {
        g_snprintf(out, outsz, "@%s", (const char *)&raw[3]);
        return;
    }
    g_strlcpy(out, (const char *)&raw[2], outsz);
}

static void user_trace_iov_first(CPUState *cs, uint32_t iov_addr,
                                 uint32_t *addr, uint32_t *len)
{
    uint8_t iov[8];

    *addr = 0;
    *len = 0;
    if (!iov_addr) {
        return;
    }
    if (cpu_memory_rw_debug(cs, iov_addr, iov, 8, false) == 0) {
        *addr = ldl_le_p(iov);
        *len = ldl_le_p(iov + 4);
    }
}

static uint32_t user_trace_copy_guest(CPUState *cs, uint32_t addr, uint32_t len,
                                      uint8_t *out, uint32_t cap)
{
    uint32_t n = len > cap ? cap : len;
    uint32_t i;

    if (!addr || !n) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        if (cpu_memory_rw_debug(cs, addr + i, &out[i], 1, false) != 0) {
            return i;
        }
    }
    return n;
}

static void user_trace_poll_mask(GString *buf, uint16_t mask)
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

static void user_trace_format_poll(CPUState *cs, uint32_t fds, uint32_t nfds,
                                   uint32_t timeout, bool with_rev,
                                   char *out, size_t outsz)
{
    GString *buf = g_string_new(NULL);
    uint32_t i;
    uint32_t shown = nfds > 8 ? 8 : nfds;

    g_string_append_printf(buf, "nfds=%u timeout=%d", nfds, (int32_t)timeout);
    for (i = 0; i < shown; i++) {
        uint8_t raw[8];

        if (cpu_memory_rw_debug(cs, fds + i * 8, raw, 8, false) != 0) {
            break;
        }
        g_string_append_printf(buf, " fd%u=%d ev=", i, (int32_t)ldl_le_p(raw));
        user_trace_poll_mask(buf, lduw_le_p(raw + 4));
        if (with_rev) {
            g_string_append(buf, " rev=");
            user_trace_poll_mask(buf, lduw_le_p(raw + 6));
        }
    }
    g_strlcpy(out, buf->str, outsz);
    g_string_free(buf, TRUE);
}
#endif

static void user_trace_read_c_string(CPUState *cs, uint32_t addr,
                                     char *out, size_t out_size)
{
    size_t n;

    if (!out_size) {
        return;
    }
    out[0] = 0;
    if (addr < 0x1000) {
        return;
    }
    for (n = 0; n < out_size - 1; n++) {
        uint8_t byte;

        if (cpu_memory_rw_debug(cs, addr + n, &byte, 1, false) != 0) {
            break;
        }
        if (byte == 0) {
            break;
        }
        if (byte < 0x20 || byte > 0x7e) {
            out[n] = '?';
        } else {
            out[n] = (char)byte;
        }
    }
    out[n] = 0;
}

static void user_trace_format_mq_attr(CPUState *cs, uint32_t addr,
                                      GString *out)
{
    uint8_t raw[16];

    if (!addr || addr < 0x1000) {
        g_string_append(out, " attr=null");
        return;
    }
    if (cpu_memory_rw_debug(cs, addr, raw, 16, false) != 0) {
        g_string_append_printf(out, " attr_ptr=0x%" PRIx32 " attr=unreadable",
                               addr);
        return;
    }
    g_string_append_printf(out,
        " attr_ptr=0x%" PRIx32
        " mq_flags=%d mq_maxmsg=%d mq_msgsize=%d mq_curmsgs=%d",
        addr, (int32_t)ldl_le_p(raw), (int32_t)ldl_le_p(raw + 4),
        (int32_t)ldl_le_p(raw + 8), (int32_t)ldl_le_p(raw + 12));
}

static void user_trace_format_buf(CPUState *cs, uint32_t addr, uint32_t len,
                                  GString *out)
{
    uint8_t raw[USER_TRACE_WRITE_BYTES];
    uint32_t n = len > USER_TRACE_WRITE_BYTES ? USER_TRACE_WRITE_BYTES : len;
    uint32_t i;

    g_string_append_printf(out, "buflen=%u cap=%u hex=", len, n);
    if (!addr || !n) {
        return;
    }
    for (i = 0; i < n; i++) {
        if (cpu_memory_rw_debug(cs, addr + i, &raw[i], 1, false) != 0) {
            g_string_append(out, "??");
            return;
        }
        g_string_append_printf(out, "%02x", raw[i]);
    }
    g_string_append(out, " ascii=\"");
    for (i = 0; i < n; i++) {
        uint8_t c = raw[i];

        if (c == '\\' || c == '"') {
            g_string_append_c(out, '\\');
            g_string_append_c(out, (char)c);
        } else if (c >= 0x20 && c <= 0x7e) {
            g_string_append_c(out, (char)c);
        } else if (c == '\n') {
            g_string_append(out, "\\n");
        } else if (c == '\r') {
            g_string_append(out, "\\r");
        } else if (c == '\t') {
            g_string_append(out, "\\t");
        } else {
            g_string_append_printf(out, "\\x%02x", c);
        }
    }
    g_string_append_c(out, '"');
}

void HELPER(user_trace_svc)(CPUARMState *env, uint32_t pc)
{
    CPUState *cs = env_cpu(env);
    uint64_t ttbr0 = env->cp15.ttbr0_el[1];
    uint32_t asid = extract32(env->cp15.contextidr_el[1], 0, 8);
    uint32_t nr = env->regs[7];
    uint32_t retpc;
    uint32_t io_addr = 0;
    uint32_t io_len = 0;
    uint32_t tls = (uint32_t)env->cp15.tpidruro_ns;

    if (!tls) {
        tls = (uint32_t)env->cp15.tpidrurw_ns;
    }
    bool is_read = user_trace_syscall_is_read(nr);
    bool is_write = user_trace_syscall_is_write(nr);
    bool sock_io;
    bool bme;
    uint8_t raw[USER_TRACE_SOCK_BYTES_DEFAULT];
    uint32_t payload_n = 0;
    char extra[512];
    GString *buf;

    extra[0] = 0;
    if (arm_current_el(env) != 0 ||
        !user_trace_syscall_should_log(nr, ttbr0, asid, env->regs[0])) {
        return;
    }
    retpc = pc + (env->thumb ? 2 : 4);
    sock_io = user_trace_dsmesock_enabled() &&
              user_trace_sock_fd(ttbr0, env->regs[0]);
    bme = user_trace_is_bme_as(ttbr0);
    if (nr == 11) {
        GString *exec = g_string_new(NULL);
        uint32_t ai;

        user_trace_read_c_string(cs, env->regs[0], extra, sizeof(extra));
        g_string_append(exec, extra);
        g_string_append(exec, " argv=");
        for (ai = 0; ai < 8; ai++) {
            uint8_t argptr[4];
            uint32_t ptr;
            char arg[96];

            if (!env->regs[1] ||
                cpu_memory_rw_debug(cs, env->regs[1] + ai * 4, argptr, 4,
                                    false) != 0) {
                break;
            }
            ptr = ldl_le_p(argptr);
            if (!ptr) {
                break;
            }
            user_trace_read_c_string(cs, ptr, arg, sizeof(arg));
            if (ai) {
                g_string_append_c(exec, ',');
            }
            g_string_append_c(exec, '[');
            g_string_append(exec, arg[0] ? arg : "?");
            g_string_append_c(exec, ']');
        }
        g_strlcpy(extra, exec->str, sizeof(extra));
        g_string_free(exec, TRUE);
    } else if (nr == 114) {
        g_snprintf(extra, sizeof(extra),
                   "wpid=%d status_ptr=0x%" PRIx32 " options=0x%" PRIx32,
                   (int32_t)env->regs[0], env->regs[1], env->regs[2]);
    } else if (nr == 90 || nr == 192) {
        g_snprintf(extra, sizeof(extra),
                   "addr=0x%" PRIx32 " len=0x%" PRIx32 " prot=0x%" PRIx32
                   " flags=0x%" PRIx32 " fd=%d off=0x%" PRIx32,
                   env->regs[0], env->regs[1], env->regs[2], env->regs[3],
                   (int32_t)env->regs[4], env->regs[5]);
    } else if (nr == 5 || nr == 274 || nr == 275) {
        user_trace_read_c_string(cs, env->regs[0], extra, sizeof(extra));
        if (nr == 274) {
            GString *mq = g_string_new(extra);
            uint32_t flags = env->regs[1];
            bool have_attr = false;
            int32_t mq_flags = 0;
            int32_t mq_maxmsg = 0;
            int32_t mq_msgsize = 0;
            int32_t mq_curmsgs = 0;

            g_string_append_printf(mq,
                " flags=0x%" PRIx32 " mode=0x%" PRIx32
                " o_creat=%d o_excl=%d o_nonblock=%d",
                flags, env->regs[2], !!(flags & 0x40), !!(flags & 0x80),
                !!(flags & 0x800));
            if ((flags & 0x40) && env->regs[3] >= 0x1000) {
                uint8_t attrraw[16];
                unsigned ai;

                user_trace_format_mq_attr(cs, env->regs[3], mq);
                if (cpu_memory_rw_debug(cs, env->regs[3], attrraw, 16,
                                        false) == 0) {
                    have_attr = true;
                    mq_flags = (int32_t)ldl_le_p(attrraw);
                    mq_maxmsg = (int32_t)ldl_le_p(attrraw + 4);
                    mq_msgsize = (int32_t)ldl_le_p(attrraw + 8);
                    mq_curmsgs = (int32_t)ldl_le_p(attrraw + 12);
                    g_string_append(mq, " attr_hex=");
                    for (ai = 0; ai < 16; ai++) {
                        g_string_append_printf(mq, "%02x", attrraw[ai]);
                    }
                }
            } else {
                g_string_append(mq, " attr=null");
            }
            user_trace_nosmq_note_open(extra, flags, mq_flags, mq_maxmsg,
                                       mq_msgsize, mq_curmsgs, have_attr);
            g_strlcpy(extra, mq->str, sizeof(extra));
            g_string_free(mq, TRUE);
        }
    } else if (nr == 322) {
        user_trace_read_c_string(cs, env->regs[1], extra, sizeof(extra));
    } else if (nr == 54) {
        uint32_t req = env->regs[1];
        uint32_t ioc_nr = req & 0xff;
        uint32_t ioc_type = (req >> 8) & 0xff;
        uint32_t ioc_size = (req >> 16) & 0x3fff;
        uint32_t ioc_dir = (req >> 30) & 3;

        g_snprintf(extra, sizeof(extra),
                   "fd=%u req=0x%" PRIx32 " arg=0x%" PRIx32
                   " ioc_dir=%u ioc_type=0x%x ioc_nr=%u ioc_size=%u",
                   env->regs[0], req, env->regs[2],
                   ioc_dir, ioc_type, ioc_nr, ioc_size);
        if (ioc_type == 'D') {
            size_t pos = strlen(extra);

            g_snprintf(extra + pos, sizeof(extra) - pos, " dsp_ioc=1");
        }
        if (env->regs[1] == 0x6000) {
            size_t pos = strlen(extra);

            g_snprintf(extra + pos, sizeof(extra) - pos,
                       " urt=URT_IOCT_IRQ_SUBSCR irq=%u", env->regs[2]);
        }
        if (env->regs[2] >= 0x1000) {
            uint8_t argraw[16];
            uint32_t n = user_trace_copy_guest(cs, env->regs[2], 16, argraw,
                                               sizeof(argraw));
            size_t pos = strlen(extra);
            uint32_t i;

            if (n && pos + 8 < sizeof(extra)) {
                g_snprintf(extra + pos, sizeof(extra) - pos, " mem=");
                pos = strlen(extra);
                for (i = 0; i < n && pos + 2 < sizeof(extra); i++) {
                    extra[pos++] = "0123456789abcdef"[argraw[i] >> 4];
                    extra[pos++] = "0123456789abcdef"[argraw[i] & 0xf];
                    extra[pos] = 0;
                }
            }
            if (env->regs[1] == 0x6005 && n >= 7 &&
                pos + 48 < sizeof(extra)) {
                uint32_t field = ldl_le_p(argraw);

                g_snprintf(extra + pos, sizeof(extra) - pos,
                           " urt=TAHVO_IOCX_WRITE field=0x%" PRIx32
                           " reg=%u mask=0x%x value=0x%x",
                           field, (field >> 16) & 0x3f, field & 0xffff,
                           lduw_le_p(argraw + 4));
            } else if (env->regs[1] == 0x6004 && n >= 4 &&
                       pos + 32 < sizeof(extra)) {
                g_snprintf(extra + pos, sizeof(extra) - pos,
                           " urt=TAHVO_IOCH_READ field=0x%" PRIx32,
                           ldl_le_p(argraw));
            }
        }
    } else if (nr == 282 || nr == 283) {
        user_trace_read_unix_path(cs, env->regs[1], env->regs[2], extra,
                                  sizeof(extra));
        if (nr == 282) {
            user_trace_note_unix_bind(ttbr0, env->regs[0], extra);
        } else {
            user_trace_note_unix_connect(ttbr0, env->regs[0], extra);
        }
    } else if (nr == 168) {
        user_trace_format_poll(cs, env->regs[0], env->regs[1], env->regs[2],
                               false, extra, sizeof(extra));
    } else if (nr == 142) {
        g_snprintf(extra, sizeof(extra), "nfds=%u", env->regs[0]);
    } else if (nr == 276 || nr == 277) {
        io_addr = env->regs[1];
        io_len = env->regs[2];
        if (nr == 276) {
            buf = g_string_new(NULL);
            user_trace_format_buf(cs, io_addr, io_len, buf);
            g_string_append_printf(buf, " prio=%u timeout=%s", env->regs[3],
                                   env->regs[4] ? "ptr" : "NULL");
            g_strlcpy(extra, buf->str, sizeof(extra));
            payload_n = user_trace_copy_guest(cs, io_addr, io_len, raw,
                                              sizeof(raw));
            g_string_free(buf, TRUE);
        } else {
            g_snprintf(extra, sizeof(extra),
                       "fd=%u buflen=%u prio_ptr=0x%" PRIx32 " timeout=%s",
                       env->regs[0], env->regs[2], env->regs[3],
                       env->regs[4] ? "ptr" : "NULL");
        }
    } else if (nr == 279) {
        buf = g_string_new(NULL);
        g_string_append_printf(buf, "fd=%u", env->regs[0]);
        if (env->regs[1] >= 0x1000) {
            g_string_append(buf, " new");
            user_trace_format_mq_attr(cs, env->regs[1], buf);
        } else {
            g_string_append(buf, " new=null");
        }
        if (env->regs[2] >= 0x1000) {
            g_string_append(buf, " old");
            user_trace_format_mq_attr(cs, env->regs[2], buf);
        } else {
            g_string_append(buf, " old=null");
        }
        g_strlcpy(extra, buf->str, sizeof(extra));
        g_string_free(buf, TRUE);
    } else if (is_write || is_read) {
        io_addr = env->regs[1];
        io_len = env->regs[2];
        if (nr == 145 || nr == 146) {
            user_trace_iov_first(cs, env->regs[1], &io_addr, &io_len);
        }
        if (is_write) {
            uint8_t write_raw[USER_TRACE_WRITE_BYTES];
            uint32_t n = user_trace_copy_guest(cs, io_addr, io_len, write_raw,
                                               sizeof(write_raw));

            if (sock_io ||
                user_trace_write_interesting(ttbr0, env->regs[0], write_raw,
                                             n)) {
                buf = g_string_new(NULL);
                user_trace_format_buf(cs, io_addr, io_len, buf);
                g_strlcpy(extra, buf->str, sizeof(extra));
                g_string_free(buf, TRUE);
            }
            payload_n = n > user_trace_sock_bytes() ? user_trace_sock_bytes()
                                                    : n;
            memcpy(raw, write_raw, payload_n);
        }
    }
    user_trace_svc_arm_enter(pc, retpc, env->regs[14], nr,
                             env->regs[0], env->regs[1], env->regs[2],
                             env->regs[3], env->regs[4], env->regs[5],
                             env->regs[6], ttbr0, asid, tls, extra);
    if (nr == 5 || nr == 274 || nr == 322 || nr == 283) {
        char path[96];
        const char *sp;

        g_strlcpy(path, extra, sizeof(path));
        sp = strchr(path, ' ');
        if (sp) {
            path[sp - path] = 0;
        }
        user_trace_pending_set_path(retpc, ttbr0, path[0] ? path : extra);
    }
    if (nr == 168) {
        user_trace_pending_set_io(retpc, ttbr0, 0, env->regs[0], env->regs[1],
                                  false);
    }
    if (nr == 276 || nr == 277) {
        user_trace_pending_set_io(retpc, ttbr0, env->regs[0], io_addr, io_len,
                                  nr == 277);
        if (nr == 276 && payload_n) {
            user_trace_pending_set_payload(retpc, ttbr0, raw, payload_n);
        }
    }
    if ((sock_io || bme) && (is_write || is_read)) {
        user_trace_pending_set_io(retpc, ttbr0, env->regs[0], io_addr, io_len,
                                  is_read);
        if (is_write && payload_n) {
            user_trace_pending_set_payload(retpc, ttbr0, raw, payload_n);
        }
    }
    user_trace_sample_ensure();
    if (nr == 37 || nr == 178 || nr == 238 || nr == 268 || nr == 363) {
        uint32_t sig = (nr == 268 || nr == 363) ? env->regs[2] : env->regs[1];

        if (sig == 6) {
            user_trace_maybe_mem(env, "sigabrt", true);
        }
    }
}

void HELPER(user_trace_svc_ret)(CPUARMState *env, uint32_t pc)
{
    CPUState *cs = env_cpu(env);
    uint64_t ttbr0 = env->cp15.ttbr0_el[1];
    uint32_t asid = extract32(env->cp15.contextidr_el[1], 0, 8);
    uint32_t addr = 0;
    uint32_t len = 0;
    uint32_t nr = 0;
    int32_t ret;

    if (!user_trace_svc_ret_pending(pc)) {
        return;
    }
    ret = (int32_t)env->regs[0];
    if (user_trace_pending_info(pc, ttbr0, &nr, &addr, &len) && nr == 168 &&
        addr && len) {
        char extra[512];

        user_trace_format_poll(cs, addr, len, 0, true, extra, sizeof(extra));
        user_trace_set_ret_extra(extra);
    } else if (ret > 0 && user_trace_pending_read(pc, ttbr0, &addr, &len)) {
        uint8_t raw[USER_TRACE_SOCK_BYTES_DEFAULT];
        uint32_t want = (uint32_t)ret;
        uint32_t n;
        GString *buf;

        if (want > user_trace_sock_bytes()) {
            want = user_trace_sock_bytes();
        }
        n = user_trace_copy_guest(cs, addr, want, raw, sizeof(raw));
        user_trace_pending_set_payload(pc, ttbr0, raw, n);
        buf = g_string_new(NULL);
        user_trace_format_buf(cs, addr, (uint32_t)ret, buf);
        user_trace_set_ret_extra(buf->str);
        g_string_free(buf, TRUE);
    }
    user_trace_svc_arm_eret(pc, env->regs[0], ttbr0, asid);
    user_trace_maybe_mem(env, "svc-ret", false);
}
#endif
