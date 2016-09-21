/*
 * (c) Copyright 2016 G. Campana
 * (c) Copyright 2016 Quarkslab
 *
 * This file is part of Cappsule.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef VM_EXIT_H
#define VM_EXIT_H

#define EXIT_REASON_EXCEPTION_NMI       0
#define EXIT_REASON_EXTERNAL_INTERRUPT  1
#define EXIT_REASON_TRIPLE_FAULT        2
#define EXIT_REASON_PENDING_INTERRUPT   7
#define EXIT_REASON_NMI_WINDOW          8
#define EXIT_REASON_TASK_SWITCH         9
#define EXIT_REASON_CPUID               10
#define EXIT_REASON_GETSEC		11
#define EXIT_REASON_HLT                 12
#define EXIT_REASON_INVD                13
#define EXIT_REASON_INVLPG              14
#define EXIT_REASON_RDPMC               15
#define EXIT_REASON_RDTSC               16
#define EXIT_REASON_VMCALL              18
#define EXIT_REASON_VMCLEAR             19
#define EXIT_REASON_VMLAUNCH            20
#define EXIT_REASON_VMPTRLD             21
#define EXIT_REASON_VMPTRST             22
#define EXIT_REASON_VMREAD              23
#define EXIT_REASON_VMRESUME            24
#define EXIT_REASON_VMWRITE             25
#define EXIT_REASON_VMOFF               26
#define EXIT_REASON_VMON                27
#define EXIT_REASON_CR_ACCESS           28
#define EXIT_REASON_DR_ACCESS           29
#define EXIT_REASON_IO_INSTRUCTION      30
#define EXIT_REASON_MSR_READ            31
#define EXIT_REASON_MSR_WRITE           32
#define EXIT_REASON_INVALID_STATE       33
#define EXIT_REASON_VM_ENTRY_FAILURE_MSR	34
#define EXIT_REASON_MWAIT_INSTRUCTION   36
#define EXIT_REASON_MONITOR_INSTRUCTION 39
#define EXIT_REASON_PAUSE_INSTRUCTION   40
#define EXIT_REASON_MCE_DURING_VMENTRY  41
#define EXIT_REASON_TPR_BELOW_THRESHOLD 43
#define EXIT_REASON_APIC_ACCESS         44
#define EXIT_REASON_EOI_INDUCED         45
#define EXIT_REASON_ACCESS_GDTR_IDTR	46
#define EXIT_REASON_ACCESS_LDTR_TR	47
#define EXIT_REASON_EPT_VIOLATION       48
#define EXIT_REASON_EPT_MISCONFIG       49
#define EXIT_REASON_INVEPT		50
#define EXIT_REASON_PREEMPTION_TIMER    52
#define EXIT_REASON_INVVPID             53
#define EXIT_REASON_WBINVD              54
#define EXIT_REASON_XSETBV              55
#define EXIT_REASON_APIC_WRITE          56
#define EXIT_REASON_INVPCID             58

#define VM_EXIT_STR(VM_EXIT) [ EXIT_REASON_ ## VM_EXIT ] = # VM_EXIT,

/*
 * find . -type f -name '*.[chsS]'	      \
 *  | xargs egrep -o 'EXIT_REASON_[A-Z_0-9]+' \
 *  | cut -d : -f 2                           \
 *  | sort -u
 */
static const char *vm_exit_reasons[] = {
	VM_EXIT_STR(EXCEPTION_NMI)
	VM_EXIT_STR(EXTERNAL_INTERRUPT)
	VM_EXIT_STR(TRIPLE_FAULT)
	VM_EXIT_STR(PENDING_INTERRUPT)
	VM_EXIT_STR(CPUID)
	VM_EXIT_STR(GETSEC)
	VM_EXIT_STR(HLT)
	VM_EXIT_STR(INVD)
	VM_EXIT_STR(INVLPG)
	VM_EXIT_STR(VMCALL)
	VM_EXIT_STR(VMCLEAR)
	VM_EXIT_STR(VMLAUNCH)
	VM_EXIT_STR(VMOFF)
	VM_EXIT_STR(VMON)
	VM_EXIT_STR(VMPTRLD)
	VM_EXIT_STR(VMPTRST)
	VM_EXIT_STR(VMREAD)
	VM_EXIT_STR(VMRESUME)
	VM_EXIT_STR(VMWRITE)
	VM_EXIT_STR(INVVPID)
	VM_EXIT_STR(CR_ACCESS)
	VM_EXIT_STR(DR_ACCESS)
	VM_EXIT_STR(IO_INSTRUCTION)
	VM_EXIT_STR(MSR_READ)
	VM_EXIT_STR(MSR_WRITE)
	VM_EXIT_STR(INVALID_STATE)
	VM_EXIT_STR(VM_ENTRY_FAILURE_MSR)
	VM_EXIT_STR(MWAIT_INSTRUCTION)
	VM_EXIT_STR(MONITOR_INSTRUCTION)
	VM_EXIT_STR(ACCESS_GDTR_IDTR)
	VM_EXIT_STR(ACCESS_LDTR_TR)
	VM_EXIT_STR(EPT_MISCONFIG)
	VM_EXIT_STR(EPT_VIOLATION)
	VM_EXIT_STR(INVEPT)
	VM_EXIT_STR(XSETBV)
};

#undef VM_EXIT_STR

#endif
