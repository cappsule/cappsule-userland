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

#ifndef VMCALL_STR_H
#define VMCALL_STR_H

#include "cuapi/common/vmcall.h"

#ifndef BUILD_BUG_ON
#define BUILD_BUG_ON(condition)((void)sizeof(char[1 - 2*!!(condition)]))
#endif

#ifndef RELEASE
#  define X(s)		s
#else
/* Beware: to be accurate, vmcalls must be declared in the very same order than
 * in cuapi/common/vmcall.h. */
#  define X(s)		"vmcall-" XSTR(__COUNTER__)
#  define XSTR(s)	STR(s)
#  define STR(s)	#s
#endif

static const char *vmcall_names[] = {
	[VMCALL_STOP_VMM]		= X("stop_vmm"),
	[VMCALL_SNAPSHOT]		= X("snapshot"),
	[VMCALL_CREATE_CAPSULE]		= X("create_capsule"),
	[VMCALL_LAUNCH_CAPSULE]		= X("launch_capsule"),
	[VMCALL_RESUME_EXECUTION]	= X("resume_execution"),
	[VMCALL_FATAL_SIGNAL]		= X("fatal_signal"),
	[VMCALL_XCHAN_SET_EVENT]	= X("xchan_set_event"),
	[VMCALL_ADD_PENDING_TIMER_INTR] = X("add_pending_timer_intr"),
	[VMCALL_ADD_PENDING_XCHAN_INTR] = X("add_pending_xchan_intr"),
	[VMCALL_GPA_TO_HVA]		= X("gpa_to_hva"),
	[VMCALL_KILLALL]		= X("killall"),
	[VMCALL_GET_SHADOWP_TASK]	= X("get_shadowp_task"),
	[VMCALL_GET_FIRST_SHADOWP_TASK]	= X("get_first_shadowp_task"),
	[VMCALL_GET_CAPSULE_STATS]	= X("get_capsule_stats"),
	[VMCALL_GET_CAPSULE_IDS]	= X("get_capsule_ids"),
	[VMCALL_RESIZE_CONSOLE]		= X("resize_console"),

	[VMCALL_EXIT]			= X("exit"),
	[VMCALL_FORBIDDEN_EXECVE]	= X("forbidden_execve"),
	[VMCALL_SHARE_MEM]		= X("share_mem"),
	[VMCALL_GETTIMEOFDAY]		= X("gettimeofday"),
	[VMCALL_SET_TIMER]		= X("set_timer"),
	[VMCALL_XCHAN_NOTIFY_TRUSTED]	= X("xchan_notify_trusted"),
	[VMCALL_XCHAN_MAP_GUEST_PAGE]	= X("xchan_map_guest_page"),
	[VMCALL_XCHAN_CLOSED]		= X("xchan_closed"),
	[VMCALL_CAPSULE_ERROR]		= X("capsule_error"),
};

#undef X
#ifdef RELEASE
#  undef STR
#  undef XSTR
#endif

static inline void check_vmcall_array_size_at_compile_time(void)
{
	BUILD_BUG_ON(ARRAY_SIZE(vmcall_names) != NR_VM_CALLS);
}

#endif
