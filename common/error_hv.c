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

#include <stdio.h>
#include <unistd.h>

#include "userland.h"
#include "cuapi/error.h"

/* not thread safe */
static char msg[128];

#ifndef RELEASE

#define ARRAY_SIZE(arr)		(sizeof(arr) / sizeof(arr[0]))
#define BUILD_BUG_ON(condition)	((void)sizeof(char[1 - 2*!!(condition)]))
#define X(k, v)			[k] = v,

#define ENUM_MAP(X) 										\
	X(HV_SUCCESS,				"success")					\
												\
	/* hypervisor initialisation */ 							\
	X(ERROR_ALLOC_GUARD_PAGE,		"no memory to allocate guard page")		\
	X(ERROR_ALLOC_FAILED,			"memory allocation failure")			\
	X(ERROR_LOG_DEVICE_REGISTRATION,	"log device register failed")			\
	X(ERROR_SYMBOL_RESOLUTION,		"symbol resolution failure")			\
	X(ERROR_CHECK_BREAKPOINTS,		"a breakpoint can't be set")			\
	X(ERROR_XCHAN_INTR_VECTOR,		"can't find xchan vector")			\
	X(ERROR_MFN_DEVICE_REGISTRATION,	"mfn device registration failed")		\
	X(ERROR_SHRINK_MEMORY,			"can't shrink memory")				\
	X(ERROR_VMX_ALREADY_ENABLED,		"VMX is already enabled")			\
	X(ERROR_VMLAUNCH_FAILED,		"VMLAUNCH failed")				\
	X(ERROR_VMXON_FAILED,			"VMXON failed")					\
	X(ERROR_CPU_FORK,			"CPU fork failed")				\
	X(ERROR_CPU_NO_VMX,			"CPU doesn't support VMX")			\
	X(ERROR_CPU_NO_SECONDARY_CONTROLS,	"CPU doesn't support secondary controls")	\
	X(ERROR_CPU_NO_EPT,			"CPU doesn't support EPT")			\
	X(ERROR_CPU_VMX_DISABLED,		"VMX is disabled by BIOS")			\
	X(ERROR_CPU_WB_MEMORY_TYPE,		"CPU doesn't support WB memory")		\
	X(ERROR_CPU_NO_INVEPT,			"CPU doesn't support INVEPT instruction")	\
	X(ERROR_CPU_INVEPT_SINGLE_CONTEXT,	"CPU doesn't support INVEPT single context")	\
	X(ERROR_CPU_INVEPT_TYPE,		"CPU doesn't support INVEPT type")		\
	X(ERROR_CLEAR_TRUSTED_VMCS,		"failed to clear trusted vmcs")			\
	X(ERROR_LOAD_TRUSTED_VMCS,		"failed to load trusted vmcs")			\
	X(ERROR_CLEAR_CAPSULE_VMCS,		"failed to clear capsule vmcs")			\
	X(ERROR_LOAD_CAPSULE_VMCS,		"failed to load capsule vmcs")			\
												\
	/* snapshot */										\
	X(ERROR_SNAP_ALREADY_DONE,		"snapshot already done")			\
	X(ERROR_SNAP_MODULE_BEING_REMOVED,	"module being removed")				\
	X(ERROR_SNAP_PARAMS_NPAGES_TOO_LARGE,	"params size is too large")			\
	X(ERROR_SNAP_CPUS_ONLINE,		"more than 1 CPU online")			\
	X(ERROR_SNAP_FIX_SET_HOOK,		"a hook can't be set")				\
	X(ERROR_SNAP_FIX_INVALID_ADDR,		"invalid hook address")				\
	X(ERROR_SNAP_FIX_MULTIPLE_PAGES,	"hook on multuple pages")			\
	X(ERROR_SNAP_ERASE_MODULE_MEMORY,	"failed to erase module memory")		\
	X(ERROR_SNAP_ARGV_GPA,			"can't get GPA of argv")			\
												\
	X(ERROR_SNAP_PID_BITMAP_ALLOC_FAILED,	"memory allocation failure (pid bitmap)")	\
	X(ERROR_SNAP_SET_PFN_ALLOC_FAILED,	"memory allocation failure (set_pfn)")		\
	X(ERROR_SNAP_ALLOC_COPY_PAGES,		"memory allocation failure (copy pages)")	\
	X(ERROR_SNAP_COUNT_DATA_PAGES,		"failed to count data pages")			\
	X(ERROR_SNAP_CREATE_SNAP_ALLOC_FAILED,	"memory allocation failure (create snapshot)")	\
	X(ERROR_SNAP_INVALID_PTE,		"invalid pte in snapshot")			\
	X(ERROR_SNAP_PTE_LEVEL_SET,		"pte level already set")			\
												\
	/* capsule creation */									\
	X(ERROR_CREATION_NO_SNAPSHOT,		"memory hasn't been snapshoted")		\
	X(ERROR_CREATION_MODULE_BEING_REMOVED,	"module is being removed")			\
	X(ERROR_CREATION_MAX_CAPSULE,		"maximum number of capsules reached")		\
	X(ERROR_CREATION_ALLOC_FAILED,		"memory allocation failure (capsule)")		\
	X(ERROR_CREATION_INVALID_USER_PAGES,	"user pages are invalid")			\
	X(ERROR_CREATION_KTHREAD_FAILED,	"failed to create kthread")			\
	X(ERROR_CREATION_XCHAN_ALLOC_FAILED,	"failed to allocate xchan pages")		\
												\
	/* xchan */										\
	X(ERROR_XCHAN_DEVICE_REGISTRATION,	"can't register xchan device")

static const char *error_msg[] = {
	ENUM_MAP(X)
};
#undef X

#define X(n, v)		+ 1
#define NB_MSG		(0 ENUM_MAP(X))

const char *hv_error_message(int caps_errno)
{
	/* ensure at compile time that each err_t (included from hv/) has an
	 * index in error_msg array */
	BUILD_BUG_ON(NB_MSG != HV_ERROR_MAX);

	caps_errno -= CAPPSULE_ERRNO_BASE;

	if (caps_errno >= 0 && (unsigned int)caps_errno < ARRAY_SIZE(error_msg)) {
		return error_msg[caps_errno];
	} else {
		sprintf(msg, "unknown error %d", caps_errno + CAPPSULE_ERRNO_BASE);
		return msg;
	}
}

#else

const char *hv_error_message(int caps_errno)
{
	sprintf(msg, "error %d", caps_errno);
	return msg;
}

#endif /* RELEASE */

// vim: noet:ts=8:
