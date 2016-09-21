#
# The following macros affect compilation:
#
#   -DRELEASE       if undefined, hypervisor errors are displayed as strings,
#                   otherwise the error number is used.
#
# Set corresponding environment variable to 1 do define them.
#

mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
mkfile_dir := $(patsubst %/,%,$(dir $(mkfile_path)))


################################################################################
# userland macros
################################################################################

USERLAND_MACROS :=

ifeq ($(RELEASE),1)
	USERLAND_MACROS += -DRELEASE
endif

ifeq ($(NOGUI),1)
	USERLAND_MACROS += -DNOGUI
endif

GIT_VERSION := $(shell git -C ./ describe --always --tags --abbrev=7)
USERLAND_MACROS += -DGIT_VERSION=\"$(GIT_VERSION)\"


################################################################################
# compilation flags
################################################################################

CUAPI_INCLUDE_PATH := $(mkfile_dir)/../hv/include
CFLAGS := -W -Wall -Wextra -Wfatal-errors -O3 $(USERLAND_MACROS)
LDFLAGS :=
STRIP := strip

ifeq ($(COVERAGE),1)
	CFLAGS += -fprofile-arcs -ftest-coverage
	LDFLAGS += --coverage
endif


################################################################################
# makefile colors
################################################################################

ifneq ($(VERBOSE),1)
	# MAKEFLAGS contains the flags passed to make in a fairly parseable format;
	# options that have a single-character form are grouped in its first word if
	# any are passed, and if none were passed, MAKEFLAGS either begins with a -
	# or is empty.

	# don't print the commands as they are executed
	ifeq (,$(findstring s,$(firstword $(MAKEFLAGS))))
		MAKEFLAGS := s$(MAKEFLAGS)
	endif

	# don't print messages containing the working directory
	ifeq (,$(findstring --no-print-directory,$(MAKEFLAGS)))
		MAKEFLAGS := $(MAKEFLAGS) --no-print-directory
	endif

	# call make-color.sh instead of $(CC)
	CC := $(mkfile_dir)/make-color.sh $(CC)
endif
