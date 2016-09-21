# CFLAGS variable could be communicated to sub-make using the following line:
#     export CFLAGS := $(CFLAGS)
# Nevertheless, it doesn't work if make is directly called from a subdirectory.
# Use an include instead.
include Makefile.inc

TSUBDIRS := api common
SUBDIRS_PARALLEL := daemon devices logger snapshot
SUBDIRS_NOTPARALLEL := api common
SUBDIRS := $(SUBDIRS_NOTPARALLEL) $(SUBDIRS_PARALLEL)

STRIP-SUBDIRS := $(addprefix strip-,$(SUBDIRS))
CLEAN-SUBDIRS := $(addprefix clean-,$(SUBDIRS))
TESTS-SUBDIRS := $(addprefix test-,$(TSUBDIRS))

.PHONY: all clean strip check $(SUBDIRS) $(CLEAN-SUBDIRS) $(STRIP-SUBDIRS)

# api/*.o and common/*.o are required by several targets, and sometimes lead to
# an error with make -j.
# Building them before other targets seems to solve this issue.
all:
	$(MAKE) -C common
	$(MAKE) -C api
	$(MAKE) $(SUBDIRS_PARALLEL)

strip: $(STRIP-SUBDIRS)
clean: $(CLEAN-SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

$(STRIP-SUBDIRS): strip-%:
	$(MAKE) -C $* strip

$(CLEAN-SUBDIRS): clean-%:
	$(MAKE) -C $* clean

check: $(TESTS-SUBDIRS)

$(TESTS-SUBDIRS): test-%:
	$(MAKE) -C $* check
