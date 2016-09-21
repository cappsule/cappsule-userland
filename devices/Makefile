SUBDIRS := common console fs net

ifneq ($(NOGUI),1)
	SUBDIRS += gui
endif

CLEAN-SUBDIRS := $(addprefix clean-,$(SUBDIRS))
STRIP-SUBDIRS := $(addprefix strip-,$(SUBDIRS))

.PHONY: all clean strip $(SUBDIRS) $(CLEAN-SUBDIRS) $(STRIP-SUBDIRS)

all: $(SUBDIRS)
strip: $(STRIP-SUBDIRS)
clean: $(CLEAN-SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

$(STRIP-SUBDIRS): strip-%:
	$(MAKE) -C $* strip

$(CLEAN-SUBDIRS): clean-%:
	$(MAKE) -C $* clean
