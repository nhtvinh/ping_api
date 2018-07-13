#
# Configuration
#

# Path to parent kernel include files directory
LIBC_INCLUDE=/usr/include
# Libraries
ADDLIB=

# -------------------------------------
# What a pity, all new gccs are buggy and -Werror does not work. Sigh.
# CFLAGS+=-fno-strict-aliasing -Wstrict-prototypes -Wall -Werror -g
CFLAGS?=-O3 -g
CFLAGS+=-fno-strict-aliasing -Wstrict-prototypes -Wall
CPPFLAGS+=-D_GNU_SOURCE
LDLIB=

# -------------------------------------
TARGETS=ping
 
LDLIBS=$(LDLIB) $(ADDLIB)

TODAY=$(shell date +%Y-%m-%d)
DATE=$(shell date -d $(TODAY) +%Y%m%d)
TAG:=$(shell date -d $(TODAY) +s%Y%m%d)


# -------------------------------------
.PHONY: all ninfod clean distclean man html snapshot

all: $(TARGETS)

%.s: %.c
	$(COMPILE.c) $< $(DEF_$(patsubst %.o,%,$@)) -S -o $@
%.o: %.c
	$(COMPILE.c) $< $(DEF_$(patsubst %.o,%,$@)) -o $@
LINK.o += $(CFLAGS)
$(TARGETS): %: %.o
	$(LINK.o) $^ $(LIB_$@) $(LDLIBS) -o $@

# ping / ping6
DEF_ping = $(DEF_CAP) $(DEF_IDN) $(DEF_CRYPTO) $(DEF_WITHOUT_IFADDRS)
DEF_ping_common = $(DEF_ping)
LIB_ping = $(LIB_CAP) $(LIB_IDN) $(LIB_CRYPTO) $(LIB_RESOLV) $(LDFLAG_M)

ping: test.o ping_common.o
ping.o ping_common.o: ping.h

clean:
	@rm -f *.o $(TARGETS)
