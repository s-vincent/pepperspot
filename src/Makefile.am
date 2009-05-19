sbin_PROGRAMS = pepper

# add -pg to enable gprof
AM_CFLAGS = -D_GNU_SOURCE -fno-builtin -DSBINDIR='"$(sbindir)"' -std=gnu99 -Wall -Wextra -pedantic -Wstrict-prototypes -Wredundant-decls -Werror -fno-strict-aliasing 

if ENABLE_DEBUG_BUILD
AM_CFLAGS += -g
else
AM_CFLAGS += -DNDEBUG
endif

pepper_SOURCES = pepper.c tun.c tun.h cmdline.c cmdline.h ippool.c ippool.h radius.h radius.c md5.c md5.h redir.h redir.c dhcp.c dhcp.h syserr.c syserr.h iphash.c iphash.h lookup.c lookup.h tun6.c tun6.h ndisc.c ndisc.h util.h icmp6.c icmp6.h 
#compat.c compat.h

pepper_LDFLAGS =

