sbin_PROGRAMS = pepper

# add -pg to enable gprof
AM_CFLAGS = -D_GNU_SOURCE -D_POSIX_C_SOURCE=200112L -fno-builtin -DSBINDIR='"$(sbindir)"' -Wall -W -pedantic -std=c99 -Wstrict-prototypes -Wredundant-decls -Waggregate-return

pepper_SOURCES = pepper.c tun.c tun.h cmdline.c cmdline.h ippool.c ippool.h radius.h radius.c md5.c md5.h redir.h redir.c dhcp.c dhcp.h syserr.c syserr.h iphash.c iphash.h lookup.c lookup.h tun6.c  tun6.h ndisc.c ndisc.h util.h icmp6.c icmp6.h compat.c compat.h

pepper_LDFLAGS =

