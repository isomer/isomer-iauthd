# $Id: Makefile.am,v 1.3 2008/02/01 19:40:31 danielaustin Exp $

INCLUDES = \
	-I../include \
        $(PACKAGE_CFLAGS)

AM_CFLAGS = \
         -Wall \
	 -Werror \
	 -Wno-long-long \
	 -Wmissing-prototypes \
	 -pedantic

bin_PROGRAMS = iauthd 

iauthd_SOURCES = \
	compat.c \
	clientdata.c \
	config.c \
	main.c \
	match.c \
	\
	cache.c \
	actionlist.c \
	check_challenge.c \
	check_dnsrbl.c \
	check_ident.c \
	check_misc.c \
	check_pass.c \
	check_program.c \
	check_regex.c \
	check_user.c 

iauthd_LDFLAGS = \
	$(PCRE_LIB)

iauthd_LDADD =  \
        $(PACKAGE_LIBS)

