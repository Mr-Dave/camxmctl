ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS= -Dsysconfdir=\"$(sysconfdir)/camxmctl\" -DLOCALEDIR=\"$(DESTDIR)$(localedir)\"

LDADD = $(LIBINTL)

bin_PROGRAMS = camxmctl

camxmctl_SOURCES = \
	camxmctl.hpp    camxmctl.cpp \
	util.hpp        util.cpp     \
	logger.hpp      logger.cpp   \
	conf.hpp        conf.cpp     \
	webu.hpp        webu.cpp     \
	webu_json.hpp   webu_json.cpp

###################################################################
## Create pristine directories to match exactly distributed files
###################################################################
cleanall: distclean
	@rm -rf autom4te.cache m4
	@rm -f config.hpp.in config.hpp.in~ aclocal.m4 config.sub ABOUT-NLS missing
	@rm -f compile config.guess config.rpath configure depcomp install-sh
	@rm -f Makefile.in
