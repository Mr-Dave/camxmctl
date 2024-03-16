ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src

pkgsysconfdir = $(sysconfdir)/@PACKAGE@
dist_pkgsysconf_DATA = \
	data/camxmctl-dist.conf \
	data/sample-dist.html

###################################################################
## Create pristine directories to match exactly distributed files
###################################################################
cleanall: distclean
	@rm -rf autom4te.cache m4
	@rm -f config.hpp.in config.hpp.in~ aclocal.m4 config.sub ABOUT-NLS missing
	@rm -f compile config.guess config.rpath configure depcomp install-sh
	@rm -f Makefile.in src/Makefile.in
	@rm -f data/camxmctl-dist.conf data/sample-dist.html
