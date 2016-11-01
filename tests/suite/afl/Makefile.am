## Process this file with automake to produce Makefile.in
# Copyright (C) 2016 Red Hat, Inc.
#
# Author: Nikos Mavrogiannopoulos
#
# This file is part of GnuTLS.
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this file; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

EXTRA_DIST = afl-dn.in/dn1.der afl-dn.in/dn2.der \
	afl-dn.in/dn3.der afl-dn.in/dn4.der

AM_CFLAGS = $(WARN_CFLAGS) $(WERROR_CFLAGS)
AM_CPPFLAGS = \
	$(P11_KIT_CFLAGS) \
	-I$(top_srcdir)/lib/includes		\
	-I$(top_builddir)/lib/includes		\
	-I$(top_srcdir)/libdane/includes	\
	-I$(top_builddir)/libdane/includes	\
	-I$(top_srcdir)/extra/includes		\
	-I$(top_builddir)/extra/includes	\
	-I$(top_srcdir)/lib			\
	-I$(top_srcdir)/doc/examples

LDADD = ../../../lib/libgnutls.la \
	../../../gl/libgnu.la \
	$(LIBSOCKET) $(INET_NTOP_LIB) $(INET_PTON_LIB)

noinst_SCRIPTS = afl-dn.sh

noinst_PROGRAMS = afl-dn-decode

