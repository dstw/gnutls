#!/bin/sh
# Copyright (C) 2015-2016 Red Hat, Inc.
#
# This file is part of GnuTLS.
#
# The launch_server() function was contributed by Cedric Arbogast.
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

srcdir="${srcdir:-.}"
INNAME=afl-cert.in
OUTNAME=afl-cert.out

export LD_LIBRARY_PATH=${srcdir}/../../../lib/.libs/
rm -rf $OUTNAME
mkdir -p $OUTNAME
afl-fuzz -i $INNAME -o $OUTNAME -- .libs/afl-cert-decode

exit $?
