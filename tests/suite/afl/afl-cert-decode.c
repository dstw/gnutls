/*
 * Copyright (C) 2016 Red Hat, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GnuTLS; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* This checks the low level DN encoding and decoding routines */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

static void decode(const gnutls_datum_t *raw)
{
	int ret;
	gnutls_datum_t out;
	gnutls_x509_crt_t crt;

	ret = gnutls_x509_crt_init(&crt);
	if (ret < 0) {
		fprintf(stderr, "%s\n", gnutls_strerror(ret));
		return;
	}

	ret = gnutls_x509_crt_import(crt, raw, GNUTLS_X509_FMT_DER);
	if (ret < 0) {
		fprintf(stderr, "%s\n", gnutls_strerror(ret));
		return;
	}

	ret = gnutls_x509_crt_print(crt, GNUTLS_CRT_PRINT_FULL, &out);
	if (ret < 0) {
		fprintf(stderr, "%s\n", gnutls_strerror(ret));
		return;
	}

	printf("string: '%s'\n", out.data);

	gnutls_free(out.data);
	gnutls_x509_crt_deinit(crt);

	return;
}

int main(int argc, char **argv)
{
	int ret;
	unsigned char buf[64*1024];
	gnutls_datum_t raw;

	ret = fread(buf, 1, sizeof(buf), stdin);
	if (ret <= 0)
		return 0;

	raw.data = buf;
	raw.size = ret;
	decode(&raw);

	return 0;
}

