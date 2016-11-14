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
#include <gnutls/abstract.h>

static void decode(const gnutls_datum_t *raw)
{
	int ret;
	gnutls_datum_t out;
	gnutls_x509_privkey_t key;

	ret = gnutls_x509_privkey_init(&key);
	if (ret < 0) {
		fprintf(stderr, "%s\n", gnutls_strerror(ret));
		return;
	}

	ret = gnutls_x509_privkey_import_pkcs8(key, raw, GNUTLS_X509_FMT_DER, "1234", 0);
	if (ret < 0) {
		fprintf(stderr, "%s\n", gnutls_strerror(ret));
		return;
	}

	ret = gnutls_x509_privkey_export2(key, GNUTLS_X509_FMT_DER, &out);
	if (ret < 0) {
		fprintf(stderr, "%s\n", gnutls_strerror(ret));
		return;
	}

	gnutls_free(out.data);
	gnutls_x509_privkey_deinit(key);

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

