/*
 * Copyright (C) 2017-2018 Red Hat, Inc.
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/* This program tests the ciphersuite negotiation for various key exchange
 * methods and options under TLS1.3. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <gnutls/gnutls.h>
#include "utils.h"
#include "cert-common.h"
#include "eagain-common.h"

#include "cipher-neg-common.c"

/* We remove the ECDHE and DHE key exchanges as they impose additional
 * rules in the sorting of groups.
 */
#define SPRIO "NORMAL:-VERS-TLS-ALL:+VERS-TLS1.3:-ECDHE-RSA:-ECDHE-ECDSA:-DHE-RSA:-RSA:-DHE-DSS"
#define CPRIO "NORMAL:-VERS-TLS-ALL:+VERS-TLS1.3:+VERS-TLS1.2:-ECDHE-RSA:-ECDHE-ECDSA:-DHE-RSA:-RSA:-DHE-DSS"

test_case_st tests[] = {
	{
		.name = "server TLS 1.3: AES-128-GCM with SECP256R1 (server)",
		.cipher = GNUTLS_CIPHER_AES_128_GCM,
		.group = GNUTLS_GROUP_SECP256R1,
		.server_prio = SPRIO":-CIPHER-ALL:+AES-128-GCM:+CIPHER-ALL:%SERVER_PRECEDENCE:-GROUP-ALL:+GROUP-SECP256R1:+GROUP-ALL",
		.client_prio = CPRIO":+AES-128-GCM:-GROUP-ALL:+GROUP-FFDHE2048:+GROUP-SECP384R1:+GROUP-SECP521R1:+GROUP-SECP256R1"
	},
	{
		.name = "both TLS 1.3: AES-128-GCM with X25519 (server)",
		.cipher = GNUTLS_CIPHER_AES_128_GCM,
		.group = GNUTLS_GROUP_X25519,
		.server_prio = SPRIO":-CIPHER-ALL:+AES-128-GCM:+CIPHER-ALL:%SERVER_PRECEDENCE:-GROUP-ALL:+GROUP-X25519:+GROUP-ALL",
		.client_prio = CPRIO":+AES-128-GCM:-GROUP-ALL:+GROUP-FFDHE2048:+GROUP-SECP384R1:+GROUP-SECP521R1:+GROUP-SECP256R1:+GROUP-ALL"
	},
	{
		.name = "client TLS 1.3: AES-128-GCM with SECP256R1 (client)",
		.cipher = GNUTLS_CIPHER_AES_128_GCM,
		.group = GNUTLS_GROUP_SECP256R1,
		.server_prio = SPRIO":+AES-128-GCM:-GROUP-ALL:+GROUP-FFDHE2048:+GROUP-SECP384R1:+GROUP-SECP521R1:+GROUP-SECP256R1",
		.client_prio = CPRIO":-CIPHER-ALL:+AES-128-GCM:+CIPHER-ALL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+GROUP-SECP256R1:+GROUP-ALL"
	},
	{
		.name = "both TLS 1.3: AES-128-GCM with X25519 (client)",
		.cipher = GNUTLS_CIPHER_AES_128_GCM,
		.group = GNUTLS_GROUP_X25519,
		.server_prio = SPRIO":+AES-128-GCM:-GROUP-ALL:+GROUP-FFDHE2048:+GROUP-SECP384R1:+GROUP-SECP521R1:+GROUP-SECP256R1:+GROUP-ALL",
		.client_prio = CPRIO":-CIPHER-ALL:+AES-128-GCM:+CIPHER-ALL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+GROUP-X25519:+GROUP-ALL"
	},
	{
		.name = "server TLS 1.3: AES-128-CCM and FFDHE2048 (server)",
		.cipher = GNUTLS_CIPHER_AES_128_CCM,
		.group = GNUTLS_GROUP_FFDHE2048,
		.server_prio = SPRIO":-CIPHER-ALL:+AES-128-CCM:+CIPHER-ALL:%SERVER_PRECEDENCE:-GROUP-ALL:+GROUP-FFDHE2048:+GROUP-ALL",
		.client_prio = CPRIO":+AES-128-CCM"
	},
	{
		.name = "both TLS 1.3: AES-128-CCM and FFDHE 2048 (server)",
		.cipher = GNUTLS_CIPHER_AES_128_CCM,
		.group = GNUTLS_GROUP_FFDHE2048,
		.server_prio = SPRIO":-CIPHER-ALL:+AES-128-CCM:+CIPHER-ALL:%SERVER_PRECEDENCE:-GROUP-ALL:+GROUP-FFDHE2048:+GROUP-ALL",
		.client_prio = CPRIO":+AES-128-CCM:+VERS-TLS1.3"
	},
	{
		.name = "client TLS 1.3: AES-128-CCM and FFDHE 2048 (client)",
		.cipher = GNUTLS_CIPHER_AES_128_CCM,
		.group = GNUTLS_GROUP_FFDHE2048,
		.server_prio = SPRIO":+AES-128-CCM",
		.client_prio = CPRIO":-CIPHER-ALL:+AES-128-CCM:+CIPHER-ALL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+GROUP-FFDHE2048:+GROUP-ALL"
	},
	{
		.name = "both TLS 1.3: AES-128-CCM and FFDHE 2048 (client)",
		.cipher = GNUTLS_CIPHER_AES_128_CCM,
		.group = GNUTLS_GROUP_FFDHE2048,
		.server_prio = SPRIO":+AES-128-CCM:+VERS-TLS1.3",
		.client_prio = CPRIO":-CIPHER-ALL:+AES-128-CCM:+CIPHER-ALL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+GROUP-FFDHE2048:+GROUP-ALL"
	},
	{
		.name = "server TLS 1.3: CHACHA20-POLY (server)",
		.cipher = GNUTLS_CIPHER_CHACHA20_POLY1305,
		.not_on_fips = 1,
		.server_prio = SPRIO":-CIPHER-ALL:+CHACHA20-POLY1305:+CIPHER-ALL:%SERVER_PRECEDENCE",
		.client_prio = CPRIO":+CHACHA20-POLY1305"
	},
	{
		.name = "both TLS 1.3: CHACHA20-POLY (server)",
		.cipher = GNUTLS_CIPHER_CHACHA20_POLY1305,
		.not_on_fips = 1,
		.server_prio = SPRIO":-CIPHER-ALL:+CHACHA20-POLY1305:+CIPHER-ALL:%SERVER_PRECEDENCE",
		.client_prio = CPRIO":+CHACHA20-POLY1305:+VERS-TLS1.3"
	},
	{
		.name = "client TLS 1.3: CHACHA20-POLY (client)",
		.cipher = GNUTLS_CIPHER_CHACHA20_POLY1305,
		.not_on_fips = 1,
		.server_prio = SPRIO":+CHACHA20-POLY1305",
		.client_prio = CPRIO":-CIPHER-ALL:+CHACHA20-POLY1305:+CIPHER-ALL"
	},
	{
		.name = "both TLS 1.3: CHACHA20-POLY (client)",
		.cipher = GNUTLS_CIPHER_CHACHA20_POLY1305,
		.not_on_fips = 1,
		.server_prio = SPRIO":+CHACHA20-POLY1305",
		.client_prio = CPRIO":-CIPHER-ALL:+CHACHA20-POLY1305:+CIPHER-ALL"
	}
};

void doit(void)
{
	unsigned i;
	global_init();

	for (i=0;i<sizeof(tests)/sizeof(tests[0]);i++) {
		try(&tests[i]);
	}

	gnutls_global_deinit();
}
