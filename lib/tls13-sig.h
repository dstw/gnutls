/*
 * Copyright (C) 2017 Red Hat, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

#ifndef _TLS13_SIG_H
# define _TLS13_SIG_H

#include "gnutls_int.h"

int
_gnutls13_handshake_verify_data(gnutls_session_t session,
			        unsigned verify_flags,
			        gnutls_pcert_st *cert,
			        const gnutls_datum_t *context,
			        const gnutls_datum_t *signature,
			        const gnutls_sign_entry_st *se);

#endif
