/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Compile-only regression test for the OpenSSL 3.0 ALPN alert fallback.
 */
#include <openssl/sslerr.h>

/* Force the pre-3.2 header shape even when this test runs on a newer OpenSSL. */
#undef SSL_R_TLSV1_ALERT_NO_APPLICATION_PROTOCOL

#include "openssl_compat.h"

_Static_assert(SSL_R_TLSV1_ALERT_NO_APPLICATION_PROTOCOL
                   == SSL_AD_REASON_OFFSET + TLS1_AD_NO_APPLICATION_PROTOCOL,
               "ALPN alert fallback must retain OpenSSL's reason-code mapping");

int
main(void)
{
    return 0;
}
