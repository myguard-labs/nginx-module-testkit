/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * OpenSSL compatibility definitions used by the prober.
 */
#ifndef PROBER_OPENSSL_COMPAT_H
#define PROBER_OPENSSL_COMPAT_H

#include <openssl/ssl.h>

/*
 * OpenSSL only grew this reason-code macro recently; 3.0 (Ubuntu 24.04,
 * so every GitHub-hosted runner) does not have it and the prober fails
 * to build there. The value is protocol arithmetic, not an OpenSSL
 * implementation detail: received-alert reason codes are the alert
 * number offset by SSL_AD_REASON_OFFSET, and both operands have been in
 * the public headers since ALPN existed -- the sum is exactly the 1120
 * newer sslerr.h defines.
 */
#ifndef SSL_R_TLSV1_ALERT_NO_APPLICATION_PROTOCOL
#define SSL_R_TLSV1_ALERT_NO_APPLICATION_PROTOCOL \
    (SSL_AD_REASON_OFFSET + TLS1_AD_NO_APPLICATION_PROTOCOL)
#endif

#endif
