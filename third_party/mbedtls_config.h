/*
 * Copyright (C) 2026 LogSquirl Contributors
 *
 * This file is part of logsquirl-tcpdump.
 *
 * logsquirl-tcpdump is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * logsquirl-tcpdump is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with logsquirl-tcpdump.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file mbedtls_config.h
 * @brief The Mbed TLS configuration the plugin builds the library with
 *        (CMakeLists.txt, MBEDTLS_CONFIG_FILE): only the primitives the
 *        TLS Decryption uses (tls_crypto.cpp), in portable C.
 *
 * No TLS stack, no X.509, no public-key cryptography, no random generator,
 * no PSA Crypto: the plugin decrypts records with keys from a key log and
 * makes none of its own.
 */

#ifndef LOGSQUIRL_TCPDUMP_MBEDTLS_CONFIG_H
#define LOGSQUIRL_TCPDUMP_MBEDTLS_CONFIG_H

/* Ciphers of the record protection: AES-GCM and AES-CBC (TLS 1.2, 1.3),
 * ChaCha20-Poly1305 (RFC 7905, RFC 8446). */
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_GCM_C
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_POLY1305_C
#define MBEDTLS_CHACHAPOLY_C

/* Hashes and MACs: HMAC for the TLS 1.2 PRF and the CBC suites' MACs,
 * HKDF for the TLS 1.3 key schedule. */
#define MBEDTLS_MD_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA224_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA384_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_HKDF_C

#endif /* LOGSQUIRL_TCPDUMP_MBEDTLS_CONFIG_H */
