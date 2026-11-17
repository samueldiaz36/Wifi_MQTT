/**
 * @file lab_certificates.h
 * @brief Self-Signed Root CA & Mutual TLS (mTLS) X.509 Certificates Header
 *
 * ============================================================================
 * WHY DO WE NEED THIS FILE?
 * ============================================================================
 * When the ESP32 connects to your PC's Mosquitto broker over `mqtts://` (Port 8883),
 * mbedTLS performs a TLS handshake:
 *   1. Your PC's Mosquitto broker sends its `server.crt` (public certificate).
 *   2. How does the ESP32 know `server.crt` isn't from an attacker spoofing your IP?
 *   3. The ESP32 uses `LAB_CA_CERT_PEM` below (your self-signed Root CA public
 *      certificate) to cryptographically verify the digital signature on `server.crt`
 *      AND checks that the broker's IP matches the certificate's `subjectAltName`!
 *
 * SECURITY RULE:
 *   - NEVER put `ca.key` or `server.key` (Private Keys) on the ESP32!
 *   - `LAB_CA_CERT_PEM` is the PUBLIC Root CA certificate (`ca.crt`).
 *   - Only if you do the Bonus Challenge (Mutual TLS / mTLS) will you paste a
 *     device-specific `client.crt` and `client.key` in the Bonus section below.
 */

#ifndef LAB_CERTIFICATES_H
#define LAB_CERTIFICATES_H

/* ============================================================================
 * 1. SERVER-SIDE TLS: Team Root CA Public Certificate (`ca.crt`)
 * ============================================================================ */
static const char LAB_CA_CERT_PEM[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIDozCCAougAwIBAgIUa3JPMvk/6fSng21X0dYkx2UHizEwDQYJKoZIhvcNAQEL\n"
"BQAwYTELMAkGA1UEBhMCQ08xDzANBgNVBAgMBkNhbGRhczESMBAGA1UEBwwJTWFu\n"
"aXphbGVzMRMwEQYDVQQKDApJb1QtTGFiLUNBMRgwFgYDVQQDDA9Jb1QtTGFiLVJv\n"
"b3QtQ0EwHhcNMjYxMTE2MjEyMjI0WhcNMzYxMTEzMjEyMjI0WjBhMQswCQYDVQQG\n"
"EwJDTzEPMA0GA1UECAwGQ2FsZGFzMRIwEAYDVQQHDAlNYW5pemFsZXMxEzARBgNV\n"
"BAoMCklvVC1MYWItQ0ExGDAWBgNVBAMMD0lvVC1MYWItUm9vdC1DQTCCASIwDQYJ\n"
"KoZIhvcNAQEBBQADggEPADCCAQoCggEBAIf5CcKtKEOXOkE6Nv/F+cVTH5zoVQGz\n"
"sde4Hrnde9zto11BAm6qtYrhbyuJ4EphPy0KmMCtICLbvh4qIuMb0DWvk4dqMTxH\n"
"L+WYRaH/WYYwST7jr5j+yVeFmVlkkCOhs6vW0gkP/nRqEKtLFqAgER6LgiPoK/64\n"
"fa1KVI3X0kTpmpETdLG9cVXMcfGMJer8QRFwccGxuipUKFhQ1kx3WoBSQSCjFeFc\n"
"IVbCUl6CqgewEN8h/3bmVrtb7ZSTOxUGF8GacQ3/7taA0tQaFFSIO0cYnfvEy6Pk\n"
"j7lNtjcqk6A4os64zS3rGbN80UXG1RGWxaOcPoZXUIpcM2ChmOfuv0kCAwEAAaNT\n"
"MFEwHQYDVR0OBBYEFAcZ5bxGlfqEtX+bscBoTZsotuWsMB8GA1UdIwQYMBaAFAcZ\n"
"5bxGlfqEtX+bscBoTZsotuWsMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL\n"
"BQADggEBAGBPQ6UcrhHm5TC5WbSpYrB8MQPu0flfMIW+dDQyB/0QNv8AJunVtU5N\n"
"awv6m8FUh7mXqy/0mnhFYbbggJ6ceKUD9t5AQbJaP4CRXkbAbB5Btlom/Dz/62cR\n"
"0axZpKC5S2run45eywT9XsvM1vB6eab+HO06JaVZZbVm2lNpTmqRnwLsn6gqGSLZ\n"
"lsz+xEKg/KcUBAfuTJhN9fzPGt1nyAk1oVaD0XOPmSeMvFkS4nFCl8hAHuEwRtL0\n"
"UxmRLXPAJwMCkOytYTpBbjHw+VeSDG1HQWNihJFHxVdOpuNQSUCKB7QW/yVfS1/6\n"
"ZHWc/LmgHevXs8JU1jK1xB6R3DPlOos=\n"
"-----END CERTIFICATE-----\n";

/* ============================================================================
 * 2. BONUS CHALLENGE (mTLS): ESP32 Client Certificate & Client Private Key
 * ============================================================================
 * Only used if `require_certificate true` is enabled in `mosquitto_tls.conf`.
 */
static const char LAB_CLIENT_CERT_PEM[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIDmTCCAoGgAwIBAgIUMZzsNTg2cn2kcLhIANY+tGwQWXUwDQYJKoZIhvcNAQEL\n"
"BQAwYTELMAkGA1UEBhMCQ08xDzANBgNVBAgMBkNhbGRhczESMBAGA1UEBwwJTWFu\n"
"aXphbGVzMRMwEQYDVQQKDApJb1QtTGFiLUNBMRgwFgYDVQQDDA9Jb1QtTGFiLVJv\n"
"b3QtQ0EwHhcNMjYxMTE3MDAwNDUxWhcNMjcxMTE3MDAwNDUxWjBoMQswCQYDVQQG\n"
"EwJDTzEPMA0GA1UECAwGQ2FsZGFzMRIwEAYDVQQHDAlNYW5pemFsZXMxFzAVBgNV\n"
"BAoMDklvVC1MYWItQ2xpZW50MRswGQYDVQQDDBJlc3AzMi0xNDMzNUMyRjdEMzQw\n"
"ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/nc1h4AQh/b/NtM2i2TnV\n"
"KTzWBj7dMv6PqEUCKqjwMuj2bKQPKPa88HLBSXOwUFJkNm8Tctf4s3vjBRBDHpck\n"
"h177LGqSqKgJPod5xn14oYMVv9+fdxsQ/Bx4ReUAZ1LIwuixUzBoI936m2Edl6Ks\n"
"wg6QtoffTdU6W/LpICmMr7DQMp0S5wjYLkwGRr0D0tiRCFfM1opy9WZrIjQ90JSI\n"
"m1VwC6GSKRv8Rsl8hy7CeqniBFaXmVrVLrs2tOWebLmsYoi9PKOdXepikXmRosQP\n"
"zxSTo29czQ0iZ057Dj43SZiiyodvoA1niDXPZrGywlypq9Lr4bvjtXydRIHGE11x\n"
"AgMBAAGjQjBAMB0GA1UdDgQWBBQxVzajJWOwC0b/oyTy59Q64JPpDzAfBgNVHSME\n"
"GDAWgBQHGeW8RpX6hLV/m7HAaE2bKLblrDANBgkqhkiG9w0BAQsFAAOCAQEAQY0x\n"
"JH6jNeQzh8d1bhr5oSAf3TSana07MBbMemlmfz+U1tJ4eiN69wQHT/Rqicf0Bvuj\n"
"xTwb17c0h3YoEGScZbPpWdahaFPhfZWse0Hq+S9jejd+zSLHLL3IiZO0V5JAP4sS\n"
"1GazeOd0E0mNMXBVZgWCPsyi0i360ds/2doaeL52hFlFPXTGMYzYsf+m+fJkrGJR\n"
"N6A+1acOyRdd4m0fxivinaw98XR657lmYzjmio4vq2aND+93jCYw8Ohj824S8D7p\n"
"wsdaiV28kZiWRLkiawyca/KFrgTuH/0nKr+39N5/JeQxwvBjDqX5p608Puh8UZhV\n"
"ZlERXT6vxfdnBvrLvw==\n"
"-----END CERTIFICATE-----\n";

/* PRIVATE KEY REDACTED: generate your own client.key with OpenSSL (see LAB_GUIDE.md)
 * and paste it here locally. NEVER commit a real private key to Git. */
static const char LAB_CLIENT_KEY_PEM[] =
"-----BEGIN PRIVATE KEY-----\n"
"PASTE_YOUR_OPTIONAL_MTLS_CLIENT_KEY_HERE\n"
"-----END PRIVATE KEY-----\n";

#endif /* LAB_CERTIFICATES_H */