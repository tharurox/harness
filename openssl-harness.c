#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// use openssl version 1.0.1f or older
// hint: using persistent mode will speed up the fuzzing process by approximately 20x.
// do not enable UBSAN - it will trigger on a normal non-crashing input.
// ASAN should be enabled.
//
// compile with afl-clang-fast -o harness -I./include -DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -Wa,--noexecstack -m64 -DL_ENDIAN -DTERMIO -O3 -Wall -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM harness.c libssl.a libcrypto.a

static const char* cert = "-----BEGIN CERTIFICATE-----\n"
"MIIBcTCCARugAwIBAgIUchy5I/maefLig2rMjfMqV5ZaQAowDQYJKoZIhvcNAQEL\n"
"BQAwDDEKMAgGA1UEAwwBYTAgFw0yNDEwMTAwMDUxMzFaGA8yMDUyMDIyNTAwNTEz\n"
"MVowDDEKMAgGA1UEAwwBYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC8CdZRRMtO\n"
"Eg+w1gKC6yqOvdqxTA+cXp3/eF9L7wAvBSaeD1IUYrvygeZ/yEBsylTwjTWbnlps\n"
"Wa+7M2nEWlsjAgMBAAGjUzBRMB0GA1UdDgQWBBRbMsYgkVlEa6fmJAfi8xeI81ij\n"
"cjAfBgNVHSMEGDAWgBRbMsYgkVlEa6fmJAfi8xeI81ijcjAPBgNVHRMBAf8EBTAD\n"
"AQH/MA0GCSqGSIb3DQEBCwUAA0EAssJJzLsuWHm7JQ8HQXqT+2/CGW/v6Q/L3pK5\n"
"HaepavR7xwJonHKFD1Peu9tSIVPeQopwyui3Q7IbIMPEXfICtg==\n"
"-----END CERTIFICATE-----";

// Don't use this private key for anything!
static const char* key = "-----BEGIN PRIVATE KEY-----\n"
"MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEAvAnWUUTLThIPsNYC\n"
"gusqjr3asUwPnF6d/3hfS+8ALwUmng9SFGK78oHmf8hAbMpU8I01m55abFmvuzNp\n"
"xFpbIwIDAQABAkEAjhx5Ju5xIE2yIhl7yGnmvf5qW3h6i9lOW5cjnoXAg8d4fpm5\n"
"N4Malp5Lrc9xhhl7isy08hhcerafnMd74jAXUQIhAPkAQF1jYOs240EPicBpWLs9\n"
"HOlSvYk/vyfc1d7P2b0dAiEAwVLqHM242uf2K2W0a2nxIcSDrnaFN2njE0ddXRc8\n"
"RT8CIQCjJ1UFXB6fQMG7WbELEHwBg9Oz1nE2wzw/pGXGry6eyQIgBS7Q4fbN9uhz\n"
"HBS88ohDk7EuCpZY2fR3xwOJyD4gOocCIQDuqc0EaziAZW3n5Jsd9B172OX3oK4u\n"
"fTiD72omvvp8Hw==\n"
"-----END PRIVATE KEY-----";

static char* ReadInputFile(const char* filename, size_t* size)
{
  FILE* fp = fopen(filename, "rb");
  if (!fp)
    return strdup("");

  fseek(fp, 0, SEEK_END);
  *size = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  if (*size == 0)
    return strdup("");

  char* data = (char*)malloc(*size + 1);
  data[*size] = 0;
  fread(data, *size, 1, fp);
  fclose(fp);
  return data;
}

int main(int argc, char* argv[])
{
  if (argc < 2)
    return 1;

  SSL_library_init();
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();

  BIO* cbio = BIO_new_mem_buf((void*)cert, -1);
  X509* xcert = PEM_read_bio_X509(cbio, NULL, 0, NULL);
  BIO* kbio = BIO_new_mem_buf((void*)key, -1);
  EVP_PKEY* pkey = PEM_read_bio_PrivateKey(kbio, NULL, NULL, NULL);

  SSL_CTX* ctx = SSL_CTX_new(TLSv1_method());
  SSL_CTX_use_certificate(ctx, xcert);
  SSL_CTX_use_PrivateKey(ctx, pkey);

  size_t data_len;
  char* data = ReadInputFile(argv[1], &data_len);
  SSL* ssl = SSL_new(ctx);
  BIO* in = BIO_new(BIO_s_mem());
  BIO* out = BIO_new(BIO_s_mem());
  SSL_set_bio(ssl, in, out);
  SSL_set_accept_state(ssl);
  BIO_write(in, data, data_len);
  SSL_do_handshake(ssl);
  SSL_free(ssl);
  free(data);

  SSL_CTX_free(ctx);

  EVP_PKEY_free(pkey);
  BIO_free(kbio);
  X509_free(xcert);
  BIO_free(cbio);
}


