/* Benchmark the unmodified QAPP signer and verifier with a fixed key.
 *
 * gcc -O2 -I<qapp>/include/shipovnik -I<qapp>/src qapp_benchmark.c \
 *     <qapp-build>/libshipovnik.a <qapp-build>/streebog/libstreebog.a \
 *     -o qapp_benchmark
 *
 * Unlike qapp_interop.c this file does not replace shuffle, gen_vector, or
 * randombytes, so the measured signing path is the unchanged upstream code.
 */
#include "params.h"
#include "shipovnik.h"
#include "syndrome.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(void) {
  static const uint8_t message[] = "Shipovnik unchanged QAPP benchmark";
  uint8_t secret[SHIPOVNIK_SECRETKEYBYTES];
  uint8_t public_key[SHIPOVNIK_PUBLICKEYBYTES];
  uint8_t *signature = malloc(SHIPOVNIK_SIGBYTES);
  if (signature == NULL) {
    return 2;
  }
  memset(secret, 0, sizeof(secret));
  for (size_t i = 0; i < W; ++i) {
    secret[i / 8] |= (uint8_t)(1u << (7 - i % 8));
  }
  syndrome(H_PRIME, secret, public_key);

  size_t signature_size = 0;
  clock_t start = clock();
  shipovnik_sign(secret, message, sizeof(message) - 1, signature,
                 &signature_size);
  clock_t signed_at = clock();
  int failed = shipovnik_verify(public_key, signature, message,
                                sizeof(message) - 1);
  clock_t verified_at = clock();

  printf("signature_bytes=%zu sign_seconds=%.6f verify_seconds=%.6f\n",
         signature_size, (double)(signed_at - start) / CLOCKS_PER_SEC,
         (double)(verified_at - signed_at) / CLOCKS_PER_SEC);
  memset(secret, 0, sizeof(secret));
  free(signature);
  return failed ? 1 : 0;
}
