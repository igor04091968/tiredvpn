/* Reproduce the fixed-secret syndrome KAT with the pinned QAPP source tree:
 *
 * gcc -O2 -I<qapp>/include/shipovnik -I<qapp>/src qapp_syndrome_kat.c \
 *     <qapp>/src/h_prime.c <qapp>/src/syndrome.c -o qapp_syndrome_kat
 */
#include "params.h"
#include "syndrome.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  uint8_t secret[SHIPOVNIK_SECRETKEYBYTES];
  uint8_t public_key[SHIPOVNIK_PUBLICKEYBYTES];
  memset(secret, 0, sizeof(secret));
  for (size_t i = 0; i < W; ++i) {
    secret[i / 8] |= (uint8_t)(1u << (7 - i % 8));
  }
  syndrome(H_PRIME, secret, public_key);
  for (size_t i = 0; i < sizeof(public_key); ++i) {
    printf("%02x", public_key[i]);
  }
  putchar('\n');
  return 0;
}
