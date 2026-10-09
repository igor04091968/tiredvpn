/*
 * Small cross-verification driver for the pinned QAPP implementation. It also
 * supplies a deterministic, O(n log n) test-only replacement for the upstream
 * sorting-network entropy plumbing so fixture generation is practical. The
 * signature format and all cryptographic computations remain QAPP's code.
 *
 * Build this file against a QAPP library configured for the desired DELTA. The
 * Go test guarded by the "cinterop" build tag documents the executable protocol.
 */
#include "genvector.h"
#include "params.h"
#include "shipovnik.h"
#include "syndrome.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t rng_state = UINT64_C(0x736869706f766e69);

static uint64_t splitmix64(void) {
  uint64_t z = (rng_state += UINT64_C(0x9e3779b97f4a7c15));
  z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
  z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
  return z ^ (z >> 31);
}

void randombytes(uint8_t *out, size_t outlen) {
  while (outlen != 0) {
    uint64_t word = splitmix64();
    size_t take = outlen < sizeof(word) ? outlen : sizeof(word);
    memcpy(out, &word, take);
    out += take;
    outlen -= take;
  }
}

static int compare_u64(const void *left, const void *right) {
  uint64_t a = *(const uint64_t *)left;
  uint64_t b = *(const uint64_t *)right;
  return (a > b) - (a < b);
}

void shuffle(const uint32_t *entropy, uint16_t *permutation, uint64_t *scratch,
             size_t len) {
  for (size_t i = 0; i < len; ++i) {
    scratch[i] = ((uint64_t)entropy[i] << 16) | permutation[i];
  }
  qsort(scratch, len, sizeof(*scratch), compare_u64);
  for (size_t i = 0; i < len; ++i) {
    permutation[i] = (uint16_t)scratch[i];
  }
}

void gen_vector(uint16_t *vector) {
  uint16_t permutation[N];
  uint32_t entropy[N];
  uint64_t scratch[N];
  for (size_t i = 0; i < N; ++i) {
    permutation[i] = (uint16_t)i;
    vector[i] = i < W;
  }
  randombytes((uint8_t *)entropy, sizeof(entropy));
  shuffle(entropy, permutation, scratch, N);
  memset(vector, 0, N * sizeof(*vector));
  for (size_t i = 0; i < W; ++i) {
    vector[permutation[i]] = 1;
  }
}

static uint8_t *read_file(const char *path, size_t *size) {
  FILE *file = fopen(path, "rb");
  if (file == NULL || fseek(file, 0, SEEK_END) != 0) {
    return NULL;
  }
  long length = ftell(file);
  if (length < 0 || fseek(file, 0, SEEK_SET) != 0) {
    fclose(file);
    return NULL;
  }
  uint8_t *data = malloc(length == 0 ? 1 : (size_t)length);
  if (data == NULL || fread(data, 1, (size_t)length, file) != (size_t)length) {
    free(data);
    fclose(file);
    return NULL;
  }
  fclose(file);
  *size = (size_t)length;
  return data;
}

static int write_file(const char *path, const uint8_t *data, size_t size) {
  FILE *file = fopen(path, "wb");
  if (file == NULL) {
    return 1;
  }
  int failed = fwrite(data, 1, size, file) != size || fclose(file) != 0;
  return failed;
}

static int sign_files(const char *sk_path, const char *message_path,
                      const char *signature_path, const char *pk_path) {
  size_t sk_size = 0, message_size = 0;
  uint8_t *sk = read_file(sk_path, &sk_size);
  uint8_t *message = read_file(message_path, &message_size);
  if (sk == NULL || message == NULL || sk_size != SHIPOVNIK_SECRETKEYBYTES) {
    free(sk);
    free(message);
    return 2;
  }
  uint8_t pk[SHIPOVNIK_PUBLICKEYBYTES];
  syndrome(H_PRIME, sk, pk);
  uint8_t *signature = malloc(SHIPOVNIK_SIGBYTES);
  if (signature == NULL) {
    free(sk);
    free(message);
    return 2;
  }
  size_t signature_size = 0;
  shipovnik_sign(sk, message, message_size, signature, &signature_size);
  int failed = write_file(signature_path, signature, signature_size) ||
               write_file(pk_path, pk, sizeof(pk));
  free(signature);
  free(message);
  memset(sk, 0, sk_size);
  free(sk);
  return failed ? 2 : 0;
}

static int verify_files(const char *pk_path, const char *message_path,
                        const char *signature_path) {
  size_t pk_size = 0, message_size = 0, signature_size = 0;
  uint8_t *pk = read_file(pk_path, &pk_size);
  uint8_t *message = read_file(message_path, &message_size);
  uint8_t *signature = read_file(signature_path, &signature_size);
  if (pk == NULL || message == NULL || signature == NULL ||
      pk_size != SHIPOVNIK_PUBLICKEYBYTES || signature_size > SHIPOVNIK_SIGBYTES) {
    free(pk);
    free(message);
    free(signature);
    return 2;
  }
  int failed = shipovnik_verify(pk, signature, message, message_size);
  free(pk);
  free(message);
  free(signature);
  return failed ? 1 : 0;
}

int main(int argc, char **argv) {
  if (argc == 6 && strcmp(argv[1], "sign") == 0) {
    return sign_files(argv[2], argv[3], argv[4], argv[5]);
  }
  if (argc == 5 && strcmp(argv[1], "verify") == 0) {
    return verify_files(argv[2], argv[3], argv[4]);
  }
  fprintf(stderr,
          "usage: %s sign SK MESSAGE SIGNATURE PK\n"
          "       %s verify PK MESSAGE SIGNATURE\n",
          argv[0], argv[0]);
  return 2;
}
