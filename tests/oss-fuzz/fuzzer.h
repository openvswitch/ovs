#ifndef FUZZER_H
#define FUZZER_H 1

#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#endif  /* fuzzer.h */
