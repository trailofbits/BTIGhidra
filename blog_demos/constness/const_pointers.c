#include <stddef.h>

void copy_ptr(const size_t *src, size_t* dst) {
    *dst = *src;
}