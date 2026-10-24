#include <assert.h>
#include <stddef.h>
#include <string.h>
#include "shim.h"

int main(void) {
    unsigned char buffer[4098];
    const size_t lengths[] = {0, 1, 7, 8, 9, 4096};
    ck_memzero(NULL, 0);
    ck_memzero(NULL, 8);
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        memset(buffer, 0xa5, sizeof(buffer));
        ck_memzero(buffer + 1, lengths[i]);
        assert(buffer[0] == 0xa5);
        for (size_t j = 1; j <= lengths[i]; j++) {
            assert(buffer[j] == 0);
        }
        for (size_t j = lengths[i] + 1; j < sizeof(buffer); j++) {
            assert(buffer[j] == 0xa5);
        }
    }
    return 0;
}
