#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void from_hex(const char *hex, unsigned char *out) {
    while (*hex) {
        sscanf(hex, "%2hhx", out);
        hex += 2;
        out++;
    }
}

int main(void) {
    const char *hex = "3139322E3136382E3132322E31";
    unsigned char out[256] = {0};

    from_hex(hex, out);

    printf("Decoded: %s\n", out);
    return 0;
}

