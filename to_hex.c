#include <stdio.h>
#include <string.h>

void to_hex(const unsigned char *in, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(out + (i * 2), "%02X", in[i]);
    }
    out[len * 2] = '\0';
}

int main(void) {
    const char *str = "192.168.122.1";
    char hex[256];

    to_hex((const unsigned char *)str, strlen(str), hex);

    printf("Hex: %s\n", hex);
    return 0;
}

