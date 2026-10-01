/* Test the portable SHA-256 in src/crypto.c against FIPS 180-4 vectors.
 * Standalone: includes crypto.c directly so no full relay build is needed. */
#include "../src/crypto.c"
#include <assert.h>

static void hexdump32(const uint8_t *d, char *out) {
    for (int i = 0; i < 32; i++) sprintf(out + i * 2, "%02x", d[i]);
}

int main(void) {
    uint8_t digest[32];
    char hex[65];

    /* Vector 1: "" -> e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */
    sha256((const uint8_t *)"", 0, digest);
    hexdump32(digest, hex);
    printf("\"\":            %s\n", hex);
    assert(strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0);

    /* Vector 2: "abc" -> ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad */
    sha256((const uint8_t *)"abc", 3, digest);
    hexdump32(digest, hex);
    printf("\"abc\":         %s\n", hex);
    assert(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);

    /* Vector 3: 448-bit message (exactly 56 bytes -> exercises the
     * two-block padding path, i.e. the >=56 branch of final()) */
    const char *m56 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha256((const uint8_t *)m56, strlen(m56), digest);
    hexdump32(digest, hex);
    printf("56-byte msg:   %s\n", hex);
    assert(strcmp(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0);

    /* Vector 4: multi-block large input (million 'a', 1,000,000 bytes).
     * Exercises multi-block padding through the public one-shot API
     * (the old version used the non-Windows-internal streaming API). */
    {
        static char chunk[1000];
        uint8_t *mega;
        size_t i;
        memset(chunk, 'a', sizeof(chunk));
        mega = (uint8_t *)malloc(1000000);
        assert(mega != NULL);
        for (i = 0; i < 1000; i++) memcpy(mega + i * 1000, chunk, sizeof(chunk));
        sha256(mega, 1000000, digest);
        free(mega);
        hexdump32(digest, hex);
        printf("1M x 'a':      %s\n", hex);
        assert(strcmp(hex, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") == 0);
    }

    printf("ALL SHA-256 VECTORS PASSED\n");
    return 0;
}
