/* Reads lines "scalar_hex u_hex" from stdin and prints x25519(scalar, u) in
 * hex, one line each, using the X25519 file it's built with. Used by
 * check_x25519.py. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "x25519.h"

static int unhex(const char *s, uint8_t *out) {
	for (int i = 0; i < 32; i++) {
		unsigned v;
		if (sscanf(s + 2 * i, "%2x", &v) != 1) return -1;
		out[i] = (uint8_t)v;
	}
	return 0;
}

int main(void) {
	char a[80], b[80];
	while (scanf("%79s %79s", a, b) == 2) {
		/* Separate buffers, offset by one byte so the ladder can't rely on
		 * the caller's alignment */
		uint8_t scalar[32], ubuf[33], out[32];
		uint8_t *u = ubuf + 1;
		if (strlen(a) != 64 || strlen(b) != 64 || unhex(a, scalar) || unhex(b, u)) return 2;
		uint8_t u_before[32];
		memcpy(u_before, u, 32);
		x25519(out, scalar, u, 1);
		for (int i = 0; i < 32; i++) printf("%02x", out[i]);
		/* The input must be left as it was */
		printf(" %s\n", memcmp(u, u_before, 32) ? "INPUT-CHANGED" : "ok");
	}
	return 0;
}
