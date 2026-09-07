#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "filter") == 0) {
        int c;
        while ((c = getchar()) != EOF) putchar(c >= 'a' && c <= 'z' ? c - 'a' + 'A' : c);
    } else if (argc > 1 && strcmp(argv[1], "args") == 0) {
        for (int i = 2; i < argc; ++i) puts(argv[i]);
    } else if (argc > 1 && strcmp(argv[1], "exit") == 0) {
        return 7;
    } else if (argc > 1 && strcmp(argv[1], "stderr") == 0) {
        fputs("out\n", stdout); fputs("err\n", stderr);
    } else {
        puts("Hello from C WASI!");
    }
    return 0;
}
