#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

char c[68];

int main(int ac, char **av) {
    uintptr_t *a;
    uintptr_t *b;
    FILE *f;

    a = malloc(2 * sizeof(uintptr_t));
    a[0] = 1;
    a[1] = (uintptr_t)malloc(8);

    b = malloc(2 * sizeof(uintptr_t));
    b[0] = 2;
    b[1] = (uintptr_t)malloc(8);

    strcpy((char *)a[1], av[1]);
    strcpy((char *)b[1], av[2]);

    f = fopen("/home/user/level8/.pass", "r");
    fgets(c, 68, f);

    puts("~~");
    return 0;
}
