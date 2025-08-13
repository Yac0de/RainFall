#include <stdlib.h>
#include <string.h>

void m(void *a, int b, char *c, int d, int e);

int main(int ac, char **av) {
    char *dest;
    void (**fp)(void);

    dest = malloc(0x40);
    fp = malloc(4);
    *fp = (void (*)(void))m;
    strcpy(dest, av[1]);
    (*fp)();
    return 0;
}
