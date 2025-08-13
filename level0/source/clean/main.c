#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int ac, char **av) {
    if (atoi(av[1]) == 423) {
        char *sh = strdup("/bin/sh");

        setresgid(getegid(), getegid(), getegid());
        setresuid(geteuid(), geteuid(), geteuid());

        execv("/bin/sh", &sh);
    }

    fwrite("No !\n", 1, 5, stderr);
    return 0;
}
