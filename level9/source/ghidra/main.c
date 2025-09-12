// Ghidra — selected relevant parts only


// main
void main(int argc, int argv)
{
N *a;
N *b;
if (argc < 2) _exit(1);
a = (N*)operator_new(0x6c); N::N(a,5);
b = (N*)operator_new(0x6c); N::N(b,6);
N::setAnnotation(a, *(char**)(argv + 4));
(*(code *)**(void**)b)(b, a);
}


// N::N(int)
void __thiscall N::N(N *this, int v)
{
*(void ***)this = &PTR_operator__08048848; // vtable pointer at +0x00
*(int *)(this + 0x68) = v; // value at +0x68
}


// N::setAnnotation(char*)
void __thiscall N::setAnnotation(N *this, char *s)
{
size_t n = strlen(s);
memcpy(this + 4, s, n); // unchecked copy starting at +0x04 (overflow primitive)
}


// optional: arithmetic operators present in the binary
int __thiscall N::operator+(N *this, N *o)
{
return *(int *)(o + 0x68) + *(int *)(this + 0x68);
}


int __thiscall N::operator-(N *this, N *o)
{
return *(int *)(this + 0x68) - *(int *)(o + 0x68);
}
