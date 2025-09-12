#include <cstring>
#include <cstdlib>

class N {
public:
    N(int v) {
        this->vptr  = VTable;
        this->value = v;
    }

    void setAnnotation(char *s) {
        size_t n = std::strlen(s);
        std::memcpy((char*)this + 4, s, n);
    }

    int operator+(N &o) { return this->value + o.value; }
    int operator-(N &o) { return this->value - o.value; }

    void **vptr;
    char   pad[0x64];
    int    value;

    static void *VTable[1];
};

void *N::VTable[1] = { (void*)0 };

using Fn = int (*)(N*, N*);

int main(int ac, char **av) {
    if (ac < 2) std::exit(1);

    N *a = new N(5);
    N *b = new N(6);

    a->setAnnotation(av[1]);

    // double deref of vptr, then call with (b, a)
    Fn f = *(Fn*)(*(void**)b);
    return f(b, a);
}
