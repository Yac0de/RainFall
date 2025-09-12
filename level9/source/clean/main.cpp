#include <cstring>
#include <cstdlib>


typedef struct N N;
typedef int (*Fn)(N*, N*);


struct N {
	void **vptr;
	char buf[0x64];
	int value;
	
	
	N(int v) { vptr = VTable; value = v; }
	
	
	void setAnnotation(char *s) {
		size_t n = std::strlen(s);
		std::memcpy(buf, s, n); // vulnerable unchecked copy
	}	
	
	int operator+(N &o) { return value + o.value; }
	int operator-(N &o) { return value - o.value; }
	
	
	static void *VTable[1];
};


void *N::VTable[1] = { (void*)0 }; // placeholder


int main(int ac, char **av) {
	if (ac < 2) std::exit(1);
	
	
	N *a = new N(5);
	N *b = new N(6);
	
	
	a->setAnnotation(av[1]);
	
	
	Fn f = *(Fn*)(*(void**)b);
	return f(b, a);
}
