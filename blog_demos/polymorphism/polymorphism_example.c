#include <stdlib.h>


struct a {
    size_t b;
    size_t c;
    size_t d; 
};

struct x {
    size_t y;
    size_t z;
};


struct a* produce(struct a* foo,struct x* bar) {
    foo->b = bar->z;
    foo->c = bar->y;
    foo->d = bar->y;
    
    free(foo);
    free(bar);

    return foo;
};