#include <stdlib.h>

struct LL {
  struct LL* next;
  int handle;
};

int close_last(struct LL* list) {
  while (list->next != NULL) {
    list = list->next;
  }
  
  return  close(list->handle);
}