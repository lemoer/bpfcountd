#include <stdlib.h>
#include <stdio.h>
#include "list.h"

int main() {
	struct list* l = list_new();
	
	int *z = malloc(sizeof(int));
	*z = 42;
	list_insert(l, z);
	
	z = malloc(sizeof(int));
	*z = 43;
	list_insert(l, z);
	
	z = malloc(sizeof(int));
	*z = 44;
	list_insert(l, z);

	list_foreach(l, li) {
		int *data = list_data(li, int);
		printf("%d\n", *data);
		free(data);
	}

	list_free(l);
}
