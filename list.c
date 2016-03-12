#include <stdlib.h>
#include "list.h"

struct list* list_new() {
	struct list* tmp = (struct list*) malloc(sizeof(struct list));
	tmp->first = NULL;
	return tmp;
}

void list_free(struct list* list) {
	struct list_item *li = list->first;
	struct list_item *tmp;

	while(li != NULL) {
		tmp = li->next;
		free(li);
		li = tmp;
	}

	free(list);
}

void list_insert(struct list* list, void* data) {
	struct list_item* tmp = malloc(sizeof(struct list_item));
	tmp->next = list->first;
	tmp->data = data;

	list->first = tmp;
}


