#ifndef __LIST__H
#define __LIST__H


struct list_item {
	struct list_item *next;
	void* data;
};

struct list {
	struct list_item *first;
};

struct list* list_new();
void list_free(struct list* list);

void list_insert(struct list* list, void* data);

#define list_foreach(list, list_item_name) \
	struct list_item* list_item_name; \
	for(list_item_name = list->first; \
			list_item_name != NULL; \
			list_item_name = list_item_name->next)

#define list_data(list_item_name, type)							\
	((type*) (list_item_name->data))

#endif
