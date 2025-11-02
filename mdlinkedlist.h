#ifndef _MD_LINKED_LIST_H
#define _MD_LINKED_LIST_H
typedf struct md_linked_linkedlist_el {
    void* data;
    md_linked_linkedlist_el* prev;
    md_linked_linkedlist_el* next;
} md_linked_linkedlist_el;

md_linked_linkedlist_el* md_linked_linkedlist_add(md_linked_linkedlist_el* exist_el, void* data);
void md_linked_linkedlist_remove(md_linked_linkedlist_el* remove_el, void (*data_free_fn)(void* data));
size_t md_linked_linkedlist_count(md_linked_linkedlist_el* first_el);
void md_linked_linkedlist_free_all(md_linked_linkedlist_el* first_el, void (*data_free_fn)(void* data));
#endif