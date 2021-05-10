#include <stdio.h>
#include <limits.h>
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define STATIC_ASSERT(COND,MSG) typedef char static_assertion_##MSG[(COND)?1:-1]
STATIC_ASSERT(sizeof(size_t) == 8, short_should_be_8_byte); 

#if USHRT_MAX != 0xFFFF
#error "Size of short not equal to 2"
#endif

#if UINT_MAX != 0xFFFFFFFF
#error "Size of int not equal to 4"
#endif

#if SIZE_MAX != 0xFFFFFFFFFFFFFFFFUL
#error "Size of size_t not equal to 4"
#endif

#if ULONG_MAX != 0xFFFFFFFFFFFFFFFF
#error "Size of long not equal to 8"
#endif
/*
Assume sizes:
short 2
int 4
long 8
char * 8
size_t 4

Assume (for now):
1. NoGC memory management - malloc and never free
2. No exceptions: panic aborts
*/

#define HEADER_TAG_UNINIT 0
#define HEADER_TAG_STRING 1
#define HEADER_TAG_MAPPING 2


typedef struct {
    unsigned char tag;
    unsigned char gc_reserved;
    unsigned short spare1;
    unsigned int spare2;
} bal_header_t;

typedef union {
    // if imm is 0 not a valid valid 
    unsigned long imm;
    bal_header_t *ptr;
} bal_value_t;


#define BAL_NULL ((bal_value_t){ .imm = 0 })

typedef struct {
    bal_header_t header;
    size_t n_bytes;
    size_t n_code_points;
    // not zero-terminated
    unsigned char bytes[];
} bal_string_t, *bal_string_ptr_t;

typedef struct {
    bal_string_ptr_t key;
    bal_value_t value;
} bal_hash_entry_t;

#define LOAD_FACTOR 0.6f
#define HASH_TABLE_MIN_SIZE 8

typedef struct {
    bal_header_t header;
    // how many of entries are used
    size_t used;
    // used must be < capacity
    // capacity = LOAD_FACTOR * n_entries
    size_t capacity;
    // always a power of 2
    // length of entries array
    size_t n_entries;
    bal_hash_entry_t *entries;
} bal_map_t, *bal_map_ptr_t;

bal_map_ptr_t bal_map_create(int capacity);
void bal_map_insert(bal_map_ptr_t map, bal_string_ptr_t key, bal_value_t value);
void bal_map_insert_with_hash(bal_map_ptr_t map, bal_string_ptr_t key, bal_value_t value, unsigned long hash);
void bal_map_grow(bal_map_ptr_t map);
bal_value_t bal_map_lookup(bal_map_ptr_t map, bal_string_ptr_t key);
bal_value_t bal_map_lookup_with_hash(bal_map_ptr_t map, bal_string_ptr_t key, unsigned long hash);
unsigned long bal_string_hash(bal_string_ptr_t s);
bal_string_ptr_t bal_string_create_ascii(char *s);
bool bal_string_equals(bal_string_ptr_t s1, bal_string_ptr_t s2);
bal_header_t *alloc_value(size_t n_bytes);
void *zalloc(size_t n_members, size_t member_size);



bal_map_ptr_t bal_map_create(int min_capacity) {
     // Want n_entries * LOAD_FACTOR > capacity
    bal_map_ptr_t map = (bal_map_ptr_t)alloc_value(sizeof(bal_map_t));
    map->used = 0;

    size_t n = HASH_TABLE_MIN_SIZE;
    while ((size_t)(n * LOAD_FACTOR) < min_capacity) {
        n <<= 1;
        assert(n != 0);
    }
    map->capacity = (size_t)(n * LOAD_FACTOR);
    assert(map->capacity >= min_capacity);
    // printf("Creating map for capacity %ld with n_entries %ld\n", map->capacity, n);
    map->n_entries = n;
    map->entries = zalloc(map->n_entries, sizeof(bal_hash_entry_t));
    map->header.tag = HEADER_TAG_MAPPING;
    return map;
}

void bal_map_insert(bal_map_ptr_t map, bal_string_ptr_t key, bal_value_t value){
    bal_map_insert_with_hash(map, key, value, bal_string_hash(key));
}

void bal_map_insert_with_hash(bal_map_ptr_t map, bal_string_ptr_t key, bal_value_t value, unsigned long hash) {
    int i = hash & (map->n_entries - 1);
    assert(i >= 0 && i < map->n_entries);
    bal_hash_entry_t *entries = map->entries;
    for (;;) {
        if (entries[i].key == 0) {
            break;
        }
        if (bal_string_equals(key, entries[i].key)) {
            entries[i].value = value;
            return;
        }
        if (i > 0) {
            --i;
        }
        else {
            i = map->n_entries - 1;
        }
    }
    entries[i].value = value;
    entries[i].key = key;
    assert(map->used < map->n_entries);
    map->used += 1;
    if (map->used >= map->capacity) {
        bal_map_grow(map);
    }
}

void bal_map_grow(bal_map_ptr_t map) {
    bal_map_ptr_t nmap = bal_map_create(map->used + 1);
    // printf("Growing from %ld to %ld\n", map->capacity, nmap->capacity);

    bal_hash_entry_t *entries = map->entries;
    size_t n = map->n_entries;
    for (int i = 0; i < n; i++) {
        if (entries[i].key != 0) {
            bal_map_insert(nmap, entries[i].key, entries[i].value);
        }
    }
    memcpy(map, nmap, sizeof(bal_map_t));
}    

bal_value_t bal_map_lookup(bal_map_ptr_t map, bal_string_ptr_t key) {
    return bal_map_lookup_with_hash(map, key, bal_string_hash(key));
}

bool bal_string_equals(bal_string_ptr_t s1, bal_string_ptr_t s2) {
    if (s1 == s2) {
        return true;
    }
    if (s1->n_bytes != s2->n_bytes) {
        return false;
    }
    return memcmp(s1->bytes, s2->bytes, s1->n_bytes) == 0;
}

// Returns BAL_NULL if not found
bal_value_t bal_map_lookup_with_hash(bal_map_ptr_t map, bal_string_ptr_t key, unsigned long hash) {
    int i = hash & (map->n_entries - 1);
    assert(i >= 0 && i < map->n_entries);
    bal_hash_entry_t *entries = map->entries;
    for (;;) {
        if (entries[i].key == 0) {
            return BAL_NULL;
        }
        if (bal_string_equals(key, entries[i].key)) {
            return entries[i].value;
        }
        if (i > 0) {
            --i;
        }
        else {
            i = map->n_entries - 1;
        }
    }
}

// DJB2 hash function
unsigned long bal_string_hash(bal_string_ptr_t s) {
    unsigned long hash = 5381;
    size_t n = s->n_bytes;
    unsigned char *p = s->bytes;
    while (n-- > 0) {
        hash = hash*33 + *p++;
    }
    return hash;
}

// Only use if you know that every byte is <= 127
bal_string_ptr_t bal_string_create_ascii(char *s) {
    size_t len = strlen(s);
    bal_string_ptr_t str = (bal_string_ptr_t)alloc_value(sizeof(bal_string_t) + len);
    memcpy(str->bytes, s, len);
    str->n_bytes = len;
    str->n_code_points = len;
    str->header.tag = HEADER_TAG_STRING;
    return str;
}

bal_header_t *alloc_value(size_t n_bytes) {
    void *mem = malloc(n_bytes);
    assert(mem != 0);
    assert((((unsigned long)mem) & 0b111) == 0);
    bal_header_t *h = mem;
    h->tag = HEADER_TAG_UNINIT;
    return h;
}

void *zalloc(size_t n_members, size_t member_size) {
    void *mem = calloc(n_members, member_size);
    assert(mem != 0);
    return mem;
}

int main() {
    char buf[32];
    bal_map_ptr_t map = bal_map_create(42);
    printf("Inserting\n");

    for (int i = 0; i < 1000000; i++) {
        sprintf(buf, "str%i", i);
        bal_string_ptr_t s = bal_string_create_ascii(buf);
        bal_value_t val = { .ptr = s };
        bal_map_insert(map, s, val);
        //printf("Inserted %d\n", i);
    }

    printf("Looking up\n");
    for (int i = 0; i < 1000000; i++) {
        sprintf(buf, "str%i", i);
        bal_string_ptr_t s = bal_string_create_ascii(buf);
        bal_value_t val = bal_map_lookup(map, s);
        assert(bal_string_equals(val.ptr, s));        
    }
    printf("End\n");
    return 0;
}
