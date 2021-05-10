#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _MSC_VER
// MSC does not support aligned_alloc
// _aligned_malloc is like aligned_alloc except that
// the allocated memory has to be freed with _aligned_free
#define aligned_alloc(a, n) _aligned_malloc(n, a)
#endif
/*
Assume sizes:
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
    uint8_t tag;
    uint8_t gc_reserved;
    uint16_t spare1;
    uint32_t spare2;
} BalHeader, *BalHeaderPtr;

typedef union {
    // if imm is 0 not a valid valid
    uintptr_t imm;
    BalHeaderPtr ptr;
} BalValue;

// Not a Ballerina value
#define BAL_NULL ((BalValue){.imm = 0})

typedef struct {
    BalHeader header;
    size_t n_bytes;
    size_t n_code_points;
    // not zero-terminated
    uint8_t bytes[];
} BalString, *BalStringPtr;

typedef struct {
    BalStringPtr key;
    BalValue value;
} BalHashEntry;

#define LOAD_FACTOR 0.6f
#define HASH_TABLE_MIN_SIZE 8

typedef struct {
    BalHeader header;
    // how many of entries are used
    size_t used;
    // used must be < capacity
    // capacity = LOAD_FACTOR * n_entries
    size_t capacity;
    // always a power of 2
    // length of entries array
    size_t n_entries;
    BalHashEntry *entries;
} BalMap, *BalMapPtr;

BalMapPtr bal_map_create(size_t capacity);
void bal_map_insert(BalMapPtr map, BalStringPtr key, BalValue value);
void bal_map_insert_with_hash(BalMapPtr map, BalStringPtr key, BalValue value, unsigned long hash);
void bal_map_grow(BalMapPtr map);
BalValue bal_map_lookup(BalMapPtr map, BalStringPtr key);
BalValue bal_map_lookup_with_hash(BalMapPtr map, BalStringPtr key, unsigned long hash);
unsigned long bal_string_hash(BalStringPtr s);
BalStringPtr bal_string_create_ascii(char *s);
bool bal_string_equals(BalStringPtr s1, BalStringPtr s2);
BalHeader *alloc_value(size_t n_bytes);
void *zalloc(size_t n_members, size_t member_size);

BalMapPtr bal_map_create(size_t min_capacity) {
    // Want n_entries * LOAD_FACTOR > capacity
    BalMapPtr map = (BalMapPtr)alloc_value(sizeof(BalMap));
    map->used = 0;

    size_t n = HASH_TABLE_MIN_SIZE;
    while ((size_t)(n * LOAD_FACTOR) < min_capacity) {
        n <<= 1;
        assert(n != 0);
    }
    map->capacity = (size_t)(n * LOAD_FACTOR);
    assert(map->capacity >= min_capacity);
    // printf("Creating map for capacity %ld with n_entries %ld\n", map->capacity,
    // n);
    map->n_entries = n;
    map->entries = zalloc(map->n_entries, sizeof(BalHashEntry));
    map->header.tag = HEADER_TAG_MAPPING;
    return map;
}

void bal_map_insert(BalMapPtr map, BalStringPtr key, BalValue value) {
    bal_map_insert_with_hash(map, key, value, bal_string_hash(key));
}

void bal_map_insert_with_hash(BalMapPtr map, BalStringPtr key, BalValue value, unsigned long hash) {
    size_t i = hash & (map->n_entries - 1);
    assert(i >= 0 && i < map->n_entries);
    BalHashEntry *entries = map->entries;
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
        } else {
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

void bal_map_grow(BalMapPtr map) {
    BalMapPtr nMap = bal_map_create(map->used + 1);
    // printf("Growing from %ld to %ld\n", map->capacity, nMap->capacity);

    BalHashEntry *entries = map->entries;
    size_t n = map->n_entries;
    for (size_t i = 0; i < n; i++) {
        if (entries[i].key != 0) {
            bal_map_insert(nMap, entries[i].key, entries[i].value);
        }
    }
    memcpy(map, nMap, sizeof(BalMap));
}

BalValue bal_map_lookup(BalMapPtr map, BalStringPtr key) {
    return bal_map_lookup_with_hash(map, key, bal_string_hash(key));
}

bool bal_string_equals(BalStringPtr s1, BalStringPtr s2) {
    if (s1 == s2) {
        return true;
    }
    if (s1->n_bytes != s2->n_bytes) {
        return false;
    }
    return memcmp(s1->bytes, s2->bytes, s1->n_bytes) == 0;
}

// Returns BAL_NULL if not found
BalValue bal_map_lookup_with_hash(BalMapPtr map, BalStringPtr key, unsigned long hash) {
    size_t i = hash & (map->n_entries - 1);
    assert(i >= 0 && i < map->n_entries);
    BalHashEntry *entries = map->entries;
    for (;;) {
        if (entries[i].key == 0) {
            return BAL_NULL;
        }
        if (bal_string_equals(key, entries[i].key)) {
            return entries[i].value;
        }
        if (i > 0) {
            --i;
        } else {
            i = map->n_entries - 1;
        }
    }
}

// DJB2 hash function
unsigned long bal_string_hash(BalStringPtr s) {
    unsigned long hash = 5381;
    size_t n = s->n_bytes;
    unsigned char *p = s->bytes;
    while (n-- > 0) {
        hash = hash * 33 + *p++;
    }
    return hash;
}

// Only use if you know that every byte is <= 127
BalStringPtr bal_string_create_ascii(char *s) {
    size_t len = strlen(s);
    BalStringPtr str = (BalStringPtr)alloc_value(sizeof(BalString) + len);
    memcpy(str->bytes, s, len);
    str->n_bytes = len;
    str->n_code_points = len;
    str->header.tag = HEADER_TAG_STRING;
    return str;
}

BalHeaderPtr alloc_value(size_t n_bytes) {
    void *mem = aligned_alloc(8, n_bytes);
    assert(mem != 0);
    BalHeaderPtr h = mem;
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
    BalMapPtr map = bal_map_create(42);
    printf("Inserting\n");

    for (int i = 0; i < 1000000; i++) {
        sprintf(buf, "str%i", i);
        BalStringPtr s = bal_string_create_ascii(buf);
        BalValue val = {.ptr = &(s->header)};
        bal_map_insert(map, s, val);
        // printf("Inserted %d\n", i);
    }

    printf("Looking up\n");
    for (int i = 0; i < 1000000; i++) {
        sprintf(buf, "str%i", i);
        BalStringPtr s = bal_string_create_ascii(buf);
        BalValue val = bal_map_lookup(map, s);
        assert(bal_string_equals((BalStringPtr)val.ptr, s));
    }
    printf("End\n");
    return 0;
}
