/* Prototype of runtime for nBallerina */

/*
Assume (for now):
1. NoGC memory management - malloc and never free
2. No exceptions: panic aborts
*/

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
// Since we're not freeing anything, this doesn't affect us
#define aligned_alloc(a, n) _aligned_malloc(n, a)
#endif

#define HEADER_TAG_UNINIT 0
#define HEADER_TAG_INT 1
#define HEADER_TAG_STRING 2
#define HEADER_TAG_LIST 3
#define HEADER_TAG_MAPPING 4

// Types

typedef struct {
    uint8_t tag;
    uint8_t gc_reserved;
    uint16_t spare1;
    uint32_t spare2;
} BalHeader, *BalHeaderPtr;

// Bottom 3 bits of BalValue are a tag
// 000 means a pointer to a BalHeader
// XX1 means all but low bit is a signed integer
// 010 means nil
// 110 means a  boolean (next bit is whether true or false)
// 100 is spare

#define IMMED_TAG_MASK    0b0111
#define IMMED_TAG_PTR     0b0000
#define IMMED_TAG_BOOLEAN 0b0010
// This bit is set to indicate that an immed value is an integer
#define IMMED_TAG_INT_MASK 0b1

#define IMMED_VALUE_NIL   0b0010
#define IMMED_VALUE_FALSE 0b0110
#define IMMED_VALUE_TRUE  0b1110

// Range of int that can stored directly within a BalValue
#define IMMED_INT_MAX (INTPTR_MAX >> 1)
#define IMMED_INT_MIN (INTPTR_MIN >> 1)

typedef union {
    // if immed is 0, not a valid value
    intptr_t immed;
    BalHeaderPtr ptr;
} BalValue;

// Not a Ballerina value
#define BAL_NULL ((BalValue){.ptr = 0})

typedef struct {
    BalHeader header;
    int64_t value;
} BalInt, *BalIntPtr;

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
#define ARRAY_MIN_SIZE 4

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

typedef struct {
    BalHeader header;
    // length of the array
    size_t length;
    // allocated size
    size_t capacity;
    // may be null if capacity is 0
    BalValue *values;
} BalArray, *BalArrayPtr;


// Function declarations

BalMapPtr bal_map_create(size_t min_capacity);
void bal_map_init(BalMapPtr map, size_t min_capacity);
void bal_map_insert(BalMapPtr map, BalStringPtr key, BalValue value);
void bal_map_insert_with_hash(BalMapPtr map, BalStringPtr key, BalValue value, unsigned long hash);
void bal_map_grow(BalMapPtr map);
BalValue bal_map_lookup(BalMapPtr map, BalStringPtr key);
BalValue bal_map_lookup_with_hash(BalMapPtr map, BalStringPtr key, unsigned long hash);
unsigned long bal_string_hash(BalStringPtr s);
BalArrayPtr bal_array_create(size_t capacity);
BalValue bal_array_get(BalArrayPtr array, int64_t index);
void bal_array_push(BalArrayPtr array, BalValue value);
void bal_array_grow(BalArrayPtr array);

BalStringPtr bal_string_create_ascii(char *s);
bool bal_string_equals(BalStringPtr s1, BalStringPtr s2);
BalValue bal_int_create(int64_t n);

BalHeader *alloc_value(size_t n_bytes);
void *zalloc(size_t n_members, size_t member_size);

#define panic(msg) assert(0 && msg)

// Inline functions

inline BalValue bal_immediate(uintptr_t immed) {
    BalValue v = { .immed = immed };
    return v;
}

inline BalValue bal_pointer(BalHeaderPtr ptr) {
    BalValue v = { .ptr = ptr };
    return v;
}

inline bool bal_value_is_boolean(BalValue v) {
    return (v.immed & IMMED_TAG_MASK) == IMMED_TAG_BOOLEAN;
}

inline bool bal_value_is_nil(BalValue v) {
    return v.immed == IMMED_VALUE_NIL;
}

inline bool bal_value_is_true(BalValue v) {
    return v.immed == IMMED_VALUE_TRUE;
}

inline bool bal_value_is_false(BalValue v) {
    return v.immed == IMMED_VALUE_FALSE;
}

inline bool bal_value_is_int(BalValue v) {
    if (v.immed & IMMED_TAG_INT_MASK) {
        return true;
    }
    if ((v.immed & IMMED_TAG_MASK) == 0) {
        return v.ptr->tag == HEADER_TAG_INT;
    }
    return false;
}

inline bool bal_value_is_mapping(BalValue v) {
    return (v.immed & IMMED_TAG_MASK) == IMMED_TAG_PTR && v.ptr->tag == HEADER_TAG_MAPPING;
}

inline bool bal_value_is_list(BalValue v) {
    return (v.immed & IMMED_TAG_MASK) == IMMED_TAG_PTR && v.ptr->tag == HEADER_TAG_LIST;
}


inline BalValue bal_nil() {
    return bal_immediate(IMMED_VALUE_NIL);
}

inline BalValue bal_false() {
    return bal_immediate(IMMED_VALUE_FALSE);
}

inline BalValue bal_true() {
    return bal_immediate(IMMED_VALUE_TRUE);
}

// This assumes v represents an int
// If it doesn't, then it gets an assertion failure
// or undefined behaviour if assertions are violated
int64_t bal_value_to_int_unsafe(BalValue v) {
    if ((v.immed & IMMED_TAG_MASK) == 0) {
        assert(v.ptr->tag == HEADER_TAG_INT);
        return ((BalIntPtr)v.ptr)->value;
    }
    assert(v.immed & IMMED_TAG_INT_MASK);
    return v.immed >> 1;
}

inline BalValue bal_int(int64_t i) {
    if (IMMED_INT_MIN <= i && i <= IMMED_INT_MAX) {
        return bal_immediate((i << 1) | IMMED_TAG_INT_MASK);
    }
    return bal_int_create(i);
}

inline bool bal_value_is_byte(BalValue v) {
    return (v.immed & IMMED_TAG_INT_MASK) && (uintptr_t)v.immed <= 0x1FF;
}

inline BalValue bal_byte(uint8_t i) {
    return bal_immediate((i << 1) | IMMED_TAG_INT_MASK);
}

inline uint8_t bal_value_to_byte_unsafe(BalValue v) {
    assert((uintptr_t)v.immed <= 0x1FF && (v.immed & IMMED_TAG_INT_MASK));
    return (uint8_t)(v.immed >> 1);
}

// Implementation

BalMapPtr bal_map_create(size_t min_capacity) {
    // Want n_entries * LOAD_FACTOR > capacity
    BalMapPtr map = (BalMapPtr)alloc_value(sizeof(BalMap));
    bal_map_init(map, min_capacity);
    map->header.tag = HEADER_TAG_MAPPING;
    return map;
}

void bal_map_init(BalMapPtr map, size_t min_capacity) {
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
    BalMap nMap;
    bal_map_init(&nMap, map->used + 1);
    // printf("Growing from %ld to %ld\n", map->capacity, nMap->capacity);

    BalHashEntry *entries = map->entries;
    size_t n = map->n_entries;
    for (size_t i = 0; i < n; i++) {
        if (entries[i].key != 0) {
            bal_map_insert(&nMap, entries[i].key, entries[i].value);
        }
    }
    map->used = nMap.used;
    map->capacity = nMap.capacity;
    map->n_entries = nMap.n_entries;
    map->entries = nMap.entries;
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

BalArrayPtr bal_array_create(size_t capacity) {
    BalArrayPtr array = (BalArrayPtr)alloc_value(sizeof(BalArray));
    array->capacity = capacity;
    array->length = 0;
    array->values = capacity == 0 ? (void *)0 : zalloc(capacity, sizeof(BalValue));
    array->header.tag = HEADER_TAG_LIST;
    return array;
}

BalValue bal_array_get(BalArrayPtr array, int64_t index) {
    if (index < 0 || (uint64_t)index >= array->length) {
        panic("array index out of bounds");
    }
    return array->values[(size_t)index];
}

void bal_array_push(BalArrayPtr array, BalValue value) {
    if (array->length >= array->capacity) {
        bal_array_grow(array);
    }
    array->values[array->length] = value;
    array->length += 1;
}

void bal_array_grow(BalArrayPtr array) {
    size_t capacity = array->capacity;
    if (capacity == 0) {
        capacity = ARRAY_MIN_SIZE;
    }
    else {
        capacity <<= 1;
        // catch overflow
        assert(capacity != 0);
    }
    BalValue *values = zalloc(capacity, sizeof(BalValue));
    if (array->values != NULL) {
        // we assume zalloc will have failed if capacity*sizeof(BalValue) exceeds a size_t
        memcpy(values, array->values, sizeof(BalValue)*array->length);
    }
    array->capacity = capacity;
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

BalValue bal_int_create(int64_t i) {
    BalIntPtr ip = (BalIntPtr)alloc_value(sizeof(BalInt));
    ip->value = i;
    ip->header.tag = HEADER_TAG_INT;
    return bal_pointer(&(ip->header));
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

// Testing

#define test_int_roundtrip(i) assert((i) == bal_value_to_int_unsafe(bal_int(i)))

void test_int() {
    test_int_roundtrip(0);
    test_int_roundtrip(1);
    test_int_roundtrip(2);
    test_int_roundtrip(3);
    test_int_roundtrip(100);
    test_int_roundtrip(1024);
    test_int_roundtrip(-1);
    test_int_roundtrip(-2);
    test_int_roundtrip(-3);
    test_int_roundtrip(-4611686018427387906);
    test_int_roundtrip(-4611686018427387905);
    test_int_roundtrip(-4611686018427387904);
    test_int_roundtrip(0x3FFFFFFFFFFFFFFF - 1);
    test_int_roundtrip(0x3FFFFFFFFFFFFFFF);
    test_int_roundtrip(0x3FFFFFFFFFFFFFFF + 1);
}

void test_map() {
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
}

int main() {
    printf("Testing map\n");
    test_map();
    printf("Testing int\n");
    test_int();
    return 0;
}
