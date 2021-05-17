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

// Uniform type tag
// Uniform types are like basic types, except that selectively immutable basic types are
// split into mutable and readonly uniform types.
typedef enum {
    UTYPE_NIL,
    UTYPE_BOOLEAN,
    UTYPE_INT,
    UTYPE_STRING,
    UTYPE_LIST_RW,
    UTYPE_MAPPING_RW
} BalUTypeTag;

// nil is never boxed
#define HEADER_TAG_UNINIT UTYPE_NIL

// Types

typedef struct {
    // These are from BalUTypeTag
    // Not declared as UType, because we want it to be a uint8_t
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

#define IMMED_TAG_MASK    0b111
#define IMMED_TAG_PTR     0b000
#define IMMED_TAG_BOOLEAN 0b110
// This bit is set to indicate that an immed value is an integer
#define IMMED_FLAG_INT 0b1

#define IMMED_TAG_NIL     0b010     
#define IMMED_VALUE_NIL   IMMED_TAG_NIL
#define IMMED_VALUE_FALSE IMMED_TAG_BOOLEAN
#define IMMED_FLAG_BOOLEAN 0b1000
#define IMMED_VALUE_TRUE  (IMMED_TAG_BOOLEAN|IMMED_FLAG_BOOLEAN)

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

// All allocations go through one of these
#define ALLOC_FIXED_VALUE(T) ((T*)alloc_value(sizeof(T)))

BalHeader *alloc_value(size_t n_bytes);
void *alloc_array(size_t n_members, size_t member_size);

#define panic(msg) assert(0 && msg)

// Inline functions

inline BalValue bal_immediate(intptr_t immed) {
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

inline BalUTypeTag bal_value_utype_tag(BalValue v) {
    int tag = v.immed & IMMED_TAG_MASK;
    if (tag == IMMED_TAG_PTR) {
        return v.ptr->tag;
    }
    // Don't use ?: for this
    // clang optimizes less well
    if (tag == IMMED_TAG_NIL) {
        return UTYPE_NIL;
    }
    if (tag == IMMED_TAG_BOOLEAN) {
        return UTYPE_BOOLEAN;
    }
    return UTYPE_INT;
}

inline bool bal_value_is_int(BalValue v) {
    if (v.immed & IMMED_FLAG_INT) {
        return true;
    }
    if ((v.immed & IMMED_TAG_MASK) == 0) {
        return v.ptr->tag == UTYPE_INT;
    }
    return false;
}

inline bool bal_value_is_mapping(BalValue v) {
    return (v.immed & IMMED_TAG_MASK) == IMMED_TAG_PTR && v.ptr->tag == UTYPE_MAPPING_RW;
}

inline bool bal_value_is_list(BalValue v) {
    return (v.immed & IMMED_TAG_MASK) == IMMED_TAG_PTR && v.ptr->tag == UTYPE_LIST_RW;
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
        assert(v.ptr->tag == UTYPE_INT);
        return ((BalIntPtr)v.ptr)->value;
    }
    assert(v.immed & IMMED_FLAG_INT);
    return v.immed >> 1;
}

inline BalValue bal_int(int64_t i) {
    if (IMMED_INT_MIN <= i && i <= IMMED_INT_MAX) {
        return bal_immediate(((intptr_t)i << 1) | IMMED_FLAG_INT);
    }
    return bal_int_create(i);
}

inline bool bal_value_is_byte(BalValue v) {
    return (v.immed & IMMED_FLAG_INT) && (uintptr_t)v.immed <= 0x1FF;
}

inline BalValue bal_byte(uint8_t i) {
    return bal_immediate((i << 1) | IMMED_FLAG_INT);
}

inline uint8_t bal_value_to_byte_unsafe(BalValue v) {
    assert((uintptr_t)v.immed <= 0x1FF && (v.immed & IMMED_FLAG_INT));
    return (uint8_t)(v.immed >> 1);
}

// Implementation

BalMapPtr bal_map_create(size_t min_capacity) {
    // Want n_entries * LOAD_FACTOR > capacity
    BalMapPtr map = ALLOC_FIXED_VALUE(BalMap);
    bal_map_init(map, min_capacity);
    map->header.tag = UTYPE_MAPPING_RW;
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
    map->entries = alloc_array(map->n_entries, sizeof(BalHashEntry));
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
    BalArrayPtr array = ALLOC_FIXED_VALUE(BalArray);
    array->capacity = capacity;
    array->length = 0;
    array->values = capacity == 0 ? (void *)0 : alloc_array(capacity, sizeof(BalValue));
    array->header.tag = UTYPE_LIST_RW;
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
    BalValue *values = alloc_array(capacity, sizeof(BalValue));
    if (array->values != NULL) {
        // we assume alloc_array will have failed if capacity*sizeof(BalValue) exceeds a size_t
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
    str->header.tag = UTYPE_STRING;
    return str;
}

BalValue bal_int_create(int64_t i) {
    BalIntPtr ip = ALLOC_FIXED_VALUE(BalInt);
    ip->value = i;
    ip->header.tag = UTYPE_INT;
    return bal_pointer(&(ip->header));
}

BalHeaderPtr alloc_value(size_t n_bytes) {
    void *mem = aligned_alloc(8, n_bytes);
    assert(mem != 0);
    BalHeaderPtr h = mem;
    h->tag = HEADER_TAG_UNINIT;
    return h;
}

void *alloc_array(size_t n_members, size_t member_size) {
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
