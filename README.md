Dynamic Strings
===

RDS is a library for dynamic strings. It implements dynamic strings that are more efficient than the traditional varieties that use a structure, and also maintains compatibility with regular C strings. RDS achieves this with a metadata prefix, aka header. 
The header contains the smallest possible metadata that can accommodate the size of the C string. 

An rds has the following format:

    +--------+-----------------------------+----+
    | Header |        C-like string        | \0 |
    +--------+-----------------------------+----+
             |
             `-> Pointer returned to the user


Since all rds pointers point to the beginning of the string buffer, an rds is fully compatible with C string logic, so it can be used interchangeably.
However, since the metadata contains the C string's size and with the implicit null byte at the end, regardless of the string's contents,
the string is binary-safe. Meaning the string may or may not contain null bytes. It's up to the user to know what is in their strings.

## API

An rds is defined as a char pointer:
```C
/* It's recommended to use rds instead of char * to distinguish between the two types, though functionally it should be the same */
typedef char *rds;
````

rds creation functions:
```C
/* initialize new rds from string s and its len */
rds rds_new_len(const void *s, size_t len); 

/* initialize new rds from empty */
rds rds_init(void);

/* initialize new rds from string s */
rds rds_new(const char *s);
```

rds deletion (freeing from memory and setting the pointer to NULL):
```C

/* delete an rds, pointer is invalid after */
void rds_del(rds s); 
```

String concatenation:
```C
/* append cstring 'b' to rds 'a' knowing 'b''s len 
 * NOTE: 1. ptr 'a' may or may not be trashed after the call (e.g. realloc/malloc could fail)
 *       2. ptr 'a' may or may not hold a different value after the call (e.g. realloc/new malloc)
 * */
void rds_append_len(rds *a, const void *b, size_t b_len);

/* append buffer of rds 'b' to rds 'a'
 * NOTE: 1. ptr 'a' may or may not be trashed after the call (e.g. realloc/malloc could fail)
 *       2. ptr 'a' may or may not hold a different value after the call (e.g. realloc/new malloc)
 * */
void rds_append(rds *a, const rds b);

/* append cstring 'b' to rds 'a'
 * NOTE: 1. ptr 'a' may or may not be trashed after the call (e.g. realloc/malloc could fail)
 *       2. ptr 'a' may or may not hold a different value after the call (e.g. realloc/new malloc)
 * */
void rds_append_str(rds *a, const char *b);
```

Misc:
```C
/* get length of an rds' buffer */
size_t rds_strlen(const rds s);
```

## Using RDS

Just copy rds.c and rds.h into your project. All that's needed is a C/C++ compiler and a libc.

