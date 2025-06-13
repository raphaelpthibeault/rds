#ifndef __RDS_H__
#define __RDS_H__

#ifdef __cplusplus
extern "C" {
#endif // !__cplusplus

#include <stddef.h>
#include <stdint.h>

/* API
 *
 * NOTE:
 * all rds' pointers point to the beginning of the string buffer, so there's no use difference between them and a cstring in that aspect
 * all rds have implicit null termination, so you can printf
 * However, the string is "binary-safe" since its length is stored in the header, meaning in reality the string could be an array of bytes which may or may not have \0 in the middle
 * So it's up to the user to know what's in the string
 * */

#define RDS_MAX_PREALLOC 0x100000 /* 1 MiB; an aribtrary limit for the linear increase growth of the string, once a string has reached this size use constant growth instead  */

/* types of rds, must fit in 3 bits */
#define RDS_TYPE_64 4
#define RDS_TYPE_32 3
#define RDS_TYPE_16 2
#define RDS_TYPE_8  1
#define RDS_TYPE_5  0

#define RDS_TYPE_MASK 0b00000111
#define RDS_TYPE_BITS 3

/* DESIGN DECISIONS
 * format:
 * [ header | C string | '\0' ]
 * header: 
 *	the smallest possible that can accomodate the C string's size
 *	don't have a capacity variable because that's implicit to the type
 *	uint64 -> 2**64 - 1 
 *	uint32 -> 2**32 - 1
 *	uint16 -> 2**16 - 1
 *	uint8  -> 2**8  - 1
 *	then a special 5-bit for really short, size <= 31 
 *	no struct for that, the flags field will be used directly
 *
 *	Notes:
 *	if an rds is returned by a function, the pointer points to the beginning of the C string
 *
 *	structure:
 *	rds_header## {
 *		unsigned## size;     <- size of the string
 *		unsigned## allocated;<- allocated size of the string
 *		unsigned char flags; <- flags, used to determine the type of the string. 5 msb are unused or for size in case of special 5-bit case, and 3 lsb are for type
 *		                        will do rds_str[-1] to get flags, since the pointer for a rds points to the buffer
 *		                        and then mask with 0b00000111 to get the type since the 3 lsb are for type
 *		char buf[];          <- variable length array
 *	};
 * */

struct rds_header64
{
	uint64_t size;
	uint64_t allocated;
	unsigned char flags; /* 5 msb unused, 3 lsb for type */
	char buf[];
} __attribute__((packed));

struct rds_header32
{
	uint32_t size;
	uint32_t allocated;
	unsigned char flags; /* 5 msb unused, 3 lsb for type */
	char buf[];
} __attribute__((packed));

struct rds_header16
{
	uint16_t size;
	uint16_t allocated;
	unsigned char flags; /* 5 msb unused, 3 lsb for type */
	char buf[];
} __attribute__((packed));

struct rds_header8
{
	uint8_t size;
	uint8_t allocated;
	unsigned char flags; /* 5 msb unused, 3 lsb for type */
	char buf[];	
} __attribute__((packed));

struct rds_header5
{
	unsigned char flags; /* 5 msb for size, 3 lsb for type */
	char buf[];	
} __attribute__((packed));
/* I recommend to use rds instead of char * in programs to distinguish between the two types, though functionally it should be the same */
typedef char *rds;

/* get length of an rds' buffer */
size_t rds_strlen(const rds s);

/* get length of an rds' header */
size_t rds_get_header_size(unsigned char flags);

/* initialize new rds from string s and its len */
rds rds_new_len(const void *s, size_t len);

/* initialize new rds from empty */
rds rds_init(void);

/* initialize new rds from string s */
rds rds_new(const char *s);

/* delete an rds, pointer is invalid after */
void rds_del(rds s); 

/* append null-terminated cstring 'b' to rds 'a' knowing 'b''s len 
 * NOTE: 1. ptr 'a' may or may not be trashed after the call (e.g. realloc could fail)
 *       2. ptr 'a' may or may not hold a different value after the call (e.g. changed rds type, requiring a malloc instead of a realloc)
 * */
void rds_append_len(rds *a, const void *b, size_t b_len);

/* append buffer of rds 'b' to rds 'a'
 * NOTE: 1. ptr 'a' may or may not be trashed after the call (e.g. realloc could fail)
 *       2. ptr 'a' may or may not hold a different value after the call (e.g. changed rds type, requiring a malloc instead of a realloc)
 * */
void rds_append(rds *a, const rds b);

/* append null-terminated cstring 'b' to rds 'a'
 * NOTE: 1. ptr 'a' may or may not be trashed after the call (e.g. realloc could fail)
 *       2. ptr 'a' may or may not hold a different value after the call (e.g. changed rds type, requiring a malloc instead of a realloc)
 * */
void rds_append_str(rds *a, const char *b);

#ifdef __cplusplus
};
#endif // !__cplusplus
#endif // !__RDS_H__
