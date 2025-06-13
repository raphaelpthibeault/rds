#include <rds.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <assert.h>

#define RDS_TYPE_5_GET_LEN(f) ((f) >> RDS_TYPE_BITS) /* recall form 0bxxxxx000, 000 being type */
#define RDS_GET_HEADER(t, s) ((struct rds_header##t *)((s) - (sizeof(struct rds_header##t)))) /* recall pointer s is at beginning of buf */
#define RDS_GET_HEADER_VAR(t, s) struct rds_header##t *hdr = (void*)((s) - (sizeof(struct rds_header##t))); 

static inline __attribute__((always_inline)) unsigned char 
rds_get_recommended_header_type(size_t len)
{
	if (len < 1<<5) return RDS_TYPE_5;
	if (len < 1<<8) return RDS_TYPE_8;
	if (len < 1<<16) return RDS_TYPE_16;
#if (LONG_MAX == LLONG_MAX)
	/* 64-bit system */
	if (len < 1LL<<32) return RDS_TYPE_32;
	return RDS_TYPE_64;
#else
	return RDS_TYPE_32;	
#endif
}

size_t
rds_get_header_size(unsigned char flags) 
{
	/* could have done this with a macro but I wanted it to work with flags and type */
	switch (flags & RDS_TYPE_MASK) 
	{
		case RDS_TYPE_5:
			return sizeof(struct rds_header5);
		case RDS_TYPE_8:
			return sizeof(struct rds_header8);
		case RDS_TYPE_16:
			return sizeof(struct rds_header16);
		case RDS_TYPE_32:
			return sizeof(struct rds_header32);
		case RDS_TYPE_64:
			return sizeof(struct rds_header64);
	}

	return 0;
}

/* get length of the buffer (not entire string) 
 * */
size_t 
rds_strlen(const rds s)
{
	if (s == NULL) return 0;

	unsigned char flags = s[-1];

	switch (flags & RDS_TYPE_MASK) 
	{
		case RDS_TYPE_5:
			return RDS_TYPE_5_GET_LEN(flags);
		case RDS_TYPE_8:
			return RDS_GET_HEADER(8, s)->size;
		case RDS_TYPE_16:
			return RDS_GET_HEADER(16, s)->size;
		case RDS_TYPE_32:
			return RDS_GET_HEADER(32, s)->size;
		case RDS_TYPE_64:
			return RDS_GET_HEADER(64, s)->size;
	}

	return 0;
}

rds 
rds_new_len(const void *s, size_t len)
{
	rds ret;
	void *alloc;
	size_t header_size;
	unsigned char type, *fp;

	type = rds_get_recommended_header_type(len);
	header_size = rds_get_header_size(type);

	alloc = malloc(header_size + len + 1);
	if (!alloc) return NULL; // might very well happen with rds_type64, I define that as the user's problem

	ret = (char *)alloc + header_size;
	fp = (unsigned char *)ret - 1; /* flags pointer */

	switch (type) 
	{
		case RDS_TYPE_5: 
		{
			*fp = (len << RDS_TYPE_BITS) | type;
			break;
		}
		case RDS_TYPE_8: 
		{
			struct rds_header8 *hdr = (struct rds_header8 *)alloc;
			hdr->size = len;
			hdr->allocated = len;
			*fp = type;
			break;
		}
		case RDS_TYPE_16: 
		{
			struct rds_header16 *hdr = (struct rds_header16 *)alloc;
			hdr->size = len;
			hdr->allocated = len;
			*fp = type;
			break;
		}
		case RDS_TYPE_32:
		{
			struct rds_header32 *hdr = (struct rds_header32 *)alloc;
			hdr->size = len;
			hdr->allocated = len;
			*fp = type;
			break;
		}
		case RDS_TYPE_64:
		{
			struct rds_header64 *hdr = (struct rds_header64 *)alloc;
			hdr->size = len;
			hdr->allocated = len;
			*fp = type;
			break;
		}
	}

	/* actually put the string in allocated space */
	if (s && len) 
	{
		memcpy(ret, s, len);	
	}
	else if (!s) // input len can be 0
	{ /* accept the null/empty string, just memset */
		memset(alloc, 0, header_size + len + 1);
	}

	ret[len] = 0;
	return ret;
}

rds 
rds_init(void)
{
	return rds_new_len("", 0);	
}

rds 
rds_new(const char *s)
{
	size_t size = (!s) ? 0 : strlen(s);
	return rds_new_len(s, size);	
}

void
rds_del(rds s)
{
	if (s == NULL) return;

	free((char *)(s - rds_get_header_size(s[-1])));
	s = NULL;
}

static size_t
rds_get_available_memory(const rds s)
{
	if (s == NULL) return 0;

	unsigned char flags = s[-1];

	switch (flags & RDS_TYPE_MASK) 
	{
		case RDS_TYPE_5:
		{
			return 0;
		}
		case RDS_TYPE_8:
		{
			RDS_GET_HEADER_VAR(8, s);
			return hdr->allocated - hdr->size;
		}
		case RDS_TYPE_16:
		{
			RDS_GET_HEADER_VAR(16, s);
			return hdr->allocated - hdr->size;
		}
		case RDS_TYPE_32:
		{
			RDS_GET_HEADER_VAR(32, s);
			return hdr->allocated - hdr->size;
		}
		case RDS_TYPE_64:
		{
			RDS_GET_HEADER_VAR(64, s);
			return hdr->allocated - hdr->size;
		}
	}

	return 0;
}

static void
rds_set_len(rds s, size_t len)
{
	if (s == NULL) return;

	unsigned char flags = s[-1];

	switch (flags & RDS_TYPE_MASK) 
	{
		case RDS_TYPE_5:
		{
			unsigned char *fp = (unsigned char *)s - 1;
			*fp = RDS_TYPE_5 | (len << RDS_TYPE_BITS);
			break;
		}
		case RDS_TYPE_8:
		{
			RDS_GET_HEADER(8, s)->size = len;
			break;
		}
		case RDS_TYPE_16:
		{
			RDS_GET_HEADER(16, s)->size = len;
			break;
		}
		case RDS_TYPE_32:
		{
			RDS_GET_HEADER(32, s)->size = len;
			break;
		}
		case RDS_TYPE_64:
		{
			RDS_GET_HEADER(64, s)->size = len;
			break;
		}
	}
}

static void
rds_set_allocated(rds s, size_t allocated)
{
	if (s == NULL) return;

	unsigned char flags = s[-1];

	switch (flags & RDS_TYPE_MASK) 
	{
		case RDS_TYPE_5:
		{
			break;
		}
		case RDS_TYPE_8:
		{
			RDS_GET_HEADER(8, s)->allocated = allocated;
			break;
		}
		case RDS_TYPE_16:
		{
			RDS_GET_HEADER(16, s)->allocated = allocated;
			break;
		}
		case RDS_TYPE_32:
		{
			RDS_GET_HEADER(32, s)->allocated = allocated;
			break;
		}
		case RDS_TYPE_64:
		{
			RDS_GET_HEADER(64, s)->allocated = allocated;
			break;
		}
	}
}
/* NOTE: grown memory is uninitialized 
 * increase 's' by length 'add_len' */
static rds
rds_grow(rds s, size_t add_len)
{
	size_t available, curr_len, new_len, min_len, hdr_len;
	unsigned char old_type, new_type;
	void *tmp;

	if (s == NULL) return NULL;

	old_type = s[-1] & RDS_TYPE_MASK;
	available = rds_get_available_memory(s); // that's already been allocated
	if (available >= add_len) return s; // don't need to grow

	curr_len = rds_strlen(s);

	/* minimum length required (new_len will be used in array growth algorithm) */
	min_len = new_len = (curr_len + add_len); 

	/* classic array grow algorithm, linear increase */
	if (new_len < RDS_MAX_PREALLOC) {
		new_len *= 2;
	} else {
		new_len += RDS_MAX_PREALLOC;
	}

	/* header stuff before allocation */
	new_type = rds_get_recommended_header_type(new_len);
	/* don't use type 5, since it has no 'allocated' variable it cannot remember available space so rds_grow would get called each append call */
	if (new_type == RDS_TYPE_5) 
		new_type = RDS_TYPE_8;
		
	hdr_len = rds_get_header_size(new_type);
	assert(hdr_len + new_len + 1 > min_len); // technically the size_t could overflow
	if (new_type != old_type) 
	{
		/* header size is going to change, so can't use realloc since buffer pointer must move forward 
		 * (freeing with pointer to beginning of header frees entire string) */
		tmp = malloc(hdr_len + new_len + 1);
		memcpy((char *)tmp + hdr_len, s, curr_len + 1);
		rds_del(s); // free s, a is now NULL

		s = (char *)tmp + hdr_len;
		s[-1] = new_type;
		rds_set_len(s, curr_len); /* NOTE: haven't copied a new string over so 's''s length is still the same, just allocated will change */
	}
	else 
	{
		// just use realloc
		tmp = realloc((char *)s - hdr_len, new_len);
		if (tmp == NULL) return NULL;
		s = (char *)tmp + hdr_len;
	}

	rds_set_allocated(s, new_len);	
	return s;
}

void
rds_append_len(rds *_a, const void *b, size_t b_len)
{
	if (_a == NULL) return;
	rds a = *_a;

	if (a == NULL || b == NULL) return;
	size_t a_len = rds_strlen(a);
	a = rds_grow(a, a_len + b_len);
	if (a == NULL) return; // realloc (if it occurred, may fail)


	memcpy(a + a_len, b, b_len);
	rds_set_len(a, a_len + b_len);
	a[a_len + b_len] = 0;

	*_a = a;
}

void
rds_append(rds *a, const rds b)
{
	rds_append_len(a, b, rds_strlen(b));	
}

void
rds_append_str(rds *a, const char *b)
{
	rds_append_len(a, b, strlen(b));	
}

