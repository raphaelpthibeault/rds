#include <rds.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define RDS_TYPE_5_GET_LEN(f) ((f) >> RDS_TYPE_BITS) /* recall form 0bxxxxx000, 000 being type */
#define RDS_GET_HEADER(t, s) ((struct rds_header##t *)((s) - (sizeof(struct rds_header##t)))) /* recall pointer s is at beginning of buf */

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
	if (s == NULL) 
	{
		return 0;		
	}

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
	if (!alloc) // might very well happen with rds_type64, I define that as the user's problem
	{
		return NULL;
	}

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

