#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <rds.h>
#include <string.h>
#include <stdlib.h>

static void 
rds_init_should_create_empty(void **state)
{
	(void)state;

	rds s = rds_init();

	assert_string_equal(s, "\0");
	rds_del(s);
}

static void
rds_get_header_size_should_get_type5(void **state)
{
	(void)state;	
	unsigned char flags = RDS_TYPE_5;

	size_t hdr_sz = rds_get_header_size(flags);

	assert_int_equal(hdr_sz, sizeof(struct rds_header5));
}

static void
rds_get_header_size_should_get_type8(void **state)
{
	(void)state;	
	unsigned char flags = RDS_TYPE_8;

	size_t hdr_sz = rds_get_header_size(flags);

	assert_int_equal(hdr_sz, sizeof(struct rds_header8));
}

static void
rds_get_header_size_should_get_type16(void **state)
{
	(void)state;	
	unsigned char flags = RDS_TYPE_16;

	size_t hdr_sz = rds_get_header_size(flags);

	assert_int_equal(hdr_sz, sizeof(struct rds_header16));
}

static void
rds_get_header_size_should_get_type32(void **state)
{
	(void)state;	
	unsigned char flags = RDS_TYPE_32;

	size_t hdr_sz = rds_get_header_size(flags);

	assert_int_equal(hdr_sz, sizeof(struct rds_header32));
}

static void
rds_get_header_size_should_get_type64(void **state)
{
	(void)state;	
	unsigned char flags = RDS_TYPE_64;

	size_t hdr_sz = rds_get_header_size(flags);

	assert_int_equal(hdr_sz, sizeof(struct rds_header64));
}

static void
rds_new_len_should_create_type5(void **state)
{
	(void)state;
	size_t len_expected = (1 << 5) - 1;
	char cstr[len_expected];
	memset(cstr, 0, len_expected);

	rds s = rds_new_len(cstr, len_expected);
	size_t len = rds_strlen(s);

	assert_int_equal(len, len_expected);
	rds_del(s);
}

static void
rds_new_len_should_create_type8(void **state)
{
	(void)state;
	size_t len_expected = (1 << 8) - 1;
	char cstr[len_expected]; // byte-safe so this should just work
	memset(cstr, 0, len_expected);

	rds s = rds_new_len(cstr, len_expected);
	size_t len = rds_strlen(s);

	assert_int_equal(len, len_expected);
	rds_del(s);
}

static void
rds_new_len_should_create_type16(void **state)
{
	(void)state;
	size_t len_expected = (1 << 16) - 1;
	char *cstr = malloc(len_expected * sizeof(char)); // byte-safe so this should just work
	memset(cstr, 0, len_expected);

	rds s = rds_new_len(cstr, len_expected);
	size_t len = rds_strlen(s);

	assert_int_equal(len, len_expected);
	free(cstr);
	rds_del(s);
}

#ifdef TEST_LARGE

static void
rds_new_len_should_create_type32(void **state)
{
	(void)state;
	size_t len_expected = (1ULL << 32) - 1;
	char *cstr = malloc(len_expected * sizeof(char)); // byte-safe so this should just work
	memset(cstr, 0, len_expected);

	rds s = rds_new_len(cstr, len_expected);
	size_t len = rds_strlen(s);

	assert_int_equal(len, len_expected);
	free(cstr);
	rds_del(s);
}

static void
rds_new_len_should_create_type64(void **state)
{
	(void)state;
	size_t len_expected = (1ULL << 32); // minimum size for a type64, fragile test but whatever, the API is stable
	char *cstr = malloc(len_expected * sizeof(char)); // byte-safe so this should just work
	memset(cstr, 0, len_expected);

	rds s = rds_new_len(cstr, len_expected);

	size_t len = rds_strlen(s);

	assert_int_equal(len, len_expected);
	free(cstr);
	rds_del(s);
}

#endif

static void 
rds_strlen_should_return_zero_when_zero(void **state)
{
	(void)state;
	rds s = rds_init();

	size_t len = rds_strlen(s);

	assert_int_equal(len, 0);
}

static void
rds_append_len_should_append_type5(void **state)
{
	(void)state;
	rds s = rds_init();
	size_t s_len = rds_strlen(s);
	size_t cstr_len = (1 << 5) - 1;
	char cstr[cstr_len];
	memset(cstr, 1, cstr_len);

	rds_append_len(&s, cstr, cstr_len);
	
	assert_int_equal(s_len + cstr_len, rds_strlen(s));
	assert_string_equal(s + s_len, cstr);
}

static void
rds_append_len_should_append_type8(void **state)
{
	(void)state;
	rds s = rds_init();
	size_t s_len = rds_strlen(s);
	size_t cstr_len = (1 << 8) - 1;
	char cstr[cstr_len];
	memset(cstr, 1, cstr_len);

	rds_append_len(&s, cstr, cstr_len);
	
	assert_int_equal(s_len + cstr_len, rds_strlen(s));
	assert_string_equal(s + s_len, cstr);
}

static void
rds_append_len_should_append_type16(void **state)
{
	(void)state;
	rds s = rds_init();
	size_t s_len = rds_strlen(s);
	size_t cstr_len = (1 << 16) - 1;
	char *cstr = malloc(cstr_len * sizeof(char)); 
	memset(cstr, 1, cstr_len);

	rds_append_len(&s, cstr, cstr_len);
	
	assert_int_equal(s_len + cstr_len, rds_strlen(s));
	assert_string_equal(s + s_len, cstr);
}

#ifdef TEST_LARGE

static void
rds_append_len_should_append_type32(void **state)
{
	(void)state;
	rds s = rds_init();
	size_t s_len = rds_strlen(s);
	size_t cstr_len = (1ULL << 32) - 1;
	char *cstr = malloc(cstr_len * sizeof(char)); 
	memset(cstr, 1, cstr_len);

	rds_append_len(&s, cstr, cstr_len);
	
	assert_int_equal(s_len + cstr_len, rds_strlen(s));
	assert_string_equal(s + s_len, cstr);
}

static void
rds_append_len_should_append_type64(void **state)
{
	(void)state;
	rds s = rds_init();
	size_t s_len = rds_strlen(s);
	size_t cstr_len = 1ULL << 32;
	char *cstr = malloc(cstr_len * sizeof(char)); 
	memset(cstr, 1, cstr_len);

	rds_append_len(&s, cstr, cstr_len);
	
	assert_int_equal(s_len + cstr_len, rds_strlen(s));
	assert_string_equal(s + s_len, cstr);
}

#endif

int
main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(rds_init_should_create_empty),
		cmocka_unit_test(rds_get_header_size_should_get_type5),
		cmocka_unit_test(rds_get_header_size_should_get_type8),
		cmocka_unit_test(rds_get_header_size_should_get_type16),
		cmocka_unit_test(rds_get_header_size_should_get_type32),
		cmocka_unit_test(rds_get_header_size_should_get_type64),
		cmocka_unit_test(rds_new_len_should_create_type5),
		cmocka_unit_test(rds_new_len_should_create_type8),
		cmocka_unit_test(rds_new_len_should_create_type16),
#ifdef TEST_LARGE
		cmocka_unit_test(rds_new_len_should_create_type32),
		cmocka_unit_test(rds_new_len_should_create_type64),
#endif
		cmocka_unit_test(rds_strlen_should_return_zero_when_zero),
		cmocka_unit_test(rds_append_len_should_append_type5),
		cmocka_unit_test(rds_append_len_should_append_type8),
		cmocka_unit_test(rds_append_len_should_append_type16),
#ifdef TEST_LARGE
		cmocka_unit_test(rds_append_len_should_append_type32),
		//cmocka_unit_test(rds_append_len_should_append_type64), // uncomment if you want to run it, will munch all of your memory
#endif
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
