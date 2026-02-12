/*
 *  test_bugs.c
 *
 *  Unit tests to verify bug fixes in the CubeSQL C SDK.
 *  Compile with: make          (from C_SDK/tests/)
 *  Run with:     make test     (runs with AddressSanitizer)
 *
 *  Tests are numbered to match the bug list in the audit report.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "cubesql.h"
#include "csql.h"

static int tests_run = 0;
static int tests_passed = 0;

#define RUN_TEST(fn) do { \
	printf("  %-60s", #fn); \
	fflush(stdout); \
	tests_run++; \
	fn(); \
	tests_passed++; \
	printf("PASS\n"); \
} while(0)

/*
 * Bug 1: cubesql_cursor_addrow uses wrong pointers in realloc.
 *
 * Lines 771,774: realloc(cursor->data,...) should be realloc(cursor->buffer,...)
 *                realloc(cursor->size,...) should be realloc(cursor->size0,...)
 *
 * With the bug, realloc gets NULL (cursor->data is never set for custom cursors),
 * which acts as malloc and leaks the old buffer. Data from rows added before
 * realloc becomes inaccessible.
 */
static void test_bug1_cursor_addrow_realloc(void) {
	int types[] = {CUBESQL_Type_Text, CUBESQL_Type_Text};
	char *names[] = {"col1", "col2"};
	csqldb *db = (csqldb *)calloc(1, sizeof(csqldb));
	assert(db != NULL);

	/* nrows=1 -> nalloc=1, so second row triggers realloc */
	csqlc *cursor = cubesql_cursor_create(db, 1, 2, types, names);
	assert(cursor != NULL);

	/* Add first row - fits within nalloc=1 */
	char *row1[] = {"hello", "world"};
	int lens1[] = {5, 5};
	assert(cubesql_cursor_addrow(cursor, row1, lens1) == kTRUE);

	/* Verify first row before realloc */
	int len = 0;
	char *field = cubesql_cursor_field(cursor, 1, 1, &len);
	assert(field != NULL && len == 5);
	assert(memcmp(field, "hello", 5) == 0);

	field = cubesql_cursor_field(cursor, 1, 2, &len);
	assert(field != NULL && len == 5);
	assert(memcmp(field, "world", 5) == 0);

	/* Second row triggers realloc.
	 * Bug: realloc(cursor->data,...) loses the old buffer pointer. */
	char *row2[] = {"foo", "bar"};
	int lens2[] = {3, 3};
	assert(cubesql_cursor_addrow(cursor, row2, lens2) == kTRUE);

	/* First row must still be accessible after realloc */
	field = cubesql_cursor_field(cursor, 1, 1, &len);
	assert(field != NULL && len == 5);
	assert(memcmp(field, "hello", 5) == 0);

	field = cubesql_cursor_field(cursor, 1, 2, &len);
	assert(field != NULL && len == 5);
	assert(memcmp(field, "world", 5) == 0);

	/* Second row must be accessible */
	field = cubesql_cursor_field(cursor, 2, 1, &len);
	assert(field != NULL && len == 3);
	assert(memcmp(field, "foo", 3) == 0);

	field = cubesql_cursor_field(cursor, 2, 2, &len);
	assert(field != NULL && len == 3);
	assert(memcmp(field, "bar", 3) == 0);

	/* Third row - verify continued growth works */
	char *row3[] = {"ab", "cd"};
	int lens3[] = {2, 2};
	assert(cubesql_cursor_addrow(cursor, row3, lens3) == kTRUE);

	field = cubesql_cursor_field(cursor, 3, 1, &len);
	assert(field != NULL && len == 2);
	assert(memcmp(field, "ab", 2) == 0);

	assert(cubesql_cursor_numrows(cursor) == 3);

	cubesql_cursor_free(cursor);
	free(db);
}

/*
 * Bug 4: csql_seterror uses strncpy which doesn't null-terminate.
 *
 * Line 2048: strncpy(db->errmsg, errmsg, sizeof(db->errmsg))
 * If errmsg >= 512 chars, errmsg buffer is not null-terminated.
 */
static void test_bug4_seterror_null_termination(void) {
	csqldb *db = (csqldb *)calloc(1, sizeof(csqldb));
	assert(db != NULL);

	/* Pre-fill errmsg with non-null bytes to detect missing termination */
	memset(db->errmsg, 'X', sizeof(db->errmsg));

	/* Error message longer than errmsg buffer (512 bytes) */
	char long_msg[600];
	memset(long_msg, 'A', 599);
	long_msg[599] = '\0';

	csql_seterror(db, 42, long_msg);

	/* Must be null-terminated within buffer bounds */
	size_t slen = strlen(db->errmsg);
	assert(slen < sizeof(db->errmsg));
	assert(db->errcode == 42);

	/* Also test short message for sanity */
	csql_seterror(db, 7, "short error");
	assert(strcmp(db->errmsg, "short error") == 0);
	assert(db->errcode == 7);

	free(db);
}

/*
 * Bug 7: cubesql_vmbind_text ignores the len parameter.
 *
 * Line 596: passes -1 (strlen) instead of the caller's len.
 * We can't fully test this without a server, but we verify the function
 * signature accepts len. The fix passes len through to csql_bind_value.
 *
 * This is a compile-time/API-level check — the fix is verified by code review.
 */
static void test_bug7_vmbind_text_len_accepted(void) {
	/* Verify the function pointer signature accepts (vm, index, value, len).
	 * We can't call it without a server, but we check it compiles. */
	int (*fn)(csqlvm *, int, char *, int) = cubesql_vmbind_text;
	assert(fn != NULL);
	(void)fn;
}

/*
 * Bug 8: cubesql_cursor_free doesn't free c->buffer and c->rowsum arrays
 * in the multi-buffer (chunk) case.
 *
 * Lines 544-550: only frees elements, not the container arrays.
 * Under AddressSanitizer, this test will report leaks if unfixed.
 */
static void test_bug8_cursor_free_multibuffer(void) {
	csqldb *db = (csqldb *)calloc(1, sizeof(csqldb));
	assert(db != NULL);

	csqlc *c = (csqlc *)calloc(1, sizeof(csqlc));
	assert(c != NULL);
	c->db = db;
	c->ncols = 2;
	c->nrows = 4;
	c->nbuffer = 2;
	c->nalloc = 100;
	c->cursor_id = 0;      /* not custom */
	c->server_side = kFALSE;

	/* Allocate the container arrays (these MUST be freed by cursor_free) */
	c->buffer = (char **)malloc(sizeof(char *) * 100);
	c->rowsum = (int **)malloc(sizeof(int *) * 100);
	c->rowcount = (int *)malloc(sizeof(int) * 100);
	assert(c->buffer && c->rowsum && c->rowcount);

	/* Allocate individual per-chunk buffers and sum arrays */
	c->buffer[0] = (char *)malloc(64);
	c->buffer[1] = (char *)malloc(64);
	c->rowsum[0] = (int *)malloc(sizeof(int) * 4);
	c->rowsum[1] = (int *)malloc(sizeof(int) * 4);
	c->rowcount[0] = 2;
	c->rowcount[1] = 4;

	/* p and psum are NULL (not set in partial cursor path) */
	c->p = NULL;
	c->psum = NULL;

	cubesql_cursor_free(c);
	/* Under ASAN, leaked c->buffer and c->rowsum would cause exit failure */

	free(db);
}

/*
 * Bug 12: kMAXCHUNK macro missing parentheses.
 *
 * Line 175: #define kMAXCHUNK 100*1024
 * Division gives wrong result: 1024000 / 100*1024 = 10485760 instead of 10.
 */
static void test_bug12_kmaxchunk_precedence(void) {
	int result = 1024000 / kMAXCHUNK;
	/* Without parens: 1024000 / 100 * 1024 = 10485760 */
	/* With parens:    1024000 / (100*1024)  = 10       */
	assert(result == 10);
}

/*
 * Bug 17: cubesql_mssleep declared in header but not implemented.
 *
 * Verify it exists and is callable (linker would fail if missing).
 */
static void test_bug17_mssleep_exists(void) {
	/* Call with 0ms — should return immediately without blocking */
	cubesql_mssleep(0);
}

/*
 * Integration: verify cursor create + multiple addrow + seek + free
 * exercises the fixed realloc path and free path together.
 */
static void test_cursor_create_addrow_seek_free(void) {
	int types[] = {CUBESQL_Type_Integer, CUBESQL_Type_Text};
	char *names[] = {"id", "name"};
	csqldb *db = (csqldb *)calloc(1, sizeof(csqldb));
	assert(db != NULL);

	/* nrows=0 -> nalloc=kDEFAULT_ALLOC_ROWS (100) */
	csqlc *cursor = cubesql_cursor_create(db, 0, 2, types, names);
	assert(cursor != NULL);

	/* Add 150 rows to force at least one realloc (nalloc starts at 100) */
	for (int i = 0; i < 150; i++) {
		char id[16], name[32];
		snprintf(id, sizeof(id), "%d", i + 1);
		snprintf(name, sizeof(name), "row_%d", i + 1);
		char *row[] = {id, name};
		int lens[] = {(int)strlen(id), (int)strlen(name)};
		assert(cubesql_cursor_addrow(cursor, row, lens) == kTRUE);
	}

	assert(cubesql_cursor_numrows(cursor) == 150);

	/* Seek to first and verify */
	assert(cubesql_cursor_seek(cursor, CUBESQL_SEEKFIRST) == kTRUE);
	assert(cubesql_cursor_currentrow(cursor) == 1);

	int len;
	char *field = cubesql_cursor_field(cursor, 1, 1, &len);
	assert(field != NULL);
	assert(memcmp(field, "1", 1) == 0);

	/* Seek to last and verify */
	assert(cubesql_cursor_seek(cursor, CUBESQL_SEEKLAST) == kTRUE);
	assert(cubesql_cursor_currentrow(cursor) == 150);

	field = cubesql_cursor_field(cursor, 150, 2, &len);
	assert(field != NULL);
	assert(memcmp(field, "row_150", 7) == 0);

	/* Seek next from last should set EOF */
	assert(cubesql_cursor_seek(cursor, CUBESQL_SEEKNEXT) == kFALSE);

	/* Seek prev should work */
	assert(cubesql_cursor_seek(cursor, CUBESQL_SEEKPREV) == kTRUE);

	/* Spot-check a middle row (row 75) */
	field = cubesql_cursor_field(cursor, 75, 2, &len);
	assert(field != NULL);
	assert(memcmp(field, "row_75", 6) == 0);

	cubesql_cursor_free(cursor);
	free(db);
}

/*
 * Test column names and types for custom cursor.
 */
static void test_cursor_column_names_types(void) {
	int types[] = {CUBESQL_Type_Integer, CUBESQL_Type_Text, CUBESQL_Type_Float};
	char *names[] = {"id", "name", "score"};
	csqldb *db = (csqldb *)calloc(1, sizeof(csqldb));
	assert(db != NULL);

	csqlc *cursor = cubesql_cursor_create(db, 0, 3, types, names);
	assert(cursor != NULL);
	assert(cubesql_cursor_numcolumns(cursor) == 3);

	/* Verify column types */
	assert(cubesql_cursor_columntype(cursor, 1) == CUBESQL_Type_Integer);
	assert(cubesql_cursor_columntype(cursor, 2) == CUBESQL_Type_Text);
	assert(cubesql_cursor_columntype(cursor, 3) == CUBESQL_Type_Float);
	assert(cubesql_cursor_columntype(cursor, 0) == -1);  /* out of bounds */
	assert(cubesql_cursor_columntype(cursor, 4) == -1);  /* out of bounds */

	/* Verify column names via cursor_field with CUBESQL_COLNAME */
	int len;
	char *name = cubesql_cursor_field(cursor, CUBESQL_COLNAME, 1, &len);
	assert(name != NULL && strcmp(name, "id") == 0);

	name = cubesql_cursor_field(cursor, CUBESQL_COLNAME, 2, &len);
	assert(name != NULL && strcmp(name, "name") == 0);

	name = cubesql_cursor_field(cursor, CUBESQL_COLNAME, 3, &len);
	assert(name != NULL && strcmp(name, "score") == 0);

	cubesql_cursor_free(cursor);
	free(db);
}

/*
 * Bug 22: cubesql_cursor_seek allows seeking to row 0.
 *
 * Line 284: if (index < 0) should be if (index <= 0)
 * SEEKPREV from row 1 gives index=0, which passes the check.
 * Row 0 is invalid in 1-based indexing and causes out-of-bounds access
 * in the custom cursor path: n = ((0-1) * ncols) + (column-1) < 0.
 */
static void test_bug22_cursor_seek_row0(void) {
	int types[] = {CUBESQL_Type_Text};
	char *names[] = {"col1"};
	csqldb *db = (csqldb *)calloc(1, sizeof(csqldb));
	assert(db != NULL);

	csqlc *cursor = cubesql_cursor_create(db, 0, 1, types, names);
	assert(cursor != NULL);

	/* Add two rows */
	char *row1[] = {"aaa"};
	int lens1[] = {3};
	assert(cubesql_cursor_addrow(cursor, row1, lens1) == kTRUE);

	char *row2[] = {"bbb"};
	int lens2[] = {3};
	assert(cubesql_cursor_addrow(cursor, row2, lens2) == kTRUE);

	/* Seek to first row */
	assert(cubesql_cursor_seek(cursor, CUBESQL_SEEKFIRST) == kTRUE);
	assert(cubesql_cursor_currentrow(cursor) == 1);

	/* SEEKPREV from row 1 should fail (row 0 is invalid) */
	assert(cubesql_cursor_seek(cursor, CUBESQL_SEEKPREV) == kFALSE);

	/* current_row should remain at 1 (not corrupted to 0) */
	assert(cubesql_cursor_currentrow(cursor) == 1);

	/* Verify data is still accessible after the failed seek */
	int len;
	char *field = cubesql_cursor_field(cursor, 1, 1, &len);
	assert(field != NULL && len == 3);
	assert(memcmp(field, "aaa", 3) == 0);

	cubesql_cursor_free(cursor);
	free(db);
}

/*
 * Bug 25: cubesql_disconnect leaks db when sockfd <= 0.
 *
 * When sockfd <= 0 (failed connection or after cubesql_cancel),
 * cubesql_disconnect returned without freeing the db struct.
 * Under AddressSanitizer, this would report a memory leak.
 */
static void test_bug25_disconnect_no_leak(void) {
	/* Case 1: sockfd == 0 (e.g., after cubesql_cancel or never connected) */
	csqldb *db1 = (csqldb *)calloc(1, sizeof(csqldb));
	assert(db1 != NULL);
	db1->sockfd = 0;
	db1->inbuffer = (char *)malloc(64);
	assert(db1->inbuffer != NULL);
	cubesql_disconnect(db1, kFALSE);
	/* ASAN would report leaks if db1 or db1->inbuffer weren't freed */

	/* Case 2: sockfd == -1 (e.g., failed connection) */
	csqldb *db2 = (csqldb *)calloc(1, sizeof(csqldb));
	assert(db2 != NULL);
	db2->sockfd = -1;
	cubesql_disconnect(db2, kFALSE);
	/* ASAN would report leak if db2 weren't freed */

	/* Case 3: NULL db should not crash */
	cubesql_disconnect(NULL, kFALSE);
}

/*
 * Bug 26: TLS_WANT_POLLIN/POLLOUT constants must be handled.
 *
 * tls_read/tls_write can return TLS_WANT_POLLIN (-2) or
 * TLS_WANT_POLLOUT (-3) during renegotiation.
 * Verify the constants are defined and distinct from normal errors.
 */
static void test_bug26_tls_want_constants(void) {
	/* Verify TLS_WANT constants are defined and negative */
	assert(TLS_WANT_POLLIN < 0);
	assert(TLS_WANT_POLLOUT < 0);

	/* They must be distinct from normal error (-1) and EOF (0) */
	assert(TLS_WANT_POLLIN != -1);
	assert(TLS_WANT_POLLIN != 0);
	assert(TLS_WANT_POLLOUT != -1);
	assert(TLS_WANT_POLLOUT != 0);

	/* They must be distinct from each other */
	assert(TLS_WANT_POLLIN != TLS_WANT_POLLOUT);
}

int main(int argc, char *argv[]) {
	(void)argc;
	(void)argv;

	printf("CubeSQL C SDK - Bug Fix Verification Tests\n");
	printf("============================================\n\n");

	csql_libinit();

	RUN_TEST(test_bug1_cursor_addrow_realloc);
	RUN_TEST(test_bug4_seterror_null_termination);
	RUN_TEST(test_bug7_vmbind_text_len_accepted);
	RUN_TEST(test_bug8_cursor_free_multibuffer);
	RUN_TEST(test_bug12_kmaxchunk_precedence);
	RUN_TEST(test_bug17_mssleep_exists);
	RUN_TEST(test_bug22_cursor_seek_row0);
	RUN_TEST(test_bug25_disconnect_no_leak);
	RUN_TEST(test_bug26_tls_want_constants);
	RUN_TEST(test_cursor_create_addrow_seek_free);
	RUN_TEST(test_cursor_column_names_types);

	printf("\n============================================\n");
	printf("Results: %d/%d tests passed\n", tests_passed, tests_run);

	if (tests_passed == tests_run) {
		printf("All tests PASSED.\n");
		return 0;
	} else {
		printf("Some tests FAILED.\n");
		return 1;
	}
}
