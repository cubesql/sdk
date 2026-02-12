/*
 *  test_integration.c
 *
 *  Integration tests for the CubeSQL C SDK against a running server.
 *  Requires a CubeSQL server on localhost:4430 with admin/admin credentials.
 *
 *  Build:  make -f Makefile.integration
 *  Run:    ./test_integration
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "cubesql.h"
#include "csql.h"

// Server connection defaults
#define TEST_HOST       "localhost"
#define TEST_PORT       4430
#define TEST_USER       "admin"
#define TEST_PASS       "admin"
#define TEST_TIMEOUT    12
#define TEST_DB         "integration_test.db"

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define RUN_TEST(fn) do { \
	printf("  %-60s", #fn); \
	fflush(stdout); \
	tests_run++; \
	if (fn()) { \
		tests_passed++; \
		printf("PASS\n"); \
	} else { \
		tests_failed++; \
		printf("FAIL\n"); \
	} \
} while(0)

// Helper: connect to server, returns NULL on failure
static csqldb *test_connect(void) {
	csqldb *db = NULL;
	int err = cubesql_connect(&db, TEST_HOST, TEST_PORT, TEST_USER, TEST_PASS,
	                          TEST_TIMEOUT, CUBESQL_ENCRYPTION_NONE);
	if (err != CUBESQL_NOERR) {
		fprintf(stderr, "    connect failed: %d\n", err);
		return NULL;
	}
	return db;
}

// Helper: connect and select a test database (creates it if needed)
static csqldb *test_connect_with_db(void) {
	csqldb *db = test_connect();
	if (!db) return NULL;
	// Create the test database if it doesn't exist (CubeSQL custom command)
	cubesql_execute(db, "CREATE DATABASE " TEST_DB " IF NOT EXISTS;");
	int err = cubesql_set_database(db, TEST_DB);
	if (err != CUBESQL_NOERR) {
		fprintf(stderr, "    set_database failed: %s\n", cubesql_errmsg(db));
		cubesql_disconnect(db, kTRUE);
		return NULL;
	}
	// Ensure no implicit transaction is active
	cubesql_execute(db, "END;");
	cubesql_clear_errors(db);
	return db;
}

// ---------------------------------------------------------------------------
// Test 1: Basic connect and disconnect
// ---------------------------------------------------------------------------
static int test_connect_disconnect(void) {
	csqldb *db = test_connect();
	if (!db) return 0;
	cubesql_disconnect(db, kTRUE);
	return 1;
}

// ---------------------------------------------------------------------------
// Test 2: Connect with AES256 encryption
// ---------------------------------------------------------------------------
static int test_connect_aes256(void) {
	csqldb *db = NULL;
	int err = cubesql_connect(&db, TEST_HOST, TEST_PORT, TEST_USER, TEST_PASS,
	                          TEST_TIMEOUT, CUBESQL_ENCRYPTION_AES256);
	if (err != CUBESQL_NOERR) {
		fprintf(stderr, "    AES256 connect failed: %d\n", err);
		return 0;
	}
	cubesql_disconnect(db, kTRUE);
	return 1;
}

// ---------------------------------------------------------------------------
// Test 3: Ping
// ---------------------------------------------------------------------------
static int test_ping(void) {
	csqldb *db = test_connect();
	if (!db) return 0;

	int err = cubesql_ping(db);
	if (err != CUBESQL_NOERR) {
		fprintf(stderr, "    ping failed: %s\n", cubesql_errmsg(db));
		cubesql_disconnect(db, kTRUE);
		return 0;
	}

	cubesql_disconnect(db, kTRUE);
	return 1;
}

// ---------------------------------------------------------------------------
// Test 4: Set database and execute CREATE/INSERT/SELECT
// ---------------------------------------------------------------------------
static int test_execute_and_select(void) {
	csqldb *db = test_connect_with_db();
	if (!db) return 0;
	int ok = 0;

	// Create table
	cubesql_execute(db, "DROP TABLE IF EXISTS test_basic;");
	int err = cubesql_execute(db, "CREATE TABLE test_basic (id INTEGER PRIMARY KEY, name TEXT, value REAL);");
	if (err != CUBESQL_NOERR) {
		fprintf(stderr, "    CREATE TABLE failed: %s\n", cubesql_errmsg(db));
		goto done;
	}

	// Insert rows
	err = cubesql_execute(db, "INSERT INTO test_basic VALUES (1, 'alpha', 1.1);");
	if (err != CUBESQL_NOERR) { fprintf(stderr, "    INSERT failed: %s\n", cubesql_errmsg(db)); goto done; }

	err = cubesql_execute(db, "INSERT INTO test_basic VALUES (2, 'beta', 2.2);");
	if (err != CUBESQL_NOERR) { fprintf(stderr, "    INSERT failed: %s\n", cubesql_errmsg(db)); goto done; }

	err = cubesql_execute(db, "INSERT INTO test_basic VALUES (3, 'gamma', 3.3);");
	if (err != CUBESQL_NOERR) { fprintf(stderr, "    INSERT failed: %s\n", cubesql_errmsg(db)); goto done; }

	// SELECT
	csqlc *cursor = cubesql_select(db, "SELECT * FROM test_basic ORDER BY id;", kFALSE);
	if (!cursor) { fprintf(stderr, "    SELECT failed: %s\n", cubesql_errmsg(db)); goto done; }

	if (cubesql_cursor_numrows(cursor) != 3) {
		fprintf(stderr, "    expected 3 rows, got %d\n", cubesql_cursor_numrows(cursor));
		cubesql_cursor_free(cursor);
		goto done;
	}
	if (cubesql_cursor_numcolumns(cursor) != 3) {
		fprintf(stderr, "    expected 3 columns, got %d\n", cubesql_cursor_numcolumns(cursor));
		cubesql_cursor_free(cursor);
		goto done;
	}

	// Check column names
	int len;
	char *colname = cubesql_cursor_field(cursor, CUBESQL_COLNAME, 1, &len);
	if (!colname || strcmp(colname, "id") != 0) {
		fprintf(stderr, "    expected column name 'id', got '%s'\n", colname ? colname : "NULL");
		cubesql_cursor_free(cursor);
		goto done;
	}

	// Check data: row 1, column 2 should be "alpha"
	char *val = cubesql_cursor_cstring(cursor, 1, 2);
	if (!val || strcmp(val, "alpha") != 0) {
		fprintf(stderr, "    expected 'alpha', got '%s'\n", val ? val : "NULL");
		cubesql_cursor_free(cursor);
		goto done;
	}

	// Check data: row 3, column 2 should be "gamma"
	val = cubesql_cursor_cstring(cursor, 3, 2);
	if (!val || strcmp(val, "gamma") != 0) {
		fprintf(stderr, "    expected 'gamma', got '%s'\n", val ? val : "NULL");
		cubesql_cursor_free(cursor);
		goto done;
	}

	// Check int accessor
	int id = cubesql_cursor_int(cursor, 2, 1, -1);
	if (id != 2) {
		fprintf(stderr, "    expected id=2, got %d\n", id);
		cubesql_cursor_free(cursor);
		goto done;
	}

	// Check double accessor
	double dval = cubesql_cursor_double(cursor, 2, 3, 0.0);
	if (dval < 2.1 || dval > 2.3) {
		fprintf(stderr, "    expected ~2.2, got %f\n", dval);
		cubesql_cursor_free(cursor);
		goto done;
	}

	cubesql_cursor_free(cursor);
	ok = 1;

done:
	cubesql_execute(db, "DROP TABLE IF EXISTS test_basic;");
	cubesql_disconnect(db, kTRUE);
	return ok;
}

// ---------------------------------------------------------------------------
// Test 5: cubesql_changes and cubesql_affected_rows
// ---------------------------------------------------------------------------
static int test_changes(void) {
	csqldb *db = test_connect_with_db();
	if (!db) return 0;
	int ok = 0;

	cubesql_execute(db, "DROP TABLE IF EXISTS test_changes;");
	cubesql_execute(db, "CREATE TABLE test_changes (id INTEGER PRIMARY KEY, val TEXT);");
	cubesql_execute(db, "INSERT INTO test_changes VALUES (1, 'a');");
	cubesql_execute(db, "INSERT INTO test_changes VALUES (2, 'b');");
	cubesql_execute(db, "INSERT INTO test_changes VALUES (3, 'c');");

	// Update 2 rows
	cubesql_execute(db, "UPDATE test_changes SET val = 'x' WHERE id >= 2;");
	int64 changes = cubesql_changes(db);
	if (changes != 2) {
		fprintf(stderr, "    expected changes=2, got %lld\n", (long long)changes);
		goto done;
	}

	// Delete 1 row
	cubesql_execute(db, "DELETE FROM test_changes WHERE id = 1;");
	int64 affected = cubesql_affected_rows(db);
	if (affected != 1) {
		fprintf(stderr, "    expected affected_rows=1, got %lld\n", (long long)affected);
		goto done;
	}

	ok = 1;
done:
	cubesql_execute(db, "DROP TABLE IF EXISTS test_changes;");
	cubesql_disconnect(db, kTRUE);
	return ok;
}

// ---------------------------------------------------------------------------
// Test 6: Cursor seek operations (FIRST, NEXT, PREV, LAST)
// ---------------------------------------------------------------------------
static int test_cursor_seek(void) {
	csqldb *db = test_connect_with_db();
	if (!db) return 0;
	int ok = 0;

	cubesql_execute(db, "DROP TABLE IF EXISTS test_seek;");
	cubesql_execute(db, "CREATE TABLE test_seek (id INTEGER);");
	for (int i = 1; i <= 5; i++) {
		char sql[64];
		snprintf(sql, sizeof(sql), "INSERT INTO test_seek VALUES (%d);", i);
		cubesql_execute(db, sql);
	}

	csqlc *c = cubesql_select(db, "SELECT id FROM test_seek ORDER BY id;", kFALSE);
	if (!c) { fprintf(stderr, "    SELECT failed: %s\n", cubesql_errmsg(db)); goto done; }

	// SEEKFIRST
	if (!cubesql_cursor_seek(c, CUBESQL_SEEKFIRST)) {
		fprintf(stderr, "    SEEKFIRST failed\n");
		cubesql_cursor_free(c); goto done;
	}
	if (cubesql_cursor_currentrow(c) != 1) {
		fprintf(stderr, "    after SEEKFIRST, row=%d (expected 1)\n", cubesql_cursor_currentrow(c));
		cubesql_cursor_free(c); goto done;
	}

	// SEEKNEXT
	if (!cubesql_cursor_seek(c, CUBESQL_SEEKNEXT)) {
		fprintf(stderr, "    SEEKNEXT failed\n");
		cubesql_cursor_free(c); goto done;
	}
	if (cubesql_cursor_currentrow(c) != 2) {
		fprintf(stderr, "    after SEEKNEXT, row=%d (expected 2)\n", cubesql_cursor_currentrow(c));
		cubesql_cursor_free(c); goto done;
	}

	// SEEKLAST
	if (!cubesql_cursor_seek(c, CUBESQL_SEEKLAST)) {
		fprintf(stderr, "    SEEKLAST failed\n");
		cubesql_cursor_free(c); goto done;
	}
	if (cubesql_cursor_currentrow(c) != 5) {
		fprintf(stderr, "    after SEEKLAST, row=%d (expected 5)\n", cubesql_cursor_currentrow(c));
		cubesql_cursor_free(c); goto done;
	}

	// SEEKPREV
	if (!cubesql_cursor_seek(c, CUBESQL_SEEKPREV)) {
		fprintf(stderr, "    SEEKPREV failed\n");
		cubesql_cursor_free(c); goto done;
	}
	if (cubesql_cursor_currentrow(c) != 4) {
		fprintf(stderr, "    after SEEKPREV, row=%d (expected 4)\n", cubesql_cursor_currentrow(c));
		cubesql_cursor_free(c); goto done;
	}

	// Bug 22: SEEKPREV from row 1 must NOT go to row 0
	cubesql_cursor_seek(c, CUBESQL_SEEKFIRST);
	if (cubesql_cursor_seek(c, CUBESQL_SEEKPREV) != kFALSE) {
		fprintf(stderr, "    SEEKPREV from row 1 should return kFALSE\n");
		cubesql_cursor_free(c); goto done;
	}
	if (cubesql_cursor_currentrow(c) != 1) {
		fprintf(stderr, "    after SEEKPREV from row 1, row=%d (expected 1)\n", cubesql_cursor_currentrow(c));
		cubesql_cursor_free(c); goto done;
	}

	// SEEKNEXT past last row should return kFALSE and set EOF
	cubesql_cursor_seek(c, CUBESQL_SEEKLAST);
	if (cubesql_cursor_seek(c, CUBESQL_SEEKNEXT) != kFALSE) {
		fprintf(stderr, "    SEEKNEXT from last row should return kFALSE\n");
		cubesql_cursor_free(c); goto done;
	}
	if (!cubesql_cursor_iseof(c)) {
		fprintf(stderr, "    expected EOF after SEEKNEXT past last row\n");
		cubesql_cursor_free(c); goto done;
	}

	cubesql_cursor_free(c);
	ok = 1;
done:
	cubesql_execute(db, "DROP TABLE IF EXISTS test_seek;");
	cubesql_disconnect(db, kTRUE);
	return ok;
}

// ---------------------------------------------------------------------------
// Test 7: Transactions (begin, commit, rollback)
// ---------------------------------------------------------------------------
static int test_transactions(void) {
	csqldb *db = test_connect_with_db();
	if (!db) return 0;
	int ok = 0;

	cubesql_execute(db, "DROP TABLE IF EXISTS test_txn;");
	cubesql_execute(db, "CREATE TABLE test_txn (id INTEGER, val TEXT);");

	// Insert a row, then verify it exists (baseline, no explicit transaction)
	cubesql_execute(db, "INSERT INTO test_txn VALUES (99, 'baseline');");
	csqlc *c = cubesql_select(db, "SELECT COUNT(*) FROM test_txn;", kFALSE);
	if (!c) { fprintf(stderr, "    SELECT baseline failed: %s\n", cubesql_errmsg(db)); goto done; }
	int baseline = cubesql_cursor_int(c, 1, 1, -1);
	cubesql_cursor_free(c);
	if (baseline != 1) {
		fprintf(stderr, "    baseline expected 1 row, got %d\n", baseline);
		goto done;
	}

	// Make sure autocommit is active
	cubesql_execute(db, "COMMIT;");
	cubesql_clear_errors(db);

	// Test COMMIT: begin, insert, commit, verify row exists
	if (cubesql_begintransaction(db) != CUBESQL_NOERR) {
		fprintf(stderr, "    BEGIN (commit test) failed: %s\n", cubesql_errmsg(db)); goto done;
	}
	cubesql_execute(db, "INSERT INTO test_txn VALUES (1, 'committed');");
	if (cubesql_commit(db) != CUBESQL_NOERR) {
		fprintf(stderr, "    COMMIT failed: %s\n", cubesql_errmsg(db)); goto done;
	}

	c = cubesql_select(db, "SELECT val FROM test_txn WHERE id = 1;", kFALSE);
	if (!c) { fprintf(stderr, "    SELECT after commit failed: %s\n", cubesql_errmsg(db)); goto done; }
	char *val = cubesql_cursor_cstring(c, 1, 1);
	if (!val || strcmp(val, "committed") != 0) {
		fprintf(stderr, "    expected 'committed', got '%s'\n", val ? val : "NULL");
		cubesql_cursor_free(c); goto done;
	}
	cubesql_cursor_free(c);

	// Test ROLLBACK: begin, insert, rollback, verify row does NOT exist
	if (cubesql_begintransaction(db) != CUBESQL_NOERR) {
		fprintf(stderr, "    BEGIN (rollback test) failed: %s\n", cubesql_errmsg(db)); goto done;
	}
	cubesql_execute(db, "INSERT INTO test_txn VALUES (2, 'rolled_back');");
	if (cubesql_rollback(db) != CUBESQL_NOERR) {
		fprintf(stderr, "    ROLLBACK failed: %s\n", cubesql_errmsg(db)); goto done;
	}

	c = cubesql_select(db, "SELECT COUNT(*) FROM test_txn WHERE id = 2;", kFALSE);
	if (!c) { fprintf(stderr, "    SELECT after rollback failed: %s\n", cubesql_errmsg(db)); goto done; }
	int count = cubesql_cursor_int(c, 1, 1, -1);
	cubesql_cursor_free(c);
	if (count != 0) {
		fprintf(stderr, "    after rollback expected 0 rows with id=2, got %d\n", count);
		goto done;
	}

	ok = 1;
done:
	cubesql_execute(db, "DROP TABLE IF EXISTS test_txn;");
	cubesql_disconnect(db, kTRUE);
	return ok;
}

// ---------------------------------------------------------------------------
// Test 8: Prepared statements (VM interface)
// ---------------------------------------------------------------------------
static int test_vm_prepared_statements(void) {
	csqldb *db = test_connect_with_db();
	if (!db) return 0;
	int ok = 0;

	cubesql_execute(db, "DROP TABLE IF EXISTS test_vm;");
	cubesql_execute(db, "CREATE TABLE test_vm (id INTEGER, name TEXT, data BLOB);");

	// Insert using VM bind
	csqlvm *vm = cubesql_vmprepare(db, "INSERT INTO test_vm VALUES (?1, ?2, ?3);");
	if (!vm) { fprintf(stderr, "    vmprepare failed: %s\n", cubesql_errmsg(db)); goto done; }

	cubesql_vmbind_int(vm, 1, 42);
	cubesql_vmbind_text(vm, 2, "hello world", 11);
	unsigned char blob_data[] = {0x00, 0x01, 0x02, 0xFF, 0xFE};
	cubesql_vmbind_blob(vm, 3, blob_data, 5);
	if (cubesql_vmexecute(vm) != CUBESQL_NOERR) {
		fprintf(stderr, "    vmexecute failed: %s\n", cubesql_errmsg(db));
		cubesql_vmclose(vm);
		goto done;
	}
	cubesql_vmclose(vm);

	// Insert with NULL
	vm = cubesql_vmprepare(db, "INSERT INTO test_vm VALUES (?1, ?2, ?3);");
	if (!vm) { fprintf(stderr, "    vmprepare 2 failed\n"); goto done; }
	cubesql_vmbind_int(vm, 1, 43);
	cubesql_vmbind_null(vm, 2);
	cubesql_vmbind_null(vm, 3);
	cubesql_vmexecute(vm);
	cubesql_vmclose(vm);

	// Insert with int64
	vm = cubesql_vmprepare(db, "INSERT INTO test_vm VALUES (?1, ?2, ?3);");
	if (!vm) { fprintf(stderr, "    vmprepare 3 failed\n"); goto done; }
	int64 big_id = 9223372036854775807LL;  // INT64_MAX
	cubesql_vmbind_int64(vm, 1, big_id);
	cubesql_vmbind_text(vm, 2, "big", 3);
	cubesql_vmbind_null(vm, 3);
	cubesql_vmexecute(vm);
	cubesql_vmclose(vm);

	// SELECT using VM
	vm = cubesql_vmprepare(db, "SELECT * FROM test_vm WHERE id = ?1;");
	if (!vm) { fprintf(stderr, "    vmprepare select failed\n"); goto done; }
	cubesql_vmbind_int(vm, 1, 42);
	csqlc *c = cubesql_vmselect(vm);
	cubesql_vmclose(vm);
	if (!c) { fprintf(stderr, "    vmselect failed: %s\n", cubesql_errmsg(db)); goto done; }

	if (cubesql_cursor_numrows(c) != 1) {
		fprintf(stderr, "    expected 1 row, got %d\n", cubesql_cursor_numrows(c));
		cubesql_cursor_free(c); goto done;
	}

	char *name = cubesql_cursor_cstring(c, 1, 2);
	if (!name || strcmp(name, "hello world") != 0) {
		fprintf(stderr, "    expected 'hello world', got '%s'\n", name ? name : "NULL");
		cubesql_cursor_free(c); goto done;
	}

	// Verify BLOB data
	int bloblen;
	char *blobfield = cubesql_cursor_field(c, 1, 3, &bloblen);
	if (!blobfield || bloblen != 5) {
		fprintf(stderr, "    blob: expected len=5, got %d\n", bloblen);
		cubesql_cursor_free(c); goto done;
	}
	if (memcmp(blobfield, blob_data, 5) != 0) {
		fprintf(stderr, "    blob data mismatch\n");
		cubesql_cursor_free(c); goto done;
	}

	cubesql_cursor_free(c);

	// Verify int64
	vm = cubesql_vmprepare(db, "SELECT id FROM test_vm WHERE name = ?1;");
	if (!vm) { fprintf(stderr, "    vmprepare int64 select failed\n"); goto done; }
	cubesql_vmbind_text(vm, 1, "big", 3);
	c = cubesql_vmselect(vm);
	cubesql_vmclose(vm);
	if (!c) { fprintf(stderr, "    vmselect int64 failed\n"); goto done; }

	int64 got_id = cubesql_cursor_int64(c, 1, 1, 0);
	if (got_id != big_id) {
		fprintf(stderr, "    expected int64 %lld, got %lld\n", (long long)big_id, (long long)got_id);
		cubesql_cursor_free(c); goto done;
	}
	cubesql_cursor_free(c);

	ok = 1;
done:
	cubesql_execute(db, "DROP TABLE IF EXISTS test_vm;");
	cubesql_disconnect(db, kTRUE);
	return ok;
}

// ---------------------------------------------------------------------------
// Test 9: Bind interface (non-VM)
// ---------------------------------------------------------------------------
static int test_bind(void) {
	csqldb *db = test_connect_with_db();
	if (!db) return 0;
	int ok = 0;

	cubesql_execute(db, "DROP TABLE IF EXISTS test_bind;");
	cubesql_execute(db, "CREATE TABLE test_bind (id INTEGER, name TEXT);");

	// Use cubesql_bind to insert
	char *colvalue[] = { "100", "bind_test" };
	int colsize[] = { 3, 9 };
	int coltype[] = { CUBESQL_BIND_INTEGER, CUBESQL_BIND_TEXT };
	int err = cubesql_bind(db, "INSERT INTO test_bind VALUES (?1, ?2);",
	                       colvalue, colsize, coltype, 2);
	if (err != CUBESQL_NOERR) {
		fprintf(stderr, "    bind failed: %s\n", cubesql_errmsg(db));
		goto done;
	}

	// Verify
	csqlc *c = cubesql_select(db, "SELECT * FROM test_bind;", kFALSE);
	if (!c) { fprintf(stderr, "    SELECT failed\n"); goto done; }
	if (cubesql_cursor_numrows(c) != 1) {
		fprintf(stderr, "    expected 1 row, got %d\n", cubesql_cursor_numrows(c));
		cubesql_cursor_free(c); goto done;
	}
	int id = cubesql_cursor_int(c, 1, 1, -1);
	char *name = cubesql_cursor_cstring(c, 1, 2);
	if (id != 100 || !name || strcmp(name, "bind_test") != 0) {
		fprintf(stderr, "    bind data mismatch: id=%d name=%s\n", id, name ? name : "NULL");
		cubesql_cursor_free(c); goto done;
	}
	cubesql_cursor_free(c);

	ok = 1;
done:
	cubesql_execute(db, "DROP TABLE IF EXISTS test_bind;");
	cubesql_disconnect(db, kTRUE);
	return ok;
}

// ---------------------------------------------------------------------------
// Test 10: Error handling
// ---------------------------------------------------------------------------
static int test_error_handling(void) {
	csqldb *db = test_connect_with_db();
	if (!db) return 0;
	int ok = 0;

	// Execute invalid SQL
	int err = cubesql_execute(db, "THIS IS NOT VALID SQL;");
	if (err == CUBESQL_NOERR) {
		fprintf(stderr, "    expected error for invalid SQL\n");
		goto done;
	}

	int errcode = cubesql_errcode(db);
	if (errcode == CUBESQL_NOERR) {
		fprintf(stderr, "    errcode should be non-zero after error\n");
		goto done;
	}

	char *errmsg = cubesql_errmsg(db);
	if (!errmsg || strlen(errmsg) == 0) {
		fprintf(stderr, "    errmsg should be non-empty after error\n");
		goto done;
	}

	// Select on non-existent table
	csqlc *c = cubesql_select(db, "SELECT * FROM no_such_table_xyz;", kFALSE);
	if (c != NULL) {
		fprintf(stderr, "    expected NULL cursor for bad table\n");
		cubesql_cursor_free(c);
		goto done;
	}

	// clear_errors should reset
	cubesql_clear_errors(db);
	if (cubesql_errcode(db) != CUBESQL_NOERR) {
		fprintf(stderr, "    errcode should be 0 after clear_errors\n");
		goto done;
	}

	// Connection should still be usable after errors
	err = cubesql_ping(db);
	if (err != CUBESQL_NOERR) {
		fprintf(stderr, "    ping failed after errors: %s\n", cubesql_errmsg(db));
		goto done;
	}

	ok = 1;
done:
	cubesql_disconnect(db, kTRUE);
	return ok;
}

// ---------------------------------------------------------------------------
// Test 11: Connect with bad credentials should fail
// ---------------------------------------------------------------------------
static int test_bad_credentials(void) {
	csqldb *db = NULL;
	int err = cubesql_connect(&db, TEST_HOST, TEST_PORT, "bad_user", "bad_pass",
	                          TEST_TIMEOUT, CUBESQL_ENCRYPTION_NONE);
	if (err == CUBESQL_NOERR) {
		fprintf(stderr, "    should have failed with bad credentials\n");
		if (db) cubesql_disconnect(db, kTRUE);
		return 0;
	}
	// db may or may not be allocated depending on where the error occurred
	if (db) cubesql_disconnect(db, kFALSE);
	return 1;
}

// ---------------------------------------------------------------------------
// Test 12: NULL parameter handling
// ---------------------------------------------------------------------------
static int test_null_parameters(void) {
	csqldb *db = NULL;

	// NULL host
	int err = cubesql_connect(&db, NULL, TEST_PORT, TEST_USER, TEST_PASS,
	                          TEST_TIMEOUT, CUBESQL_ENCRYPTION_NONE);
	if (err != CUBESQL_PARAMETER_ERROR) {
		fprintf(stderr, "    expected PARAMETER_ERROR for NULL host, got %d\n", err);
		if (db) cubesql_disconnect(db, kFALSE);
		return 0;
	}

	// NULL username
	err = cubesql_connect(&db, TEST_HOST, TEST_PORT, NULL, TEST_PASS,
	                      TEST_TIMEOUT, CUBESQL_ENCRYPTION_NONE);
	if (err != CUBESQL_PARAMETER_ERROR) {
		fprintf(stderr, "    expected PARAMETER_ERROR for NULL username, got %d\n", err);
		if (db) cubesql_disconnect(db, kFALSE);
		return 0;
	}

	// NULL password
	err = cubesql_connect(&db, TEST_HOST, TEST_PORT, TEST_USER, NULL,
	                      TEST_TIMEOUT, CUBESQL_ENCRYPTION_NONE);
	if (err != CUBESQL_PARAMETER_ERROR) {
		fprintf(stderr, "    expected PARAMETER_ERROR for NULL password, got %d\n", err);
		if (db) cubesql_disconnect(db, kFALSE);
		return 0;
	}

	return 1;
}

// ---------------------------------------------------------------------------
// Test 13: Large result set (exercises multi-chunk cursor path)
// ---------------------------------------------------------------------------
static int test_large_result_set(void) {
	csqldb *db = test_connect_with_db();
	if (!db) return 0;
	int ok = 0;

	cubesql_execute(db, "DROP TABLE IF EXISTS test_large;");
	cubesql_execute(db, "CREATE TABLE test_large (id INTEGER, payload TEXT);");

	// Insert 1000 rows in a transaction for speed
	cubesql_begintransaction(db);
	for (int i = 1; i <= 1000; i++) {
		char sql[256];
		snprintf(sql, sizeof(sql),
			"INSERT INTO test_large VALUES (%d, 'row_%d_payload_data_padding_to_increase_size');", i, i);
		cubesql_execute(db, sql);
	}
	cubesql_commit(db);

	// Select all rows
	csqlc *c = cubesql_select(db, "SELECT * FROM test_large ORDER BY id;", kFALSE);
	if (!c) { fprintf(stderr, "    SELECT 1000 rows failed: %s\n", cubesql_errmsg(db)); goto done; }

	if (cubesql_cursor_numrows(c) != 1000) {
		fprintf(stderr, "    expected 1000 rows, got %d\n", cubesql_cursor_numrows(c));
		cubesql_cursor_free(c); goto done;
	}

	// Verify first, middle, and last rows
	int id_first = cubesql_cursor_int(c, 1, 1, -1);
	int id_500 = cubesql_cursor_int(c, 500, 1, -1);
	int id_last = cubesql_cursor_int(c, 1000, 1, -1);
	if (id_first != 1 || id_500 != 500 || id_last != 1000) {
		fprintf(stderr, "    data mismatch: first=%d mid=%d last=%d\n", id_first, id_500, id_last);
		cubesql_cursor_free(c); goto done;
	}

	cubesql_cursor_free(c);
	ok = 1;
done:
	cubesql_execute(db, "DROP TABLE IF EXISTS test_large;");
	cubesql_disconnect(db, kTRUE);
	return ok;
}

// ---------------------------------------------------------------------------
// Test 14: cubesql_cursor_cstring_static
// ---------------------------------------------------------------------------
static int test_cursor_cstring_static(void) {
	csqldb *db = test_connect_with_db();
	if (!db) return 0;
	int ok = 0;

	cubesql_execute(db, "DROP TABLE IF EXISTS test_static;");
	cubesql_execute(db, "CREATE TABLE test_static (val TEXT);");
	cubesql_execute(db, "INSERT INTO test_static VALUES ('hello_static');");

	csqlc *c = cubesql_select(db, "SELECT val FROM test_static;", kFALSE);
	if (!c) { fprintf(stderr, "    SELECT failed\n"); goto done; }

	// Use static buffer variant
	char buf[64];
	char *result = cubesql_cursor_cstring_static(c, 1, 1, buf, sizeof(buf));
	if (!result || strcmp(result, "hello_static") != 0) {
		fprintf(stderr, "    expected 'hello_static', got '%s'\n", result ? result : "NULL");
		cubesql_cursor_free(c); goto done;
	}
	// Result should be in our buffer
	if (result != buf) {
		fprintf(stderr, "    cstring_static did not use provided buffer\n");
		cubesql_cursor_free(c); goto done;
	}

	cubesql_cursor_free(c);
	ok = 1;
done:
	cubesql_execute(db, "DROP TABLE IF EXISTS test_static;");
	cubesql_disconnect(db, kTRUE);
	return ok;
}

// ---------------------------------------------------------------------------
// Test 15: Column types from server
// ---------------------------------------------------------------------------
static int test_column_types(void) {
	csqldb *db = test_connect_with_db();
	if (!db) return 0;
	int ok = 0;

	cubesql_execute(db, "DROP TABLE IF EXISTS test_types;");
	cubesql_execute(db, "CREATE TABLE test_types (i INTEGER, r REAL, t TEXT, b BLOB);");
	cubesql_execute(db, "INSERT INTO test_types VALUES (1, 2.5, 'text', X'AABB');");

	csqlc *c = cubesql_select(db, "SELECT * FROM test_types;", kFALSE);
	if (!c) { fprintf(stderr, "    SELECT failed\n"); goto done; }

	// Verify column types reported by server
	// Note: CubeSQL server column types are based on declared column type,
	// not SQLite storage class. REAL is reported based on actual value type.
	int t1 = cubesql_cursor_columntype(c, 1);
	int t3 = cubesql_cursor_columntype(c, 3);
	int t4 = cubesql_cursor_columntype(c, 4);

	if (t1 != CUBESQL_Type_Integer) {
		fprintf(stderr, "    col1 type: expected %d (Integer), got %d\n", CUBESQL_Type_Integer, t1);
		cubesql_cursor_free(c); goto done;
	}
	if (t3 != CUBESQL_Type_Text) {
		fprintf(stderr, "    col3 type: expected %d (Text), got %d\n", CUBESQL_Type_Text, t3);
		cubesql_cursor_free(c); goto done;
	}
	if (t4 != CUBESQL_Type_Blob) {
		fprintf(stderr, "    col4 type: expected %d (Blob), got %d\n", CUBESQL_Type_Blob, t4);
		cubesql_cursor_free(c); goto done;
	}

	// Verify all types are valid (non-negative, within range)
	int t2 = cubesql_cursor_columntype(c, 2);
	if (t2 < CUBESQL_Type_None || t2 > CUBESQL_Type_Currency) {
		fprintf(stderr, "    col2 type out of range: %d\n", t2);
		cubesql_cursor_free(c); goto done;
	}

	cubesql_cursor_free(c);
	ok = 1;
done:
	cubesql_execute(db, "DROP TABLE IF EXISTS test_types;");
	cubesql_disconnect(db, kTRUE);
	return ok;
}

// ---------------------------------------------------------------------------
// Test 16: Multiple concurrent connections
// ---------------------------------------------------------------------------
static int test_multiple_connections(void) {
	// Use a separate database to avoid lock contention with other tests
	#define TEST_MULTI_DB "integration_test_multi.db"

	csqldb *db1 = test_connect();
	csqldb *db2 = test_connect();
	if (!db1 || !db2) {
		if (db1) cubesql_disconnect(db1, kTRUE);
		if (db2) cubesql_disconnect(db2, kTRUE);
		return 0;
	}
	int ok = 0;

	// Create and use a separate database for this test
	cubesql_execute(db1, "CREATE DATABASE " TEST_MULTI_DB " IF NOT EXISTS;");
	if (cubesql_set_database(db1, TEST_MULTI_DB) != CUBESQL_NOERR) {
		fprintf(stderr, "    set_database db1 failed: %s\n", cubesql_errmsg(db1));
		goto done;
	}
	if (cubesql_set_database(db2, TEST_MULTI_DB) != CUBESQL_NOERR) {
		fprintf(stderr, "    set_database db2 failed: %s\n", cubesql_errmsg(db2));
		goto done;
	}

	cubesql_execute(db1, "DROP TABLE IF EXISTS test_multi;");
	cubesql_commit(db1);
	int err = cubesql_execute(db1, "CREATE TABLE test_multi (id INTEGER, source TEXT);");
	if (err != CUBESQL_NOERR) {
		fprintf(stderr, "    CREATE TABLE failed: %s\n", cubesql_errmsg(db1));
		goto done;
	}
	cubesql_commit(db1);

	// Insert from connection 1, then commit to release the write lock
	err = cubesql_execute(db1, "INSERT INTO test_multi VALUES (1, 'conn1');");
	if (err != CUBESQL_NOERR) {
		fprintf(stderr, "    INSERT from conn1 failed: %s\n", cubesql_errmsg(db1));
		goto done;
	}
	cubesql_commit(db1);

	// Insert from connection 2 (lock is now released by conn1's commit)
	err = cubesql_execute(db2, "INSERT INTO test_multi VALUES (2, 'conn2');");
	if (err != CUBESQL_NOERR) {
		fprintf(stderr, "    INSERT from conn2 failed: %s\n", cubesql_errmsg(db2));
		goto done;
	}
	cubesql_commit(db2);

	// Both connections should see both rows after commits
	csqlc *c1 = cubesql_select(db1, "SELECT COUNT(*) FROM test_multi;", kFALSE);
	if (!c1) {
		fprintf(stderr, "    SELECT from conn1 failed: %s\n", cubesql_errmsg(db1));
		goto done;
	}
	int count1 = cubesql_cursor_int(c1, 1, 1, -1);
	cubesql_cursor_free(c1);

	csqlc *c2 = cubesql_select(db2, "SELECT COUNT(*) FROM test_multi;", kFALSE);
	if (!c2) {
		fprintf(stderr, "    SELECT from conn2 failed: %s\n", cubesql_errmsg(db2));
		goto done;
	}
	int count2 = cubesql_cursor_int(c2, 1, 1, -1);
	cubesql_cursor_free(c2);

	if (count1 != 2 || count2 != 2) {
		fprintf(stderr, "    expected both connections to see 2 rows, got %d and %d\n", count1, count2);
		goto done;
	}

	ok = 1;
done:
	cubesql_execute(db1, "DROP TABLE IF EXISTS test_multi;");
	cubesql_disconnect(db1, kTRUE);
	cubesql_disconnect(db2, kTRUE);
	return ok;
	#undef TEST_MULTI_DB
}

// ---------------------------------------------------------------------------
// Test 17: last_inserted_rowID
// ---------------------------------------------------------------------------
static int test_last_inserted_rowid(void) {
	csqldb *db = test_connect_with_db();
	if (!db) return 0;
	int ok = 0;

	cubesql_execute(db, "DROP TABLE IF EXISTS test_rowid;");
	cubesql_execute(db, "CREATE TABLE test_rowid (id INTEGER PRIMARY KEY, val TEXT);");

	cubesql_execute(db, "INSERT INTO test_rowid (val) VALUES ('first');");
	int64 rowid1 = cubesql_last_inserted_rowID(db);
	if (rowid1 != 1) {
		fprintf(stderr, "    expected rowid=1, got %lld\n", (long long)rowid1);
		goto done;
	}

	cubesql_execute(db, "INSERT INTO test_rowid (val) VALUES ('second');");
	int64 rowid2 = cubesql_last_inserted_rowID(db);
	if (rowid2 != 2) {
		fprintf(stderr, "    expected rowid=2, got %lld\n", (long long)rowid2);
		goto done;
	}

	ok = 1;
done:
	cubesql_execute(db, "DROP TABLE IF EXISTS test_rowid;");
	cubesql_disconnect(db, kTRUE);
	return ok;
}

// ---------------------------------------------------------------------------
// Test 18: cubesql_cursor_rowid
// ---------------------------------------------------------------------------
static int test_cursor_rowid(void) {
	csqldb *db = test_connect_with_db();
	if (!db) return 0;
	int ok = 0;

	cubesql_execute(db, "DROP TABLE IF EXISTS test_crowid;");
	cubesql_execute(db, "CREATE TABLE test_crowid (id INTEGER PRIMARY KEY, val TEXT);");
	cubesql_execute(db, "INSERT INTO test_crowid VALUES (10, 'ten');");
	cubesql_execute(db, "INSERT INTO test_crowid VALUES (20, 'twenty');");
	cubesql_execute(db, "INSERT INTO test_crowid VALUES (30, 'thirty');");

	csqlc *c = cubesql_select(db, "SELECT rowid, * FROM test_crowid ORDER BY id;", kFALSE);
	if (!c) { fprintf(stderr, "    SELECT failed\n"); goto done; }

	// Verify we get 3 rows
	if (cubesql_cursor_numrows(c) != 3) {
		fprintf(stderr, "    expected 3 rows, got %d\n", cubesql_cursor_numrows(c));
		cubesql_cursor_free(c); goto done;
	}

	// For INTEGER PRIMARY KEY, rowid == id (10, 20, 30)
	int64 rid1 = cubesql_cursor_int64(c, 1, 1, -1);
	int64 rid2 = cubesql_cursor_int64(c, 2, 1, -1);
	int64 rid3 = cubesql_cursor_int64(c, 3, 1, -1);
	if (rid1 != 10 || rid2 != 20 || rid3 != 30) {
		fprintf(stderr, "    rowid mismatch: %lld, %lld, %lld\n",
			(long long)rid1, (long long)rid2, (long long)rid3);
		cubesql_cursor_free(c); goto done;
	}

	cubesql_cursor_free(c);
	ok = 1;
done:
	cubesql_execute(db, "DROP TABLE IF EXISTS test_crowid;");
	cubesql_disconnect(db, kTRUE);
	return ok;
}

// ---------------------------------------------------------------------------
// Test 19: Unicode/UTF-8 data
// ---------------------------------------------------------------------------
static int test_unicode_data(void) {
	csqldb *db = test_connect_with_db();
	if (!db) return 0;
	int ok = 0;

	cubesql_execute(db, "DROP TABLE IF EXISTS test_utf8;");
	cubesql_execute(db, "CREATE TABLE test_utf8 (id INTEGER, text_val TEXT);");

	// Insert UTF-8 strings using prepared statements
	const char *utf8_strings[] = {
		"Hello World",
		"Héllo Wörld",
		"日本語テスト",
		"Привет мир",
		"🎉🚀💯"
	};
	int nstrings = sizeof(utf8_strings) / sizeof(utf8_strings[0]);

	for (int i = 0; i < nstrings; i++) {
		csqlvm *vm = cubesql_vmprepare(db, "INSERT INTO test_utf8 VALUES (?1, ?2);");
		if (!vm) { fprintf(stderr, "    vmprepare failed for string %d\n", i); goto done; }
		cubesql_vmbind_int(vm, 1, i + 1);
		cubesql_vmbind_text(vm, 2, (char *)utf8_strings[i], (int)strlen(utf8_strings[i]));
		cubesql_vmexecute(vm);
		cubesql_vmclose(vm);
	}

	// Read them back
	csqlc *c = cubesql_select(db, "SELECT text_val FROM test_utf8 ORDER BY id;", kFALSE);
	if (!c) { fprintf(stderr, "    SELECT failed\n"); goto done; }
	if (cubesql_cursor_numrows(c) != nstrings) {
		fprintf(stderr, "    expected %d rows, got %d\n", nstrings, cubesql_cursor_numrows(c));
		cubesql_cursor_free(c); goto done;
	}

	for (int i = 0; i < nstrings; i++) {
		char *val = cubesql_cursor_cstring(c, i + 1, 1);
		if (!val || strcmp(val, utf8_strings[i]) != 0) {
			fprintf(stderr, "    row %d: expected '%s', got '%s'\n",
				i + 1, utf8_strings[i], val ? val : "NULL");
			cubesql_cursor_free(c); goto done;
		}
	}

	cubesql_cursor_free(c);
	ok = 1;
done:
	cubesql_execute(db, "DROP TABLE IF EXISTS test_utf8;");
	cubesql_disconnect(db, kTRUE);
	return ok;
}

// ---------------------------------------------------------------------------
// Test 20: Empty result set
// ---------------------------------------------------------------------------
static int test_empty_result_set(void) {
	csqldb *db = test_connect_with_db();
	if (!db) return 0;
	int ok = 0;

	cubesql_execute(db, "DROP TABLE IF EXISTS test_empty;");
	cubesql_execute(db, "CREATE TABLE test_empty (id INTEGER);");

	// Select from empty table
	csqlc *c = cubesql_select(db, "SELECT * FROM test_empty;", kFALSE);
	if (!c) { fprintf(stderr, "    SELECT on empty table returned NULL\n"); goto done; }

	if (cubesql_cursor_numrows(c) != 0) {
		fprintf(stderr, "    expected 0 rows, got %d\n", cubesql_cursor_numrows(c));
		cubesql_cursor_free(c); goto done;
	}
	if (cubesql_cursor_numcolumns(c) != 1) {
		fprintf(stderr, "    expected 1 column, got %d\n", cubesql_cursor_numcolumns(c));
		cubesql_cursor_free(c); goto done;
	}

	// EOF should be set
	if (!cubesql_cursor_iseof(c)) {
		fprintf(stderr, "    expected EOF on empty result\n");
		cubesql_cursor_free(c); goto done;
	}

	cubesql_cursor_free(c);
	ok = 1;
done:
	cubesql_execute(db, "DROP TABLE IF EXISTS test_empty;");
	cubesql_disconnect(db, kTRUE);
	return ok;
}

// ---------------------------------------------------------------------------
// Test 21: Bug 25 - disconnect after cancel (sockfd = 0)
// ---------------------------------------------------------------------------
static int test_disconnect_after_cancel(void) {
	csqldb *db = test_connect();
	if (!db) return 0;

	// Cancel sets sockfd to 0
	cubesql_cancel(db);

	// Disconnect should not crash or leak (Bug 25 fix)
	cubesql_disconnect(db, kFALSE);
	return 1;
}

// ---------------------------------------------------------------------------
// Test 22: cubesql_version returns valid string
// ---------------------------------------------------------------------------
static int test_version(void) {
	const char *ver = cubesql_version();
	if (!ver || strlen(ver) == 0) {
		fprintf(stderr, "    version returned NULL or empty\n");
		return 0;
	}
	// Should be "060500" format
	if (strlen(ver) != 6) {
		fprintf(stderr, "    version length unexpected: '%s'\n", ver);
		return 0;
	}
	return 1;
}

// ---------------------------------------------------------------------------
// Setup: register the server if needed
// ---------------------------------------------------------------------------
static int setup_server(void) {
	csqldb *db = test_connect();
	if (!db) {
		fprintf(stderr, "  SETUP FAILED: cannot connect to server at %s:%d\n", TEST_HOST, TEST_PORT);
		return 0;
	}

	// Register server (idempotent if already registered)
	int err = cubesql_execute(db,
		"SET REGISTRATION TO 'SQLabs srl' WITH KEY 'CSQL75ZZ-PPJHAG9L-27X2W3C4-8DX6BAXX-35XBX46W';");
	if (err != CUBESQL_NOERR) {
		// May already be registered, check if we can create a database
		cubesql_clear_errors(db);
		err = cubesql_execute(db, "CREATE DATABASE " TEST_DB " IF NOT EXISTS;");
		if (err != CUBESQL_NOERR) {
			fprintf(stderr, "  SETUP FAILED: cannot register server or create database: %s\n",
				cubesql_errmsg(db));
			cubesql_disconnect(db, kTRUE);
			return 0;
		}
	}

	cubesql_disconnect(db, kTRUE);
	return 1;
}

int main(int argc, char *argv[]) {
	(void)argc;
	(void)argv;

	printf("CubeSQL C SDK - Integration Tests\n");
	printf("Server: %s:%d  User: %s\n", TEST_HOST, TEST_PORT, TEST_USER);
	printf("============================================\n\n");

	csql_libinit();

	if (!setup_server()) {
		printf("Server setup failed. Is the server running?\n");
		return 1;
	}
	printf("  Server registered and ready.\n\n");

	// Connection tests
	RUN_TEST(test_connect_disconnect);
	RUN_TEST(test_connect_aes256);
	RUN_TEST(test_ping);
	RUN_TEST(test_bad_credentials);
	RUN_TEST(test_null_parameters);

	// Data manipulation
	RUN_TEST(test_execute_and_select);
	RUN_TEST(test_changes);
	RUN_TEST(test_last_inserted_rowid);
	RUN_TEST(test_cursor_rowid);

	// Cursor operations
	RUN_TEST(test_cursor_seek);
	RUN_TEST(test_cursor_cstring_static);
	RUN_TEST(test_column_types);
	RUN_TEST(test_empty_result_set);
	RUN_TEST(test_large_result_set);

	// Advanced features
	RUN_TEST(test_transactions);
	RUN_TEST(test_vm_prepared_statements);
	RUN_TEST(test_bind);
	RUN_TEST(test_unicode_data);

	// Multi-connection and edge cases
	RUN_TEST(test_multiple_connections);
	RUN_TEST(test_error_handling);
	RUN_TEST(test_disconnect_after_cancel);
	RUN_TEST(test_version);

	printf("\n============================================\n");
	printf("Results: %d passed, %d failed, %d total\n", tests_passed, tests_failed, tests_run);

	if (tests_failed == 0) {
		printf("All tests PASSED.\n");
		return 0;
	} else {
		printf("Some tests FAILED.\n");
		return 1;
	}
}
