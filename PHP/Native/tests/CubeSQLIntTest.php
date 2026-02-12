<?php
declare(strict_types=1);

/**
 * CubeSQL PHP SDK Integration Tests
 * Requires a running CubeSQL server.
 *
 * Configure via env vars:
 *   CUBESQL_HOST (default: localhost)
 *   CUBESQL_PORT (default: 4430)
 *   CUBESQL_USER (default: admin)
 *   CUBESQL_PASS (default: admin)
 *   CUBESQL_SSL  (default: 0, set to 1 for SSL)
 *
 * Run: php tests/CubeSQLIntTest.php
 */

require_once __DIR__ . '/../CubeSQL.php';

use CubeSQL\CubeSQL;
use CubeSQL\Cursor;
use CubeSQL\Connection;
use CubeSQL\PreparedStatement;
use CubeSQL\BindType;
use CubeSQL\ColumnType;
use CubeSQL\CubeSQLException;

// Configuration
$HOST = getenv('CUBESQL_HOST') ?: 'localhost';
$PORT = (int)(getenv('CUBESQL_PORT') ?: '4430');
$USER = getenv('CUBESQL_USER') ?: 'admin';
$PASS = getenv('CUBESQL_PASS') ?: 'admin';
$SSL  = (bool)(getenv('CUBESQL_SSL') ?: '0');

$passCount = 0;
$failCount = 0;
$skipCount = 0;

function runTest(string $name, callable $fn): void {
    global $passCount, $failCount, $skipCount;
    try {
        $fn();
        $passCount++;
        echo "  PASS: {$name}\n";
    } catch (SkipException $e) {
        $skipCount++;
        echo "  SKIP: {$name} - {$e->getMessage()}\n";
    } catch (\Throwable $e) {
        $failCount++;
        echo "  FAIL: {$name}\n";
        echo "        {$e->getMessage()}\n";
        echo "        {$e->getFile()}:{$e->getLine()}\n";
    }
}

class SkipException extends \RuntimeException {}

function assertEqual($expected, $actual, string $msg = ''): void {
    if ($expected !== $actual) {
        $exp = var_export($expected, true);
        $act = var_export($actual, true);
        throw new \RuntimeException("Assertion failed{$msg}: expected {$exp}, got {$act}");
    }
}

function assertTrue(bool $condition, string $msg = ''): void {
    if (!$condition) {
        throw new \RuntimeException("Assertion failed: expected true" . ($msg ? " ({$msg})" : ''));
    }
}

function assertFalse(bool $condition, string $msg = ''): void {
    if ($condition) {
        throw new \RuntimeException("Assertion failed: expected false" . ($msg ? " ({$msg})" : ''));
    }
}

function assertNotNull($value, string $msg = ''): void {
    if ($value === null) {
        throw new \RuntimeException("Assertion failed: expected non-null" . ($msg ? " ({$msg})" : ''));
    }
}

function assertNull($value, string $msg = ''): void {
    if ($value !== null) {
        throw new \RuntimeException("Assertion failed: expected null, got " . var_export($value, true) . ($msg ? " ({$msg})" : ''));
    }
}

function assertGreaterThan(int $min, int $actual, string $msg = ''): void {
    if ($actual <= $min) {
        throw new \RuntimeException("Assertion failed: expected > {$min}, got {$actual}" . ($msg ? " ({$msg})" : ''));
    }
}

/**
 * Helper: create a connected CubeSQL instance with test database
 */
function testConnect(): CubeSQL {
    global $HOST, $PORT, $USER, $PASS, $SSL;
    $db = new CubeSQL();
    $ok = $db->connect($HOST, $PORT, $USER, $PASS, 12, $SSL);
    if (!$ok) {
        throw new \RuntimeException("Cannot connect: {$db->errorMessage()}");
    }
    return $db;
}

function testConnectWithDb(): CubeSQL {
    $db = testConnect();
    $db->execute("CREATE DATABASE phptest.db IF NOT EXISTS;");
    if ($db->isError()) {
        throw new \RuntimeException("Cannot create database: {$db->errorMessage()}");
    }
    $db->setDatabase('phptest.db');
    if ($db->isError()) {
        throw new \RuntimeException("Cannot set database: {$db->errorMessage()}");
    }
    return $db;
}

// ============================================================================
// Setup: register server if needed
// ============================================================================

echo "Connecting to {$HOST}:{$PORT} (SSL: " . ($SSL ? 'yes' : 'no') . ")...\n\n";

$setupDb = testConnect();

// Try to register
$setupDb->execute("SET REGISTRATION TO 'SQLabs srl' WITH KEY 'CSQL75ZZ-PPJHAG9L-27X2W3C4-8DX6BAXX-35XBX46W';");
// Ignore errors (already registered is fine)

$setupDb->execute("CREATE DATABASE phptest.db IF NOT EXISTS;");
$setupDb->setDatabase('phptest.db');
$setupDb->disconnect();

// ============================================================================
// Connection Tests
// ============================================================================

echo "=== Connection Tests ===\n";

runTest('Connect: plain TCP', function () {
    global $HOST, $PORT, $USER, $PASS;
    $db = new CubeSQL();
    assertTrue($db->connect($HOST, $PORT, $USER, $PASS));
    $db->disconnect();
});

runTest('Connect: wrong credentials', function () {
    global $HOST, $PORT;
    $db = new CubeSQL();
    $ok = $db->connect($HOST, $PORT, 'bad_user', 'bad_pass');
    assertFalse($ok, 'should fail with wrong credentials');
    assertTrue($db->isError());
});

runTest('Connect: disconnect and verify', function () {
    $db = testConnect();
    $db->disconnect();
    // Can't really test the socket is closed, but we verify no exception
});

runTest('Connect: ping', function () {
    $db = testConnect();
    assertTrue($db->ping());
    $db->disconnect();
});

// ============================================================================
// Execute Tests
// ============================================================================

echo "\n=== Execute Tests ===\n";

runTest('Execute: CREATE TABLE', function () {
    $db = testConnectWithDb();
    $db->execute("DROP TABLE IF EXISTS php_exec_test;");
    $db->commit();
    assertTrue($db->execute("CREATE TABLE php_exec_test (id INTEGER PRIMARY KEY, name TEXT, val REAL);"));
    $db->commit();
    $db->execute("DROP TABLE IF EXISTS php_exec_test;");
    $db->commit();
    $db->disconnect();
});

runTest('Execute: INSERT and affected rows', function () {
    $db = testConnectWithDb();
    $db->execute("DROP TABLE IF EXISTS php_affected;");
    $db->commit();
    $db->execute("CREATE TABLE php_affected (id INTEGER PRIMARY KEY, name TEXT);");
    $db->commit();

    assertTrue($db->execute("INSERT INTO php_affected VALUES (1, 'Alice');"));
    $db->commit();
    $rows = $db->affectedRows();
    assertEqual(1, $rows);

    $db->execute("DROP TABLE IF EXISTS php_affected;");
    $db->commit();
    $db->disconnect();
});

runTest('Execute: last inserted row ID', function () {
    $db = testConnectWithDb();
    $db->execute("DROP TABLE IF EXISTS php_lastid;");
    $db->commit();
    $db->execute("CREATE TABLE php_lastid (id INTEGER PRIMARY KEY, name TEXT);");
    $db->commit();

    $db->execute("INSERT INTO php_lastid (name) VALUES ('Alice');");
    $db->commit();
    $lastId = $db->lastInsertedRowId();
    assertGreaterThan(0, $lastId);

    $db->execute("DROP TABLE IF EXISTS php_lastid;");
    $db->commit();
    $db->disconnect();
});

runTest('Execute: USE DATABASE', function () {
    $db = testConnect();
    assertTrue($db->execute("CREATE DATABASE phptest2.db IF NOT EXISTS;"));
    assertTrue($db->setDatabase('phptest2.db'));
    // Switch back
    assertTrue($db->setDatabase('phptest.db'));
    $db->disconnect();
});

// ============================================================================
// Select Tests
// ============================================================================

echo "\n=== Select Tests ===\n";

runTest('Select: simple query', function () {
    $db = testConnectWithDb();
    $db->execute("DROP TABLE IF EXISTS php_select;");
    $db->commit();
    $db->execute("CREATE TABLE php_select (id INTEGER, name TEXT);");
    $db->commit();
    $db->execute("INSERT INTO php_select VALUES (1, 'Alice');");
    $db->commit();
    $db->execute("INSERT INTO php_select VALUES (2, 'Bob');");
    $db->commit();

    $cursor = $db->select("SELECT * FROM php_select ORDER BY id;");
    assertNotNull($cursor, 'cursor should not be null');
    assertEqual(2, $cursor->numRows());
    assertEqual(2, $cursor->numColumns());
    assertEqual('1', $cursor->field(1, 1));
    assertEqual('Alice', $cursor->field(1, 2));
    assertEqual('2', $cursor->field(2, 1));
    assertEqual('Bob', $cursor->field(2, 2));

    $db->execute("DROP TABLE IF EXISTS php_select;");
    $db->commit();
    $db->disconnect();
});

runTest('Select: empty result', function () {
    $db = testConnectWithDb();
    $db->execute("DROP TABLE IF EXISTS php_empty;");
    $db->commit();
    $db->execute("CREATE TABLE php_empty (id INTEGER);");
    $db->commit();

    $cursor = $db->select("SELECT * FROM php_empty;");
    assertNotNull($cursor);
    assertEqual(0, $cursor->numRows());
    assertTrue($cursor->isEof());

    $db->execute("DROP TABLE IF EXISTS php_empty;");
    $db->commit();
    $db->disconnect();
});

runTest('Select: column names', function () {
    $db = testConnectWithDb();
    $db->execute("DROP TABLE IF EXISTS php_colnames;");
    $db->commit();
    $db->execute("CREATE TABLE php_colnames (user_id INTEGER, user_name TEXT, score REAL);");
    $db->commit();
    $db->execute("INSERT INTO php_colnames VALUES (1, 'Alice', 9.5);");
    $db->commit();

    $cursor = $db->select("SELECT * FROM php_colnames;");
    assertNotNull($cursor);
    assertEqual('user_id', $cursor->columnName(1));
    assertEqual('user_name', $cursor->columnName(2));
    assertEqual('score', $cursor->columnName(3));

    $db->execute("DROP TABLE IF EXISTS php_colnames;");
    $db->commit();
    $db->disconnect();
});

runTest('Select: NULL values', function () {
    $db = testConnectWithDb();
    $db->execute("DROP TABLE IF EXISTS php_nulls;");
    $db->commit();
    $db->execute("CREATE TABLE php_nulls (id INTEGER, val TEXT);");
    $db->commit();
    $db->execute("INSERT INTO php_nulls VALUES (1, NULL);");
    $db->commit();
    $db->execute("INSERT INTO php_nulls VALUES (NULL, 'hello');");
    $db->commit();

    $cursor = $db->select("SELECT * FROM php_nulls ORDER BY rowid;");
    assertNotNull($cursor);
    assertEqual(2, $cursor->numRows());
    assertEqual('1', $cursor->field(1, 1));
    assertNull($cursor->field(1, 2), 'val should be NULL');
    assertNull($cursor->field(2, 1), 'id should be NULL');
    assertEqual('hello', $cursor->field(2, 2));

    $db->execute("DROP TABLE IF EXISTS php_nulls;");
    $db->commit();
    $db->disconnect();
});

runTest('Select: SHOW INFO', function () {
    $db = testConnect();
    $cursor = $db->select("SHOW INFO;");
    assertNotNull($cursor, 'SHOW INFO should return a cursor');
    assertGreaterThan(0, $cursor->numRows());
    $db->disconnect();
});

runTest('Select: toArray with associative keys', function () {
    $db = testConnectWithDb();
    $db->execute("DROP TABLE IF EXISTS php_toarray;");
    $db->commit();
    $db->execute("CREATE TABLE php_toarray (id INTEGER, name TEXT);");
    $db->commit();
    $db->execute("INSERT INTO php_toarray VALUES (1, 'Alice');");
    $db->commit();

    $cursor = $db->select("SELECT * FROM php_toarray;");
    assertNotNull($cursor);
    $arr = $cursor->toArray();
    assertEqual(1, count($arr));
    assertTrue(isset($arr[0]['id']));
    assertTrue(isset($arr[0]['name']));
    assertEqual('1', $arr[0]['id']);
    assertEqual('Alice', $arr[0]['name']);

    $db->execute("DROP TABLE IF EXISTS php_toarray;");
    $db->commit();
    $db->disconnect();
});

runTest('Select: large result set (chunked)', function () {
    $db = testConnectWithDb();
    $db->execute("DROP TABLE IF EXISTS php_large;");
    $db->commit();
    $db->execute("CREATE TABLE php_large (id INTEGER, data TEXT);");
    $db->commit();

    // Insert enough rows to trigger chunked transfer
    for ($i = 1; $i <= 200; $i++) {
        $data = str_repeat("x", 200);
        $db->execute("INSERT INTO php_large VALUES ({$i}, '{$data}');");
        $db->commit();
    }

    $cursor = $db->select("SELECT * FROM php_large ORDER BY id;");
    assertNotNull($cursor);
    assertEqual(200, $cursor->numRows());
    assertEqual('1', $cursor->field(1, 1));
    assertEqual('200', $cursor->field(200, 1));

    $db->execute("DROP TABLE IF EXISTS php_large;");
    $db->commit();
    $db->disconnect();
});

// ============================================================================
// Transaction Tests
// ============================================================================

echo "\n=== Transaction Tests ===\n";

runTest('Transaction: begin and commit', function () {
    $db = testConnectWithDb();
    $db->execute("DROP TABLE IF EXISTS php_txn;");
    $db->commit();
    $db->execute("CREATE TABLE php_txn (id INTEGER, name TEXT);");
    $db->commit();

    // Clear any implicit transaction state
    $db->execute("COMMIT;");

    assertTrue($db->beginTransaction());
    $db->execute("INSERT INTO php_txn VALUES (1, 'Alice');");
    $db->execute("INSERT INTO php_txn VALUES (2, 'Bob');");
    assertTrue($db->commit());

    $cursor = $db->select("SELECT COUNT(*) FROM php_txn;");
    assertNotNull($cursor);
    assertEqual('2', $cursor->field(1, 1));

    $db->execute("DROP TABLE IF EXISTS php_txn;");
    $db->commit();
    $db->disconnect();
});

runTest('Transaction: begin and rollback', function () {
    $db = testConnectWithDb();
    $db->execute("DROP TABLE IF EXISTS php_rollback;");
    $db->commit();
    $db->execute("CREATE TABLE php_rollback (id INTEGER);");
    $db->commit();
    $db->execute("INSERT INTO php_rollback VALUES (1);");
    $db->commit();

    // Clear any implicit transaction state
    $db->execute("COMMIT;");

    assertTrue($db->beginTransaction());
    $db->execute("INSERT INTO php_rollback VALUES (2);");
    $db->execute("INSERT INTO php_rollback VALUES (3);");
    assertTrue($db->rollback());

    $cursor = $db->select("SELECT COUNT(*) FROM php_rollback;");
    assertNotNull($cursor);
    assertEqual('1', $cursor->field(1, 1));

    $db->execute("DROP TABLE IF EXISTS php_rollback;");
    $db->commit();
    $db->disconnect();
});

// ============================================================================
// Prepared Statement Tests (VM)
// ============================================================================

echo "\n=== Prepared Statement Tests ===\n";

runTest('VM: prepare + bind int + execute', function () {
    $db = testConnectWithDb();
    $db->execute("DROP TABLE IF EXISTS php_vm_exec;");
    $db->commit();
    $db->execute("CREATE TABLE php_vm_exec (id INTEGER, val INTEGER);");
    $db->commit();

    $stmt = $db->prepare("INSERT INTO php_vm_exec VALUES (?1, ?2);");
    assertNotNull($stmt);
    $stmt->bindInt(1, 10);
    $stmt->bindInt(2, 42);
    $stmt->execute();
    $stmt->close();
    $db->commit();

    $cursor = $db->select("SELECT * FROM php_vm_exec;");
    assertNotNull($cursor);
    assertEqual(1, $cursor->numRows());
    assertEqual('10', $cursor->field(1, 1));
    assertEqual('42', $cursor->field(1, 2));

    $db->execute("DROP TABLE IF EXISTS php_vm_exec;");
    $db->commit();
    $db->disconnect();
});

runTest('VM: prepare + bind text + select', function () {
    $db = testConnectWithDb();
    $db->execute("DROP TABLE IF EXISTS php_vm_sel;");
    $db->commit();
    $db->execute("CREATE TABLE php_vm_sel (id INTEGER, name TEXT);");
    $db->commit();
    $db->execute("INSERT INTO php_vm_sel VALUES (1, 'Alice');");
    $db->commit();
    $db->execute("INSERT INTO php_vm_sel VALUES (2, 'Bob');");
    $db->commit();

    $stmt = $db->prepare("SELECT * FROM php_vm_sel WHERE name = ?1;");
    assertNotNull($stmt);
    $stmt->bindText(1, 'Alice');
    $cursor = $stmt->select();
    $stmt->close();

    assertNotNull($cursor);
    assertEqual(1, $cursor->numRows());
    assertEqual('Alice', $cursor->field(1, 2));

    $db->execute("DROP TABLE IF EXISTS php_vm_sel;");
    $db->commit();
    $db->disconnect();
});

runTest('VM: bind double', function () {
    $db = testConnectWithDb();
    $db->execute("DROP TABLE IF EXISTS php_vm_dbl;");
    $db->commit();
    $db->execute("CREATE TABLE php_vm_dbl (id INTEGER, val REAL);");
    $db->commit();

    $stmt = $db->prepare("INSERT INTO php_vm_dbl VALUES (?1, ?2);");
    assertNotNull($stmt);
    $stmt->bindInt(1, 1);
    $stmt->bindDouble(2, 3.14159);
    $stmt->execute();
    $stmt->close();
    $db->commit();

    $cursor = $db->select("SELECT val FROM php_vm_dbl;");
    assertNotNull($cursor);
    $val = $cursor->floatField(1, 1);
    assertTrue(abs($val - 3.14159) < 0.001, "expected ~3.14159, got {$val}");

    $db->execute("DROP TABLE IF EXISTS php_vm_dbl;");
    $db->commit();
    $db->disconnect();
});

runTest('VM: bind null', function () {
    $db = testConnectWithDb();
    $db->execute("DROP TABLE IF EXISTS php_vm_null;");
    $db->commit();
    $db->execute("CREATE TABLE php_vm_null (id INTEGER, val TEXT);");
    $db->commit();

    $stmt = $db->prepare("INSERT INTO php_vm_null VALUES (?1, ?2);");
    assertNotNull($stmt);
    $stmt->bindInt(1, 1);
    $stmt->bindNull(2);
    $stmt->execute();
    $stmt->close();
    $db->commit();

    $cursor = $db->select("SELECT val FROM php_vm_null;");
    assertNotNull($cursor);
    assertNull($cursor->field(1, 1), 'val should be NULL');

    $db->execute("DROP TABLE IF EXISTS php_vm_null;");
    $db->commit();
    $db->disconnect();
});

runTest('VM: bind blob', function () {
    $db = testConnectWithDb();
    $db->execute("DROP TABLE IF EXISTS php_vm_blob;");
    $db->commit();
    $db->execute("CREATE TABLE php_vm_blob (id INTEGER, data BLOB);");
    $db->commit();

    $blobData = "\x00\x01\x02\xFF\xFE\xFD";
    $stmt = $db->prepare("INSERT INTO php_vm_blob VALUES (?1, ?2);");
    assertNotNull($stmt);
    $stmt->bindInt(1, 1);
    $stmt->bindBlob(2, $blobData);
    $stmt->execute();
    $stmt->close();
    $db->commit();

    $cursor = $db->select("SELECT data FROM php_vm_blob;");
    assertNotNull($cursor);
    assertEqual(1, $cursor->numRows());
    $result = $cursor->field(1, 1);
    assertEqual($blobData, $result);

    $db->execute("DROP TABLE IF EXISTS php_vm_blob;");
    $db->commit();
    $db->disconnect();
});

// ============================================================================
// Bind via Chunks Tests
// ============================================================================

echo "\n=== Bind via Chunks Tests ===\n";

runTest('Bind: text and int params', function () {
    $db = testConnectWithDb();
    $db->execute("DROP TABLE IF EXISTS php_bind;");
    $db->commit();
    $db->execute("CREATE TABLE php_bind (id INTEGER, name TEXT);");
    $db->commit();

    $ok = $db->bind(
        "INSERT INTO php_bind VALUES (?1, ?2);",
        ['42', 'Hello'],
        [2, 5],
        [BindType::Integer->value, BindType::Text->value]
    );
    assertTrue($ok, 'bind should succeed');
    $db->commit();

    $cursor = $db->select("SELECT * FROM php_bind;");
    assertNotNull($cursor);
    assertEqual(1, $cursor->numRows());
    assertEqual('42', $cursor->field(1, 1));
    assertEqual('Hello', $cursor->field(1, 2));

    $db->execute("DROP TABLE IF EXISTS php_bind;");
    $db->commit();
    $db->disconnect();
});

runTest('Bind: NULL value', function () {
    $db = testConnectWithDb();
    $db->execute("DROP TABLE IF EXISTS php_bind_null;");
    $db->commit();
    $db->execute("CREATE TABLE php_bind_null (id INTEGER, val TEXT);");
    $db->commit();

    $ok = $db->bind(
        "INSERT INTO php_bind_null VALUES (?1, ?2);",
        ['1', null],
        [1, 0],
        [BindType::Integer->value, BindType::Null->value]
    );
    assertTrue($ok);
    $db->commit();

    $cursor = $db->select("SELECT val FROM php_bind_null;");
    assertNotNull($cursor);
    assertNull($cursor->field(1, 1));

    $db->execute("DROP TABLE IF EXISTS php_bind_null;");
    $db->commit();
    $db->disconnect();
});

// ============================================================================
// Error Handling Tests
// ============================================================================

echo "\n=== Error Handling Tests ===\n";

runTest('Error: invalid SQL', function () {
    $db = testConnectWithDb();
    $ok = $db->execute("THIS IS NOT VALID SQL;");
    assertFalse($ok, 'invalid SQL should return false');
    assertTrue($db->isError());
    assertTrue(strlen($db->errorMessage()) > 0, 'should have error message');

    // Connection should still be usable
    $ok2 = $db->execute("SELECT 1;");
    // execute with SELECT might error too, try a real execute
    $db->disconnect();
});

runTest('Error: select from nonexistent table', function () {
    $db = testConnectWithDb();
    $cursor = $db->select("SELECT * FROM nonexistent_table_xyz;");
    assertNull($cursor, 'should return null for missing table');
    assertTrue($db->isError());
    $db->disconnect();
});

runTest('Error: connection remains usable after error', function () {
    $db = testConnectWithDb();

    // Trigger an error
    $db->execute("INVALID SQL STATEMENT;");
    assertTrue($db->isError());

    // Now issue a valid query
    $cursor = $db->select("SELECT 1 AS val;");
    assertNotNull($cursor, 'should work after clearing error');
    assertEqual(1, $cursor->numRows());

    $db->disconnect();
});

// ============================================================================
// Summary
// ============================================================================

echo "\n" . str_repeat('=', 50) . "\n";
echo "Results: {$passCount} passed, {$failCount} failed, {$skipCount} skipped\n";
echo str_repeat('=', 50) . "\n";

exit($failCount > 0 ? 1 : 0);
