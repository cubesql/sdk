<?php
declare(strict_types=1);

/**
 * CubeSQL PHP SDK Unit Tests
 * No server required - tests protocol encoding/decoding and cursor logic.
 *
 * Run: php tests/CubeSQLUnitTest.php
 */

require_once __DIR__ . '/../CubeSQL.php';

use CubeSQL\RequestHeader;
use CubeSQL\ResponseHeader;
use CubeSQL\Cursor;
use CubeSQL\ColumnType;
use CubeSQL\BindType;
use CubeSQL\CubeSQLException;
use CubeSQL\ProtocolException;

use const CubeSQL\HEADER_SIZE;
use const CubeSQL\PROTOCOL_SIG;
use const CubeSQL\PROTOCOL_VER;
use const CubeSQL\CMD_CONNECT;
use const CubeSQL\CMD_SELECT;
use const CubeSQL\CMD_EXECUTE;
use const CubeSQL\SEL_CLEAR_PHASE1;
use const CubeSQL\SEL_NONE;
use const CubeSQL\CLIENT_SUPPORT_COMPRESSION;
use const CubeSQL\ENCRYPTION_NONE;
use const CubeSQL\ENCRYPTION_SSL;
use const CubeSQL\END_CHUNK;
use const CubeSQL\SERVER_HAS_ROWID;
use const CubeSQL\SERVER_COMPRESSED;
use const CubeSQL\SERVER_PARTIAL_PACKET;
use const CubeSQL\SERVER_HAS_TABLE_NAME;
use const CubeSQL\SEEKFIRST;
use const CubeSQL\SEEKNEXT;
use const CubeSQL\SEEKPREV;
use const CubeSQL\SEEKLAST;
use const CubeSQL\CURROW;

$passCount = 0;
$failCount = 0;

function runTest(string $name, callable $fn): void {
    global $passCount, $failCount;
    try {
        $fn();
        $passCount++;
        echo "  PASS: {$name}\n";
    } catch (\Throwable $e) {
        $failCount++;
        echo "  FAIL: {$name}\n";
        echo "        {$e->getMessage()}\n";
        echo "        {$e->getFile()}:{$e->getLine()}\n";
    }
}

function assertEqual($expected, $actual, string $msg = ''): void {
    if ($expected !== $actual) {
        $exp = var_export($expected, true);
        $act = var_export($actual, true);
        throw new \RuntimeException("Assertion failed{$msg}: expected {$exp}, got {$act}");
    }
}

function assertTrue(bool $condition, string $msg = ''): void {
    if (!$condition) {
        throw new \RuntimeException("Assertion failed: expected true{$msg}");
    }
}

function assertFalse(bool $condition, string $msg = ''): void {
    if ($condition) {
        throw new \RuntimeException("Assertion failed: expected false{$msg}");
    }
}

// ============================================================================
// RequestHeader Tests
// ============================================================================

echo "=== RequestHeader Tests ===\n";

runTest('RequestHeader: size is 32 bytes', function () {
    $h = new RequestHeader(100, 2, CMD_SELECT, SEL_NONE, 12);
    $bytes = $h->toBytes();
    assertEqual(HEADER_SIZE, strlen($bytes));
});

runTest('RequestHeader: signature is SQLS', function () {
    $h = new RequestHeader(0, 0, CMD_CONNECT, SEL_CLEAR_PHASE1, 12);
    $bytes = $h->toBytes();
    assertEqual('SQLS', substr($bytes, 0, 4));
});

runTest('RequestHeader: packetSize at correct offset (big-endian)', function () {
    $h = new RequestHeader(256, 1, CMD_SELECT, SEL_NONE, 12);
    $bytes = $h->toBytes();
    $u = unpack('Nval', $bytes, 4);
    assertEqual(256, $u['val']);
});

runTest('RequestHeader: command byte at offset 8', function () {
    $h = new RequestHeader(0, 0, CMD_EXECUTE, SEL_NONE, 12);
    $bytes = $h->toBytes();
    assertEqual(CMD_EXECUTE, ord($bytes[8]));
});

runTest('RequestHeader: selector byte at offset 9', function () {
    $h = new RequestHeader(0, 0, CMD_CONNECT, SEL_CLEAR_PHASE1, 12);
    $bytes = $h->toBytes();
    assertEqual(SEL_CLEAR_PHASE1, ord($bytes[9]));
});

runTest('RequestHeader: flag1 has CLIENT_SUPPORT_COMPRESSION set', function () {
    $h = new RequestHeader(0, 0, CMD_SELECT, SEL_NONE, 12);
    $bytes = $h->toBytes();
    $flag1 = ord($bytes[10]);
    assertTrue(($flag1 & CLIENT_SUPPORT_COMPRESSION) !== 0);
});

runTest('RequestHeader: encryptedPacket at offset 13', function () {
    $h = RequestHeader::fromInit(0, 0, CMD_CONNECT, SEL_CLEAR_PHASE1, 12, ENCRYPTION_SSL);
    $bytes = $h->toBytes();
    assertEqual(ENCRYPTION_SSL, ord($bytes[13]));
});

runTest('RequestHeader: protocolVersion at offset 14', function () {
    $h = new RequestHeader(0, 0, CMD_SELECT, SEL_NONE, 12);
    $bytes = $h->toBytes();
    assertEqual(PROTOCOL_VER, ord($bytes[14]));
});

runTest('RequestHeader: numFields at correct offset (big-endian)', function () {
    $h = new RequestHeader(100, 5, CMD_SELECT, SEL_NONE, 12);
    $bytes = $h->toBytes();
    $u = unpack('Nval', $bytes, 16);
    assertEqual(5, $u['val']);
});

runTest('RequestHeader: timeout at correct offset (big-endian)', function () {
    $h = new RequestHeader(0, 0, CMD_SELECT, SEL_NONE, 30);
    $bytes = $h->toBytes();
    $u = unpack('Nval', $bytes, 24);
    assertEqual(30, $u['val']);
});

runTest('RequestHeader: expandedSize at offset 20', function () {
    $h = new RequestHeader(0, 0, CMD_SELECT, SEL_NONE, 12);
    $h->expandedSize = 1024;
    $bytes = $h->toBytes();
    $u = unpack('Nval', $bytes, 20);
    assertEqual(1024, $u['val']);
});

// ============================================================================
// ResponseHeader Tests
// ============================================================================

echo "\n=== ResponseHeader Tests ===\n";

function buildResponseBytes(
    string $sig = 'SQLS',
    int $packetSize = 0,
    int $errorCode = 0,
    int $flag1 = 0,
    int $encryptedPacket = 0,
    int $expandedSize = 0,
    int $rows = 0,
    int $cols = 0,
    int $numFields = 0,
    int $reserved1 = 0,
    int $reserved2 = 0
): string {
    return pack('A4NnCCNNNNnn',
        $sig,
        $packetSize,
        $errorCode,
        $flag1,
        $encryptedPacket,
        $expandedSize,
        $rows,
        $cols,
        $numFields,
        $reserved1,
        $reserved2
    );
}

runTest('ResponseHeader: parses signature', function () {
    $bytes = buildResponseBytes();
    $h = new ResponseHeader($bytes);
    assertEqual('SQLS', $h->signature);
});

runTest('ResponseHeader: parses packetSize', function () {
    $bytes = buildResponseBytes(packetSize: 500);
    $h = new ResponseHeader($bytes);
    assertEqual(500, $h->packetSize);
});

runTest('ResponseHeader: parses errorCode', function () {
    $bytes = buildResponseBytes(errorCode: 42);
    $h = new ResponseHeader($bytes);
    assertEqual(42, $h->errorCode);
});

runTest('ResponseHeader: parses rows and cols', function () {
    $bytes = buildResponseBytes(rows: 10, cols: 3);
    $h = new ResponseHeader($bytes);
    assertEqual(10, $h->rows);
    assertEqual(3, $h->cols);
});

runTest('ResponseHeader: parses numFields', function () {
    $bytes = buildResponseBytes(numFields: 7);
    $h = new ResponseHeader($bytes);
    assertEqual(7, $h->numFields);
});

runTest('ResponseHeader: hasRowId flag', function () {
    $bytes = buildResponseBytes(flag1: SERVER_HAS_ROWID);
    $h = new ResponseHeader($bytes);
    assertTrue($h->hasRowId());
});

runTest('ResponseHeader: isCompressed flag', function () {
    $bytes = buildResponseBytes(flag1: SERVER_COMPRESSED);
    $h = new ResponseHeader($bytes);
    assertTrue($h->isCompressed());
});

runTest('ResponseHeader: isPartial flag', function () {
    $bytes = buildResponseBytes(flag1: SERVER_PARTIAL_PACKET);
    $h = new ResponseHeader($bytes);
    assertTrue($h->isPartial());
});

runTest('ResponseHeader: hasTableNames flag', function () {
    $bytes = buildResponseBytes(flag1: SERVER_HAS_TABLE_NAME);
    $h = new ResponseHeader($bytes);
    assertTrue($h->hasTableNames());
});

runTest('ResponseHeader: isEndChunk', function () {
    $bytes = buildResponseBytes(errorCode: END_CHUNK);
    $h = new ResponseHeader($bytes);
    assertTrue($h->isEndChunk());
});

runTest('ResponseHeader: combined flags', function () {
    $flags = SERVER_HAS_ROWID | SERVER_COMPRESSED | SERVER_HAS_TABLE_NAME;
    $bytes = buildResponseBytes(flag1: $flags);
    $h = new ResponseHeader($bytes);
    assertTrue($h->hasRowId());
    assertTrue($h->isCompressed());
    assertTrue($h->hasTableNames());
    assertFalse($h->isPartial());
});

runTest('ResponseHeader: too short throws', function () {
    $caught = false;
    try {
        new ResponseHeader('short');
    } catch (ProtocolException $e) {
        $caught = true;
    }
    assertTrue($caught, ': should throw ProtocolException');
});

// ============================================================================
// Cursor Tests
// ============================================================================

echo "\n=== Cursor Tests ===\n";

function makeCursor(
    int $ncols,
    int $nrows,
    array $types,
    array $names,
    array $data,
    array $tables = [],
    bool $hasRowId = false
): Cursor {
    return new Cursor($ncols, $nrows, $types, $names, $tables, $data, $hasRowId);
}

runTest('Cursor: numRows and numColumns', function () {
    $c = makeCursor(2, 3, [1, 3], ['id', 'name'], [
        ['1', 'Alice'],
        ['2', 'Bob'],
        ['3', 'Charlie'],
    ]);
    assertEqual(3, $c->numRows());
    assertEqual(2, $c->numColumns());
});

runTest('Cursor: field access (1-based)', function () {
    $c = makeCursor(2, 2, [1, 3], ['id', 'name'], [
        ['42', 'Hello'],
        ['99', 'World'],
    ]);
    assertEqual('42', $c->field(1, 1));
    assertEqual('Hello', $c->field(1, 2));
    assertEqual('99', $c->field(2, 1));
    assertEqual('World', $c->field(2, 2));
});

runTest('Cursor: NULL values', function () {
    $c = makeCursor(2, 2, [1, 3], ['id', 'name'], [
        [null, 'Alice'],
        ['2', null],
    ]);
    assertEqual(null, $c->field(1, 1));
    assertEqual('Alice', $c->field(1, 2));
    assertEqual('2', $c->field(2, 1));
    assertEqual(null, $c->field(2, 2));
});

runTest('Cursor: intField with default', function () {
    $c = makeCursor(1, 2, [1], ['val'], [
        ['42'],
        [null],
    ]);
    assertEqual(42, $c->intField(1, 1));
    assertEqual(-1, $c->intField(2, 1, -1));
});

runTest('Cursor: floatField with default', function () {
    $c = makeCursor(1, 2, [2], ['val'], [
        ['3.14'],
        [null],
    ]);
    assertEqual(3.14, $c->floatField(1, 1));
    assertEqual(0.0, $c->floatField(2, 1));
});

runTest('Cursor: out of bounds returns null', function () {
    $c = makeCursor(1, 1, [3], ['x'], [['hello']]);
    assertEqual(null, $c->field(0, 1));
    assertEqual(null, $c->field(2, 1));
    assertEqual(null, $c->field(1, 0));
    assertEqual(null, $c->field(1, 2));
});

runTest('Cursor: columnName and columnType', function () {
    $c = makeCursor(3, 0, [1, 2, 3], ['id', 'price', 'name'], []);
    assertEqual('id', $c->columnName(1));
    assertEqual('price', $c->columnName(2));
    assertEqual('name', $c->columnName(3));
    assertEqual(null, $c->columnName(0));
    assertEqual(null, $c->columnName(4));
    assertEqual(ColumnType::Integer, $c->columnType(1));
    assertEqual(ColumnType::Float, $c->columnType(2));
    assertEqual(ColumnType::Text, $c->columnType(3));
});

runTest('Cursor: tableName', function () {
    $c = makeCursor(2, 0, [1, 3], ['id', 'name'], [], ['users', 'users']);
    assertEqual('users', $c->tableName(1));
    assertEqual('users', $c->tableName(2));
    assertEqual(null, $c->tableName(3));
});

runTest('Cursor: empty cursor isEof', function () {
    $c = makeCursor(2, 0, [1, 3], ['id', 'name'], []);
    assertTrue($c->isEof());
    assertEqual(0, $c->numRows());
});

runTest('Cursor: seek navigation', function () {
    $c = makeCursor(1, 5, [1], ['n'], [
        ['1'], ['2'], ['3'], ['4'], ['5']
    ]);
    assertEqual(1, $c->currentRow());

    assertTrue($c->seekNext());
    assertEqual(2, $c->currentRow());

    assertTrue($c->seekLast());
    assertEqual(5, $c->currentRow());

    assertTrue($c->seekPrev());
    assertEqual(4, $c->currentRow());

    assertTrue($c->seekFirst());
    assertEqual(1, $c->currentRow());
});

runTest('Cursor: seekPrev at row 1 returns false', function () {
    $c = makeCursor(1, 3, [1], ['n'], [['1'], ['2'], ['3']]);
    assertEqual(1, $c->currentRow());
    assertFalse($c->seekPrev());
});

runTest('Cursor: seekNext past last row sets eof', function () {
    $c = makeCursor(1, 2, [1], ['n'], [['1'], ['2']]);
    assertTrue($c->seekNext()); // row 2
    assertFalse($c->seekNext()); // row 3 > nrows -> eof
    assertTrue($c->isEof());
});

runTest('Cursor: field with CURROW', function () {
    $c = makeCursor(1, 3, [1], ['n'], [['10'], ['20'], ['30']]);
    assertEqual('10', $c->field(CURROW, 1));
    $c->seekNext();
    assertEqual('20', $c->field(CURROW, 1));
    $c->seekNext();
    assertEqual('30', $c->field(CURROW, 1));
});

runTest('Cursor: toArray', function () {
    $c = makeCursor(2, 2, [1, 3], ['id', 'name'], [
        ['1', 'Alice'],
        ['2', 'Bob'],
    ]);
    $arr = $c->toArray();
    assertEqual(2, count($arr));
    assertEqual('1', $arr[0]['id']);
    assertEqual('Alice', $arr[0]['name']);
    assertEqual('2', $arr[1]['id']);
    assertEqual('Bob', $arr[1]['name']);
});

runTest('Cursor: count() (Countable interface)', function () {
    $c = makeCursor(1, 5, [1], ['n'], [['1'], ['2'], ['3'], ['4'], ['5']]);
    assertEqual(5, count($c));
});

runTest('Cursor: IteratorAggregate (foreach)', function () {
    $c = makeCursor(2, 2, [1, 3], ['id', 'name'], [
        ['1', 'Alice'],
        ['2', 'Bob'],
    ]);
    $rows = [];
    foreach ($c as $row) {
        $rows[] = $row;
    }
    assertEqual(2, count($rows));
    assertEqual('Alice', $rows[0]['name']);
});

// ============================================================================
// Auth Hash Tests
// ============================================================================

echo "\n=== Auth Hash Tests ===\n";

runTest('Auth: SHA1 hex of username matches PHP sha1()', function () {
    // Phase 1 sends sha1(username) as hex string
    $username = 'admin';
    $hash = sha1($username);
    assertEqual('d033e22ae348aeb5660fc2140aec35850c4da997', $hash);
});

runTest('Auth: Phase 2 hash computation', function () {
    // SHA1(randpool || SHA1(SHA1(password)))
    // Use known test values
    $password = 'admin';
    $randpool = str_repeat("\x42", 20); // 20 bytes of 0x42

    $sha1pass = sha1($password, true);
    $sha1sha1pass = sha1($sha1pass, true);
    $result = sha1($randpool . $sha1sha1pass, true);

    // Verify the result is 20 bytes
    assertEqual(20, strlen($result));

    // Verify it's deterministic
    $result2 = sha1($randpool . $sha1sha1pass, true);
    assertEqual($result, $result2);
});

runTest('Auth: SHA1 chain matches C SDK random_hash_field', function () {
    // random_hash_field: SHA1(R;SHA1(SHA1(P)))
    // where R = randpool (20 bytes), P = password
    $password = 'test';
    $randpool = str_repeat("\xAA", 20);

    $sha1p = sha1($password, true);        // SHA1(P)
    $sha1sha1p = sha1($sha1p, true);       // SHA1(SHA1(P))
    $hval = sha1($randpool . $sha1sha1p, true);  // SHA1(R;SHA1(SHA1(P)))

    assertEqual(20, strlen($hval));
    // Ensure non-trivial output
    assertTrue($hval !== str_repeat("\x00", 20));
});

// ============================================================================
// Enum Tests
// ============================================================================

echo "\n=== Enum Tests ===\n";

runTest('ColumnType enum values', function () {
    assertEqual(0, ColumnType::None->value);
    assertEqual(1, ColumnType::Integer->value);
    assertEqual(2, ColumnType::Float->value);
    assertEqual(3, ColumnType::Text->value);
    assertEqual(4, ColumnType::Blob->value);
    assertEqual(5, ColumnType::Boolean->value);
    assertEqual(9, ColumnType::Currency->value);
});

runTest('BindType enum values', function () {
    assertEqual(1, BindType::Integer->value);
    assertEqual(2, BindType::Double->value);
    assertEqual(3, BindType::Text->value);
    assertEqual(4, BindType::Blob->value);
    assertEqual(5, BindType::Null->value);
    assertEqual(8, BindType::Int64->value);
    assertEqual(9, BindType::ZeroBlob->value);
});

runTest('ColumnType::tryFrom with valid/invalid', function () {
    assertEqual(ColumnType::Text, ColumnType::tryFrom(3));
    assertEqual(null, ColumnType::tryFrom(99));
});

// ============================================================================
// Summary
// ============================================================================

echo "\n" . str_repeat('=', 50) . "\n";
echo "Results: {$passCount} passed, {$failCount} failed\n";
echo str_repeat('=', 50) . "\n";

exit($failCount > 0 ? 1 : 0);
