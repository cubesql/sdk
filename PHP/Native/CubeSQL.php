<?php
declare(strict_types=1);

namespace CubeSQL;

// ============================================================================
// Constants
// ============================================================================

const SDK_VERSION = '070000'; // 7.0.0

const DEFAULT_PORT    = 4430;
const DEFAULT_TIMEOUT = 12;

const HEADER_SIZE    = 32;
const RANDPOOL_SIZE  = 20;
const SHA1_SIZE      = 20;
const PROTOCOL_SIG   = 'SQLS';
const PROTOCOL_VER   = 4;

// Commands (client -> server)
const CMD_CONNECT      = 1;
const CMD_SELECT       = 2;
const CMD_EXECUTE      = 3;
const CMD_CLOSE        = 7;
const CMD_PING         = 8;
const CMD_CHUNK        = 9;
const CMD_ENDCHUNK     = 10;
const CMD_CURSOR_STEP  = 11;
const CMD_CURSOR_CLOSE = 12;
const CMD_CHUNK_BIND   = 19;

// VM commands
const VM_PREPARE = 50;
const VM_BIND    = 51;
const VM_EXECUTE = 52;
const VM_SELECT  = 53;
const VM_CLOSE   = 54;

// Selectors
const SEL_NONE              = 0;
const SEL_CLEAR_PHASE1      = 20;
const SEL_CLEAR_PHASE2      = 21;
const SEL_ENCRYPT_PHASE1    = 22;
const SEL_ENCRYPT_PHASE2    = 23;
const SEL_ENCRYPT_PHASE3    = 24;
const SEL_CHUNK_OK          = 25;
const SEL_CHUNK_ABORT       = 26;
const SEL_BIND_START        = 0;
const SEL_BIND_STEP         = 27;
const SEL_BIND_FINALIZE     = 28;
const SEL_BIND_ABORT        = 29;

// Client flags (flag1)
const CLIENT_SUPPORT_COMPRESSION = 0x01;
const CLIENT_COMPRESSED_PACKET   = 0x08;
const CLIENT_ADD_ROWID           = 0x10;
const CLIENT_PARTIAL_PACKET      = 0x20;
const CLIENT_REQUEST_SERVER_SIDE = 0x40;

// Server flags (flag1)
const SERVER_PROTOCOL_2009    = 0x01;
const SERVER_HAS_ROWID        = 0x04;
const SERVER_COMPRESSED       = 0x08;
const SERVER_PARTIAL_PACKET   = 0x20;
const SERVER_SERVER_SIDE      = 0x40;
const SERVER_HAS_TABLE_NAME   = 0x80;

// Encryption
const ENCRYPTION_NONE   = 0;
const ENCRYPTION_AES128 = 2;
const ENCRYPTION_AES192 = 3;
const ENCRYPTION_AES256 = 4;
const ENCRYPTION_SSL    = 8;

// Cursor field access
const COLNAME  = 0;
const CURROW   = -1;
const COLTABLE = -2;
const ROWID    = -666;

// Seek
const SEEKNEXT  = -2;
const SEEKFIRST = -3;
const SEEKLAST  = -4;
const SEEKPREV  = -5;

// Error codes
const NOERR           = 0;
const ERR             = -1;
const ERR_MEMORY      = -2;
const ERR_PARAMETER   = -3;
const ERR_PROTOCOL    = -4;
const ERR_ZLIB        = -5;
const ERR_SSL         = -6;

// END_CHUNK sentinel
const END_CHUNK = 777;

// NULL value sentinel in sizes
const NULL_VALUE = -1;

// ============================================================================
// Enums
// ============================================================================

enum ColumnType: int {
    case None      = 0;
    case Integer   = 1;
    case Float     = 2;
    case Text      = 3;
    case Blob      = 4;
    case Boolean   = 5;
    case Date      = 6;
    case Time      = 7;
    case Timestamp = 8;
    case Currency  = 9;
}

enum BindType: int {
    case Integer  = 1;
    case Double   = 2;
    case Text     = 3;
    case Blob     = 4;
    case Null     = 5;
    case Int64    = 8;
    case ZeroBlob = 9;
}

// ============================================================================
// Exceptions
// ============================================================================

class CubeSQLException extends \RuntimeException {}
class ConnectionException extends CubeSQLException {}
class ProtocolException extends CubeSQLException {}
class TimeoutException extends CubeSQLException {}

// ============================================================================
// RequestHeader (client -> server, 32 bytes)
// ============================================================================

class RequestHeader {
    public int $packetSize    = 0;
    public int $command       = 0;
    public int $selector      = 0;
    public int $flag1         = 0;
    public int $flag2         = 0;
    public int $flag3         = 0;
    public int $encryptedPacket = 0;
    public int $protocolVersion = PROTOCOL_VER;
    public int $clientType    = 0;
    public int $numFields     = 0;
    public int $expandedSize  = 0;
    public int $timeout       = 0;
    public int $reserved1     = 0;
    public int $reserved2     = 0;

    public function __construct(
        int $packetSize = 0,
        int $numFields = 0,
        int $command = 0,
        int $selector = 0,
        int $timeout = 0
    ) {
        $this->packetSize = $packetSize;
        $this->command = $command;
        $this->selector = $selector;
        $this->numFields = $numFields;
        $this->timeout = $timeout;
        $this->flag1 = CLIENT_SUPPORT_COMPRESSION;
    }

    public function toBytes(): string {
        // signature(4) + packetSize(4) + command(1) + selector(1) +
        // flag1(1) + flag2(1) + flag3(1) + encryptedPacket(1) +
        // protocolVersion(1) + clientType(1) + numFields(4) +
        // expandedSize(4) + timeout(4) + reserved1(2) + reserved2(2) = 32
        return pack('A4NC5C3NNNnn',
            PROTOCOL_SIG,
            $this->packetSize,
            $this->command,
            $this->selector,
            $this->flag1,
            $this->flag2,
            $this->flag3,
            $this->encryptedPacket,
            $this->protocolVersion,
            $this->clientType,
            $this->numFields,
            $this->expandedSize,
            $this->timeout,
            $this->reserved1,
            $this->reserved2
        );
    }

    public static function fromInit(
        int $packetSize,
        int $numFields,
        int $command,
        int $selector,
        int $timeout = 0,
        int $encryption = ENCRYPTION_NONE
    ): self {
        $h = new self($packetSize, $numFields, $command, $selector, $timeout);
        $h->encryptedPacket = $encryption;
        return $h;
    }
}

// ============================================================================
// ResponseHeader (server -> client, 32 bytes)
// ============================================================================

class ResponseHeader {
    public string $signature;
    public int $packetSize;
    public int $errorCode;
    public int $flag1;
    public int $encryptedPacket;
    public int $expandedSize;
    public int $rows;
    public int $cols;
    public int $numFields;
    public int $reserved1;
    public int $reserved2;

    public function __construct(string $bytes) {
        if (\strlen($bytes) < HEADER_SIZE) {
            throw new ProtocolException('Response header too short: ' . \strlen($bytes) . ' bytes');
        }
        $this->signature = \substr($bytes, 0, 4);
        $u = \unpack('NpacketSize', $bytes, 4);
        $this->packetSize = $u['packetSize'];
        $u = \unpack('nerrorCode', $bytes, 8);
        $this->errorCode = $u['errorCode'];
        $this->flag1 = \ord($bytes[10]);
        $this->encryptedPacket = \ord($bytes[11]);
        $u = \unpack('NexpandedSize/Nrows/Ncols/NnumFields/nreserved1/nreserved2', $bytes, 12);
        $this->expandedSize = $u['expandedSize'];
        $this->rows = $u['rows'];
        $this->cols = $u['cols'];
        $this->numFields = $u['numFields'];
        $this->reserved1 = $u['reserved1'];
        $this->reserved2 = $u['reserved2'];
    }

    public function hasRowId(): bool {
        return ($this->flag1 & SERVER_HAS_ROWID) !== 0;
    }

    public function isCompressed(): bool {
        return ($this->flag1 & SERVER_COMPRESSED) !== 0;
    }

    public function isPartial(): bool {
        return ($this->flag1 & SERVER_PARTIAL_PACKET) !== 0;
    }

    public function hasTableNames(): bool {
        return ($this->flag1 & SERVER_HAS_TABLE_NAME) !== 0;
    }

    public function isEndChunk(): bool {
        return $this->errorCode === END_CHUNK;
    }

    public function isServerSide(): bool {
        return ($this->flag1 & SERVER_SERVER_SIDE) !== 0;
    }
}

// ============================================================================
// Connection (internal transport layer)
// ============================================================================

class Connection {
    /** @var resource|null */
    private $socket = null;

    private string $host;
    private int $port;
    private string $username;
    private string $password;
    private int $timeout;
    private bool $useSSL;

    private ?ResponseHeader $lastReply = null;
    private string $inbuffer = '';
    private int $insize = 0;
    private int $toread = 0;

    private int $errcode = NOERR;
    private string $errmsg = '';

    public function __construct(
        string $host,
        int $port,
        string $username,
        string $password,
        int $timeout,
        bool $useSSL = false
    ) {
        $this->host = $host;
        $this->port = $port;
        $this->username = $username;
        $this->password = $password;
        $this->timeout = $timeout;
        $this->useSSL = $useSSL;
    }

    // --- Socket I/O --------------------------------------------------------

    public function connect(): void {
        $scheme = $this->useSSL ? 'ssl' : 'tcp';
        $addr = \gethostbyname($this->host);
        $target = "{$scheme}://{$addr}:{$this->port}";

        $context = null;
        if ($this->useSSL) {
            $context = \stream_context_create([
                'ssl' => [
                    'verify_peer' => false,
                    'verify_peer_name' => false,
                    'allow_self_signed' => true,
                ],
            ]);
        }

        $errno = 0;
        $errstr = '';
        $this->socket = $context
            ? @\stream_socket_client($target, $errno, $errstr, $this->timeout, STREAM_CLIENT_CONNECT, $context)
            : @\stream_socket_client($target, $errno, $errstr, $this->timeout);

        if ($this->socket === false) {
            $this->socket = null;
            throw new ConnectionException("Failed to connect to {$target}: {$errstr}", $errno);
        }

        \stream_set_timeout($this->socket, $this->timeout);

        // Perform clear-text authentication (Phase 1 + Phase 2)
        $this->authClearPhase1();
        $this->authClearPhase2();
    }

    private function authClearPhase1(): void {
        // Send SHA1 hex of username
        $hashUsername = \sha1($this->username); // 40 hex chars
        $data = $hashUsername . "\x00";
        $datasize = \strlen($data);
        $nfields = 1;
        $sizeArrayLen = 4 * $nfields;
        $packetSize = $datasize + $sizeArrayLen;

        $header = RequestHeader::fromInit($packetSize, $nfields, CMD_CONNECT, SEL_CLEAR_PHASE1, $this->timeout);
        $sizeArray = \pack('N', $datasize);

        $this->socketWrite($header->toBytes());
        $this->socketWrite($sizeArray);
        $this->socketWrite($data);

        // Read server response: 20-byte random pool
        $this->netRead(RANDPOOL_SIZE, 1);
    }

    private function authClearPhase2(): void {
        $randpool = $this->inbuffer;

        // Compute SHA1(randpool || SHA1(SHA1(password)))
        $sha1pass = \sha1($this->password, true);        // SHA1(P) - binary
        $sha1sha1pass = \sha1($sha1pass, true);           // SHA1(SHA1(P)) - binary
        $hval = \sha1($randpool . $sha1sha1pass, true);   // SHA1(R;SHA1(SHA1(P))) - binary

        $nfields = 1;
        $sizeArrayLen = 4 * $nfields;
        $datasize = SHA1_SIZE;
        $packetSize = $datasize + $sizeArrayLen;

        $header = RequestHeader::fromInit($packetSize, $nfields, CMD_CONNECT, SEL_CLEAR_PHASE2, $this->timeout);
        $sizeArray = \pack('N', $datasize);

        $this->socketWrite($header->toBytes());
        $this->socketWrite($sizeArray);
        $this->socketWrite($hval);

        // Read reply and check for success
        $this->netRead(0, 0);
    }

    private function socketWrite(string $data): void {
        if ($this->socket === null) {
            throw new ConnectionException('Socket is not connected');
        }
        $len = \strlen($data);
        $written = 0;
        while ($written < $len) {
            $result = @\fwrite($this->socket, \substr($data, $written));
            if ($result === false || $result === 0) {
                throw new ConnectionException('Socket write error');
            }
            $written += $result;
        }
    }

    private function socketRead(int $length): string {
        if ($this->socket === null) {
            throw new ConnectionException('Socket is not connected');
        }
        if ($length <= 0) {
            return '';
        }
        $data = '';
        $start = \time();
        while (\strlen($data) < $length) {
            if (\time() - $start > $this->timeout) {
                throw new TimeoutException('Timeout while reading from socket');
            }
            $chunk = @\fread($this->socket, $length - \strlen($data));
            if ($chunk === false || $chunk === '') {
                $meta = \stream_get_meta_data($this->socket);
                if (!empty($meta['timed_out'])) {
                    throw new TimeoutException('Socket read timed out');
                }
                if (!empty($meta['eof'])) {
                    throw new ConnectionException('Connection closed by server');
                }
                throw new ConnectionException('Socket read error');
            }
            $data .= $chunk;
        }
        return $data;
    }

    private function netRead(int $expectedSize, int $expectedFields): bool {
        // Read 32-byte header
        $headerBytes = $this->socketRead(HEADER_SIZE);
        $this->lastReply = new ResponseHeader($headerBytes);

        return $this->checkHeaderAndRead($expectedSize, $expectedFields);
    }

    private function checkHeaderAndRead(int $expectedSize, int $expectedFields): bool {
        $reply = $this->lastReply;

        if ($reply->signature !== PROTOCOL_SIG) {
            throw new ProtocolException('Wrong SIGNATURE HEADER from the server');
        }

        $isEndChunk = false;
        $err = $reply->errorCode;
        if ($err === END_CHUNK) {
            $isEndChunk = true;
            $err = 0;
        }

        if ($err !== 0) {
            $this->toread = 0;
            $errMsg = '';
            if ($reply->packetSize > 0) {
                $errMsg = $this->socketRead($reply->packetSize);
            }
            $this->errcode = $err;
            $this->errmsg = $errMsg;
            throw new CubeSQLException($errMsg, $err);
        }

        $this->toread = $reply->packetSize;

        if ($expectedSize !== -1 && $expectedSize !== $reply->packetSize) {
            throw new ProtocolException(
                "Wrong PACKET SIZE: expected {$expectedSize}, got {$reply->packetSize}"
            );
        }

        if ($expectedFields !== -1 && $expectedFields !== (int)$reply->numFields) {
            throw new ProtocolException(
                "Wrong NUMBER OF FIELDS: expected {$expectedFields}, got {$reply->numFields}"
            );
        }

        if ($isEndChunk) {
            return true;
        }

        if ($this->toread > 0) {
            $this->inbuffer = $this->socketRead($this->toread);
            $this->insize = \strlen($this->inbuffer);
        } else {
            $this->inbuffer = '';
            $this->insize = 0;
        }

        if ($reply->encryptedPacket !== ENCRYPTION_NONE) {
            throw new ProtocolException('Server sent an AES-encrypted packet (not supported in PHP SDK)');
        }

        if ($reply->isCompressed()) {
            $expanded = @\gzuncompress($this->inbuffer);
            if ($expanded === false) {
                throw new ProtocolException('Failed to decompress server response');
            }
            $this->inbuffer = $expanded;
            $this->insize = \strlen($expanded);
        }

        return $isEndChunk;
    }

    // --- Send Statement ----------------------------------------------------

    private function sendStatement(int $commandType, string $sql): void {
        $data = $sql . "\x00";
        $datasize = \strlen($data);
        $nfields = 1;
        $sizeArrayLen = 4 * $nfields;
        $packetSize = $datasize + $sizeArrayLen;

        $header = RequestHeader::fromInit($packetSize, $nfields, $commandType, SEL_NONE, $this->timeout);
        $sizeArray = \pack('N', $datasize);

        $this->socketWrite($header->toBytes());
        $this->socketWrite($sizeArray);
        $this->socketWrite($data);
    }

    // --- Public Query Methods -----------------------------------------------

    public function execute(string $sql): void {
        $this->clearErrors();
        $this->sendStatement(CMD_EXECUTE, $sql);
        $this->netRead(-1, -1);
    }

    public function select(string $sql): Cursor {
        $this->clearErrors();
        $this->sendStatement(CMD_SELECT, $sql);
        return $this->readCursor();
    }

    // --- Cursor Reading -----------------------------------------------------

    private function readCursor(): Cursor {
        $types = [];
        $names = [];
        $tables = [];
        $allData = [];
        $totalRows = 0;
        $ncols = 0;
        $hasRowId = false;
        $isFirst = true;

        $isEndChunk = $this->netRead(-1, -1);

        while (true) {
            if ($isEndChunk) {
                break;
            }

            $reply = $this->lastReply;
            $hasRowId = $reply->hasRowId();
            $serverColCount = (int)$reply->cols;
            $serverRowCount = (int)$reply->rows;
            $cursorColCount = $hasRowId ? $serverColCount - 1 : $serverColCount;
            $ncols = $cursorColCount;

            $parsed = $this->parseCursorPacket(
                $serverColCount,
                $serverRowCount,
                $hasRowId,
                $reply->hasTableNames(),
                $isFirst,
                $types,
                $names,
                $tables
            );

            $allData = \array_merge($allData, $parsed);
            $totalRows += $serverRowCount;
            $isFirst = false;

            $isPartial = $reply->isPartial();
            if (!$isPartial) {
                break;
            }

            // Send ACK for partial packet
            $this->ack(SEL_CHUNK_OK);
            $isEndChunk = $this->netRead(-1, -1);
        }

        return new Cursor($ncols, $totalRows, $types, $names, $tables, $allData, $hasRowId);
    }

    private function parseCursorPacket(
        int $serverColCount,
        int $serverRowCount,
        bool $hasRowId,
        bool $hasTables,
        bool $isFirst,
        array &$types,
        array &$names,
        array &$tables
    ): array {
        $buf = $this->inbuffer;
        $pos = 0;

        // First packet: read types, then sizes, then names, then table names, then data
        // Subsequent packets: read sizes, then data
        if ($isFirst) {
            // Read column types (serverColCount * 4 bytes)
            $types = [];
            for ($i = 0; $i < $serverColCount; $i++) {
                $t = \unpack('Nval', $buf, $pos);
                $types[] = (int)$t['val'];
                $pos += 4;
            }
        }

        // Read sizes (serverRowCount * serverColCount * 4 bytes)
        $count = $serverColCount * $serverRowCount;
        $sizes = [];
        $sums = [];
        $afterSizesPos = $pos;

        for ($i = 0; $i < $count; $i++) {
            // Read as signed 32-bit big-endian
            $raw = \unpack('Nval', $buf, $pos);
            $val = (int)$raw['val'];
            // Convert unsigned to signed for NULL detection
            if ($val === 0xFFFFFFFF) {
                $val = -1;
            }
            $sizes[] = $val;

            if ($val === -1) {
                $sums[] = ($i === 0) ? 0 : $sums[$i - 1];
            } else {
                $sums[] = ($i === 0) ? $val : ($val + $sums[$i - 1]);
            }
            $pos += 4;
        }

        // First packet: read names (null-terminated strings)
        $dataSectionStart = $pos;
        if ($isFirst) {
            $names = [];
            for ($i = 0; $i < $serverColCount; $i++) {
                $end = \strpos($buf, "\x00", $pos);
                if ($end === false) {
                    $end = \strlen($buf);
                }
                $names[] = \substr($buf, $pos, $end - $pos);
                $pos = $end + 1;
            }

            // Table names
            $tables = [];
            if ($hasTables) {
                for ($i = 0; $i < $serverColCount; $i++) {
                    $end = \strpos($buf, "\x00", $pos);
                    if ($end === false) {
                        $end = \strlen($buf);
                    }
                    $tables[] = \substr($buf, $pos, $end - $pos);
                    $pos = $end + 1;
                }
            }
        }

        // Data starts at current $pos
        $dataStart = $pos;

        // Extract row data
        $rows = [];
        $idx = 0;
        for ($row = 0; $row < $serverRowCount; $row++) {
            $rowData = [];
            for ($col = 0; $col < $serverColCount; $col++) {
                $len = $sizes[$idx];
                $offset = ($idx === 0) ? $dataStart : ($dataStart + $sums[$idx - 1]);

                // Skip rowid column (first column when hasRowId)
                if (!($hasRowId && $col === 0)) {
                    if ($len === -1) {
                        $rowData[] = null;
                    } else {
                        $rowData[] = \substr($buf, $offset, $len);
                    }
                }
                $idx++;
            }
            $rows[] = $rowData;
        }

        return $rows;
    }

    // --- VM / Prepared Statements -------------------------------------------

    public function vmPrepare(string $sql): int {
        $this->clearErrors();
        $this->sendStatement(VM_PREPARE, $sql);
        $this->netRead(-1, -1);
        return 0; // VM index (server tracks it per-connection)
    }

    public function vmBindValue(int $index, BindType $bindType, ?string $value, int $len): void {
        $nfields = 0;
        $sizeArrayLen = 0;
        $packetSize = 0;
        $datasize = 0;
        $sizeArray = '';

        if ($bindType === BindType::Null || $bindType === BindType::ZeroBlob) {
            $value = null;
        } else {
            if ($value === null) {
                $value = '';
                $len = 0;
            }
            if ($len === -1) {
                $len = \strlen($value);
            }
            $nfields = 1;
            $sizeArrayLen = 4;
            $datasize = $len;
            $packetSize = $datasize + $sizeArrayLen;
            $sizeArray = \pack('N', $datasize);
        }

        $header = RequestHeader::fromInit($packetSize, $nfields, VM_BIND, SEL_NONE, $this->timeout);
        $header->flag3 = $bindType->value;
        $header->reserved1 = $index;

        if ($bindType === BindType::ZeroBlob) {
            $header->expandedSize = $len;
        }

        // Pack the header with proper network byte order for reserved1
        $headerBytes = $this->packHeaderWithReserved1($header);

        $this->socketWrite($headerBytes);
        if ($sizeArrayLen > 0) {
            $this->socketWrite($sizeArray);
        }
        if ($value !== null && $datasize > 0) {
            $this->socketWrite($value);
        }

        $this->netRead(-1, -1);
    }

    private function packHeaderWithReserved1(RequestHeader $header): string {
        // We need reserved1 as network-order unsigned short
        return \pack('A4NC5C3NNNnn',
            PROTOCOL_SIG,
            $header->packetSize,
            $header->command,
            $header->selector,
            $header->flag1,
            $header->flag2,
            $header->flag3,
            $header->encryptedPacket,
            $header->protocolVersion,
            $header->clientType,
            $header->numFields,
            $header->expandedSize,
            $header->timeout,
            $header->reserved1,
            $header->reserved2
        );
    }

    public function vmExecute(): void {
        $this->clearErrors();
        $header = RequestHeader::fromInit(0, 0, VM_EXECUTE, SEL_NONE, $this->timeout);
        $this->socketWrite($header->toBytes());
        $this->netRead(-1, -1);
    }

    public function vmSelect(): Cursor {
        $this->clearErrors();
        $header = RequestHeader::fromInit(0, 0, VM_SELECT, SEL_NONE, $this->timeout);
        $this->socketWrite($header->toBytes());
        return $this->readCursor();
    }

    public function vmClose(): void {
        $header = RequestHeader::fromInit(0, 0, VM_CLOSE, SEL_NONE, $this->timeout);
        $this->socketWrite($header->toBytes());
        $this->netRead(-1, -1);
    }

    // --- Bind via Chunks ----------------------------------------------------

    public function bindExecute(string $sql, array $values, array $sizes, array $types): void {
        $this->clearErrors();

        // Send SQL as CHUNK_BIND command
        $this->sendStatement(CMD_CHUNK_BIND, $sql);

        // Read ACK
        $headerBytes = $this->socketRead(HEADER_SIZE);
        $this->lastReply = new ResponseHeader($headerBytes);
        $this->checkHeaderSimple();

        // Send each parameter as a chunk
        $nvalues = \count($values);
        for ($i = 0; $i < $nvalues; $i++) {
            $val = $values[$i];
            $size = $sizes[$i];
            $type = $types[$i];

            // Fix null values
            if ($type === BindType::Null->value || ($type === BindType::Text->value && $val === null)) {
                $val = '';
                $size = 0;
            }

            // For non-blob types, include the null terminator
            if ($type !== BindType::Blob->value) {
                $size++;
                $val = ($val ?? '') . "\x00";
            }

            $this->sendChunk($val, $size, $type, true);

            // Read ACK
            $headerBytes = $this->socketRead(HEADER_SIZE);
            $this->lastReply = new ResponseHeader($headerBytes);
            $this->checkHeaderSimple();
        }

        // Send BIND_FINALIZE
        $this->ackBindFinalize();
    }

    private function checkHeaderSimple(): void {
        $reply = $this->lastReply;
        if ($reply->signature !== PROTOCOL_SIG) {
            throw new ProtocolException('Wrong SIGNATURE HEADER from the server');
        }
        $err = $reply->errorCode;
        if ($err === END_CHUNK) {
            $err = 0;
        }
        if ($err !== 0) {
            $errMsg = '';
            if ($reply->packetSize > 0) {
                $errMsg = $this->socketRead($reply->packetSize);
            }
            $this->errcode = $err;
            $this->errmsg = $errMsg;
            throw new CubeSQLException($errMsg, $err);
        }
    }

    private function sendChunk(string $buffer, int $bufferLen, int $bufferType, bool $isBind): void {
        if ($isBind) {
            $header = RequestHeader::fromInit($bufferLen, 1, CMD_CHUNK_BIND, SEL_BIND_STEP, $this->timeout);
            $header->flag3 = $bufferType;
        } else {
            $header = RequestHeader::fromInit($bufferLen, 1, CMD_CHUNK, SEL_NONE, $this->timeout);
        }
        $header->flag1 |= CLIENT_PARTIAL_PACKET;

        $this->socketWrite($header->toBytes());
        if ($bufferLen > 0) {
            $this->socketWrite(\substr($buffer, 0, $bufferLen));
        }
    }

    private function ack(int $chunkCode): void {
        $header = RequestHeader::fromInit(0, 0, CMD_CHUNK, $chunkCode, $this->timeout);
        $this->socketWrite($header->toBytes());
    }

    private function ackBindFinalize(): void {
        $header = RequestHeader::fromInit(0, 0, CMD_CHUNK_BIND, SEL_BIND_FINALIZE, $this->timeout);
        $this->socketWrite($header->toBytes());
        $this->netRead(-1, -1);
    }

    // --- Data Transfer -------------------------------------------------------

    public function sendData(string $buffer, int $len): void {
        $this->sendChunk($buffer, $len, 0, false);
        $this->netRead(-1, -1);
    }

    public function sendEndData(): void {
        $header = RequestHeader::fromInit(0, 0, CMD_ENDCHUNK, SEL_NONE, $this->timeout);
        $this->socketWrite($header->toBytes());
        $this->netRead(-1, -1);
    }

    public function receiveData(): array {
        $isEndChunk = $this->netRead(-1, -1);
        if ($isEndChunk) {
            return ['data' => '', 'isEnd' => true];
        }
        // Send ACK
        $this->ack(SEL_CHUNK_OK);
        return ['data' => $this->inbuffer, 'isEnd' => false];
    }

    // --- Utilities -----------------------------------------------------------

    public function setDatabase(string $dbname): void {
        $this->execute("USE DATABASE '{$dbname}';");
    }

    public function affectedRows(): int {
        $cursor = $this->select('SHOW CHANGES;');
        if ($cursor->numRows() === 0) {
            return 0;
        }
        return (int)($cursor->intField(1, 1, 0));
    }

    public function lastInsertedRowId(): int {
        $cursor = $this->select('SHOW LASTROWID;');
        if ($cursor->numRows() === 0) {
            return 0;
        }
        return (int)($cursor->intField(1, 1, 0));
    }

    public function changes(): int {
        $cursor = $this->select('SELECT changes();');
        if ($cursor->numRows() === 0) {
            return 0;
        }
        return (int)($cursor->intField(1, 1, 0));
    }

    public function ping(): void {
        $this->execute('PING;');
    }

    public function disconnect(bool $gracefully = true): void {
        if ($this->socket === null) {
            return;
        }

        if ($gracefully) {
            try {
                $header = RequestHeader::fromInit(0, 0, CMD_CLOSE, SEL_NONE, $this->timeout);
                $this->socketWrite($header->toBytes());
                // Try to read the response but don't throw on failure
                try {
                    $this->socketRead(HEADER_SIZE);
                } catch (\Throwable $e) {
                    // Ignore read errors during disconnect
                }
            } catch (\Throwable $e) {
                // Ignore write errors during disconnect
            }
        }

        @\fclose($this->socket);
        $this->socket = null;
    }

    public function isConnected(): bool {
        return $this->socket !== null;
    }

    public function getErrorCode(): int {
        return $this->errcode;
    }

    public function getErrorMessage(): string {
        return $this->errmsg;
    }

    private function clearErrors(): void {
        $this->errcode = NOERR;
        $this->errmsg = '';
    }

    public function getLastReply(): ?ResponseHeader {
        return $this->lastReply;
    }
}

// ============================================================================
// Cursor
// ============================================================================

class Cursor implements \Countable, \IteratorAggregate {
    private int $ncols;
    private int $nrows;
    /** @var int[] column types (indexed without rowid) */
    private array $types;
    /** @var string[] column names (indexed without rowid) */
    private array $names;
    /** @var string[] table names */
    private array $tables;
    /** @var array<int, array<int, string|null>> rows[rowIdx][colIdx] (0-based internal) */
    private array $data;
    private bool $hasRowId;
    private int $currentRow = 1;
    private bool $eof = false;

    public function __construct(
        int $ncols,
        int $nrows,
        array $types,
        array $names,
        array $tables,
        array $data,
        bool $hasRowId = false
    ) {
        $this->ncols = $ncols;
        $this->nrows = $nrows;
        $this->hasRowId = $hasRowId;
        $this->data = $data;

        // Strip the rowid column from types/names if present
        if ($hasRowId && \count($types) > $ncols) {
            $this->types = \array_slice($types, 1);
        } else {
            $this->types = $types;
        }

        if ($hasRowId && \count($names) > $ncols) {
            $this->names = \array_slice($names, 1);
        } else {
            $this->names = $names;
        }

        if ($hasRowId && \count($tables) > $ncols) {
            $this->tables = \array_slice($tables, 1);
        } else {
            $this->tables = $tables;
        }

        if ($nrows === 0) {
            $this->eof = true;
        }
    }

    // --- Metadata -----------------------------------------------------------

    public function numRows(): int {
        return $this->nrows;
    }

    public function numColumns(): int {
        return $this->ncols;
    }

    public function columnName(int $column): ?string {
        if ($column < 1 || $column > $this->ncols) {
            return null;
        }
        return $this->names[$column - 1] ?? null;
    }

    public function columnType(int $column): ?ColumnType {
        if ($column < 1 || $column > $this->ncols) {
            return null;
        }
        $t = $this->types[$column - 1] ?? 0;
        return ColumnType::tryFrom($t);
    }

    public function tableName(int $column): ?string {
        if ($column < 1 || $column > $this->ncols || empty($this->tables)) {
            return null;
        }
        return $this->tables[$column - 1] ?? null;
    }

    // --- Navigation ---------------------------------------------------------

    public function seek(int $index): bool {
        if ($index === SEEKNEXT) {
            $index = $this->currentRow + 1;
        } elseif ($index === SEEKFIRST) {
            $index = 1;
        } elseif ($index === SEEKPREV) {
            $index = $this->currentRow - 1;
        } elseif ($index === SEEKLAST) {
            $index = $this->nrows;
        }

        if ($index > $this->nrows) {
            $this->eof = true;
            return false;
        }
        if ($index <= 0) {
            return false;
        }

        $this->eof = ($index === $this->nrows + 1);
        $this->currentRow = $index;
        return true;
    }

    public function seekFirst(): bool { return $this->seek(SEEKFIRST); }
    public function seekNext(): bool  { return $this->seek(SEEKNEXT); }
    public function seekPrev(): bool  { return $this->seek(SEEKPREV); }
    public function seekLast(): bool  { return $this->seek(SEEKLAST); }

    public function currentRow(): int {
        return $this->currentRow;
    }

    public function isEof(): bool {
        if ($this->nrows === 0) {
            $this->eof = true;
        }
        return $this->eof;
    }

    // --- Field Access (1-based row/col) -------------------------------------

    public function field(int $row, int $column): ?string {
        if ($row === CURROW) {
            $row = $this->currentRow;
        }
        if ($row < 1 || $row > $this->nrows) {
            return null;
        }
        if ($column < 1 || $column > $this->ncols) {
            return null;
        }
        return $this->data[$row - 1][$column - 1] ?? null;
    }

    public function intField(int $row, int $column, int $default = 0): int {
        $v = $this->field($row, $column);
        if ($v === null) {
            return $default;
        }
        return (int)$v;
    }

    public function floatField(int $row, int $column, float $default = 0.0): float {
        $v = $this->field($row, $column);
        if ($v === null) {
            return $default;
        }
        return (float)$v;
    }

    public function stringField(int $row, int $column): ?string {
        return $this->field($row, $column);
    }

    // --- Conversion ---------------------------------------------------------

    public function toArray(): array {
        $result = [];
        for ($r = 0; $r < $this->nrows; $r++) {
            $row = [];
            for ($c = 0; $c < $this->ncols; $c++) {
                $name = $this->names[$c] ?? "col{$c}";
                $row[$name] = $this->data[$r][$c] ?? null;
            }
            $result[] = $row;
        }
        return $result;
    }

    // --- Countable / IteratorAggregate --------------------------------------

    public function count(): int {
        return $this->nrows;
    }

    public function getIterator(): \ArrayIterator {
        return new \ArrayIterator($this->toArray());
    }
}

// ============================================================================
// PreparedStatement
// ============================================================================

class PreparedStatement {
    private Connection $conn;
    private int $vmIndex;
    private bool $closed = false;

    public function __construct(Connection $conn, int $vmIndex) {
        $this->conn = $conn;
        $this->vmIndex = $vmIndex;
    }

    public function bindInt(int $index, int $value): void {
        $this->conn->vmBindValue($index, BindType::Integer, (string)$value, -1);
    }

    public function bindDouble(int $index, float $value): void {
        $this->conn->vmBindValue($index, BindType::Double, \sprintf('%f', $value), -1);
    }

    public function bindText(int $index, string $value): void {
        $this->conn->vmBindValue($index, BindType::Text, $value, \strlen($value));
    }

    public function bindBlob(int $index, string $value): void {
        $this->conn->vmBindValue($index, BindType::Blob, $value, \strlen($value));
    }

    public function bindNull(int $index): void {
        $this->conn->vmBindValue($index, BindType::Null, null, 0);
    }

    public function bindInt64(int $index, int $value): void {
        $this->conn->vmBindValue($index, BindType::Int64, (string)$value, -1);
    }

    public function bindZeroBlob(int $index, int $len): void {
        $this->conn->vmBindValue($index, BindType::ZeroBlob, null, $len);
    }

    public function execute(): void {
        $this->conn->vmExecute();
    }

    public function select(): Cursor {
        return $this->conn->vmSelect();
    }

    public function close(): void {
        if (!$this->closed) {
            $this->conn->vmClose();
            $this->closed = true;
        }
    }

    public function __destruct() {
        // Don't auto-close to avoid surprises with disconnected sockets
    }
}

// ============================================================================
// CubeSQL (public facade)
// ============================================================================

class CubeSQL {
    private ?Connection $conn = null;
    private int $errcode = NOERR;
    private string $errmsg = '';

    public function connect(
        string $host,
        int $port = DEFAULT_PORT,
        string $username = 'admin',
        string $password = 'admin',
        int $timeout = DEFAULT_TIMEOUT,
        bool $ssl = false
    ): bool {
        $this->resetError();
        try {
            $this->conn = new Connection($host, $port, $username, $password, $timeout, $ssl);
            $this->conn->connect();
            return true;
        } catch (\Throwable $e) {
            $this->errcode = $e->getCode() ?: ERR;
            $this->errmsg = $e->getMessage();
            return false;
        }
    }

    public function connectDatabase(
        string $host,
        int $port,
        string $username,
        string $password,
        string $database,
        int $timeout = DEFAULT_TIMEOUT,
        bool $ssl = false
    ): bool {
        if (!$this->connect($host, $port, $username, $password, $timeout, $ssl)) {
            return false;
        }
        try {
            $this->conn->setDatabase($database);
            return true;
        } catch (\Throwable $e) {
            $this->errcode = $e->getCode() ?: ERR;
            $this->errmsg = $e->getMessage();
            return false;
        }
    }

    public function disconnect(): void {
        if ($this->conn) {
            $this->conn->disconnect();
            $this->conn = null;
        }
    }

    public function execute(string $sql): bool {
        $this->resetError();
        try {
            $this->conn->execute($sql);
            return true;
        } catch (\Throwable $e) {
            $this->errcode = $e->getCode() ?: ERR;
            $this->errmsg = $e->getMessage();
            return false;
        }
    }

    public function select(string $sql): ?Cursor {
        $this->resetError();
        try {
            return $this->conn->select($sql);
        } catch (\Throwable $e) {
            $this->errcode = $e->getCode() ?: ERR;
            $this->errmsg = $e->getMessage();
            return null;
        }
    }

    public function prepare(string $sql): ?PreparedStatement {
        $this->resetError();
        try {
            $vmIndex = $this->conn->vmPrepare($sql);
            return new PreparedStatement($this->conn, $vmIndex);
        } catch (\Throwable $e) {
            $this->errcode = $e->getCode() ?: ERR;
            $this->errmsg = $e->getMessage();
            return null;
        }
    }

    public function bind(string $sql, array $values, array $sizes, array $types): bool {
        $this->resetError();
        try {
            $this->conn->bindExecute($sql, $values, $sizes, $types);
            return true;
        } catch (\Throwable $e) {
            $this->errcode = $e->getCode() ?: ERR;
            $this->errmsg = $e->getMessage();
            return false;
        }
    }

    public function beginTransaction(): bool {
        return $this->execute('BEGIN TRANSACTION;');
    }

    public function commit(): bool {
        return $this->execute('COMMIT;');
    }

    public function rollback(): bool {
        return $this->execute('ROLLBACK;');
    }

    public function sendData(string $buffer, int $len): bool {
        $this->resetError();
        try {
            $this->conn->sendData($buffer, $len);
            return true;
        } catch (\Throwable $e) {
            $this->errcode = $e->getCode() ?: ERR;
            $this->errmsg = $e->getMessage();
            return false;
        }
    }

    public function sendEndData(): bool {
        $this->resetError();
        try {
            $this->conn->sendEndData();
            return true;
        } catch (\Throwable $e) {
            $this->errcode = $e->getCode() ?: ERR;
            $this->errmsg = $e->getMessage();
            return false;
        }
    }

    public function receiveData(): ?array {
        $this->resetError();
        try {
            return $this->conn->receiveData();
        } catch (\Throwable $e) {
            $this->errcode = $e->getCode() ?: ERR;
            $this->errmsg = $e->getMessage();
            return null;
        }
    }

    public function ping(): bool {
        $this->resetError();
        try {
            $this->conn->ping();
            return true;
        } catch (\Throwable $e) {
            $this->errcode = $e->getCode() ?: ERR;
            $this->errmsg = $e->getMessage();
            return false;
        }
    }

    public function setDatabase(string $dbname): bool {
        $this->resetError();
        try {
            $this->conn->setDatabase($dbname);
            return true;
        } catch (\Throwable $e) {
            $this->errcode = $e->getCode() ?: ERR;
            $this->errmsg = $e->getMessage();
            return false;
        }
    }

    public function affectedRows(): int {
        try {
            return $this->conn->affectedRows();
        } catch (\Throwable $e) {
            return 0;
        }
    }

    public function lastInsertedRowId(): int {
        try {
            return $this->conn->lastInsertedRowId();
        } catch (\Throwable $e) {
            return 0;
        }
    }

    public function isError(): bool {
        return $this->errcode !== NOERR;
    }

    public function errorCode(): int {
        return $this->errcode;
    }

    public function errorMessage(): string {
        return $this->errmsg;
    }

    public function getConnection(): ?Connection {
        return $this->conn;
    }

    private function resetError(): void {
        $this->errcode = NOERR;
        $this->errmsg = '';
    }
}
