<?php

/**
 *    Native PHP connector for CubeSQL based on official C SDK
 *
 *    Only unencrypted connections are supported in this version
 *    but SSL can be used.
 *
 * @author Marco Bambini <marco@sqlabs.com>
 * @see    https://github.com/cubesql/connectors
 */


/**
 * Class inhead
 *
 * client -> server header
 */
class inhead
{
    public $signature; //unsigned int					// PROTOCOL_SIGNATURE defined as 'SQLS'
    public $packetSize; //unsigned int					// size of the entire packet (header excluded)
    public $command; //unsigned char					// main command
    public $selector; //unsigned char					// sub command selector
    public $flag1; //unsigned char						// bit field
    public $flag2; //unsigned char						// bit field
    public $flag3; //unsigned char						// bit field
    public $encryptedPacket; //unsigned char			// kEmptyField, kAESNONE, kAES128, kAES192, kAES256
    public $protocolVersion; //unsigned char			// always 3 in 2007, 4 in 2011
    public $clientType; //unsigned char					// always 3 in 2007 and 2008
    public $numFields; //unsigned int					// number of fields in the command (I could use 2 bytes instead of 4)
    public $expandedSize; //unsigned int				// if packet is compressed, this is the expanded size of the packet
    public $timeout; //unsigned int						// timeout value
    public $reserved1; //unsigned short					// unused in this version
    public $reserved2; //unsigned short					// unused in this version

    public function to_bytes()
    {
        $r = '';
        $r .= $this->signature;
        $r .= $this->packetSize;
        $r .= $this->command;
        $r .= $this->selector;
        $r .= $this->flag1 . $this->flag2 . $this->flag3;
        $r .= $this->encryptedPacket;
        $r .= $this->protocolVersion;
        $r .= $this->clientType;
        $r .= $this->numFields;
        $r .= $this->expandedSize;
        $r .= $this->timeout;
        $r .= $this->reserved1;
        $r .= $this->reserved2;
        return $r;
    }

    public function __construct($packetsize, $nfields, $command, $selector, $timeout)
    {
        $this->signature = 'SQLS';//pack('V',[ord('S'),ord('Q'),ord('L'),ord('S')]);
        $this->packetSize = pack('N', $packetsize);
        $this->command = pack('C', $command);
        $this->selector = pack('C', $selector);
        $this->flag1 = pack('C', 0x01); //CLIENT_SUPPORT_COMPRESSION
        $this->flag2 = pack('C', 0x00);
        $this->flag3 = pack('C', 0x00);
        $this->encryptedPacket = pack('C', 0); //kAESNONE
        $this->numFields = pack('N', $nfields);
        $this->expandedSize = pack('N', 0);
        $this->timeout = pack('N', $timeout);
        $this->protocolVersion = pack('C', 4); //k2011PROTOCOL;
        $this->clientType = pack('C', 0);
        $this->reserved1 = pack('v', 0);
        $this->reserved2 = pack('v', 0);
    }
}


/**
 * Class outhead
 *
 * server -> client header
 */
class outhead
{
    /** @var  int (unsigned) PROTOCOL_SIGNATURE defined as 'SQLS' */
    public $signature;

    /** @var  int (unsigned) size of the entire packet (header excluded) */
    public $packetSize;

    /** @var  int (unsigned short) 0 means no error */
    public $errorCode;

    /** @var  string (unsigned char) bit field */
    public $flag1;

    /** @var  string (unsigned char) kEmptyField, kAESNONE, kAES128, kAES192, kAES256 */
    public $encryptedPacket;

    /** @var  int (unsigned) if flag1 is COMPRESSED_PACKET this is the expanded size of the entire buffer */
    public $expandedSize;

    /** @var  int (unsigned) number of rows in the cursor */
    public $rows;

    /** @var  int (unsigned) number of columns in the cursor (it could be 2 bytes instead of 4?) */
    public $cols;

    /** @var  int (unsigned) number of fields in the command (I could use 2 bytes instead of 4) */
    public $numFields;

    /** @var  int (unsigned short) unused in this version */
    public $reserved1;

    /** @var  int (unsigned short) unused in this version */
    public $reserved2;

    /**
     * outhead constructor.
     * @param string $bytes
     */
    function __construct($bytes)
    {
        // Unpack binary data
        $unpackedData = unpack("NpacketSize", substr($bytes, 4, 4));
        $unpackedData += unpack("nerrorCode", substr($bytes, 8, 2));
        $unpackedData += unpack("NexpandedSize", substr($bytes, 12, 4));
        $unpackedData += unpack("Nrows", substr($bytes, 16, 4));
        $unpackedData += unpack("Ncols", substr($bytes, 20, 4));
        $unpackedData += unpack("NnumFields", substr($bytes, 24, 4));
        $unpackedData += unpack("nreserved1", substr($bytes, 28, 2));
        $unpackedData += unpack("nreserved2", substr($bytes, 30, 2));
            // Map data to properties
        $this->signature = substr($bytes, 0, 4);
        $this->packetSize = $unpackedData["packetSize"];
        $this->errorCode = $unpackedData["errorCode"];
        $this->flag1 = ord(substr($bytes, 10, 1));
        $this->encryptedPacket = ord(substr($bytes, 11, 1));
        $this->expandedSize = $unpackedData["expandedSize"];
        $this->rows = $unpackedData["rows"];
        $this->cols = $unpackedData["cols"];
        $this->numFields = $unpackedData["numFields"];
        $this->reserved1 = $unpackedData["reserved1"];
        $this->reserved2 = $unpackedData["reserved2"];
    }
}


/**
 * Class csqldb
 *
 * @author Marco Bambini <marco@sqlabs.com>
 */
class csqldb
{
    /** @var  int Timeout used in the socket I/O operations */
    public $timeout;

    /** @var  mixed The socket */
    public $sockfd;

    /** @var  int Port used for the connection */
    public $port;

    /** @var  string Hostname */
    public $host;

    /** @var  string Username */
    public $username;

    /** @var  string Password */
    public $password;

    /** @var string Last error message */
    public $errormsg;

    /** @var int Last error code */
    public $errorcode;

//	public $useOldProtocol;	// flag to set if you want to use the old REALSQLServer protocol
    public $verifyPeer; // flag to check if peer verification must be performed

//	char			*token;						// optional token used in token connect
//	char			*hostverification;			// optional host verification name to use in SSL peer verification
//	void			*userptr;					// optional pointer saved by the user
//	int				encryption;					// kAESNONE - kAES128 - kAES192 - kAES256
//	aes_encrypt_ctx	encryptkey[1];				// session key used to encrypt data
//	aes_decrypt_ctx decryptkey[1];				// session key used to decrypt data

    public $toread;
    public $inbuffer;
    public $insize;

    /** @var inhead object Request Header */
    public $request;

    /** @var  outhead object Response Header */
    public $reply;

    //SSL_CTX			*ssl_ctx;
    //SSL				*ssl;

    //void (*trace)  (const char*, void*);		// trace function
    //void			*traceArgument;				// user argument to be passed to the trace function
    public function __construct($host, $port, $username, $password, $timeout)
    {
        $this->host = $host;
        $this->port = $port;
        $this->username = $username;
        $this->password = $password;
        $this->timeout = $timeout;

        //connect
        $addr = gethostbyname($this->host); //no way to specify a timeout
        $this->socketfd = stream_socket_client("tcp://$addr:" . $this->port, $this->errorcode, $this->errormsg, $this->timeout);

        if ($this->socketfd === false) {
            $this->errorcode = -1;
            $this->errormsg = "Failed to connect: '" . $this->errormsg . "'";
            throw new UnexpectedValueException("Failed to connect: '" . $this->errormsg . "'");
        }
        $nfields = 1;
        $sizeof_int = 4;
        $nsizedim = $sizeof_int * $nfields;
        $SHA1_DIGEST_SIZE = 20;
        $datasize = $SHA1_DIGEST_SIZE * 2 + 1;
        $packet_size = $datasize + $nsizedim;
        $kCOMMAND_CONNECT = 1;
        $kCLEAR_CONNECT_PHASE1 = 20;
        $this->request = new inhead($packet_size, $nfields, $kCOMMAND_CONNECT, $kCLEAR_CONNECT_PHASE1, $this->timeout);
        $field_size = pack('N', $datasize);
        $this->netwrite($field_size, sha1($this->username) . chr(0));

        // read random pool
        $kRANDPOOLSIZE = 20;
        $this->netread($kRANDPOOLSIZE, 1);
        $randpool = $this->inbuffer;

        $nfields = 1;
        $sizeof_int = 4;
        $nsizedim = $sizeof_int * $nfields;
        $datasize = $SHA1_DIGEST_SIZE;

        // build packet
        $packet_size = $datasize + $nsizedim;
        $kCLEAR_CONNECT_PHASE2 = 21;
        $this->request = new inhead($packet_size, $nfields, $kCOMMAND_CONNECT, $kCLEAR_CONNECT_PHASE2, $this->timeout);
        $field_size = pack('N', $SHA1_DIGEST_SIZE);
        $this->netwrite($field_size, sha1($randpool . sha1(sha1($this->password, true), true), true));
        // read header reply and sanity check it
        $this->netread(0, 0);
    }

    function disconnect()
    {
        $kCOMMAND_CLOSE = 7;
        $kNO_SELECTOR = 0;
        $this->request = new inhead(0, 0, $kCOMMAND_CLOSE, $kNO_SELECTOR, $this->timeout);
        fwrite($this->socketfd, $this->request->to_bytes());
        $this->netread(-1, -1);
    }

    function checkheader($expected_size, $expected_nfields)
    {
        /***************************************************************
         * echo "packetSize: ".$this->reply->packetSize."\n";
         * echo "errorCode: ".$this->reply->errorCode."\n";
         * echo "flag1: ".$this->reply->flag1."\n";
         * echo "encryptedPacket: ".$this->reply->encryptedPacket."\n";
         * echo "expandedSize: ".$this->reply->expandedSize."\n";
         * echo "rows: ".$this->reply->rows."\n";
         * echo "cols: ".$this->reply->cols."\n";
         * echo "numFields: ".$this->reply->numFields."\n";
         * echo "reserved1: ".$this->reply->reserved1."\n";
         * echo "reserved2: ".$this->reply->reserved2."\n";
         ***************************************************************/
        if ($this->reply->signature != "SQLS") {
            $this->errormsg = "Wrong SIGNATURE HEADER from the server";
            $this->errorcode = -1;
            throw new UnexpectedValueException("Wrong SIGNATURE HEADER from the server");
        }
        $is_end_chunk = false;
        $END_CHUNK = 777;
        if ($this->reply->errorCode == $END_CHUNK) {
            $is_end_chunk = true;
            $err = 0;
        } else {
            $err = $this->reply->errorCode;
        }
        if ($err) {
            $this->toread = 0;
            $bytes = $this->socket_read($this->reply->packetSize);
            $this->errorcode = $err;
            $this->errormsg = "Error from server: '$bytes'";
            throw new UnexpectedValueException("Error from server: '$bytes'");

        } else {
            $this->toread = $this->reply->packetSize;
        }

        if ($expected_size != -1 && $expected_size != $this->reply->packetSize) {
            $this->errorcode = -1;
            $this->errormsg = "Wrong PACKET SIZE received from the server";
            throw new UnexpectedValueException("Wrong PACKET SIZE received from the server");
        }

        if ($expected_nfields != -1 && $expected_nfields != $this->reply->numFields) {
            $this->errorcode = -1;
            $this->errormsg = "Wrong NUMBER OF FIELDS received from the server";
            throw new UnexpectedValueException("Wrong NUMBER OF FIELDS received from the server");
        }
        return $is_end_chunk;

    }

    /**
     * @param int    $command_type
     * @param string $sql
     */
    function send_statement($command_type, $sql)
    {
        $nfields = 1;
        $sizeof_int = 4;
        $nsizedim = $sizeof_int * $nfields;
        $datasize = strlen($sql) + 1;

        // build packet
        $packet_size = $datasize + $nsizedim;
        $kNO_SELECTOR = 0;
        $this->request = new inhead($packet_size, $nfields, $command_type, $kNO_SELECTOR, $this->timeout);
        $field_size = pack('N', $datasize);
        $this->netwrite($field_size, $sql . chr(0));
    }

    function netwrite($size_array, $buffer)
    {
        fwrite($this->socketfd, $this->request->to_bytes());
        fwrite($this->socketfd, $size_array);
        fwrite($this->socketfd, $buffer);
    }

    function socket_read($expected_size)
    {
        $bytes = "";
        $start = time();
        while (strlen($bytes) < $expected_size) {
            if (time() - $start > $this->timeout) {
                $this->errorcode = -1;
                $this->errormsg = "Timeout while reading from network socket.";
                throw new UnexpectedValueException("Timeout while reading from network socket.");
            }
            $bytes .= fread($this->socketfd, $expected_size - strlen($bytes));
        }
        return $bytes;

    }

    function netread($expected_size, $expected_nfields)
    {
        $kHEADER_SIZE = 32;
        $bytes = $this->socket_read($kHEADER_SIZE);
        /***************************************************************
         * echo "netread: ";
         * for($j=0;$j<strlen($bytes);$j++) {
         * echo sprintf("%02x ",ord($bytes[$j]));
         * }
         * echo "\n";
         ***************************************************************/
        $this->reply = new outhead($bytes);
        $is_end_chunk = $this->checkheader($expected_size, $expected_nfields);
        if ($is_end_chunk) return true;
        if ($this->toread > 0) {
            $this->inbuffer = $this->socket_read($this->toread);
        }
        $kAESNONE = 0;
        if ($this->reply->encryptedPacket != $kAESNONE) {
            $this->errorcode = -1;
            $this->errormsg = "Server sent an encrypted packet.";
            throw new UnexpectedValueException("Server sent an encrypted packet.");
        }
        $SERVER_COMPRESSED_PACKET = 0x08;
        if ($this->reply->flag1 & $SERVER_COMPRESSED_PACKET) {
            $this->inbuffer = gzuncompress($this->inbuffer);
        }

        return $is_end_chunk;
    }

    function parse_packet(&$server_types, &$col_names)
    {
        $nfields = $this->reply->numFields;
        $server_rowcount = $this->reply->rows;
        $nrows = $this->reply->rows;

        //$SERVER_PARTIAL_PACKET = 0x20;
        //print "read_cursor() !is_end_chunk: ".!$is_end_chunk."\n";
        //print "(this->reply->flag1 & SERVER_PARTIAL_PACKET): ".!!(($this->reply->flag1 & $SERVER_PARTIAL_PACKET))."\n";
        //print "read_cursor() nrows: $nrows\n";

        $server_colcount = $this->reply->cols;
        $SERVER_HAS_ROWID_COLUMN = 0x04;
        if ($this->reply->flag1 & $SERVER_HAS_ROWID_COLUMN) {
            $has_rowid = true;
            $ncols = $this->reply->cols - 1;
        } else {
            $has_rowid = false;
            $ncols = $this->reply->cols;
        }
        $SERVER_HAS_TABLE_NAME = 0x80;
        if ($this->reply->flag1 & $SERVER_HAS_TABLE_NAME) {
            $has_tables = true;
        } else {
            $has_tables = false;
        }

        $sizeof_int = 4;
        if (count($server_types) == 0) {
            $server_sizes = $sizeof_int * $server_colcount;
            for ($j = 0; $j < $server_colcount; $j++) {
                $type = unpack("Ntype", substr($this->inbuffer, $j * $sizeof_int, 4));
                $type = $type["type"];
                //echo "type $j: $type\n";
            }
            $server_names = $server_sizes + ($server_rowcount * $server_colcount * $sizeof_int);
            $server_data = $server_names;
            $temp = $server_names;
            $data_seek = 0;
            for ($j = 0; $j < $server_colcount; $j++) {
                $len = strpos($this->inbuffer, 0, $temp) - $temp + 1;
                $col_names[$j] = substr($this->inbuffer, $temp, $len - 1);
                $data_seek += $len;
                $temp += $len;
                $server_types[$j] = unpack("Ntype", substr($this->inbuffer, $j * $sizeof_int, 4));
                $server_types[$j] = $server_types[$j]["type"];
            }
            $table_names = array();
            if ($has_tables) {
                $server_tables = $server_data + $data_seek;
                $temp = $server_tables;
                for ($j = 0; $j < $server_colcount; $j++) {
                    $len = strpos($this->inbuffer, 0, $temp) - $temp + 1;
                    $table_names[$j] = substr($this->inbuffer, $temp, $len - 1);
                    $data_seek += $len;
                    $temp += $len;
                }
            }
            $server_data += $data_seek;
            $after_sizes_if_exist = $sizeof_int * $server_colcount;
        } else {
            $server_data = $sizeof_int * $server_colcount * $nrows;
            $after_sizes_if_exist = 0;
        }
        $count = $server_colcount * $server_rowcount;
        $server_sizes = array();
        $server_sum = array();
        for ($j = 0; $j < $count; $j++) {
            $pos = $after_sizes_if_exist + $j * $sizeof_int;
            if ($pos + 4 >= strlen($this->inbuffer)) {
                throw new UnexpectedValueException("Buffer from server too short.");
            }
            $server_sizes[$j] = unpack("lsize", strrev(substr($this->inbuffer, $pos, 4)));
            $server_sizes[$j] = $server_sizes[$j]["size"];
            if ($server_sizes[$j] == -1) //if ($server_sizes[$j] == 4294967295)  //interesting side-effect of unpack not returning -1 for a value of FF FF FF FF.
            {
                $server_sizes[$j] = -1;
                // special NULL case
                if ($j == 0) {
                    $server_sum[$j] = 0;
                } else {
                    $server_sum[$j] = $server_sum[$j - 1];
                }
            } else {
                if ($j == 0) {
                    $server_sum[$j] = $server_sizes[$j];
                } else {
                    $server_sum[$j] = $server_sizes[$j] + $server_sum[$j - 1];
                }
            }
        }
        $data = array();
        $j = 0;
        for ($row = 0; $row < $nrows; $row++) {
            $rowdata = array();
            for ($col = 0; $col < $server_colcount; $col++) {
                $len = $server_sizes[$j];
                if ($j == 0) {
                    $pos = $server_data;
                } else {
                    $pos = $server_data + $server_sum[$j - 1];
                }
                if (!($has_rowid && $col == 0)) {
                    if ($server_sizes[$j] == -1) {
                        $val = NULL;
                    } else {
                        //syslog(1, "pulling out $len characters from inbuffer starting from ". $pos);
                        $str = substr($this->inbuffer, $pos, $len);
                        //syslog(1, "pulled out: " . $str);
                        $type = $server_types[$col];
                        switch ($type) {
                            case 0: //None
                                $val = $str;
                                break;
                            case 1: //Integer
                                $val = intval($str);
                                break;
                            case 2: //Float
                                $val = floatval($str);
                                break;
                            case 3: //REAL or TEXT (maybe should be UTF-8???)
                                $val = $str;
                                break;
                            case 4: //BLOB (definitely not UTF-8)
                                $val = $str;
                                break;
                            case 5: //None
                                $val = boolval($str);
                                break;
                            case 6: //Date
                                $val = $str;
                                break;
                            case 7: //Time
                                $val = $str;
                                break;
                            case 8: //Timestamp
                                $val = $str;
                                break;
                            case 9: //Currency
                                $val = floatval($str);
                                break;
                            default:
                                syslog(1, "unknown type: $type, for data: '$str'\n");
                                $val = $str;
                        }
                    }
                    $rowdata[$col_names[$col]] = $val;
                }
                $j++;
            }
            $data[$row] = $rowdata;
        }
        //echo "nrows: $nrows, ncols: $ncols\n";
        //var_dump($table_names); //if $has_rowid, the first table_name can be dropped
        //var_dump($col_names); //if $has_rowid, the first col_name can be dropped
        //var_dump($server_types); //if $has_rowid, the first server_type can be dropped
        //syslog(1,"*#$*#$*#*$:parse_packet::complete.");

        return $data;
    }

    function read_cursor()
    {
        //print "---------\n";
        //print "read_cursor()\n";
        $is_end_chunk = $this->netread(-1, -1);
        $server_types = array();
        $col_names = array();
        $data = $this->parse_packet($server_types, $col_names);
        //echo "server_types: ";
        //print_r($server_types);
        //echo "\n";
        //echo "col_names: ";
        //print_r($col_names);
        //echo "\n";
        //syslog(1, "read_cursor::first packet: " . var_export($data, true));
        $SERVER_PARTIAL_PACKET = 0x20;

        while (!$is_end_chunk && ($this->reply->flag1 & $SERVER_PARTIAL_PACKET)) {
            $kCHUNK_OK = 25;
            $this->ack($kCHUNK_OK);
            $is_end_chunk = $this->netread(-1, -1);
            if (!$is_end_chunk) {
                //$inbuffer .= $this->inbuffer;
                //$nrows += $this->reply->rows;
                //print "read_cursor() ";
                //print $this->reply->rows;
                //print " more rows\n";
                //syslog(1, "read_cursor:: reading another row....");
                $newData = $this->parse_packet($server_types, $col_names);
                //syslog(1, "read_cursor:: new row data: " . var_export($newData, true));
                $data = array_merge($data, $newData);
                //syslog(1, "read_cursor::merged new data.  Now have: " . var_export($data, true));
                //syslog(1, "=---------=");
            }
        }
        return $data;
    }

    function ack($chunk_code)
    {
        //if ($chunk_code == $kCOMMAND_ENDCHUNK) {
        //	initrequest(db, 0, 0, kCOMMAND_ENDCHUNK, kNO_SELECTOR);
        //	csql_netwrite(db, NULL, 0, NULL, 0);
        //	return csql_netread(db, -1, -1, kFALSE, NULL, NO_TIMEOUT);
        //}
        //
        //if ((chunk_code == kBIND_FINALIZE) || (chunk_code == kBIND_ABORT)) {
        //	initrequest(db, 0, 0, kCOMMAND_CHUNK_BIND, chunk_code);
        //	csql_netwrite(db, NULL, 0, NULL, 0);
        //	return csql_netread(db, -1, -1, kFALSE, NULL, NO_TIMEOUT);
        //}
        $kCOMMAND_ENDCHUNK = 10;
        $kBIND_FINALIZE = 28;
        $kBIND_ABORT = 29;
        if ($chunk_code == $kCOMMAND_ENDCHUNK ||
            $chunk_code == $kBIND_FINALIZE ||
            $chunk_code == $kBIND_ABORT
        ) {
            throw new UnexpectedValueException("ack called with unexpected chunk_code value.");
        }
        // other cases
        $packet_size = 0;
        $nfields = 0;
        $kCOMMAND_CHUNK = 9;
        $this->request = new inhead($packet_size, $nfields, $kCOMMAND_CHUNK, $chunk_code, $this->timeout);
        //function netwrite($size_array, $buffer)
        //int csql_netwrite (csqldb *db, char *size_array, int nsize_array, char *buffer, int nbuffer)
        return $this->netwrite('', '');
    }

}

/**
 * Class cubeSQLServer
 *
 * The cubeSQLServer is a class that allows to connect to a cubeSQL server open a database and send SQL statements or
 * queries to that database. It returns the results for queries as an array. Errors that occur during this process are
 * stored within the error properties of that object.
 */
class cubeSQLServer
{
    /** @var  csqldb object Stores the connection object. */
    public $db;

    /** @var  int Stores the error code. 0 means no error. */
    public $errorCode;

    /** @var  string Stores the error message. */
    public $errorMessage;

    /**
     * Connect to CubeSQL instance
     *
     * On host and port using username and password. Allowing up to timeout for connection to
     * occur. Sets internal error indicators errorCode and errorMessage on error. Returns boolean connection status.
     *
     * @param string $host     Hostname/IP of the cubeSQL Server
     * @param int    $port     Port number of the cubeSQL Server
     * @param string $username Username
     * @param string $password Password
     * @param int    $timeout  [optional] Time until the connection attempt fails. Default is 12 seconds.
     * @return bool True on success, false on failure
     */
    public function connect($host, $port, $username, $password, $timeout = 12)
    {
        $this->_resetError();

        try {
            $this->db = new csqldb($host, $port, $username, $password, $timeout);
        } catch (Exception $e) {
            $this->errorCode = $this->db->errorcode;
            $this->errorMessage = $this->db->errormsg;
            syslog(1, $e);
        }

        return !$this->isError();
    }

    /**
     * Connect to CubeSQL instance and open a database
     *
     * On host and port using username and password and opens a database. Allowing up to timeout for connection to
     * occur. Sets internal error indicators errorCode and errorMessage on error. Returns boolean connection status.
     *
     * @param string $host     Hostname/IP of the cubeSQL Server
     * @param int    $port     Port number of the cubeSQL Server
     * @param string $username Username
     * @param string $password Password
     * @param string $database Name of the database
     * @param int    $timeout  [optional] Time until the connection attempt fails. Default is 12 seconds.
     * @return bool True on success, false on failure
     */
    public function connect_database($host, $port, $username, $password, $database, $timeout = 12)
    {
        $this->_resetError();
        try {
            $this->db = new csqldb($host, $port, $username, $password, $timeout);
            $kCOMMAND_EXECUTE = 3;
            $this->db->send_statement($kCOMMAND_EXECUTE, 'USE DATABASE "' . $database . '";');
            $this->db->netread(-1, -1);
            // Test if an error occured
        } catch (Exception $e) {
            $this->errorCode = $this->db->errorcode;
            $this->errorMessage = $this->db->errormsg;
            syslog(1, "Database connection error: " . $this->errorMessage);
            //echo $e;
        }
        return !$this->isError();
    }

    /**
     * Execute given SQL statement on the server
     *
     * Uses current connection. Sets internal error indicators errorCode and errorMessage on error.
     *
     * @param string $sql
     */
    public function execute($sql)
    {
        $this->_resetError();
        try {
            $kCOMMAND_EXECUTE = 3;
            $this->db->send_statement($kCOMMAND_EXECUTE, $sql);
            $this->db->netread(-1, -1);
        } catch (Exception $e) {
            $this->errorCode = $this->db->errorcode;
            $this->errorMessage = $this->db->errormsg;
            syslog(1, $e);
            syslog(1, $this->errorCode);
            syslog(1, $this->errorMessage);
        }
    }

    /**
     * Execute given SQL select query on the server
     *
     * Uses current connection. Sets internal error indicators errorCode and errorMessage on error.
     *
     * @param string $sql Select query statement.
     * @return array|null 2D associative array of results.
     */
    public function select($sql)
    {
        $data = null;
        $this->_resetError();
        try {
            $kCOMMAND_SELECT = 2;
            $this->db->send_statement($kCOMMAND_SELECT, $sql);
            $data = $this->db->read_cursor();
        } catch (Exception $e) {
            $this->errorCode = $this->db->errorcode;
            $this->errorMessage = $this->db->errormsg;
            syslog(1, $e);
            syslog(1, $this->errorCode);
            syslog(1, $this->errorMessage);
        }
        return $data;
    }

    /**
     * Disconnect from the currently connected CubeSQL server
     *
     * Sets internal error indicators errorCode and errorMessage on error.
     */
    public function disconnect()
    {
        $this->_resetError();

        try {
            $this->db->disconnect();
        } catch (Exception $e) {
            $this->errorCode = $this->db->errorcode;
            $this->errorMessage = $this->db->errormsg;
            syslog(1, $e);
        }
    }

    /**
     * Convenience function to check for errors
     * @return bool
     */
    public function isError()
    {
        if ($this->errorCode != 0) return true;
        return false;
    }

    /**
     * Convenience function to clear errors
     */
    private function _resetError()
    {
        $this->errorCode = 0;
        $this->errorMessage = "";
    }
}
