# Official clients repository for cubeSQL server

CubeSQL can can be freely downloaded from: [https://sqlabs.com](https://www.sqlabs.com/download/cubesql/)<br />
If you fix any issue or improve the extension please share your changes.

## C SDK
The official reference should always be the C SDK.
When linked in another project the **CUBESQL_DISABLE_SSL_ENCRYPTION** macro can be used to skip the usage of TLS code (LibreSSL). 
Starting from version 6.0.0 LibreSSL is the default static TLS library (OpenSSL is no longer required).

# Contact
Marco Bambini (marco@sqlabs.com)
