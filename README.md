# Official clients repository for cubeSQL server

cubeSQL can can be freely downloaded from: [https://sqlabs.com](https://www.sqlabs.com/download/cubesql/)<br />
If you fix any issue or improve the extension please share your changes.

## C SDK
The official reference should alway be the C SDK.
When compiled in another project several macros can be used in order to decide how OpenSSL must be linked:
* **CUBESQL_ENABLE_SSL_ENCRYPTION** if set to 0 or not set, then SSL support is disabled on client side. When set to 1 the following macros can be used to further customize how OpenSSL is loaded:
  * **CUBESQL_STATIC_SSL_LIBRARY** it means that OpenSSL is statically linked
  * **CUBESQL_EXTERN_SSL_LIBRARY** it means that OpenSSL is available somewhere in the same build and extern declarations should be used
  * **CUBESQL_DYNAMIC_SSL_LIBRARY** it means that the SDK will try to dynamically load OpenSSL library itself


# Contact
Marco Bambini (marco@sqlabs.com)
