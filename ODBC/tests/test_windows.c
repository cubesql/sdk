#define ODBCVER 0x0380
#include <windows.h>
#include <dbghelp.h>
#include <sql.h>
#include <sqlext.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static LONG WINAPI crash_handler(EXCEPTION_POINTERS *exception) {
    HANDLE process = GetCurrentProcess();
    HANDLE thread = GetCurrentThread();
    CONTEXT context = *exception->ContextRecord;
    STACKFRAME64 frame;
    DWORD machine;
    unsigned int index;
    char symbol_storage[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
    SYMBOL_INFO *symbol = (SYMBOL_INFO *)symbol_storage;
    IMAGEHLP_LINE64 line;
    const char *dump_path;

    fprintf(stderr, "Windows exception 0x%08lx at %p\n",
            (unsigned long)exception->ExceptionRecord->ExceptionCode,
            exception->ExceptionRecord->ExceptionAddress);
    fflush(stderr);

    memset(&frame, 0, sizeof(frame));
#ifdef _WIN64
    machine = IMAGE_FILE_MACHINE_AMD64;
    frame.AddrPC.Offset = context.Rip;
    frame.AddrFrame.Offset = context.Rbp;
    frame.AddrStack.Offset = context.Rsp;
#else
    machine = IMAGE_FILE_MACHINE_I386;
    frame.AddrPC.Offset = context.Eip;
    frame.AddrFrame.Offset = context.Ebp;
    frame.AddrStack.Offset = context.Esp;
#endif
    frame.AddrPC.Mode = AddrModeFlat;
    frame.AddrFrame.Mode = AddrModeFlat;
    frame.AddrStack.Mode = AddrModeFlat;

    SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES | SYMOPT_UNDNAME);
    if (SymInitialize(process, NULL, TRUE)) {
        memset(symbol_storage, 0, sizeof(symbol_storage));
        symbol->SizeOfStruct = sizeof(*symbol);
        symbol->MaxNameLen = MAX_SYM_NAME;
        memset(&line, 0, sizeof(line));
        line.SizeOfStruct = sizeof(line);

        for (index = 0; index < 64 && frame.AddrPC.Offset; ++index) {
            DWORD64 symbol_displacement = 0;
            DWORD line_displacement = 0;
            BOOL have_symbol = SymFromAddr(process, frame.AddrPC.Offset,
                                           &symbol_displacement, symbol);
            BOOL have_line = SymGetLineFromAddr64(process, frame.AddrPC.Offset,
                                                  &line_displacement, &line);

            fprintf(stderr, "  #%u %p", index,
                    (void *)(uintptr_t)frame.AddrPC.Offset);
            if (have_symbol) {
                fprintf(stderr, " %s+0x%llx", symbol->Name,
                        (unsigned long long)symbol_displacement);
            }
            if (have_line) {
                fprintf(stderr, " (%s:%lu)", line.FileName,
                        (unsigned long)line.LineNumber);
            }
            fputc('\n', stderr);

            if (!StackWalk64(machine, process, thread, &frame, &context, NULL,
                             SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
                break;
            }
        }
        SymCleanup(process);
    } else {
        fprintf(stderr, "Unable to initialize DbgHelp symbols: %lu\n",
                (unsigned long)GetLastError());
    }
    fflush(stderr);

    dump_path = getenv("CUBESQL_ODBC_DUMP_PATH");
    if (dump_path && *dump_path) {
        HANDLE dump = CreateFileA(dump_path, GENERIC_WRITE, 0, NULL,
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (dump != INVALID_HANDLE_VALUE) {
            MINIDUMP_EXCEPTION_INFORMATION info;
            BOOL written;
            info.ThreadId = GetCurrentThreadId();
            info.ExceptionPointers = exception;
            info.ClientPointers = FALSE;
            written = MiniDumpWriteDump(
                process, GetCurrentProcessId(), dump,
                (MINIDUMP_TYPE)(MiniDumpWithIndirectlyReferencedMemory |
                                MiniDumpScanMemory),
                &info, NULL, NULL);
            CloseHandle(dump);
            fprintf(stderr, "%s minidump: %s\n",
                    written ? "Wrote" : "Failed to write", dump_path);
            fflush(stderr);
        }
    }

    return EXCEPTION_EXECUTE_HANDLER;
}

static void diag(SQLSMALLINT type, SQLHANDLE handle) {
    SQLCHAR state[6], message[512]; SQLINTEGER native; SQLSMALLINT len, i = 1;
    while (SQLGetDiagRecA(type, handle, i++, state, &native, message,
                          sizeof(message), &len) == SQL_SUCCESS)
        fprintf(stderr, "[%s] %s (%ld)\n", state, message, (long)native);
}

#define ODBC(call, type, handle) do { \
    SQLRETURN rc_; \
    fprintf(stderr, "ODBC BEGIN: %s\n", #call); fflush(stderr); \
    rc_ = (call); \
    fprintf(stderr, "ODBC END: %s -> %d\n", #call, rc_); fflush(stderr); \
    if (!SQL_SUCCEEDED(rc_)) { \
        diag(type, handle); goto fail; \
    } \
} while (0)

int main(void) {
    SQLHENV env = SQL_NULL_HENV; SQLHDBC dbc = SQL_NULL_HDBC; SQLHSTMT stmt = SQL_NULL_HSTMT;
    SQLCHAR value[128], *connection = (SQLCHAR *)getenv("CUBESQL_ODBC_CONNECTION_STRING");
    SQLINTEGER answer = 0; SQLLEN indicator = 0;
    SetUnhandledExceptionFilter(crash_handler);
    if (!connection) {
        fprintf(stderr, "Set CUBESQL_ODBC_CONNECTION_STRING to run the Windows Driver Manager smoke test.\n");
        return 2;
    }
    ODBC(SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &env), SQL_HANDLE_ENV, env);
    ODBC(SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3_80, 0), SQL_HANDLE_ENV, env);
    ODBC(SQLAllocHandle(SQL_HANDLE_DBC, env, &dbc), SQL_HANDLE_ENV, env);
    ODBC(SQLDriverConnectA(dbc, NULL, connection, SQL_NTS, NULL, 0, NULL, SQL_DRIVER_NOPROMPT), SQL_HANDLE_DBC, dbc);
    ODBC(SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt), SQL_HANDLE_DBC, dbc);
    if (getenv("CUBESQL_ODBC_REGISTER_TEST_SERVER")) {
        ODBC(SQLExecDirectA(stmt,
            (SQLCHAR *)"SET REGISTRATION TO 'SQLabs srl' WITH KEY "
                       "'CSQL75ZZ-PPJHAG9L-27X2W3C4-8DX6BAXX-35XBX46W';",
            SQL_NTS), SQL_HANDLE_STMT, stmt);
    }
    ODBC(SQLExecDirectA(stmt,
        (SQLCHAR *)"CREATE DATABASE odbc_smoke.db IF NOT EXISTS;", SQL_NTS),
        SQL_HANDLE_STMT, stmt);
    ODBC(SQLSetConnectAttrA(dbc, SQL_ATTR_CURRENT_CATALOG,
        (SQLPOINTER)"odbc_smoke.db", SQL_NTS), SQL_HANDLE_DBC, dbc);
    ODBC(SQLExecDirectA(stmt, (SQLCHAR *)"SELECT 'CubeSQL ODBC', 42;", SQL_NTS), SQL_HANDLE_STMT, stmt);
    ODBC(SQLFetch(stmt), SQL_HANDLE_STMT, stmt);
    ODBC(SQLGetData(stmt, 1, SQL_C_CHAR, value, sizeof(value), &indicator), SQL_HANDLE_STMT, stmt);
    ODBC(SQLGetData(stmt, 2, SQL_C_SLONG, &answer, sizeof(answer), &indicator), SQL_HANDLE_STMT, stmt);
    if (strcmp((char *)value, "CubeSQL ODBC") != 0 || answer != 42) {
        fprintf(stderr, "Unexpected result: '%s', %ld\n", value, (long)answer);
        goto fail;
    }
    printf("%s: PASS\n", value);
    SQLFreeHandle(SQL_HANDLE_STMT, stmt); SQLDisconnect(dbc);
    SQLFreeHandle(SQL_HANDLE_DBC, dbc); SQLFreeHandle(SQL_HANDLE_ENV, env); return 0;
fail:
    if (stmt) SQLFreeHandle(SQL_HANDLE_STMT, stmt);
    if (dbc) { SQLDisconnect(dbc); SQLFreeHandle(SQL_HANDLE_DBC, dbc); }
    if (env) SQLFreeHandle(SQL_HANDLE_ENV, env);
    return 1;
}
