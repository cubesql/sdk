//
//  CubeSQL.m
//  
//
//  Created by Marco Bambini on 10/4/11.
//  Copyright 2011-2019 SQLabs. All rights reserved.
//

#import "CubeSQLObjC.h"

// Internal initializers: a cursor/VM keeps a STRONG reference to the owning CubeSQL so the
// underlying csqldb cannot be freed while the cursor/VM is still alive. Without this, releasing
// (or -disconnect'ing) the connection before its cursors/VMs frees db, and the cursor/VM dealloc
// then dereferences the freed pointer (cubesql_vmclose/cubesql_cursor_close use vm->db / c->db).
@interface CubeSQLCursor ()
- (instancetype) initWithCursor:(csqlc *)p parent:(CubeSQL *)parent;
@end

@interface CubeSQLVM ()
- (instancetype) initWithVM:(csqlvm *)p parent:(CubeSQL *)parent;
@end

@interface CubeSQL() {
    csqldb        *db;
}
@end

@implementation CubeSQL

@synthesize hostname;
@synthesize username;
@synthesize password;
@synthesize token;
@synthesize port;
@synthesize timeout;
@synthesize encryption;
@synthesize ssl_certificate;

- (id) init {
    if (self = [super init]) {
        db = NULL;
        port = CUBESQL_DEFAULT_PORT;
        timeout = CUBESQL_DEFAULT_TIMEOUT;
        encryption = CUBESQL_ENCRYPTION_NONE;
    }
    return self;
}

- (csqldb *)ref {
    return db;
}

- (int) connect {
    return cubesql_connect_token(&db, [hostname UTF8String], port, [username UTF8String],
                                 [password UTF8String], timeout, encryption, (token) ? (char *)[token UTF8String]:NULL, kFALSE,
                                 (ssl_certificate) ? (char *)[ssl_certificate UTF8String]:NULL, NULL, NULL, NULL);
}

- (void) disconnect {
    cubesql_disconnect(db, kFALSE);
    db = nil;
}

- (int) sqlExecute:(NSString *)sql {
    return cubesql_execute(db, [sql UTF8String]);
}

- (CubeSQLCursor *)    sqlSelect:(NSString *)sql {
    csqlc *c = cubesql_select(db, [sql UTF8String], kFALSE);
    if (c == NULL) return nil;

    CubeSQLCursor *cwrapper = [[CubeSQLCursor alloc] initWithCursor:c parent:self];
    return cwrapper;
}

- (CubeSQLVM *) vmPrepare:(NSString *)sql; {
    csqlvm *vm = cubesql_vmprepare(db, [sql UTF8String]);
    if (vm == NULL) return nil;

    CubeSQLVM *vmwrapper = [[CubeSQLVM alloc] initWithVM:vm parent:self];
    return vmwrapper;
}

- (int) commit {
    return cubesql_commit(db);
}

- (int) rollback {
    return cubesql_rollback(db);
}

- (int) ping {
    return cubesql_ping(db);
}

- (int64) changes {
    return cubesql_changes(db);
}

- (int) errorCode {
    return cubesql_errcode(db);
}

- (NSString *) errorMessage {
    // db is NULL before -connect, after -disconnect, and after a failed connect. cubesql_errmsg()
    // dereferences it without a guard, so protect the common "why did connect fail" call path.
    if (db == NULL) return nil;
    const char *msg = cubesql_errmsg(db);
    return msg ? [NSString stringWithUTF8String:msg] : nil;
}

- (void) dealloc {
    cubesql_disconnect(db, kFALSE);
}

@end

#pragma mark -

@interface CubeSQLCursor() {
    csqlc        *c;
    CubeSQL      *parent;   // strong (ARC default for object ivars): keeps the connection alive
}
@end

@implementation CubeSQLCursor

- (instancetype) initWithCursor:(csqlc *)p parent:(CubeSQL *)aParent {
    if (self = [super init]) {
        c = p;
        parent = aParent;
    }
    return self;
}

- (id) initWithCursor:(csqlc *)p {
    return [self initWithCursor:p parent:nil];
}

- (int) numRows {
	return cubesql_cursor_numrows(c);
}

- (int) numColumns {
	return cubesql_cursor_numcolumns(c);
}

- (int) currentRow {
	return cubesql_cursor_currentrow(c);
}

- (int) seek:(int)index {
	return cubesql_cursor_seek(c, index);
}

- (BOOL) isEOF {
	return (cubesql_cursor_iseof(c) == kTRUE);
}

- (int) columnType:(int)index {
	return cubesql_cursor_columntype(c, index);
}

- (char *) nativeType:(int)row column:(int)column len:(int *)len {
	return cubesql_cursor_field(c, row, column, len);
}

- (int64) rowid:(int)row {
	return cubesql_cursor_rowid(c, row);
}

- (int64) int64Type:(int)row column:(int)column defaultValue:(int64)defaultValue {
	return cubesql_cursor_int64(c, row, column, defaultValue);
}

- (int) intType:(int)row column:(int)column defaultValue:(int)defaultValue {
	return cubesql_cursor_int(c, row, column, defaultValue);
}

- (double) doubleType:(int)row column:(int)column defaultValue:(double)defaultValue {
	return cubesql_cursor_double(c, row, column, defaultValue);
}

- (NSString *) stringValue:(int)row column:(int)column {
	char *s = cubesql_cursor_cstring(c, row, column);
	if (s == NULL) return nil;
	
	NSString *value = [NSString stringWithUTF8String:s];
	free(s);
	return value;
}

- (NSData *) blobValue:(int)row column:(int)column {
    int dataSize = 0;

    // cubesql_cursor_field distinguishes SQL NULL (NULL pointer, len -1) from an empty blob
    // (non-NULL pointer, len 0). Only SQL NULL should map to nil; an empty blob is a real value.
    char *buffer = [self nativeType:row column:column len:&dataSize];
    if (buffer == NULL) return nil;
    if (dataSize < 0) dataSize = 0;

    return [NSData dataWithBytes:(const void *)buffer length:(NSUInteger)dataSize];
}

-(BOOL) isNULLValue:(int)row column:(int)column {
    int dataSize = 0;

    // SQL NULL is signalled by a NULL field pointer; an empty (zero-length) value is NOT NULL.
    char *buffer = [self nativeType:row column:column len:&dataSize];
    return (buffer == NULL) ? YES : NO;
}

- (void) dealloc {
	cubesql_cursor_free(c);
    c = nil;
}

@end

#pragma mark -

@interface CubeSQLVM() {
    csqlvm        *vm;
    CubeSQL       *parent;   // strong: keeps the connection alive while this VM exists
}
@end

@implementation CubeSQLVM

- (instancetype) initWithVM:(csqlvm *)p parent:(CubeSQL *)aParent {
    if (self = [super init]) {
        vm = p;
        parent = aParent;
    }
    return self;
}

- (id) initWithVM:(csqlvm *)p {
    return [self initWithVM:p parent:nil];
}

- (int) bindInt:(int)index value:(int)value {
	return cubesql_vmbind_int(vm, index, value);
}

- (int) bindDouble:(int)index value:(double)value {
	return cubesql_vmbind_double(vm, index, value);
}

- (int) bindText:(int)index value:(NSString *)value {
	const char *s = [value UTF8String];
	return cubesql_vmbind_text(vm, index, (char *)s, (int)strlen(s));
}

- (int) bindBlob:(int)index value:(void *)value len:(int)len {
	return cubesql_vmbind_blob(vm, index, value, len);
}

- (int) bindNull:(int)index {
	return cubesql_vmbind_null(vm, index);
}

- (int) bindInt64:(int)index value:(int64)value {
	return cubesql_vmbind_int64(vm, index, value);
}

- (int) bindZeroBlob:(int)index value:(int)len {
	return cubesql_vmbind_zeroblob(vm, index, len);
}

- (int) execute {
	return cubesql_vmexecute(vm);
}

- (CubeSQLCursor *) select {
	csqlc *c = cubesql_vmselect(vm);
	if (c == NULL) return nil;

	// the cursor shares the VM's owning connection, so it must keep that connection alive too
	CubeSQLCursor *cwrapper = [[CubeSQLCursor alloc] initWithCursor:c parent:parent];
	return cwrapper;
}

- (void) dealloc {
	cubesql_vmclose(vm);
    vm = nil;
}

@end

