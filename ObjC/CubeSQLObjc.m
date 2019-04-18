//
//  CubeSQL.m
//  
//
//  Created by Marco Bambini on 10/4/11.
//  Copyright 2011-2019 SQLabs. All rights reserved.
//

#import "CubeSQLObjC.h"

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
    
    CubeSQLCursor *cwrapper = [[CubeSQLCursor alloc] initWithCursor:c];
    return cwrapper;
}

- (CubeSQLVM *) vmPrepare:(NSString *)sql; {
    csqlvm *vm = cubesql_vmprepare(db, [sql UTF8String]);
    if (vm == NULL) return nil;
    
    CubeSQLVM *vmwrapper = [[CubeSQLVM alloc] initWithVM:vm];
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
    return [NSString stringWithUTF8String:cubesql_errmsg(db)];
}

- (void) dealloc {
    cubesql_disconnect(db, kFALSE);
}

@end

#pragma mark -

@interface CubeSQLCursor() {
    csqlc        *c;
}
@end

@implementation CubeSQLCursor

- (id) initWithCursor:(csqlc *)p {
    if (self = [super init]) {
        c = p;
    }
    return self;
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
    
    char *buffer = [self nativeType:row column:column len:&dataSize];
    if ((buffer == NULL) || (dataSize == 0)) return nil;
    
    return [NSData dataWithBytes:(const void *)buffer length:(NSUInteger)dataSize];
}

-(BOOL) isNULLValue:(int)row column:(int)column {
    int dataSize = 0;
    
    char *buffer = [self nativeType:row column:column len:&dataSize];
    if ((buffer == NULL) || (dataSize == 0)) return YES;
    
    return NO;
}

- (void) dealloc {
	cubesql_cursor_free(c);
    c = nil;
}

@end

#pragma mark -

@interface CubeSQLVM() {
    csqlvm        *vm;
}
@end

@implementation CubeSQLVM

- (id) initWithVM:(csqlvm *)p {
    if (self = [super init]) {
        vm = p;
    }
    return self;
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
	
	CubeSQLCursor *cwrapper = [[CubeSQLCursor alloc] initWithCursor:c];
	return cwrapper;
}

- (void) dealloc {
	cubesql_vmclose(vm);
    vm = nil;
}

@end

