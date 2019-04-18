//
//  CubeSQL.h
//  
//
//  Created by Marco Bambini on 10/4/11.
//  Copyright 2011-2019 SQLabs. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "cubesql.h"

@interface CubeSQLCursor : NSObject

- (id) initWithCursor:(csqlc *)p;
- (int) numRows;
- (int) numColumns;
- (int) currentRow;
- (int) seek:(int)index;
- (BOOL) isEOF;
- (int) columnType:(int)index;
- (char *) nativeType:(int)row column:(int)column len:(int *)len;
- (int64) rowid:(int)row;
- (int64) int64Type:(int)row column:(int)column defaultValue:(int64)defaultValue;
- (int) intType:(int)row column:(int)column defaultValue:(int)defaultValue;
- (double) doubleType:(int)row column:(int)column defaultValue:(double)defaultValue;
- (NSString *) stringValue:(int)row column:(int)column;
- (NSData *) blobValue:(int)row column:(int)column;
- (BOOL) isNULLValue:(int)row column:(int)column;

@end


@interface CubeSQLVM : NSObject

- (id) initWithVM:(csqlvm *)p;
- (int) bindInt:(int)index value:(int)value;
- (int) bindDouble:(int)index value:(double)value;
- (int) bindText:(int)index value:(NSString *)value;
- (int) bindBlob:(int)index value:(void *)value len:(int)len;
- (int) bindNull:(int)index;
- (int) bindInt64:(int)index value:(int64)value;
- (int) bindZeroBlob:(int)index value:(int)len;
- (int) execute;
- (CubeSQLCursor *) select;

@end


@interface CubeSQL : NSObject

@property (copy) NSString *hostname;
@property (copy) NSString *username;
@property (copy) NSString *password;
@property (copy) NSString *token;
@property (copy) NSString *ssl_certificate;
@property (assign) int port;
@property (assign) int timeout;
@property (assign) int encryption;
@property (nonatomic, readonly) csqldb *ref;

- (int) connect;
- (void) disconnect;
- (int) sqlExecute:(NSString *)sql;
- (CubeSQLCursor *)	sqlSelect:(NSString *)sql;
- (CubeSQLVM *) vmPrepare:(NSString *)sql;
- (int) commit;
- (int) rollback;
- (int) ping;
- (int64) changes;
- (int) errorCode;
- (NSString *) errorMessage;

@end
