//
//  AppDelegate.m
//  cubeSQLTest
//
//  Created by Marco Bambini on 04/09/2018.
//  Copyright © 2018 SQLabs. All rights reserved.
//

#import "AppDelegate.h"
#import "CubeSQLObjc.h"

#define NEWLINE     @"\n"
#define TABLINE     @"\t\t"

@interface AppDelegate () {
    IBOutlet NSTextField    *sdkversion;
    
    IBOutlet NSTextField    *username;
    IBOutlet NSTextField    *password;
    IBOutlet NSTextField    *hostname;
    IBOutlet NSTextField    *database;
    IBOutlet NSPopUpButton  *encryption;
    
    IBOutlet NSTextField    *sqlField;
    IBOutlet NSTextView     *logField;
    
    IBOutlet NSButton       *connectButton;
    IBOutlet NSButton       *executeButton;
    
    CubeSQL                 *db;
}
@property (weak) IBOutlet NSWindow *window;
@end

// MARK: -

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    const char *version = cubesql_version();
    sdkversion.stringValue = [NSString stringWithFormat:@"SDK version: %s", version];
}

- (void)applicationWillTerminate:(NSNotification *)aNotification {
}

// MARK: -

- (IBAction)doConnect:(id)sender {
    if ([connectButton.title isEqualToString:@"Disconnect"]) {
        [self doDisconnect:sender];
        return;
    }
    
    db = [[CubeSQL alloc] init];
    db.hostname = hostname.stringValue;
    db.username = username.stringValue;
    db.password = password.stringValue;
    
    // set encryption
    NSInteger index = encryption.indexOfSelectedItem;
    if (index == 0) db.encryption = CUBESQL_ENCRYPTION_NONE;
    else if (index == 1) db.encryption = CUBESQL_ENCRYPTION_AES128;
    else if (index == 2) db.encryption = CUBESQL_ENCRYPTION_AES256;
    
    if ([db connect] != CUBESQL_NOERR) {
        [self displayError:db.errorMessage];
        [db disconnect];
        return;
    }
    
    [self appendText:@"Connection succesfully executed\n" termination:NEWLINE];
    
    // connection is OK, now try to set current database
    NSString *sql = [NSString stringWithFormat:@"USE DATABASE %@;", database.stringValue];
    [self appendText:sql termination:NEWLINE];
    
    int res = [db sqlExecute:sql];
    if (res != CUBESQL_NOERR) {
        [self displayError:db.errorMessage];
        [db disconnect];
        return;
    }
    
    // connection succesfull executed
    connectButton.title = @"Disconnect";
    executeButton.enabled = YES;
    sqlField.enabled = YES;
}

- (IBAction)doDisconnect:(id)sender {
    [db disconnect];
    db = nil;
    
    // reset log field
    logField.string = @"";
    
    connectButton.title = @"Connect";
    executeButton.enabled = NO;
    sqlField.enabled = NO;
}

- (IBAction)doExecute:(id)sender {
    // small sanity check on db
    if (db == nil) {NSBeep(); return;}
    
    // retrieve command
    NSString *sql = [sqlField stringValue];
    
    // sanity check on sql
    if ([sql length] == 0) {NSBeep(); return;}
    
    // log sql
     [self appendText:sql termination:NEWLINE];
    
    // check the first word of the command
    // if it is SELECT or SHOW than its a query that returns a RecordSet
    // if it is a PRAGMA than it is a query ONLY if does not contain the = character
    // otherwise it is an EXECUTE command
    NSArray *words = [sql componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    NSString *firstWord = [[words objectAtIndex:0] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]].uppercaseString;
    BOOL isQuery = (([firstWord isEqualToString:@"SELECT"] || [firstWord isEqualToString:@"SHOW"]) ||
                    ([firstWord isEqualToString:@"PRAGMA"] && ([sql rangeOfString:@"="].location == NSNotFound)));
    
    if (isQuery) {
        CubeSQLCursor *c = [db sqlSelect:sql];
        if (c == nil) [self displayError:[db errorMessage]];
        else [self displayCursor:c];
    } else {
        int res = [db sqlExecute:sql];
        if (res == CUBESQL_NOERR) [self appendText:sql termination:NEWLINE];
        else [self displayError:[db errorMessage]];
    }
    
    [self appendText:NEWLINE termination:nil];
}

- (void)displayCursor:(CubeSQLCursor *)c {
    if (c == NULL) return;
    
    int nrows = [c numRows];
    int ncols = [c numColumns];
    
    NSMutableString *s = [[NSMutableString alloc] initWithCapacity:4096];
    [s appendFormat:@"rows: %d - columns: %d\n\n", nrows, ncols];
    
    // print column names separated by tabs
    for (int i=1; i<=ncols; i++) {
        NSString *colName = [c stringValue:CUBESQL_COLNAME column:i];
        [s appendString:colName];
        [s appendString:TABLINE];
    }
    [s appendString:NEWLINE];
    
    while ([c isEOF] == NO) {
        for (int i=1; i<=ncols; i++) {
            NSString *colValue = [c stringValue:CUBESQL_CURROW column:i];
            if (colValue == nil) colValue = @"NULL";
            [s appendString:colValue];
            [s appendString:TABLINE];
        }
        [c seek:CUBESQL_SEEKNEXT];
        [s appendString:NEWLINE];
    }
    
    [self appendText:s termination:NEWLINE];
}

- (void)displayError:(NSString *)error {
    NSAlert *alert = [[NSAlert alloc] init];
    [alert setMessageText:error];
    [alert beginSheetModalForWindow:_window completionHandler:nil];
}

-(void)appendText:(NSString *)text termination:(NSString *)text2 {
    NSAttributedString *s;
    if (text2) s = [[NSAttributedString alloc] initWithString:[text stringByAppendingString:text2]];
    else s = [[NSAttributedString alloc] initWithString:text];
    
    [logField.textStorage appendAttributedString:s];
    [logField scrollToEndOfDocument:nil];
}

@end
