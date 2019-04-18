//
//  AppDelegate.m
//  cubeSQLTest
//
//  Created by Marco Bambini on 04/09/2018.
//  Copyright © 2018 SQLabs. All rights reserved.
//

#import "AppDelegate.h"
#import "CubeSQLObjc.h"

#define NEWLINE             @"\n"
#define TABLINE             @"\t\t"
#define CHUNK_SIZE          102400

@interface AppDelegate () <NSTableViewDelegate, NSTableViewDataSource> {
    IBOutlet NSTextField    *sdkversion;
    
    IBOutlet NSTextField    *username;
    IBOutlet NSTextField    *password;
    IBOutlet NSTextField    *hostname;
    IBOutlet NSTextField    *database;
    IBOutlet NSPopUpButton  *encryption;
    
    IBOutlet NSButton       *connectButton;
    IBOutlet NSButton       *uploadButton;
    IBOutlet NSButton       *downloadButton;
    IBOutlet NSButton       *deleteButton;
    
    IBOutlet NSTableView    *tableView;
    NSMutableArray          *names;
    NSMutableArray          *sizes;
    
    CubeSQL                 *db;
}
@property (weak) IBOutlet NSWindow *window;
@end

// MARK: -

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    const char *version = cubesql_version();
    sdkversion.stringValue = [NSString stringWithFormat:@"SDK version: %s", version];
    
    names = [NSMutableArray array];
    sizes = [NSMutableArray array];
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
    
    // connection is OK, now try to set current database
    if (database.stringValue.length > 0) {
        NSString *sql = [NSString stringWithFormat:@"USE DATABASE %@;", database.stringValue];
        int res = [db sqlExecute:sql];
        if (res != CUBESQL_NOERR) {
            [self displayError:db.errorMessage];
            [db disconnect];
            return;
        }
    }

    // connection succesfull executed
    connectButton.title = @"Disconnect";
    uploadButton.enabled = YES;
    
    // automatically get file list
    [self doListFiles:nil];
}

- (IBAction)doDisconnect:(id)sender {
    [db disconnect];
    db = nil;
    
    // reset tableview
    [names removeAllObjects];
    [sizes removeAllObjects];
    [tableView reloadData];
    
    connectButton.title = @"Connect";
    uploadButton.enabled = NO;
}

- (IBAction)doListFiles:(id)sender {
    // perform query
    CubeSQLCursor *c = [db sqlSelect:@"SHOW FILES;"];
    if (c == nil) {
        [self displayError:[db errorMessage]];
        return;
    }
    
    // reset
    [names removeAllObjects];
    [sizes removeAllObjects];
    
    // parse result
    while ([c isEOF] == NO) {
        NSString *fileName = [c stringValue:CUBESQL_CURROW column:1];
        NSString *fileSize = [c stringValue:CUBESQL_CURROW column:2];
        [names addObject:fileName];
        [sizes addObject:fileSize];
        [c seek:CUBESQL_SEEKNEXT];
    }
    
    // reload table
    [tableView reloadData];
}

- (IBAction)doUploadFile:(id)sender {
    // choose file to upload
    NSOpenPanel *panel = [NSOpenPanel openPanel];
    [panel setCanChooseFiles:YES];
    [panel setCanChooseDirectories:NO];
    [panel setAllowsMultipleSelection:NO];
    [panel setMessage:@"Choose a file to upload."];
    if ([panel runModal] != NSFileHandlingPanelOKButton) return;
    
    NSURL *url = [[panel URLs] firstObject];
    if (!url) return;
    
    // not a very smart way to read a file
    NSData *data = [[NSData alloc] initWithContentsOfURL:url];
    if (!data) {NSBeep(); return;}
    
    [self uploadData:data withName:url.lastPathComponent];
    [self doListFiles:nil];
}

- (IBAction)doDownloadFile:(id)sender {
    NSInteger selectedRow = tableView.selectedRow;
    if (selectedRow == -1) return;
    NSString *fileName = names[selectedRow];
    
    NSSavePanel *panel = [NSSavePanel savePanel];
    panel.nameFieldStringValue = fileName;
    
    if ([panel runModal] != NSFileHandlingPanelOKButton) return;
    
    NSURL *url = [panel URL];
    if (!url) return;
    
    [self beginDownload:fileName toURL:url];
}

- (IBAction)doDeleteFile:(id)sender {
    NSInteger selectedRow = tableView.selectedRow;
    if (selectedRow == -1) return;
    NSString *fileName = names[selectedRow];
    // Are you sure you want to delete file with name ... ?
    
    NSString *sql = [NSString stringWithFormat:@"FILE DELETE '%@';", fileName];
    int res = [db sqlExecute:sql];
    if (res != CUBESQL_NOERR) {
        [self displayError:db.errorMessage];
    }
    
    [self doListFiles:nil];
}

// MARK: - TableView -

- (NSInteger)numberOfRowsInTableView:(NSTableView *)tableView {
    return names.count;
}

- (id)tableView:(NSTableView *)tableView viewForTableColumn:(NSTableColumn *)tableColumn row:(NSInteger)row {
    NSTableCellView *result = [tableView makeViewWithIdentifier:tableColumn.identifier owner:self];
    
    NSString *s = ([tableColumn.identifier isEqualToString:@"col1"]) ? names[row] : sizes[row];
    result.textField.stringValue = s;
    return result;
}

- (void)tableViewSelectionDidChange:(NSNotification *)notification {
    NSInteger selectedRow = tableView.selectedRow;
    downloadButton.enabled = (selectedRow != -1);
    deleteButton.enabled = (selectedRow != -1);
}

// MARK: -

- (void)beginDownload:(NSString *)fileName toURL:(NSURL *)url {
    // write binary file in C because it is much more faster than converting to NDData each time
    FILE *f = fopen(url.path.UTF8String, "wb");
    if (!f) {
        [self displayError:@"Unable to create file."];
        return;
    }
    
    // prepare file uploading
    NSString *sql = [NSString stringWithFormat:@"FILE DOWNLOAD '%@'", fileName];
    int res = [db sqlExecute:sql];
    if (res != CUBESQL_NOERR) {
        [self displayError:db.errorMessage];
        return;
    }
    
    while (1) {
        int len = 0;
        int isEndData = 0;
        char *data = cubesql_receive_data(db.ref, &len, &isEndData);
        if (isEndData) break;
        if (data && len) fwrite(data, len, 1, f);
    }
    
    fclose(f);
}

- (void)uploadData:(NSData *)data withName:(NSString *)fileName {
    // prepare file uploading
    NSString *sql = [NSString stringWithFormat:@"FILE UPLOAD '%@' WITH REPLACE;", fileName];
    int res = [db sqlExecute:sql];
    if (res != CUBESQL_NOERR) {
        [self displayError:db.errorMessage];
        return;
    }
    
    // loop to upload data in chunk
    const void *bytes = data.bytes;
    NSInteger length = data.length;
    
    while (length > 0) {
        NSInteger chunckSize = (length < CHUNK_SIZE) ? length : CHUNK_SIZE;
        
        int err = cubesql_send_data(db.ref, bytes, (int)chunckSize);
        if (err != CUBESQL_NOERR) {
            [self displayError:db.errorMessage];
            return;
        }
        
        // update length and buffer ptr
        length -= chunckSize;
        bytes += chunckSize;
    }
    
    // tell server
    cubesql_send_enddata(db.ref);
}

- (void)displayError:(NSString *)error {
    NSAlert *alert = [[NSAlert alloc] init];
    [alert setMessageText:error];
    [alert beginSheetModalForWindow:_window completionHandler:nil];
}

@end
