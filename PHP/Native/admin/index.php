<?php
declare(strict_types=1);
session_start();

require_once __DIR__ . '/../CubeSQL.php';

use CubeSQL\CubeSQL;
use CubeSQL\Cursor;

// ============================================================================
// Session helpers
// ============================================================================

function getSessionParam(string $key, $default = null) {
    return $_SESSION['cubesql'][$key] ?? $default;
}

function setSessionParam(string $key, $value): void {
    $_SESSION['cubesql'][$key] = $value;
}

function isLoggedIn(): bool {
    return !empty($_SESSION['cubesql']['host']);
}

function addToHistory(string $sql): void {
    $history = $_SESSION['cubesql']['history'] ?? [];
    array_unshift($history, ['sql' => $sql, 'time' => date('H:i:s')]);
    $_SESSION['cubesql']['history'] = array_slice($history, 0, 20);
}

// ============================================================================
// Actions
// ============================================================================

$error = '';
$success = '';
$cursor = null;
$execTime = 0;
$activeTab = $_POST['tab'] ?? $_GET['tab'] ?? 'info';
$currentDb = getSessionParam('current_db', '');

// Handle login
if (isset($_POST['action']) && $_POST['action'] === 'login') {
    $_SESSION['cubesql'] = [
        'host' => $_POST['host'] ?? 'localhost',
        'port' => (int)($_POST['port'] ?? 4430),
        'user' => $_POST['user'] ?? 'admin',
        'pass' => $_POST['pass'] ?? 'admin',
        'ssl' => !empty($_POST['ssl']),
        'history' => [],
        'current_db' => '',
    ];
    $activeTab = 'info';
}

// Handle logout
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    session_destroy();
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}

// Connect to server if logged in
$db = null;
if (isLoggedIn()) {
    $db = new CubeSQL();
    $ok = $db->connect(
        getSessionParam('host'),
        getSessionParam('port'),
        getSessionParam('user'),
        getSessionParam('pass'),
        12,
        getSessionParam('ssl', false)
    );
    if (!$ok) {
        $error = 'Connection failed: ' . $db->errorMessage();
        $db = null;
    } elseif ($currentDb) {
        $db->setDatabase($currentDb);
        if ($db->isError()) {
            $error = 'Failed to set database: ' . $db->errorMessage();
        }
    }
}

// Handle database switch
if ($db && isset($_POST['action']) && $_POST['action'] === 'use_db') {
    $dbName = $_POST['dbname'] ?? '';
    if ($dbName) {
        $db->setDatabase($dbName);
        if ($db->isError()) {
            $error = $db->errorMessage();
        } else {
            setSessionParam('current_db', $dbName);
            $currentDb = $dbName;
            $success = "Switched to database: {$dbName}";
        }
    }
    $activeTab = 'databases';
}

// Handle SQL execution
if ($db && isset($_POST['action']) && $_POST['action'] === 'query') {
    $sql = trim($_POST['sql'] ?? '');
    if ($sql) {
        addToHistory($sql);
        $start = microtime(true);

        // Detect SELECT-like statements
        $upper = strtoupper(ltrim($sql));
        $isSelect = str_starts_with($upper, 'SELECT') ||
                    str_starts_with($upper, 'SHOW') ||
                    str_starts_with($upper, 'PRAGMA');

        if ($isSelect) {
            $cursor = $db->select($sql);
            if ($cursor === null) {
                $error = $db->errorMessage();
            }
        } else {
            $ok = $db->execute($sql);
            if (!$ok) {
                $error = $db->errorMessage();
            } else {
                $success = 'Statement executed successfully.';
                $affected = $db->affectedRows();
                if ($affected > 0) {
                    $success .= " Affected rows: {$affected}";
                }
            }
        }
        $execTime = microtime(true) - $start;
    }
    $activeTab = 'sql';
}

// Fetch server info
$serverInfo = null;
if ($db && $activeTab === 'info') {
    $serverInfo = $db->select('SHOW INFO;');
    if ($serverInfo === null) {
        $error = $db->errorMessage();
    }
}

// Fetch databases
$databases = null;
$tables = null;
if ($db && $activeTab === 'databases') {
    $databases = $db->select('SHOW DATABASES;');
    if ($databases === null) {
        $error = $db->errorMessage();
    }
    if ($currentDb) {
        $tables = $db->select('SHOW TABLES;');
        if ($tables === null && $db->isError()) {
            // Ignore - may not have permission
            $tables = null;
        }
    }
}

// Disconnect
if ($db) {
    $db->disconnect();
}

?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CubeSQL Admin</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; color: #333; min-height: 100vh; display: flex; }

/* Login */
.login-wrap { display: flex; align-items: center; justify-content: center; width: 100%; min-height: 100vh; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); }
.login-box { background: #fff; padding: 40px; border-radius: 8px; width: 400px; box-shadow: 0 4px 20px rgba(0,0,0,0.3); }
.login-box h1 { font-size: 24px; margin-bottom: 8px; color: #1a1a2e; }
.login-box p { font-size: 13px; color: #888; margin-bottom: 24px; }
.form-group { margin-bottom: 16px; }
.form-group label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 4px; color: #555; }
.form-group input[type="text"],
.form-group input[type="password"],
.form-group input[type="number"] { width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; }
.form-row { display: flex; gap: 12px; }
.form-row .form-group { flex: 1; }
.form-check { display: flex; align-items: center; gap: 8px; }
.form-check input { width: 16px; height: 16px; }
.btn { padding: 10px 20px; background: #1a1a2e; color: #fff; border: none; border-radius: 4px; font-size: 14px; cursor: pointer; font-weight: 600; }
.btn:hover { background: #16213e; }
.btn-full { width: 100%; }
.btn-sm { padding: 6px 12px; font-size: 12px; }
.btn-blue { background: #2563eb; }
.btn-blue:hover { background: #1d4ed8; }

/* Layout */
.sidebar { width: 220px; background: #1a1a2e; color: #fff; min-height: 100vh; padding: 20px 0; flex-shrink: 0; }
.sidebar h2 { font-size: 18px; padding: 0 20px 16px; border-bottom: 1px solid rgba(255,255,255,0.1); margin-bottom: 16px; }
.sidebar .conn-info { font-size: 11px; color: rgba(255,255,255,0.5); padding: 0 20px; margin-bottom: 20px; }
.sidebar nav a { display: block; padding: 10px 20px; color: rgba(255,255,255,0.7); text-decoration: none; font-size: 14px; border-left: 3px solid transparent; }
.sidebar nav a:hover { background: rgba(255,255,255,0.05); color: #fff; }
.sidebar nav a.active { background: rgba(255,255,255,0.1); color: #fff; border-left-color: #60a5fa; }
.sidebar .logout { margin-top: 20px; padding-top: 16px; border-top: 1px solid rgba(255,255,255,0.1); }
.sidebar .logout a { color: rgba(255,255,255,0.5); }

.content { flex: 1; padding: 24px; overflow-x: auto; }
.content h2 { font-size: 20px; margin-bottom: 16px; }

/* Alerts */
.alert { padding: 12px 16px; border-radius: 4px; margin-bottom: 16px; font-size: 14px; }
.alert-error { background: #fef2f2; border: 1px solid #fecaca; color: #b91c1c; }
.alert-success { background: #f0fdf4; border: 1px solid #bbf7d0; color: #166534; }

/* Tables */
.data-table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 6px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 16px; }
.data-table th { background: #f8fafc; text-align: left; padding: 10px 14px; font-size: 12px; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 2px solid #e2e8f0; }
.data-table td { padding: 8px 14px; font-size: 13px; border-bottom: 1px solid #f1f5f9; }
.data-table tr:hover td { background: #f8fafc; }
.data-table .null-val { color: #94a3b8; font-style: italic; font-size: 12px; }
.data-table .info-key { font-weight: 600; color: #475569; white-space: nowrap; width: 200px; }

/* SQL Editor */
.sql-editor { margin-bottom: 16px; }
.sql-editor textarea { width: 100%; height: 120px; font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; font-size: 13px; padding: 12px; border: 1px solid #d1d5db; border-radius: 6px; resize: vertical; background: #1e293b; color: #e2e8f0; line-height: 1.5; }
.sql-editor textarea:focus { outline: none; border-color: #60a5fa; box-shadow: 0 0 0 3px rgba(96,165,250,0.2); }
.sql-toolbar { display: flex; align-items: center; gap: 12px; margin-top: 8px; }
.sql-meta { font-size: 12px; color: #94a3b8; }

/* DB list */
.db-list { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 20px; }
.db-item { display: inline-flex; align-items: center; }
.db-item button { padding: 8px 16px; background: #fff; border: 1px solid #d1d5db; border-radius: 4px; cursor: pointer; font-size: 13px; }
.db-item button:hover { background: #f1f5f9; }
.db-item button.current { background: #1a1a2e; color: #fff; border-color: #1a1a2e; }

/* History */
.history { margin-top: 24px; }
.history h3 { font-size: 14px; color: #64748b; margin-bottom: 8px; }
.history-item { font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; font-size: 12px; color: #64748b; padding: 4px 0; cursor: pointer; display: flex; gap: 8px; }
.history-item:hover { color: #1a1a2e; }
.history-item .time { color: #94a3b8; flex-shrink: 0; }
</style>
</head>
<body>

<?php if (!isLoggedIn()): ?>
<!-- Login Form -->
<div class="login-wrap">
<div class="login-box">
    <h1>CubeSQL Admin</h1>
    <p>Connect to a CubeSQL server</p>
    <form method="POST">
        <input type="hidden" name="action" value="login">
        <div class="form-row">
            <div class="form-group">
                <label>Host</label>
                <input type="text" name="host" value="localhost" required>
            </div>
            <div class="form-group" style="max-width:100px">
                <label>Port</label>
                <input type="number" name="port" value="4430" required>
            </div>
        </div>
        <div class="form-group">
            <label>Username</label>
            <input type="text" name="user" value="admin" required>
        </div>
        <div class="form-group">
            <label>Password</label>
            <input type="password" name="pass" value="admin" required>
        </div>
        <div class="form-group">
            <div class="form-check">
                <input type="checkbox" name="ssl" id="ssl" value="1">
                <label for="ssl" style="margin:0;font-weight:normal">Use SSL/TLS</label>
            </div>
        </div>
        <button type="submit" class="btn btn-full">Connect</button>
    </form>
</div>
</div>

<?php else: ?>
<!-- Dashboard -->
<div class="sidebar">
    <h2>CubeSQL Admin</h2>
    <div class="conn-info">
        <?= htmlspecialchars(getSessionParam('host')) ?>:<?= getSessionParam('port') ?>
        <?php if ($currentDb): ?><br>DB: <?= htmlspecialchars($currentDb) ?><?php endif; ?>
    </div>
    <nav>
        <a href="?tab=info" class="<?= $activeTab === 'info' ? 'active' : '' ?>">Server Info</a>
        <a href="?tab=databases" class="<?= $activeTab === 'databases' ? 'active' : '' ?>">Databases</a>
        <a href="?tab=sql" class="<?= $activeTab === 'sql' ? 'active' : '' ?>">SQL Editor</a>
        <div class="logout">
            <a href="?action=logout">Disconnect</a>
        </div>
    </nav>
</div>

<div class="content">

<?php if ($error): ?>
<div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
<?php endif; ?>

<?php if ($success): ?>
<div class="alert alert-success"><?= htmlspecialchars($success) ?></div>
<?php endif; ?>

<?php if ($activeTab === 'info'): ?>
<!-- Server Info -->
<h2>Server Info</h2>
<?php if ($serverInfo && $serverInfo->numRows() > 0): ?>
<table class="data-table">
<?php
$arr = $serverInfo->toArray();
foreach ($arr as $row):
    $vals = array_values($row);
    if (count($vals) >= 2):
?>
<tr>
    <td class="info-key"><?= htmlspecialchars((string)$vals[0]) ?></td>
    <td><?= htmlspecialchars((string)($vals[1] ?? '')) ?></td>
</tr>
<?php
    endif;
endforeach;
?>
</table>
<?php else: ?>
<p>No info available.</p>
<?php endif; ?>

<?php elseif ($activeTab === 'databases'): ?>
<!-- Databases -->
<h2>Databases</h2>
<?php if ($databases && $databases->numRows() > 0): ?>
<div class="db-list">
<?php
$arr = $databases->toArray();
foreach ($arr as $row):
    $vals = array_values($row);
    $dbName = (string)($vals[0] ?? '');
    $isCurrent = ($dbName === $currentDb);
?>
<div class="db-item">
    <form method="POST" style="display:inline">
        <input type="hidden" name="action" value="use_db">
        <input type="hidden" name="tab" value="databases">
        <input type="hidden" name="dbname" value="<?= htmlspecialchars($dbName) ?>">
        <button type="submit" class="<?= $isCurrent ? 'current' : '' ?>"><?= htmlspecialchars($dbName) ?></button>
    </form>
</div>
<?php endforeach; ?>
</div>
<?php else: ?>
<p>No databases found.</p>
<?php endif; ?>

<?php if ($tables && $tables->numRows() > 0): ?>
<h3 style="margin-bottom:12px">Tables in <?= htmlspecialchars($currentDb) ?></h3>
<table class="data-table">
<thead><tr><th>Table Name</th></tr></thead>
<tbody>
<?php
$arr = $tables->toArray();
foreach ($arr as $row):
    $vals = array_values($row);
?>
<tr><td><?= htmlspecialchars((string)($vals[0] ?? '')) ?></td></tr>
<?php endforeach; ?>
</tbody>
</table>
<?php elseif ($currentDb): ?>
<p>No tables found in <?= htmlspecialchars($currentDb) ?>.</p>
<?php endif; ?>

<?php elseif ($activeTab === 'sql'): ?>
<!-- SQL Editor -->
<h2>SQL Editor</h2>
<form method="POST" id="sql-form">
    <input type="hidden" name="action" value="query">
    <input type="hidden" name="tab" value="sql">
    <div class="sql-editor">
        <textarea name="sql" id="sql-input" placeholder="Enter SQL statement..."><?= htmlspecialchars($_POST['sql'] ?? '') ?></textarea>
        <div class="sql-toolbar">
            <button type="submit" class="btn btn-blue btn-sm">Execute</button>
            <span class="sql-meta">Ctrl+Enter to execute<?php if ($currentDb): ?> | DB: <?= htmlspecialchars($currentDb) ?><?php endif; ?></span>
            <?php if ($execTime > 0): ?>
            <span class="sql-meta">| <?= number_format($execTime * 1000, 1) ?> ms</span>
            <?php endif; ?>
        </div>
    </div>
</form>

<?php if ($cursor): ?>
<div style="font-size:12px;color:#64748b;margin-bottom:8px">
    <?= $cursor->numRows() ?> row<?= $cursor->numRows() !== 1 ? 's' : '' ?>,
    <?= $cursor->numColumns() ?> column<?= $cursor->numColumns() !== 1 ? 's' : '' ?>
</div>
<div style="overflow-x:auto">
<table class="data-table">
<thead><tr>
<?php for ($c = 1; $c <= $cursor->numColumns(); $c++): ?>
<th><?= htmlspecialchars($cursor->columnName($c) ?? "col{$c}") ?></th>
<?php endfor; ?>
</tr></thead>
<tbody>
<?php for ($r = 1; $r <= $cursor->numRows(); $r++): ?>
<tr>
<?php for ($c = 1; $c <= $cursor->numColumns(); $c++):
    $val = $cursor->field($r, $c);
?>
<td><?php if ($val === null): ?><span class="null-val">NULL</span><?php else: ?><?= htmlspecialchars($val) ?><?php endif; ?></td>
<?php endfor; ?>
</tr>
<?php endfor; ?>
</tbody>
</table>
</div>
<?php endif; ?>

<?php
$history = $_SESSION['cubesql']['history'] ?? [];
if ($history):
?>
<div class="history">
<h3>Recent Queries</h3>
<?php foreach ($history as $item): ?>
<div class="history-item" onclick="document.getElementById('sql-input').value=this.dataset.sql" data-sql="<?= htmlspecialchars($item['sql']) ?>">
    <span class="time"><?= $item['time'] ?></span>
    <span><?= htmlspecialchars(mb_strimwidth($item['sql'], 0, 80, '...')) ?></span>
</div>
<?php endforeach; ?>
</div>
<?php endif; ?>

<?php endif; // activeTab ?>

</div><!-- .content -->

<script>
document.getElementById('sql-input')?.addEventListener('keydown', function(e) {
    if (e.ctrlKey && e.key === 'Enter') {
        e.preventDefault();
        document.getElementById('sql-form').submit();
    }
});
</script>

<?php endif; // isLoggedIn ?>

</body>
</html>
