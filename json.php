<?php
session_start();

$hashed_password = '$2a$12$AF.sjRyPPrIw9pwlRq6zsuF2nEQ5/r0kJ7V6fVXAxIx1nNcqYtjl6'; // bcrypt hash

function isAuthenticated() {
    return isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
    if (password_verify($_POST['password'], $hashed_password)) {
        $_SESSION['logged_in'] = true;
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    } else {
        $error = "Access Denied!";
    }
}

if (!isAuthenticated()) :
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard Security</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 flex items-center justify-center min-h-screen">
    <div class="bg-gray-400 p-8 rounded-xl shadow-lg w-96">
        <h2 class="text-2xl font-bold text-center mb-6">@Maw3six</h2>
        
        <?php if (isset($error)) : ?>
            <p class="text-red-500 text-sm text-center mb-4"><?php echo htmlspecialchars($error); ?></p>
        <?php endif; ?>
        
        <form method="POST" class="space-y-4">
            <input type="password" name="password" placeholder="Password" required
                class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-400">
            
            <button type="submit"
                class="w-full bg-red-500 text-white py-2 rounded-lg hover:bg-blue-600 transition">
                >>
            </button>
        </form>
    </div>
</body>
</html>
<?php
    exit;
endif;
?>

<?php
session_start();
set_time_limit(0);

class PhpBackdoorDetector {
    private $baseRoot;
    private $allowedExtensions = ['php','php3','php4','php5','phtml','inc'];
    private $excludeDirs = ['vendor','node_modules','tmp','cache','storage'];
    private $patterns = [];
    private $suspiciousFilenames = [];
    private $suspiciousExtensions = [];
    private $maxFileSize = 3 * 1024 * 1024;
    private $trustedFiles = [];
    private $cacheFile;
    private $cacheTTL = 86400; // 24 jam

    public function __construct($baseRoot = null) {
        $rootCandidate = $baseRoot ?: ($_SERVER['DOCUMENT_ROOT'] ?? getcwd());
        $this->baseRoot = rtrim($rootCandidate, DIRECTORY_SEPARATOR);
        $this->cacheFile = __DIR__ . '/trusted_files.cache.json';

        $this->initPatterns();
        $this->initSuspiciousLists();
        $this->loadTrustedFiles();
    }

    private function initPatterns() {
        $this->patterns = [
            'eval' => '/\beval\s*\(/i',
            'assert' => '/\bassert\s*\(/i',
            'system' => '/\bsystem\s*\(/i',
            'exec' => '/\bexec\s*\(/i',
            'shell_exec' => '/\bshell_exec\s*\(/i',
            'passthru' => '/\bpassthru\s*\(/i',
            'popen' => '/\bpopen\s*\(/i',
            'proc_open' => '/\bproc_open\s*\(/i',
            'create_function' => '/\bcreate_function\s*\(/i',
            'base64_decode' => '/\bbase64_decode\s*\(/i',
            'gzinflate' => '/\bgzinflate\s*\(/i',
            'str_rot13' => '/\bstr_rot13\s*\(/i',
            'preg_replace_eval' => '/preg_replace\s*\([^,]+,[^,]+,[^,]+\)/i',
            'file_get_contents_post' => '/file_get_contents\s*\(\s*\$_(POST|GET|REQUEST)/i',
            'include_dollar' => '/\b(include|require|include_once|require_once)\s*\(\s*\$\w+/i',
            'dynamic_call' => '/\$[a-zA-Z_][a-zA-Z0-9_]*\s*\(/i',
            'long_base64' => '/[A-Za-z0-9+\/=]{80,}/',
            'chmod_world_writable' => '/\bchmod\s*\([^,]+,\s*(0?[0-7]{3,4}|0x[0-9a-fA-F]+)\s*\)/i',
        ];
    }

    private function initSuspiciousLists() {
        $this->suspiciousFilenames = [
            'shell.php','backdoor.php','webshell.php','cmd.php','r57.php','c99.php',
            'b374k.php','phpspy.php','tools.php','adminer.php','upload.php','uploader.php'
        ];
        $this->suspiciousExtensions = [
            '.php.bak', '.php.old', '.php.swp', '.php.swo', '.backdoor', '.shell'
        ];
    }

    private function loadTrustedFiles() {
        if (file_exists($this->cacheFile)) {
            $cache = json_decode(file_get_contents($this->cacheFile), true);
            if (json_last_error() === JSON_ERROR_NONE && !empty($cache['expires']) && time() < $cache['expires']) {
                $this->trustedFiles = $cache['files'];
                return;
            }
        }

        $url = 'https://raw.githubusercontent.com/maw3six/Py-Helper/refs/heads/main/trusted_files.json';
        $content = @file_get_contents($url);
        if ($content === false) return;

        $data = json_decode($content, true);
        if (json_last_error() === JSON_ERROR_NONE && isset($data['trusted_files'])) {
            $cacheData = [
                'files' => array_map('trim', $data['trusted_files']),
                'expires' => time() + $this->cacheTTL
            ];
            file_put_contents($this->cacheFile, json_encode($cacheData, JSON_PRETTY_PRINT));
            $this->trustedFiles = $cacheData['files'];
        }
    }

    private function isTrustedFile($filePath) {

        $relativePath = str_replace($this->baseRoot, '', $filePath);
        $relativePath = str_replace('\\', '/', $relativePath);
        
        foreach ($this->trustedFiles as $trustedPath) {
            $trustedPath = str_replace('\\', '/', trim($trustedPath));
            
            if ($relativePath === $trustedPath) {
                return true;
            }
            
            if (strlen($trustedPath) > 0 && substr($relativePath, -strlen($trustedPath)) === $trustedPath) {
                return true;
            }
            
            if (fnmatch($trustedPath, $relativePath)) {
                return true;
            }
        }
        
        return false;
    }

    public function resolveDirectory($dir) {
        $dir = trim((string)$dir);
        if ($dir === '') return $this->baseRoot;

        if (!preg_match('#^(?:/|[A-Za-z]:\\\\)#', $dir)) {
            $dir = $this->baseRoot . DIRECTORY_SEPARATOR . $dir;
        }

        $real = realpath($dir);
        if ($real === false) return false;

        $baseReal = realpath($this->baseRoot);
        if ($baseReal === false) return false;

        $baseReal = rtrim($baseReal, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        $realNormalized = rtrim($real, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;

        if (strpos($realNormalized, $baseReal) !== 0) return false;
        return rtrim($real, DIRECTORY_SEPARATOR);
    }

    public function buildFileList($directory, $maxFiles = 10000, $filterLevel = 'all') {
        $dir = $this->resolveDirectory($directory);
        if (!$dir) return ['error' => 'Invalid or disallowed directory'];

        $files = [];
        try {
            $it = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS | FilesystemIterator::FOLLOW_SYMLINKS),
                RecursiveIteratorIterator::LEAVES_ONLY
            );

            foreach ($it as $fileinfo) {
                $pathParts = explode(DIRECTORY_SEPARATOR, $fileinfo->getPath());
                $skip = false;
                foreach ($pathParts as $part) {
                    if (in_array($part, $this->excludeDirs, true)) { $skip = true; break; }
                }
                if ($skip) continue;

                if (!$fileinfo->isFile()) continue;

                $ext = strtolower($fileinfo->getExtension());
                if (!in_array($ext, $this->allowedExtensions, true)) continue;

                $size = $fileinfo->getSize();
                if ($size === false || $size > $this->maxFileSize) continue;

                $files[] = $fileinfo->getPathname();
                if (count($files) >= $maxFiles) break;
            }
        } catch (Exception $e) {
            return ['error' => 'Error listing files: ' . $e->getMessage()];
        }

        $_SESSION['detector_file_list'] = array_values($files);
        $_SESSION['detector_index'] = 0;
        $_SESSION['detector_results'] = [];
        $_SESSION['detector_scanned'] = 0;
        $_SESSION['detector_suspicious'] = 0;
        $_SESSION['detector_cleaned'] = 0;
        $_SESSION['detector_last_file'] = null;
        $_SESSION['detector_filter_level'] = $filterLevel;

        session_write_close();

        return ['count' => count($files), 'files' => array_slice($files, 0, 500), 'filter_level' => $filterLevel];
    }

    public function scanFileEntry($filepath) {
        $list = $_SESSION['detector_file_list'] ?? [];
        if (!in_array($filepath, $list, true)) {
            return ['error' => 'File not in scanning list or session expired', 'file' => $filepath];
        }

        $real = realpath($filepath);
        if ($real === false) return ['error' => 'Invalid file path'];
        $baseReal = rtrim(realpath($this->baseRoot), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        if (strpos(rtrim($real, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR, $baseReal) !== 0) {
            return ['error' => 'File outside allowed root'];
        }

        session_write_close();

        if ($this->isTrustedFile($real)) {
            session_start();
            $_SESSION['detector_scanned'] = ($_SESSION['detector_scanned'] ?? 0) + 1;
            $_SESSION['detector_results'][] = [
                'path' => $real,
                'risk_level' => 'trusted',
                'threats' => ['Core file: Known trusted file (whitelisted)'],
                'size' => filesize($real),
                'included' => true
            ];
            session_write_close();
            return [
                'path' => $real,
                'risk_level' => 'trusted',
                'threats' => ['Core file: Known trusted file (whitelisted)'],
                'size' => filesize($real),
                'skipped' => true
            ];
        }

        if (!is_readable($real)) {
            session_start();
            $_SESSION['detector_scanned'] = ($_SESSION['detector_scanned'] ?? 0) + 1;
            $_SESSION['detector_results'][] = ['path' => $filepath, 'risk_level' => 'low', 'threats' => ['Not readable'], 'size' => 0];
            session_write_close();
            return ['error' => 'File not readable'];
        }

        $content = @file_get_contents($real);
        if ($content === false) {
            session_start();
            $_SESSION['detector_scanned'] = ($_SESSION['detector_scanned'] ?? 0) + 1;
            $_SESSION['detector_results'][] = ['path' => $filepath, 'risk_level' => 'low', 'threats' => ['Failed to read'], 'size' => 0];
            session_write_close();
            return ['error' => 'Failed to read file'];
        }

        $reasons = [];
        foreach ($this->patterns as $name => $pattern) {
            if (@preg_match($pattern, $content)) {
                $reasons[] = "Pattern matched: {$name}";
            }
        }

        $basename = strtolower(basename($real));
        foreach ($this->suspiciousFilenames as $sname) {
            if (strpos($basename, strtolower($sname)) !== false) {
                $reasons[] = "Suspicious filename: {$basename}";
                break;
            }
        }

        foreach ($this->suspiciousExtensions as $ext) {
            if (substr($basename, -strlen($ext)) === $ext) {
                $reasons[] = "Suspicious extension: {$ext}";
            }
        }

        if (preg_match('/base64_decode\s*\(/i', $content) && preg_match('/[A-Za-z0-9+\/=]{100,}/', $content)) {
            $reasons[] = "Obfuscated code: long base64 + decode";
        }

        $size = strlen($content);
        if ($size < 30 && preg_match('/eval|base64_decode|gzinflate/i', $content)) {
            $reasons[] = "Very small file with eval/obfuscation";
        }

        $risk = $this->computeRisk($reasons, $content);

        session_start();
        $entry = [
            'path' => $real,
            'risk_level' => $risk,
            'threats' => $reasons,
            'size' => $size,
            'included' => $this->matchesFilter($risk, $_SESSION['detector_filter_level'] ?? 'all')
        ];

        if ($entry['included'] || $_SESSION['detector_filter_level'] === 'all') {
            $_SESSION['detector_results'][] = $entry;
        }

        $_SESSION['detector_scanned'] = ($_SESSION['detector_scanned'] ?? 0) + 1;
        if (in_array($risk, ['high','medium'], true)) {
            $_SESSION['detector_suspicious'] = ($_SESSION['detector_suspicious'] ?? 0) + 1;
        }
        $_SESSION['detector_last_file'] = $real;
        session_write_close();

        return $entry;
    }

    private function computeRisk(array $reasons, $content) {
        if (empty($reasons)) return 'low';
        $score = 0;
        foreach ($reasons as $r) {
            if (preg_match('/eval|system|exec|shell_exec|proc_open|popen|passthru|create_function/i', $r)) $score += 60;
            elseif (preg_match('/Obfuscated|base64|gzinflate|str_rot13/i', $r)) $score += 25;
            elseif (preg_match('/Suspicious filename|extension|Very small/i', $r)) $score += 15;
            else $score += 10;
        }
        if (preg_match('/[A-Za-z0-9+\/=]{200,}/', $content)) $score += 20;

        if ($score >= 60) return 'high';
        if ($score >= 25) return 'medium';
        return 'low';
    }

    private function matchesFilter($riskLevel, $filterLevel) {
        if ($filterLevel === 'all') return true;
        switch ($filterLevel) {
            case 'high_only': return $riskLevel === 'high';
            case 'medium_only': return $riskLevel === 'medium';
            case 'low_only': return $riskLevel === 'low';
            case 'high_medium': return in_array($riskLevel, ['high', 'medium']);
            case 'medium_low': return in_array($riskLevel, ['medium', 'low']);
            default: return true;
        }
    }

    public function quarantineFile($filepath, $createBackup = true) {
        $list = $_SESSION['detector_file_list'] ?? [];
        if (!in_array($filepath, $list, true)) {
            return ['error' => 'File not in scanning list or session expired'];
        }

        $real = realpath($filepath);
        if ($real === false) return ['error' => 'Invalid file path'];

        if (!is_writable(dirname($real))) {
            return ['error' => 'Cannot write to file directory (permission denied)'];
        }

        $quarantineDir = $this->baseRoot . DIRECTORY_SEPARATOR . 'detector_quarantine';
        if (!is_dir($quarantineDir)) {
            if (!mkdir($quarantineDir, 0750, true)) {
                return ['error' => 'Failed to create quarantine directory'];
            }
        }

        $timestamp = date('Ymd_His');
        $safeBase = preg_replace('/[^A-Za-z0-9_.-]/', '_', basename($real));
        $newName = $safeBase . '.quarantine.' . $timestamp;
        $dest = $quarantineDir . DIRECTORY_SEPARATOR . $newName;

        if ($createBackup) {
            $backupDir = $this->baseRoot . DIRECTORY_SEPARATOR . 'detector_backups';
            if (!is_dir($backupDir) && !mkdir($backupDir, 0750, true)) {
                return ['error' => 'Failed to create backup directory'];
            }
            $backupPath = $backupDir . DIRECTORY_SEPARATOR . $safeBase . '.bak.' . $timestamp;
            if (!copy($real, $backupPath)) {
                return ['error' => 'Failed to create backup before quarantine', 'backup' => $backupPath];
            }
        }

        if (!rename($real, $dest)) {
            return ['error' => 'Failed to move file to quarantine', 'dest' => $dest];
        }

        $_SESSION['detector_cleaned'] = ($_SESSION['detector_cleaned'] ?? 0) + 1;
        return ['ok' => true, 'quarantine' => $dest];
    }

    public function deleteFile($filepath) {
        $list = $_SESSION['detector_file_list'] ?? [];
        if (!in_array($filepath, $list, true)) {
            return ['error' => 'File not in scanning list or session expired'];
        }

        $real = realpath($filepath);
        if ($real === false) return ['error' => 'Invalid file path'];

        if (!is_writable($real)) return ['error' => 'Cannot delete file (permission denied)'];

        if (@unlink($real)) {
            $_SESSION['detector_cleaned'] = ($_SESSION['detector_cleaned'] ?? 0) + 1;
            return ['ok' => true, 'deleted' => $real];
        } else {
            return ['error' => 'Failed to delete file'];
        }
    }

    public function exportReport() {
        $results = $_SESSION['detector_results'] ?? [];
        $scanned = $_SESSION['detector_scanned'] ?? count($results);
        $suspicious = $_SESSION['detector_suspicious'] ?? 0;
        $cleaned = $_SESSION['detector_cleaned'] ?? 0;
        $score = $scanned > 0 ? round(100 - ($suspicious / $scanned * 100)) : 100;

        $report  = "Backdoor Cleaner X Maw3six - Security Report\n";
        $report .= "Generated: " . date('Y-m-d H:i:s') . "\n";
        $report .= str_repeat("=", 50) . "\n\n";
        $report .= "Scan Summary:\n";
        $report .= "Files Scanned: {$scanned}\n";
        $report .= "Suspicious Files: {$suspicious}\n";
        $report .= "Files Cleaned/Quarantined: {$cleaned}\n";
        $report .= "Security Score: {$score}%\n\n";

        if (!empty($results)) {
            $report .= "Detected Threats:\n";
            foreach ($results as $file) {
                $report .= "- {$file['path']} [" . strtoupper($file['risk_level']) . "]\n";
                foreach ($file['threats'] as $t) {
                    $report .= "  * {$t}\n";
                }
                $report .= "\n";
            }
        } else {
            $report .= "No threats detected or no files scanned.\n";
        }

        return $report;
    }

    public function status() {
        $total = count($_SESSION['detector_file_list'] ?? []);
        $idx = $_SESSION['detector_index'] ?? 0;
        $scanned = $_SESSION['detector_scanned'] ?? 0;
        $suspicious = $_SESSION['detector_suspicious'] ?? 0;
        $cleaned = $_SESSION['detector_cleaned'] ?? 0;
        $last = $_SESSION['detector_last_file'] ?? null;
        $filterLevel = $_SESSION['detector_filter_level'] ?? 'all';
        return [
            'total_files' => $total,
            'index' => $idx,
            'scanned' => $scanned,
            'suspicious' => $suspicious,
            'cleaned' => $cleaned,
            'last_file' => $last,
            'files_found' => min(50, $total),
            'filter_level' => $filterLevel
        ];
    }

    public function nextIndex() {
        $_SESSION['detector_index'] = ($_SESSION['detector_index'] ?? 0) + 1;
    }
}

// --- AJAX Router ---
$detector = new PhpBackdoorDetector();

$action = $_POST['action'] ?? $_GET['action'] ?? null;

if ($action) {
    if ($action !== 'export') header('Content-Type: application/json; charset=utf-8');

    switch ($action) {
        case 'list_files':
            $dir = $_POST['directory'] ?? $_GET['directory'] ?? getcwd();
            $filterLevel = $_POST['filter_level'] ?? 'all';
            echo json_encode($detector->buildFileList($dir, 20000, $filterLevel));
            exit;

        case 'scan_next':
            $list = $_SESSION['detector_file_list'] ?? [];
            $idx = $_SESSION['detector_index'] ?? 0;
            if (!isset($list[$idx])) {
                echo json_encode(['done' => true, 'status' => $detector->status()]);
                exit;
            }
            $file = $list[$idx];
            $_SESSION['detector_index'] = $idx + 1;
            session_write_close();
            $res = $detector->scanFileEntry($file);
            session_start();
            $out = ['file_result' => $res, 'status' => $detector->status()];
            session_write_close();
            echo json_encode($out);
            exit;

        case 'quarantine':
            $file = $_POST['file'] ?? '';
            echo json_encode($detector->quarantineFile($file, true));
            exit;

        case 'delete':
            $file = $_POST['file'] ?? '';
            echo json_encode($detector->deleteFile($file));
            exit;

        case 'export':
            header('Content-Type: text/plain; charset=utf-8');
            header('Content-Disposition: attachment; filename="security_report_' . date('Y-m-d') . '.txt"');
            echo $detector->exportReport();
            exit;

        case 'status':
            echo json_encode($detector->status());
            exit;

        case 'reset':
            unset($_SESSION['detector_file_list'], $_SESSION['detector_index'], $_SESSION['detector_results'],
                  $_SESSION['detector_scanned'], $_SESSION['detector_suspicious'], $_SESSION['detector_cleaned'],
                  $_SESSION['detector_last_file'], $_SESSION['detector_filter_level']);
            echo json_encode(['ok' => true]);
            exit;

        default:
            echo json_encode(['error' => 'Unknown action']);
            exit;
    }
}

// --- UI HTML + JavaScript ---
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Backdoor Cleaner X Maw3six</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .glass { backdrop-filter: blur(8px); background-color: rgba(17,24,39,0.45); border:1px solid rgba(255,255,255,0.06); }
        .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, "Roboto Mono", "Courier New", monospace; }
    </style>
</head>
<body class="bg-gray-900 text-gray-200 min-h-screen">
<header class="p-4">
    <div class="container mx-auto">
        <h1 class="text-2xl font-bold">Backdoor Cleaner X Maw3six</h1>
        <p class="text-sm text-gray-300">Webshell Scanner - Trusted Whitelist</p>
    </div>
</header>

<main class="container mx-auto p-6">
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div class="glass rounded p-4">
            <p class="text-sm">Files Scanned</p>
            <p id="scanned-count" class="text-2xl font-bold">0</p>
        </div>
        <div class="glass rounded p-4">
            <p class="text-sm">Threats Found</p>
            <p id="threats-count" class="text-2xl font-bold">0</p>
        </div>
        <div class="glass rounded p-4">
            <p class="text-sm">Quarantined</p>
            <p id="cleaned-count" class="text-2xl font-bold">0</p>
        </div>
        <div class="glass rounded p-4">
            <p class="text-sm">Security Score</p>
            <p id="security-score" class="text-2xl font-bold">100%</p>
        </div>
    </div>

    <div class="glass rounded p-6 mb-6">
        <h2 class="text-lg font-semibold mb-3">Scan Configuration</h2>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
                <label class="text-sm block mb-1">Directory to scan</label>
                <input id="scan-directory" class="w-full p-2 bg-gray-800 rounded mono" value="<?php echo htmlspecialchars(getcwd()); ?>">
            </div>
            <div>
                <label class="text-sm block mb-1">Risk Level Filter</label>
                <select id="filter-level" class="w-full p-2 bg-gray-800 rounded">
                    <option value="all">All Levels</option>
                    <option value="high_only">High Only</option>
                    <option value="medium_only">Medium Only</option>
                    <option value="high_medium">High + Medium</option>
                </select>
            </div>
        </div>

        <div class="flex items-center space-x-4 mt-4">
            <button id="start-btn" class="bg-blue-600 px-4 py-2 rounded">Start Scan</button>
            <button id="stop-btn" disabled class="bg-red-600 px-4 py-2 rounded">Stop</button>
            <button id="export-btn" class="bg-green-600 px-4 py-2 rounded">Export Report</button>
            <button id="reset-btn" class="bg-gray-700 px-4 py-2 rounded">Reset</button>
        </div>
    </div>

    <div id="progress-area" style="display:none;" class="glass rounded p-6 mb-6">
        <div class="flex justify-between">
            <p id="progress-text" class="text-lg font-semibold">0 / 0</p>
            <p id="current-file" class="mono text-sm max-w-xs truncate">-</p>
        </div>
        <div class="w-full bg-gray-800 h-3 rounded mt-4">
            <div id="progress-bar" class="bg-indigo-500 h-3 rounded" style="width:0%"></div>
        </div>
    </div>

    <div class="glass rounded p-6" id="results-section">
        <h3 class="text-lg font-semibold">Scan Results</h3>
        <div id="results-list" class="space-y-3 mt-3"></div>
    </div>

    <div class="glass rounded p-4 mt-6">
        <h4 class="text-sm font-medium">Live Log</h4>
        <div id="log" class="h-48 overflow-auto bg-gray-900 p-2 mono text-sm rounded mt-2"></div>
    </div>
</main>

<script>
(function(){
    const startBtn = document.getElementById('start-btn');
    const stopBtn = document.getElementById('stop-btn');
    const exportBtn = document.getElementById('export-btn');
    const resetBtn = document.getElementById('reset-btn');
    let scanning = false;

    function log(msg, type='info') {
        const el = document.getElementById('log');
        const t = new Date().toLocaleTimeString();
        const row = document.createElement('div');
        row.textContent = `[${t}] ${msg}`;
        el.appendChild(row);
        el.scrollTop = el.scrollHeight;
    }

    function api(action, data = {}, expectJson = true) {
        const form = new FormData();
        form.append('action', action);
        for (const k in data) form.append(k, data[k]);
        return fetch('', { method: 'POST', body: form }).then(r => expectJson ? r.json() : r.text());
    }

    async function startScan() {
        if (scanning) return;
        scanning = true;
        startBtn.disabled = true;
        stopBtn.disabled = false;
        document.getElementById('progress-area').style.display = 'block';

        const dir = document.getElementById('scan-directory').value || '';
        const filterLevel = document.getElementById('filter-level').value || 'all';
        log('Starting scan in: ' + (dir || 'root'));
        const res = await api('list_files', { directory: dir, filter_level: filterLevel });
        if (res.error) {
            log('Error: ' + res.error);
            stopScan();
            return;
        }
        log(`Found ${res.count} files. Starting scan...`);
        updateStatus();
        pollScan();
    }

    async function pollScan() {
        if (!scanning) return;
        try {
            const res = await api('scan_next');
            if (res.done) {
                log('Scan completed.');
                stopScan();
                return;
            }
            const fr = res.file_result;
            if (fr.error) {
                log('Error: ' + fr.error);
            } else {
                if (fr.risk_level === 'trusted') {
                    log(`Trusted: ${fr.path} -> WHITELISTED`);
                } else {
                    log(`Scanned: ${fr.path} -> ${fr.risk_level.toUpperCase()}`);
                }
                if (fr.included || res.status.filter_level === 'all') {
                    addResult(fr);
                }
            }
            updateProgressUI(res.status);
            setTimeout(() => { if (scanning) pollScan(); }, 40);
        } catch (e) {
            log('Error: ' + e.message);
            stopScan();
        }
    }

    function updateProgressUI(status) {
        const total = status.total_files || 0;
        const scanned = status.scanned || 0;
        const pct = total ? Math.round((scanned/total)*100) : 0;
        document.getElementById('progress-text').textContent = `${scanned} / ${total}`;
        document.getElementById('progress-bar').style.width = pct + '%';
        document.getElementById('scanned-count').textContent = scanned;
        document.getElementById('threats-count').textContent = status.suspicious || 0;
        document.getElementById('cleaned-count').textContent = status.cleaned || 0;
        document.getElementById('security-score').textContent = Math.round(100 - ((status.suspicious||0)/Math.max(1,total)*100)) + '%';
        if (status.last_file) document.getElementById('current-file').textContent = status.last_file;
    }

    function addResult(fr) {
        const list = document.getElementById('results-list');
        const item = document.createElement('div');
        let riskClass = 'bg-gray-800';
        let riskColor = 'text-gray-300';
        let showActions = true;
        
        switch(fr.risk_level) {
            case 'high': 
                riskClass = 'bg-red-900 border-red-500'; 
                riskColor = 'text-red-300'; 
                break;
            case 'medium': 
                riskClass = 'bg-yellow-900 border-yellow-500'; 
                riskColor = 'text-yellow-300'; 
                break;
            case 'trusted': 
                riskClass = 'bg-green-900 border-green-500'; 
                riskColor = 'text-green-300';
                showActions = true;
                break;
        }
        
        item.className = `${riskClass} border p-3 rounded`;
        const threats = (fr.threats || []).map(t=>`<li>${t}</li>`).join('');
        
        const actionsHtml = showActions ? 
            `<div class="space-y-1">
                <button class="quarantine-btn bg-yellow-600 px-2 py-1 rounded text-xs" data-path="${encodeURIComponent(fr.path)}">Quarantine</button>
                <button class="delete-btn bg-red-700 px-2 py-1 rounded text-xs" data-path="${encodeURIComponent(fr.path)}">Delete</button>
            </div>` : 
            `<div class="text-xs text-green-400">✓ Trusted</div>`;
            
        item.innerHTML = `<div class="flex justify-between">
            <div>
                <div class="mono text-sm">${fr.path}</div>
                <div class="text-xs mt-1">Risk: <strong class="${riskColor}">${fr.risk_level.toUpperCase()}</strong></div>
                <ul class="text-xs mt-2">${threats}</ul>
            </div>
            ${actionsHtml}
        </div>`;
        
        list.prepend(item);

        if (showActions) {
            item.querySelector('.quarantine-btn').addEventListener('click', async (e)=>{
                const p = decodeURIComponent(e.currentTarget.getAttribute('data-path'));
                if (!confirm('Quarantine: ' + p + '?')) return;
                const res = await api('quarantine', { file: p });
                if (res.ok) log('Quarantined: ' + res.quarantine);
                else log('Fail: ' + res.error);
                updateStatus();
            });

            item.querySelector('.delete-btn').addEventListener('click', async (e)=>{
                const p = decodeURIComponent(e.currentTarget.getAttribute('data-path'));
                if (!confirm('Delete permanently: ' + p + '?')) return;
                const res = await api('delete', { file: p });
                if (res.ok) log('Deleted: ' + res.deleted);
                else log('Fail: ' + res.error);
                updateStatus();
            });
        }
    }

    function updateStatus() {
        api('status').then(updateProgressUI).catch(console.warn);
    }

    function stopScan() {
        scanning = false;
        startBtn.disabled = false;
        stopBtn.disabled = true;
    }

    function exportReport() {
        const form = document.createElement('form');
        form.method = 'POST';
        form.style.display = 'none';
        const input = document.createElement('input');
        input.name = 'action';
        input.value = 'export';
        form.appendChild(input);
        document.body.appendChild(form);
        form.submit();
        document.body.removeChild(form);
    }

    async function reset() {
        if (!confirm('Reset session?')) return;
        await api('reset');
        document.getElementById('results-list').innerHTML = '';
        document.getElementById('log').innerHTML = '';
        updateStatus();
        log('Session reset.');
    }

    startBtn.addEventListener('click', startScan);
    stopBtn.addEventListener('click', stopScan);
    exportBtn.addEventListener('click', exportReport);
    resetBtn.addEventListener('click', reset);
    updateStatus();
})();
</script>
</body>
</html>