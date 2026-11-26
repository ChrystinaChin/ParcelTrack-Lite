<?php
declare(strict_types=1);
ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);
set_exception_handler(static function (Throwable $e): void {
    error_log('ParcelTrack PHP error: '.get_class($e));
    http_response_code(500);
    exit('Unexpected server error.');
});

const BASE_DIR = __DIR__ . '/../..';
$configFile = BASE_DIR . '/.env';
$config = is_file($configFile) ? parse_ini_file($configFile, false, INI_SCANNER_RAW) : [];
if (!is_array($config)) { http_response_code(500); exit('Configuration error.'); }
function cfg(string $key, string $fallback = ''): string {
    global $config;
    $value = getenv($key);
    return ($value !== false && $value !== '') ? $value : (string)($config[$key] ?? $fallback);
}
$key = cfg('PARCELTRACK_INTERNAL_KEY');
if (strlen($key) < 32) { http_response_code(503); exit('Server setup is incomplete.'); }
$apiBase = cfg('PARCELTRACK_API_URL', 'http://127.0.0.1:5000');
if (!preg_match('~^http://127\.0\.0\.1:[0-9]{2,5}$~', $apiBase)) {
    http_response_code(503); exit('Invalid API configuration.');
}
$secure = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
if (cfg('PARCELTRACK_ENV', 'development') === 'production' && !$secure) {
    http_response_code(403); exit('HTTPS is required.');
}
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_httponly', '1');
ini_set('session.use_trans_sid','0');
session_name('PARCELTRACKSESSID');
session_set_cookie_params([
    'lifetime'=>0,'path'=>'/','secure'=>$secure,'httponly'=>true,'samesite'=>'Strict'
]);
session_start();
if (!isset($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
if (!isset($_SESSION['last_seen'])) $_SESSION['last_seen'] = time();
if (time() - (int)$_SESSION['last_seen'] > 1800) {
    $_SESSION = [];
    session_regenerate_id(true);
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}
$_SESSION['last_seen'] = time();
if (!isset($_SESSION['regenerated_at']) || time()-(int)$_SESSION['regenerated_at'] > 900) {
    session_regenerate_id(true);
    $_SESSION['regenerated_at']=time();
}
header_remove('X-Powered-By');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
header('Cache-Control: no-store, max-age=0');
header("Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
if ($secure) header('Strict-Transport-Security: max-age=31536000; includeSubDomains');

function h(mixed $value): string {
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
function url_for(string $page, array $params = []): string {
    return '/?' . http_build_query(array_merge(['page'=>$page],$params), '', '&', PHP_QUERY_RFC3986);
}
function csrf_field(): void {
    echo '<input type="hidden" name="csrf" value="'.h($_SESSION['csrf']).'">';
}
function require_csrf(): void {
    if (!isset($_POST['csrf']) || !is_string($_POST['csrf']) ||
        !hash_equals((string)$_SESSION['csrf'], $_POST['csrf'])) {
        http_response_code(403); exit('Invalid form submission.');
    }
}
function flash(string $message, string $type='notice'): void {
    $_SESSION['flash']=['message'=>$message,'type'=>$type];
}
function redirect_page(string $page, array $params=[]): never {
    header('Location: '.url_for($page,$params),true,303);
    exit;
}
function ip_address(): string {
    // Do not trust user-controlled X-Forwarded-For headers.
    $ip = (string)($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1');
    return filter_var($ip,FILTER_VALIDATE_IP) ? $ip : '127.0.0.1';
}
function api_request(string $method, string $path, ?array $fields=null,
                     ?array $upload=null, bool $binary=false): array {
    global $apiBase, $key;
    if (!preg_match('~^/[a-zA-Z0-9/_?%=&.\-]*$~', $path)) {
        throw new RuntimeException('Unsafe internal API path.');
    }
    $headers=[
        'X-Internal-Key: '.$key,
        'X-Client-IP: '.ip_address(),
        'Accept: application/json'
    ];
    if (isset($_SESSION['token'])) $headers[]='Authorization: Bearer '.$_SESSION['token'];
    $content='';
    if ($upload !== null) {
        $boundary = 'ParcelTrack'.bin2hex(random_bytes(16));
        foreach ($fields ?? [] as $name=>$value) {
            $content .= '--'.$boundary."\r\n";
            $content .= 'Content-Disposition: form-data; name="'.$name.'"'."\r\n\r\n".(string)$value."\r\n";
        }
        if (!empty($upload['tmp_name'])) {
            $content .= '--'.$boundary."\r\n";
            $content .= 'Content-Disposition: form-data; name="proof"; filename="'.
                basename($upload['name']).'"'."\r\n";
            $content .= "Content-Type: application/octet-stream\r\n\r\n";
            $content .= file_get_contents($upload['tmp_name'])."\r\n";
        }
        $content .= '--'.$boundary."--\r\n";
        $headers[]='Content-Type: multipart/form-data; boundary='.$boundary;
    } elseif ($fields !== null) {
        $content = json_encode($fields,JSON_THROW_ON_ERROR);
        $headers[]='Content-Type: application/json';
    }
    $opts=['http'=>[
        'method'=>$method,'header'=>implode("\r\n",$headers)."\r\n",
        'content'=>$content,'ignore_errors'=>true,'timeout'=>12,'follow_location'=>0
    ]];
    $context=stream_context_create($opts);
    $result=@file_get_contents($apiBase.$path,false,$context);
    if ($result===false) {
        error_log('ParcelTrack internal API unavailable');
        return ['status'=>503,'data'=>['detail'=>'The service is temporarily unavailable.']];
    }
    $status=500;
    foreach ($http_response_header ?? [] as $header) {
        if (preg_match('~^HTTP/[0-9.]+\s+([0-9]{3})~',$header,$match)) $status=(int)$match[1];
    }
    if ($binary) return ['status'=>$status,'data'=>$result];
    $data=json_decode($result,true);
    return ['status'=>$status,'data'=>is_array($data)?$data:['detail'=>'The request could not be completed.']];
}
function problem(array $res): string {
    $detail = $res['data']['detail'] ?? 'The request could not be completed.';
    return is_string($detail) ? $detail : 'Invalid request input.';
}
function role(): string { return (string)($_SESSION['role'] ?? 'public'); }
function login_required(array $roles): void {
    if (!isset($_SESSION['token'])) redirect_page('login');
    if (!in_array(role(),$roles,true)) { http_response_code(403); render_header('Access denied');
        echo '<section class="panel"><h2>Access denied</h2><p>This page is restricted.</p></section>'; render_footer(); exit; }
}
function render_header(string $title): void {
    $role=role();
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8">';
    echo '<meta name="viewport" content="width=device-width, initial-scale=1">';
    echo '<title>'.h($title).' · ParcelTrack Lite</title>';
    echo '<link rel="stylesheet" href="/assets/style.css"></head><body>';
    echo '<header class="topbar"><div class="container nav"><a class="logo" href="/">◈ ParcelTrack <span>Lite</span></a><nav>';
    echo '<a href="'.h(url_for('track')).'">Track parcel</a>';
    if ($role==='seller') echo '<a href="'.h(url_for('seller')).'">My parcels</a><a href="'.h(url_for('new-parcel')).'">Register parcel</a>';
    if ($role==='rider') echo '<a href="'.h(url_for('rider')).'">My deliveries</a>';
    if ($role==='admin') echo '<a href="'.h(url_for('admin')).'">Dashboard</a><a href="'.h(url_for('riders')).'">Rider accounts</a>';
    if ($role==='public') echo '<a href="'.h(url_for('login')).'">Sign in</a><a href="'.h(url_for('register')).'">Seller sign up</a>';
    else {
        echo '<a href="'.h(url_for('password')).'">Password</a>';
        echo '<form class="inline" method="post"><input type="hidden" name="action" value="logout">'; csrf_field();
        echo '<button class="nav-signout" type="submit">Sign out</button></form>';
    }
    echo '</nav></div></header><main class="container">';
    if (isset($_SESSION['flash'])) {
        $f=$_SESSION['flash']; unset($_SESSION['flash']);
        echo '<div class="alert '.($f['type']==='error'?'alert-error':'alert-ok').'">'.h($f['message']).'</div>';
    }
}
function render_footer(): void { echo '</main><footer class="container footer">KirimCepat · Secure software development demonstration</footer></body></html>'; }
function field(string $label,string $name,string $type='text',string $value='',bool $required=true, string $extra=''): void {
    echo '<label class="field">'.h($label).'<input name="'.h($name).'" type="'.h($type).'" value="'.h($value).'" '.
        ($required?'required ':'').$extra.'></label>';
}
function post_form_start(string $action, string $class=''): void {
    echo '<form method="post" class="'.h($class).'"><input type="hidden" name="action" value="'.h($action).'">'; csrf_field();
}
