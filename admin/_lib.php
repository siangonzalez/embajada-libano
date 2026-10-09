<?php
/**
 * Novedades — librería compartida (almacenamiento, sesión, seguridad, sanitización).
 * Compatible con PHP 7.4+.
 *
 * Las publicaciones y usuarios se guardan FUERA del repositorio, en el servidor,
 * para que los despliegues automáticos desde GitHub nunca los borren.
 */
if (!defined('EMB_APP')) { http_response_code(403); exit; }

date_default_timezone_set('America/Bogota');

/* ───────────── Rutas ───────────── */

function emb_site_root() { return dirname(__DIR__); }

function emb_data_dir() {
    static $dir = null;
    if ($dir !== null) return $dir;
    // 1) Preferido: fuera de public_html (no accesible desde la web)
    $outside = dirname(emb_site_root()) . '/embajada-data';
    if ((is_dir($outside) || @mkdir($outside, 0750, true)) && is_writable($outside)) {
        return $dir = $outside;
    }
    // 2) Respaldo: dentro del sitio, bloqueado por .htaccess
    $inside = emb_site_root() . '/_datos_novedades';
    if (!is_dir($inside)) @mkdir($inside, 0750, true);
    $ht = $inside . '/.htaccess';
    if (!file_exists($ht)) {
        @file_put_contents($ht, "<IfModule mod_authz_core.c>\n  Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n  Order allow,deny\n  Deny from all\n</IfModule>\n");
    }
    @file_put_contents($inside . '/index.html', '');
    return $dir = $inside;
}

function emb_uploads_dir() {
    $dir = emb_site_root() . '/uploads/novedades';
    if (!is_dir($dir)) @mkdir($dir, 0755, true);
    $ht = emb_site_root() . '/uploads/.htaccess';
    if (!file_exists($ht)) {
        // Nunca ejecutar scripts dentro de uploads
        @file_put_contents($ht,
            "Options -Indexes\n" .
            "<FilesMatch \"\\.(php|php\\d|phtml|phar|pl|py|cgi|sh|shtml|htm|html|svg|js)$\">\n" .
            "  <IfModule mod_authz_core.c>\n    Require all denied\n  </IfModule>\n" .
            "  <IfModule !mod_authz_core.c>\n    Order allow,deny\n    Deny from all\n  </IfModule>\n" .
            "</FilesMatch>\n");
    }
    return $dir;
}

/* ───────────── Almacenamiento JSON con bloqueo ───────────── */

function emb_read_json($name, $default) {
    $file = emb_data_dir() . '/' . $name . '.json';
    if (!file_exists($file)) return $default;
    $fp = fopen($file, 'r');
    if (!$fp) return $default;
    flock($fp, LOCK_SH);
    $raw = stream_get_contents($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    $data = json_decode($raw, true);
    return is_array($data) ? $data : $default;
}

function emb_write_json($name, $data) {
    $dir = emb_data_dir();
    $file = $dir . '/' . $name . '.json';
    $lock = fopen($dir . '/' . $name . '.lock', 'c');
    flock($lock, LOCK_EX);
    $tmp = $file . '.' . bin2hex(random_bytes(4)) . '.tmp';
    $ok = file_put_contents($tmp, json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT)) !== false
        && rename($tmp, $file);
    if (!$ok) @unlink($tmp);
    flock($lock, LOCK_UN);
    fclose($lock);
    if (!$ok) emb_fail('No se pudo guardar la información en el servidor.', 500);
    @chmod($file, 0640);
}

/* ───────────── Respuestas ───────────── */

function emb_json($data, $code = 200) {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function emb_fail($msg, $code = 400) { emb_json(array('ok' => false, 'error' => $msg), $code); }

/* ───────────── Sesión y autenticación ───────────── */

const EMB_IDLE_TIMEOUT = 7200;       // 2 horas sin actividad
const EMB_MAX_ATTEMPTS = 5;          // intentos fallidos antes de bloquear
const EMB_LOCK_SECONDS = 900;        // 15 minutos de bloqueo

function emb_is_https() {
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https')
        || (isset($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443);
}

function emb_session_start() {
    if (session_status() === PHP_SESSION_ACTIVE) return;
    $sessDir = emb_data_dir() . '/sessions';
    if (!is_dir($sessDir)) @mkdir($sessDir, 0700, true);
    if (is_dir($sessDir) && is_writable($sessDir)) session_save_path($sessDir);
    session_name('EMB_ADMIN');
    session_set_cookie_params(array(
        'lifetime' => 0,
        'path' => '/admin/',
        'secure' => emb_is_https(),
        'httponly' => true,
        'samesite' => 'Strict',
    ));
    ini_set('session.use_strict_mode', '1');
    ini_set('session.gc_maxlifetime', (string)EMB_IDLE_TIMEOUT);
    session_start();
    if (isset($_SESSION['user'], $_SESSION['last']) && time() - $_SESSION['last'] > EMB_IDLE_TIMEOUT) {
        $_SESSION = array();
        session_regenerate_id(true);
    }
    if (isset($_SESSION['user'])) $_SESSION['last'] = time();
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

function emb_users() { return emb_read_json('users', array()); }

function emb_current_user() {
    if (empty($_SESSION['user'])) return null;
    $users = emb_users();
    $u = $_SESSION['user'];
    if (!isset($users[$u])) return null;
    $info = $users[$u];
    return array('username' => $u, 'name' => $info['name'], 'role' => $info['role']);
}

function emb_require_user() {
    $u = emb_current_user();
    if (!$u) emb_fail('Su sesión expiró. Vuelva a iniciar sesión.', 401);
    return $u;
}

function emb_require_admin() {
    $u = emb_require_user();
    if ($u['role'] !== 'admin') emb_fail('Solo un administrador puede hacer esto.', 403);
    return $u;
}

function emb_check_csrf() {
    $sent = isset($_SERVER['HTTP_X_CSRF_TOKEN']) ? $_SERVER['HTTP_X_CSRF_TOKEN'] : '';
    if (empty($_SESSION['csrf']) || !hash_equals($_SESSION['csrf'], $sent)) {
        emb_fail('La página estaba desactualizada. Recárguela e intente de nuevo.', 403);
    }
}

function emb_client_ip() { return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'desconocida'; }

function emb_login_locked() {
    $att = emb_read_json('login_attempts', array());
    $ip = emb_client_ip();
    if (!isset($att[$ip])) return 0;
    $a = $att[$ip];
    if ($a['count'] >= EMB_MAX_ATTEMPTS && time() - $a['last'] < EMB_LOCK_SECONDS) {
        return EMB_LOCK_SECONDS - (time() - $a['last']);
    }
    return 0;
}

function emb_login_attempt($success) {
    $att = emb_read_json('login_attempts', array());
    $ip = emb_client_ip();
    // limpiar registros viejos
    foreach ($att as $k => $a) { if (time() - $a['last'] > EMB_LOCK_SECONDS) unset($att[$k]); }
    if ($success) { unset($att[$ip]); }
    else {
        $c = isset($att[$ip]) ? $att[$ip]['count'] : 0;
        $att[$ip] = array('count' => $c + 1, 'last' => time());
    }
    emb_write_json('login_attempts', $att);
}

function emb_valid_username($u) { return (bool)preg_match('/^[a-z0-9._-]{3,32}$/', $u); }

function emb_password_problem($p) {
    if (strlen($p) < 10) return 'La contraseña debe tener al menos 10 caracteres.';
    if (!preg_match('/[A-Za-z]/', $p) || !preg_match('/[0-9]/', $p)) return 'La contraseña debe combinar letras y números.';
    return null;
}

function emb_setup_key() {
    $f = __DIR__ . '/setup-key.php';
    if (!file_exists($f)) return '';
    $k = include $f;
    return is_string($k) ? trim($k) : '';
}

/* ───────────── Texto y sanitización ───────────── */

function emb_clean_text($s, $max) {
    $s = is_string($s) ? $s : '';
    $s = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $s);
    $s = trim(strip_tags($s));
    if (function_exists('mb_substr')) $s = mb_substr($s, 0, $max, 'UTF-8');
    else $s = substr($s, 0, $max);
    return $s;
}

function emb_safe_url($url, $forImage) {
    $url = trim($url);
    if ($url === '') return '';
    // rutas locales de archivos subidos
    if (preg_match('#^(\./|/)?uploads/novedades/[A-Za-z0-9/_\-.]+$#', $url) && strpos($url, '..') === false) {
        return ltrim(preg_replace('#^\./#', '', $url), '/');
    }
    $p = parse_url($url);
    if (!$p || empty($p['scheme'])) return '';
    $scheme = strtolower($p['scheme']);
    if ($forImage) return $scheme === 'https' ? $url : '';
    if (in_array($scheme, array('http', 'https', 'mailto', 'tel'), true)) return $url;
    return '';
}

function emb_safe_video($url) {
    $p = parse_url(trim($url));
    if (!$p || empty($p['host']) || strtolower(isset($p['scheme']) ? $p['scheme'] : '') !== 'https') return '';
    $host = strtolower($p['host']);
    $okHosts = array('www.youtube.com', 'youtube.com', 'www.youtube-nocookie.com', 'player.vimeo.com');
    if (!in_array($host, $okHosts, true)) return '';
    $path = isset($p['path']) ? $p['path'] : '';
    if (strpos($host, 'vimeo') !== false) return preg_match('#^/video/\d+$#', $path) ? $url : '';
    return preg_match('#^/embed/[A-Za-z0-9_-]+$#', $path) ? $url : '';
}

/**
 * Deja pasar solo un conjunto pequeño y seguro de etiquetas HTML
 * (lo que produce el editor del panel).
 */
function emb_sanitize_html($html) {
    $html = is_string($html) ? trim($html) : '';
    if ($html === '' || $html === '<p><br></p>') return '';
    if (strlen($html) > 300000) $html = substr($html, 0, 300000);

    $allowed = array(
        'p' => array('class'), 'br' => array(), 'strong' => array(), 'b' => array(), 'em' => array(),
        'i' => array(), 'u' => array(), 's' => array(), 'span' => array('class'),
        'a' => array('href'), 'ul' => array('class'), 'ol' => array('class'), 'li' => array('class'),
        'h2' => array('class'), 'h3' => array('class'), 'blockquote' => array('class'),
        'img' => array('src', 'alt'), 'iframe' => array('src', 'class'),
    );

    $doc = new DOMDocument('1.0', 'UTF-8');
    libxml_use_internal_errors(true);
    $doc->loadHTML('<?xml encoding="UTF-8"><div id="emb-root">' . $html . '</div>', LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);
    libxml_clear_errors();
    $root = $doc->getElementById('emb-root');
    if (!$root) return '';

    $walk = function ($node) use (&$walk, $allowed, $doc) {
        $children = array();
        foreach ($node->childNodes as $c) $children[] = $c;
        foreach ($children as $child) {
            if ($child->nodeType === XML_TEXT_NODE) continue;
            if ($child->nodeType !== XML_ELEMENT_NODE) { $node->removeChild($child); continue; }
            $tag = strtolower($child->nodeName);
            if (in_array($tag, array('script', 'style', 'object', 'embed', 'form', 'input', 'textarea', 'button', 'select', 'link', 'meta', 'svg', 'math'), true)) {
                $node->removeChild($child); continue;
            }
            if (!isset($allowed[$tag])) {
                // desenvolver: conservar el contenido, quitar la etiqueta
                $walk($child);
                while ($child->firstChild) $node->insertBefore($child->firstChild, $child);
                $node->removeChild($child);
                continue;
            }
            // atributos
            $attrs = array();
            foreach ($child->attributes as $a) $attrs[] = $a->nodeName;
            foreach ($attrs as $name) {
                $lname = strtolower($name);
                $val = $child->getAttribute($name);
                if (!in_array($lname, $allowed[$tag], true)) { $child->removeAttribute($name); continue; }
                if ($lname === 'class') {
                    $keep = array();
                    foreach (preg_split('/\s+/', $val) as $cl) {
                        if (preg_match('/^ql-[a-z0-9-]{1,30}$/', $cl)) $keep[] = $cl;
                    }
                    if ($keep) $child->setAttribute('class', implode(' ', $keep)); else $child->removeAttribute('class');
                }
                if ($lname === 'href') {
                    $u = emb_safe_url($val, false);
                    if ($u === '') $child->removeAttribute('href'); else $child->setAttribute('href', $u);
                }
                if ($lname === 'src') {
                    $u = $tag === 'iframe' ? emb_safe_video($val) : emb_safe_url($val, true);
                    if ($u === '') { $node->removeChild($child); continue 2; }
                    $child->setAttribute('src', $u);
                }
                if ($lname === 'alt') $child->setAttribute('alt', emb_clean_text($val, 200));
            }
            if ($tag === 'a' && !$child->hasAttribute('href')) {
                // enlace inválido: dejar solo el texto
                $walk($child);
                while ($child->firstChild) $node->insertBefore($child->firstChild, $child);
                $node->removeChild($child);
                continue;
            }
            if ($tag === 'a') {
                $child->setAttribute('target', '_blank');
                $child->setAttribute('rel', 'noopener noreferrer');
            }
            if ($tag === 'img') $child->setAttribute('loading', 'lazy');
            if ($tag === 'iframe') {
                if (!$child->hasAttribute('src')) { $node->removeChild($child); continue; }
                $child->setAttribute('allowfullscreen', 'true');
                $child->setAttribute('frameborder', '0');
                $child->setAttribute('class', 'ql-video');
                $child->setAttribute('loading', 'lazy');
            }
            if ($tag !== 'img' && $tag !== 'br' && $tag !== 'iframe') $walk($child);
            else { while ($child->firstChild) $child->removeChild($child->firstChild); }
        }
    };
    $walk($root);

    $out = '';
    foreach ($root->childNodes as $c) $out .= $doc->saveHTML($c);
    // quitar párrafos vacíos al inicio y al final
    $out = preg_replace('#^(\s*<p>(\s|<br>|&nbsp;)*</p>)+|(<p>(\s|<br>|&nbsp;)*</p>\s*)+$#u', '', trim($out));
    return trim($out);
}

/* ───────────── Publicaciones ───────────── */

function emb_posts() { return emb_read_json('posts', array()); }

function emb_is_expired($post) {
    if (empty($post['expires'])) return false;
    return $post['expires'] < date('Y-m-d');
}

/** Ordena: fijadas primero, luego la más reciente. */
function emb_sort_posts($posts) {
    usort($posts, function ($a, $b) {
        $pa = !empty($a['pinned']) ? 1 : 0;
        $pb = !empty($b['pinned']) ? 1 : 0;
        if ($pa !== $pb) return $pb - $pa;
        $da = !empty($a['publishedAt']) ? $a['publishedAt'] : $a['updated'];
        $db = !empty($b['publishedAt']) ? $b['publishedAt'] : $b['updated'];
        return strcmp($db, $da);
    });
    return $posts;
}
