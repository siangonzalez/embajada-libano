<?php
/**
 * API del panel de Novedades (requiere sesión, salvo estado / configuración / ingreso).
 */
define('EMB_APP', true);
require __DIR__ . '/_lib.php';

header('X-Robots-Tag: noindex, nofollow');
emb_session_start();

$method = $_SERVER['REQUEST_METHOD'];
$action = isset($_GET['action']) ? $_GET['action'] : '';

$body = array();
if ($method === 'POST') {
    emb_check_csrf();
    $ct = isset($_SERVER['CONTENT_TYPE']) ? $_SERVER['CONTENT_TYPE'] : '';
    if (stripos($ct, 'application/json') !== false) {
        $body = json_decode(file_get_contents('php://input'), true);
        if (!is_array($body)) $body = array();
    } else {
        $body = $_POST;
    }
}

function arg($k, $d = '') { global $body; return isset($body[$k]) ? $body[$k] : $d; }

const EMB_LANGS = array('es', 'en', 'ar');

switch ($action . ':' . $method) {

/* ───────── Estado de la sesión ───────── */
case 'status:GET':
    $needsSetup = count(emb_users()) === 0;
    emb_json(array(
        'ok' => true,
        'needsSetup' => $needsSetup,
        'setupEnabled' => $needsSetup && emb_setup_key() !== '',
        'user' => emb_current_user(),
        'csrf' => $_SESSION['csrf'],
    ));

/* ───────── Configuración inicial (crea el primer administrador) ───────── */
case 'setup:POST':
    if (count(emb_users()) > 0) emb_fail('El panel ya está configurado.', 403);
    $key = emb_setup_key();
    if ($key === '') emb_fail('La configuración inicial no está habilitada.', 403);
    if ($wait = emb_login_locked()) emb_fail('Demasiados intentos. Espere ' . ceil($wait / 60) . ' minutos.', 429);
    if (!hash_equals($key, (string)arg('key'))) { emb_login_attempt(false); emb_fail('La clave de configuración no es correcta.', 403); }
    $name = emb_clean_text(arg('name'), 80);
    $user = strtolower(trim((string)arg('username')));
    $pass = (string)arg('password');
    if ($name === '') emb_fail('Escriba su nombre.');
    if (!emb_valid_username($user)) emb_fail('El usuario debe tener entre 3 y 32 caracteres: letras minúsculas, números, punto, guion o guion bajo.');
    if ($e = emb_password_problem($pass)) emb_fail($e);
    emb_write_json('users', array($user => array(
        'name' => $name, 'role' => 'admin',
        'hash' => password_hash($pass, PASSWORD_DEFAULT), 'created' => date('c'),
    )));
    emb_login_attempt(true);
    session_regenerate_id(true);
    $_SESSION['user'] = $user;
    $_SESSION['last'] = time();
    emb_json(array('ok' => true, 'user' => emb_current_user()));

/* ───────── Ingreso / salida ───────── */
case 'login:POST':
    if ($wait = emb_login_locked()) emb_fail('Demasiados intentos fallidos. Espere ' . ceil($wait / 60) . ' minutos e intente de nuevo.', 429);
    $user = strtolower(trim((string)arg('username')));
    $pass = (string)arg('password');
    $users = emb_users();
    $hash = isset($users[$user]) ? $users[$user]['hash'] : '$2y$10$usuarioInexistenteParaIgualarTiempo000000000000000000';
    if (!isset($users[$user]) || !password_verify($pass, $hash)) {
        emb_login_attempt(false);
        emb_fail('Usuario o contraseña incorrectos.', 401);
    }
    emb_login_attempt(true);
    if (password_needs_rehash($hash, PASSWORD_DEFAULT)) {
        $users[$user]['hash'] = password_hash($pass, PASSWORD_DEFAULT);
        emb_write_json('users', $users);
    }
    session_regenerate_id(true);
    $_SESSION['user'] = $user;
    $_SESSION['last'] = time();
    emb_json(array('ok' => true, 'user' => emb_current_user()));

case 'logout:POST':
    $_SESSION = array();
    session_regenerate_id(true);
    emb_json(array('ok' => true));

/* ───────── Publicaciones ───────── */
case 'posts:GET':
    emb_require_user();
    $posts = emb_sort_posts(emb_posts());
    foreach ($posts as &$p) $p['expired'] = emb_is_expired($p);
    unset($p);
    emb_json(array('ok' => true, 'posts' => $posts));

case 'save:POST':
    $me = emb_require_user();
    $in = arg('post', array());
    if (!is_array($in)) emb_fail('Datos inválidos.');
    $posts = emb_posts();
    $id = isset($in['id']) ? (string)$in['id'] : '';
    $idx = null;
    foreach ($posts as $i => $p) { if ($p['id'] === $id) { $idx = $i; break; } }
    if ($id !== '' && $idx === null) emb_fail('La publicación ya no existe. Recargue la página.', 404);
    $old = $idx !== null ? $posts[$idx] : null;

    $status = (isset($in['status']) && $in['status'] === 'published') ? 'published' : 'draft';
    $i18n = array();
    foreach (EMB_LANGS as $l) {
        $src = isset($in['i18n'][$l]) && is_array($in['i18n'][$l]) ? $in['i18n'][$l] : array();
        $i18n[$l] = array(
            'title' => emb_clean_text(isset($src['title']) ? $src['title'] : '', 150),
            'summary' => emb_clean_text(isset($src['summary']) ? $src['summary'] : '', 300),
            'content' => emb_sanitize_html(isset($src['content']) ? $src['content'] : ''),
        );
    }
    if ($i18n['es']['title'] === '') emb_fail('Escriba el título en español.');
    if ($status === 'published' && $i18n['es']['summary'] === '') emb_fail('Para publicar, escriba el resumen en español: es el texto que se ve en la tarjeta.');

    $expires = isset($in['expires']) ? trim((string)$in['expires']) : '';
    if ($expires !== '') {
        $d = DateTime::createFromFormat('Y-m-d', $expires);
        if (!$d || $d->format('Y-m-d') !== $expires) emb_fail('La fecha de vencimiento no es válida.');
        if ($status === 'published' && $expires < date('Y-m-d')) emb_fail('La fecha de vencimiento ya pasó. Cámbiela o quítela para publicar.');
    }

    $cover = emb_safe_url(isset($in['cover']) ? (string)$in['cover'] : '', true);
    $atts = array();
    if (isset($in['attachments']) && is_array($in['attachments'])) {
        foreach (array_slice($in['attachments'], 0, 20) as $a) {
            $u = emb_safe_url(isset($a['url']) ? (string)$a['url'] : '', false);
            if ($u === '' || strpos($u, 'uploads/novedades/') !== 0) continue;
            $atts[] = array(
                'name' => emb_clean_text(isset($a['name']) ? $a['name'] : 'Archivo', 150),
                'url' => $u,
                'size' => (int)(isset($a['size']) ? $a['size'] : 0),
            );
        }
    }

    $now = date('c');
    $post = array(
        'id' => $old ? $old['id'] : bin2hex(random_bytes(6)),
        'status' => $status,
        'pinned' => !empty($in['pinned']),
        'expires' => $expires,
        'cover' => $cover,
        'attachments' => $atts,
        'i18n' => $i18n,
        'created' => $old ? $old['created'] : $now,
        'author' => $old ? $old['author'] : $me['name'],
        'updated' => $now,
        'updatedBy' => $me['name'],
        'publishedAt' => ($old && !empty($old['publishedAt'])) ? $old['publishedAt'] : ($status === 'published' ? $now : ''),
    );
    if ($idx !== null) $posts[$idx] = $post; else $posts[] = $post;
    emb_write_json('posts', $posts);
    emb_cleanup_uploads($posts);
    emb_json(array('ok' => true, 'post' => $post));

case 'toggle:POST':
    emb_require_user();
    $id = (string)arg('id');
    $field = (string)arg('field');
    $posts = emb_posts();
    $found = false;
    foreach ($posts as &$p) {
        if ($p['id'] !== $id) continue;
        $found = true;
        if ($field === 'pinned') $p['pinned'] = empty($p['pinned']);
        elseif ($field === 'status') {
            if ($p['status'] === 'published') $p['status'] = 'draft';
            else {
                if ($p['i18n']['es']['summary'] === '') emb_fail('Para publicar, primero edite la publicación y escriba el resumen en español.');
                if (emb_is_expired($p)) emb_fail('Esta publicación ya venció. Edítela y cambie la fecha de vencimiento para volver a publicarla.');
                $p['status'] = 'published';
                if (empty($p['publishedAt'])) $p['publishedAt'] = date('c');
            }
        } else emb_fail('Acción no válida.');
        $p['updated'] = date('c');
    }
    unset($p);
    if (!$found) emb_fail('La publicación ya no existe.', 404);
    emb_write_json('posts', $posts);
    emb_json(array('ok' => true));

case 'delete:POST':
    emb_require_user();
    $id = (string)arg('id');
    $posts = emb_posts();
    $new = array_values(array_filter($posts, function ($p) use ($id) { return $p['id'] !== $id; }));
    if (count($new) === count($posts)) emb_fail('La publicación ya no existe.', 404);
    emb_write_json('posts', $new);
    emb_cleanup_uploads($new, true);
    emb_json(array('ok' => true));

/* ───────── Subida de imágenes y archivos ───────── */
case 'upload:POST':
    emb_require_user();
    if (empty($_FILES['file']) || !is_array($_FILES['file'])) emb_fail('No llegó ningún archivo.');
    $f = $_FILES['file'];
    if ($f['error'] === UPLOAD_ERR_INI_SIZE || $f['error'] === UPLOAD_ERR_FORM_SIZE) emb_fail('El archivo es demasiado grande para el servidor.');
    if ($f['error'] !== UPLOAD_ERR_OK || !is_uploaded_file($f['tmp_name'])) emb_fail('No se pudo subir el archivo. Intente de nuevo.');
    $kind = arg('kind') === 'image' ? 'image' : 'file';
    $orig = emb_clean_text($f['name'], 150);
    $ext = strtolower(pathinfo($orig, PATHINFO_EXTENSION));
    $imageExt = array('jpg', 'jpeg', 'png', 'gif', 'webp');
    $fileExt = array_merge($imageExt, array('pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'zip', 'mp3', 'mp4'));
    if ($kind === 'image') {
        if (!in_array($ext, $imageExt, true)) emb_fail('Solo se permiten imágenes JPG, PNG, GIF o WEBP.');
        if ($f['size'] > 10 * 1024 * 1024) emb_fail('La imagen supera 10 MB.');
        $info = @getimagesize($f['tmp_name']);
        if (!$info || !in_array($info[2], array(IMAGETYPE_JPEG, IMAGETYPE_PNG, IMAGETYPE_GIF, IMAGETYPE_WEBP), true)) emb_fail('El archivo no es una imagen válida.');
    } else {
        if (!in_array($ext, $fileExt, true)) emb_fail('Tipo de archivo no permitido. Se aceptan PDF, Word, Excel, PowerPoint, TXT, ZIP, MP3, MP4 e imágenes.');
        if ($f['size'] > 25 * 1024 * 1024) emb_fail('El archivo supera 25 MB.');
    }
    if ($ext === 'jpeg') $ext = 'jpg';
    $sub = date('Y/m');
    $dir = emb_uploads_dir() . '/' . $sub;
    if (!is_dir($dir) && !@mkdir($dir, 0755, true)) emb_fail('No se pudo crear la carpeta de archivos en el servidor.', 500);
    $name = date('Ymd') . '-' . bin2hex(random_bytes(8)) . '.' . $ext;
    $dest = $dir . '/' . $name;
    $saved = false;
    if ($kind === 'image') $saved = emb_resize_image($f['tmp_name'], $dest, $info[2]);
    if (!$saved && !move_uploaded_file($f['tmp_name'], $dest)) emb_fail('No se pudo guardar el archivo en el servidor.', 500);
    @chmod($dest, 0644);
    emb_json(array('ok' => true, 'url' => 'uploads/novedades/' . $sub . '/' . $name, 'name' => $orig, 'size' => filesize($dest)));

/* ───────── Cuenta y usuarios ───────── */
case 'password:POST':
    $me = emb_require_user();
    $users = emb_users();
    if (!password_verify((string)arg('current'), $users[$me['username']]['hash'])) emb_fail('La contraseña actual no es correcta.');
    $new = (string)arg('new');
    if ($e = emb_password_problem($new)) emb_fail($e);
    $users[$me['username']]['hash'] = password_hash($new, PASSWORD_DEFAULT);
    emb_write_json('users', $users);
    session_regenerate_id(true);
    emb_json(array('ok' => true));

case 'users:GET':
    emb_require_admin();
    $list = array();
    foreach (emb_users() as $u => $info) $list[] = array('username' => $u, 'name' => $info['name'], 'role' => $info['role']);
    emb_json(array('ok' => true, 'users' => $list));

case 'user_add:POST':
    emb_require_admin();
    $users = emb_users();
    $name = emb_clean_text(arg('name'), 80);
    $user = strtolower(trim((string)arg('username')));
    $pass = (string)arg('password');
    $role = arg('role') === 'admin' ? 'admin' : 'editor';
    if ($name === '') emb_fail('Escriba el nombre de la persona.');
    if (!emb_valid_username($user)) emb_fail('El usuario debe tener entre 3 y 32 caracteres: letras minúsculas, números, punto, guion o guion bajo.');
    if (isset($users[$user])) emb_fail('Ese usuario ya existe.');
    if ($e = emb_password_problem($pass)) emb_fail($e);
    $users[$user] = array('name' => $name, 'role' => $role, 'hash' => password_hash($pass, PASSWORD_DEFAULT), 'created' => date('c'));
    emb_write_json('users', $users);
    emb_json(array('ok' => true));

case 'user_reset:POST':
    emb_require_admin();
    $users = emb_users();
    $user = (string)arg('username');
    if (!isset($users[$user])) emb_fail('Ese usuario no existe.');
    $pass = (string)arg('password');
    if ($e = emb_password_problem($pass)) emb_fail($e);
    $users[$user]['hash'] = password_hash($pass, PASSWORD_DEFAULT);
    emb_write_json('users', $users);
    emb_json(array('ok' => true));

case 'user_delete:POST':
    $me = emb_require_admin();
    $users = emb_users();
    $user = (string)arg('username');
    if ($user === $me['username']) emb_fail('No puede eliminar su propio usuario.');
    if (!isset($users[$user])) emb_fail('Ese usuario no existe.');
    unset($users[$user]);
    emb_write_json('users', $users);
    emb_json(array('ok' => true));

default:
    emb_fail('Acción no válida.', 404);
}

/* ───────── Utilidades ───────── */

/** Reduce imágenes grandes (máx. 2000 px) y elimina metadatos. Devuelve false si no hay GD. */
function emb_resize_image($src, $dest, $type) {
    if (!function_exists('imagecreatetruecolor')) return false;
    if ($type === IMAGETYPE_GIF) return false; // conservar animaciones
    $max = 2000;
    list($w, $h) = getimagesize($src);
    if ($type === IMAGETYPE_JPEG && function_exists('imagecreatefromjpeg')) $img = @imagecreatefromjpeg($src);
    elseif ($type === IMAGETYPE_PNG && function_exists('imagecreatefrompng')) $img = @imagecreatefrompng($src);
    elseif ($type === IMAGETYPE_WEBP && function_exists('imagecreatefromwebp')) $img = @imagecreatefromwebp($src);
    else return false;
    if (!$img) return false;
    // corregir orientación de fotos de celular
    if ($type === IMAGETYPE_JPEG && function_exists('exif_read_data')) {
        $exif = @exif_read_data($src);
        $o = isset($exif['Orientation']) ? (int)$exif['Orientation'] : 1;
        if ($o === 3) $img = imagerotate($img, 180, 0);
        elseif ($o === 6) { $img = imagerotate($img, -90, 0); list($w, $h) = array($h, $w); }
        elseif ($o === 8) { $img = imagerotate($img, 90, 0); list($w, $h) = array($h, $w); }
    }
    $scale = min(1, $max / max($w, $h));
    $nw = (int)round($w * $scale); $nh = (int)round($h * $scale);
    $out = imagecreatetruecolor($nw, $nh);
    if ($type !== IMAGETYPE_JPEG) { imagealphablending($out, false); imagesavealpha($out, true); }
    imagecopyresampled($out, $img, 0, 0, 0, 0, $nw, $nh, $w, $h);
    if ($type === IMAGETYPE_JPEG) $ok = imagejpeg($out, $dest, 85);
    elseif ($type === IMAGETYPE_PNG) $ok = imagepng($out, $dest, 6);
    else $ok = imagewebp($out, $dest, 85);
    imagedestroy($img); imagedestroy($out);
    return $ok;
}

/** Borra archivos subidos que ya no usa ninguna publicación (con más de 1 día, o de inmediato si se borró una publicación). */
function emb_cleanup_uploads($posts, $immediate = false) {
    $used = array();
    $json = json_encode($posts, JSON_UNESCAPED_SLASHES);
    if (preg_match_all('#uploads/novedades/[0-9]{4}/[0-9]{2}/[A-Za-z0-9_\-.]+#', $json, $m)) {
        foreach ($m[0] as $u) $used[$u] = true;
    }
    $base = emb_uploads_dir();
    $it = @new RecursiveIteratorIterator(new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS));
    if (!$it) return;
    foreach ($it as $file) {
        if (!$file->isFile()) continue;
        $rel = 'uploads/novedades/' . ltrim(str_replace('\\', '/', substr($file->getPathname(), strlen($base))), '/');
        if (isset($used[$rel])) continue;
        $age = time() - $file->getMTime();
        if ($age > 86400 || ($immediate && $age > 3600)) @unlink($file->getPathname());
    }
}
