<?php
/**
 * API pública: devuelve las novedades publicadas y vigentes.
 * La usa la sección "Novedades" de la página principal.
 */
define('EMB_APP', true);
require __DIR__ . '/../admin/_lib.php';

if ($_SERVER['REQUEST_METHOD'] !== 'GET') emb_fail('Método no permitido', 405);

$out = array();
foreach (emb_sort_posts(emb_posts()) as $p) {
    if ($p['status'] !== 'published' || emb_is_expired($p)) continue;
    $out[] = array(
        'id' => $p['id'],
        'pinned' => !empty($p['pinned']),
        'date' => !empty($p['publishedAt']) ? $p['publishedAt'] : $p['updated'],
        'cover' => isset($p['cover']) ? $p['cover'] : '',
        'attachments' => isset($p['attachments']) ? $p['attachments'] : array(),
        'i18n' => $p['i18n'],
    );
}

emb_json(array('ok' => true, 'posts' => $out));
