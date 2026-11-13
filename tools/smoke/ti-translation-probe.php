<?php
/**
 * Probe CLI del E2E de traducciones de Threat Intelligence.
 *
 *   php tools/smoke/ti-probe.php tenants
 *   php tools/smoke/ti-probe.php seed-article <tenant_id> <chars>
 *   php tools/smoke/ti-probe.php article-delete <article_id>
 *   php tools/smoke/ti-probe.php translation-state <article_id>
 *
 * Siembra un artículo con Markdown variado (encabezados, tabla, lista, código)
 * y devuelve su id. El E2E lo borra al terminar.
 */

declare(strict_types=1);

require dirname(__DIR__, 2) . '/public_html/config/bootstrap.php';

$cmd = (string)($argv[1] ?? '');

if ($cmd === 'tenants') {
    $rows = Database::fetchAll("SELECT id, name FROM tenants ORDER BY id LIMIT 5");
    echo json_encode(['tenants' => $rows], JSON_UNESCAPED_UNICODE);
    exit(0);
}

if ($cmd === 'seed-tenant') {
    $slug = 'e2e-ti-' . bin2hex(random_bytes(3));
    $id = Database::insert(
        "INSERT INTO tenants (name, slug, tenant_id, client_id, client_secret_encrypted, client_secret_iv, permissions, is_active)
         VALUES (?, ?, ?, ?, '', '', '[]', 1)",
        ['E2E Threat Intelligence', $slug, 'e2e-tenant-' . $slug, 'e2e-client-' . $slug]
    );
    echo json_encode(['tenant_id' => $id], JSON_UNESCAPED_UNICODE);
    exit(0);
}

if ($cmd === 'tenant-delete') {
    $id = (int)($argv[2] ?? 0);
    if ($id > 0) {
        foreach (Database::fetchAll("SELECT id FROM ti_articles WHERE tenant_id = ?", [$id]) as $a) {
            Database::query("DELETE FROM ti_article_translation_chunks WHERE article_id = ?", [(int)$a['id']]);
            Database::query("DELETE FROM ti_article_translations WHERE article_id = ?", [(int)$a['id']]);
            Database::query("DELETE FROM ti_iocs WHERE article_id = ?", [(int)$a['id']]);
        }
        Database::query("DELETE FROM ti_articles WHERE tenant_id = ?", [$id]);
        Database::query("DELETE FROM ti_iocs WHERE tenant_id = ?", [$id]);
        Database::query("DELETE FROM tenants WHERE id = ?", [$id]);
    }
    echo json_encode(['deleted' => $id], JSON_UNESCAPED_UNICODE);
    exit(0);
}

if ($cmd === 'seed-article') {
    $tenantId = (int)($argv[2] ?? 0);
    $chars = max(800, (int)($argv[3] ?? 3000));
    if ($tenantId <= 0) {
        fwrite(STDERR, "Falta el tenant\n");
        exit(2);
    }

    $paragraph = 'Un actor de amenaza persistente ha desplegado una campaña de phishing dirigida a proveedores '
        . 'energéticos, usando dominios recién registrados y adjuntos con macros. El vector inicial es un correo '
        . 'con un enlace a una página falsa de inicio de sesión que imita el portal corporativo. ';

    $body = "# Campaña de prueba E2E\n\n";
    $body .= "## Resumen\n\n" . str_repeat($paragraph, 3) . "\n\n";
    $body .= "| Indicador | Tipo | Acción |\n|---|---|---|\n| 203.0.113.45 | IP | Bloquear |\n| evil.example.com | Dominio | Monitorizar |\n\n";
    $body .= "## Detalles\n\n- Primer acceso con credenciales válidas\n- Movimiento lateral por SMB\n- Exfiltración por HTTPS\n\n";
    $body .= "Consulta de cazas:\n\n`DeviceProcessEvents`\n`| where Timestamp > ago(30d)`\n`| where RemoteIP in (AttackerInfra)`\n\n";
    $body .= "```powershell\nGet-ChildItem C:\\Users -Recurse\n```\n\n";

    $filler = '';
    while (strlen($body . $filler) < $chars) {
        $filler .= "## Sección adicional\n\n" . str_repeat($paragraph, 2) . "\n\n";
    }
    $body .= $filler;

    $articleId = 'e2e-' . bin2hex(random_bytes(4));
    $id = Database::insert(
        "INSERT INTO ti_articles (tenant_id, article_id, title, created_date, last_updated, summary, body, tags)
         VALUES (?, ?, ?, datetime('now'), datetime('now'), ?, ?, ?)",
        [
            $tenantId,
            $articleId,
            'E2E traducción por bloques',
            'Artículo de prueba para el E2E de traducción (sin datos reales).',
            $body,
            json_encode(['E2E', 'Prueba']),
        ]
    );

    echo json_encode([
        'article_id' => $id,
        'tenant_id'  => $tenantId,
        'chars'      => strlen((string)$body),
    ], JSON_UNESCAPED_UNICODE);
    exit(0);
}

if ($cmd === 'article-delete') {
    $id = (int)($argv[2] ?? 0);
    if ($id > 0) {
        Database::query("DELETE FROM ti_article_translation_chunks WHERE article_id = ?", [$id]);
        Database::query("DELETE FROM ti_article_translations WHERE article_id = ?", [$id]);
        Database::query("DELETE FROM ti_iocs WHERE article_id = ?", [$id]);
        Database::query("DELETE FROM ti_articles WHERE id = ?", [$id]);
    }
    echo json_encode(['deleted' => $id], JSON_UNESCAPED_UNICODE);
    exit(0);
}

if ($cmd === 'listing') {
    $tenantId = (int)($argv[2] ?? 0);
    $rows = Database::fetchAll(
        "SELECT t.article_id, t.created_at AS translated_at, t.chunks, t.failed_chunks, t.mode,
                a.title, a.article_id AS external_id, a.last_updated, a.created_date
         FROM ti_article_translations t
         JOIN ti_articles a ON a.id = t.article_id
         WHERE a.tenant_id = ? AND t.lang = 'es'
           AND t.created_at >= datetime('now', '-90 days')
           AND COALESCE(t.source_updated, '') = COALESCE(a.last_updated, '')
           AND TRIM(COALESCE(t.content, '')) <> ''
         ORDER BY t.created_at DESC, t.article_id DESC
         LIMIT 200",
        [$tenantId]
    );
    echo json_encode(['count' => count($rows), 'rows' => $rows], JSON_UNESCAPED_UNICODE);
    exit(0);
}

if ($cmd === 'translation-state') {
    $id = (int)($argv[2] ?? 0);
    $translation = $id > 0
        ? Database::fetchOne("SELECT content, chunks, failed_chunks, mode, created_at FROM ti_article_translations WHERE article_id = ? AND lang = 'es'", [$id])
        : null;
    $chunks = $id > 0
        ? (int)(Database::fetchOne("SELECT COUNT(*) AS c FROM ti_article_translation_chunks WHERE article_id = ? AND status = 'done'", [$id])['c'] ?? 0)
        : 0;

    echo json_encode([
        'exists'        => $translation !== null,
        'chunks'        => (int)($translation['chunks'] ?? 0),
        'failed_chunks' => (int)($translation['failed_chunks'] ?? 0),
        'mode'          => (string)($translation['mode'] ?? ''),
        'saved_chunks'  => $chunks,
        'content_len'   => $translation !== null ? strlen((string)$translation['content']) : 0,
        'has_marker'    => $translation !== null && str_contains((string)$translation['content'], '[ES]'),
    ], JSON_UNESCAPED_UNICODE);
    exit(0);
}

fwrite(STDERR, "Comando no soportado: {$cmd}\n");
exit(2);
