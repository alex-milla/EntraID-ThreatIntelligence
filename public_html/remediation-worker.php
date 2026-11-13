<?php
/**
 * remediation-worker.php — resuelve una consulta del asistente de remediación
 * en segundo plano.
 *
 * Se llama desde el propio servidor (fire-and-forget) al encolar una pregunta.
 * No usa sesión: se autoriza con el token aleatorio guardado en el chat.
 *
 * URL: /remediation-worker.php?token=<token>
 */

declare(strict_types=1);

require_once __DIR__ . '/config/bootstrap.php';

if (function_exists('release_session_lock')) {
    release_session_lock();
}

@ignore_user_abort(true);
@set_time_limit(0);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

$token = (string)($_GET['token'] ?? '');
if ($token === '') {
    http_response_code(400);
    echo '{"ok":false,"error":"bad request"}';
    exit;
}

try {
    $chat = Database::fetchOne(
        "SELECT id FROM remediation_chats WHERE token = ? AND status = 'pending'",
        [$token]
    );
    if ($chat === null) {
        echo '{"ok":true,"skipped":true}';
        exit;
    }

    // Reclamo atómico: un doble lanzamiento no responde dos veces.
    $claimed = Database::update(
        "UPDATE remediation_chats SET status = 'running' WHERE id = ? AND status = 'pending'",
        [(int)$chat['id']]
    );
    if ($claimed === 0) {
        echo '{"ok":true,"skipped":true}';
        exit;
    }

    $module = ModuleManager::get('remediation');
    if (!$module || !method_exists($module, 'processPendingChat')) {
        throw new RuntimeException('El módulo de Remediación no está activo.');
    }

    $result = $module->processPendingChat((int)$chat['id']);
    echo json_encode($result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
} catch (Throwable $e) {
    try {
        Database::update(
            "UPDATE remediation_chats
             SET status = 'error', token = NULL, last_error = ?, updated_at = datetime('now')
             WHERE token = ?",
            [substr($e->getMessage(), 0, 500), $token]
        );
    } catch (Throwable $e2) {
        // Noop
    }
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => $e->getMessage()], JSON_UNESCAPED_UNICODE);
}
