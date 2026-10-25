<?php
/**
 * Comprobaciones rápidas de integridad del proyecto (CLI).
 * Uso: php tools/smoke/check.php [--users]
 */

declare(strict_types=1);

require dirname(__DIR__, 2) . '/public_html/config/bootstrap.php';

echo 'PHP ' . PHP_VERSION . PHP_EOL;
echo 'APP_VERSION=' . APP_VERSION . PHP_EOL;
echo 'APP_URL=' . APP_URL . PHP_EOL;

if (in_array('--users', $argv, true)) {
    try {
        $users = Database::fetchAll('SELECT username, role, must_change_password FROM users');
        foreach ($users as $u) {
            echo sprintf("%s | %s | %s\n", $u['username'], $u['role'], $u['is_active']);
        }
    } catch (Throwable $e) {
        echo 'ERR users: ' . $e->getMessage() . PHP_EOL;
    }
}
