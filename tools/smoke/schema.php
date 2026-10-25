<?php
/**
 * Vuelca el esquema de una tabla (CLI).
 * Uso: php tools/smoke/schema.php users
 */

declare(strict_types=1);

require dirname(__DIR__, 2) . '/public_html/config/bootstrap.php';

$table = $argv[1] ?? 'users';
$rows = Database::fetchAll("PRAGMA table_info($table)");
foreach ($rows as $r) {
    echo str_pad($r['name'], 24) . ' ' . $r['type'] . PHP_EOL;
}
