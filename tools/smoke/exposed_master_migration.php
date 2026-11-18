<?php
/**
 * exposed_master_migration.php — Migración de snapshots separados a la lista
 * maestra única (v0.4.25.3).
 *
 *   php tools/smoke/exposed_master_migration.php
 *
 * Crea una SQLite temporal con el esquema antiguo (`exposed_cves` con PK
 * (snapshot_id, cve_id)), ejecuta el mismo método que usa la aplicación y
 * comprueba que:
 *   · queda una sola fila por CVE,
 *   · se conserva la de la importación más reciente,
 *   · la PK es `cve_id` y ya no existe `snapshot_id`.
 *
 * No toca la base real.
 */

declare(strict_types=1);

require dirname(__DIR__, 2) . '/public_html/config/bootstrap.php';

$fail = 0;
$total = 0;

function check(string $label, bool $ok, string $detail = ''): void
{
    global $fail, $total;
    $total++;
    if ($ok) {
        echo "OK   {$label}\n";
        return;
    }
    $fail++;
    echo "FALLO {$label}" . ($detail !== '' ? ' — ' . $detail : '') . "\n";
}

$path = sys_get_temp_dir() . '/exposed-migration-' . bin2hex(random_bytes(4)) . '.sqlite';

try {
    $pdo = new PDO('sqlite:' . $path, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);

    // Esquema ANTIGUO (v0.4.25.2): PK compuesta con snapshot_id.
    $pdo->exec("CREATE TABLE exposed_cves (
        snapshot_id INTEGER NOT NULL,
        cve_id TEXT NOT NULL,
        severity TEXT,
        cvss REAL,
        epss REAL,
        age_days INTEGER NOT NULL DEFAULT 0,
        published_at TEXT,
        first_detected_at TEXT,
        updated_at TEXT,
        has_exploit INTEGER NOT NULL DEFAULT 0,
        has_known_threats INTEGER NOT NULL DEFAULT 0,
        has_alerts INTEGER NOT NULL DEFAULT 0,
        exposed_machines INTEGER NOT NULL DEFAULT 0,
        tvm_status TEXT,
        related_software TEXT,
        software_labels TEXT,
        software_tokens TEXT,
        software_total INTEGER NOT NULL DEFAULT 0,
        zero_day INTEGER NOT NULL DEFAULT 0,
        no_security_update INTEGER NOT NULL DEFAULT 0,
        security_update INTEGER NOT NULL DEFAULT 0,
        exploit_kit INTEGER NOT NULL DEFAULT 0,
        exploit_verified INTEGER NOT NULL DEFAULT 0,
        description TEXT,
        fingerprint TEXT,
        PRIMARY KEY (snapshot_id, cve_id)
    ) WITHOUT ROWID");

    $stmt = $pdo->prepare(
        "INSERT INTO exposed_cves
         (snapshot_id, cve_id, severity, exposed_machines, fingerprint, description)
         VALUES (?, ?, ?, ?, ?, ?)"
    );
    // Snapshot 1: A(10) y B(20). Snapshot 2: A(99) y C(30).
    $stmt->execute([1, 'CVE-2026-0001', 'high', 10, 'fp-vieja', 'A vieja']);
    $stmt->execute([1, 'CVE-2026-0002', 'medium', 20, 'fp-b', 'B']);
    $stmt->execute([2, 'CVE-2026-0001', 'critical', 99, 'fp-nueva', 'A nueva']);
    $stmt->execute([2, 'CVE-2026-0003', 'low', 30, 'fp-c', 'C']);

    // Ejecuta el método real de migración (privado) sobre esta SQLite.
    $method = new ReflectionMethod('CveDatabase', 'rebuildExposedCvesMaster');
    $method->setAccessible(true);
    $method->invoke(null, $pdo);

    $cols = [];
    foreach ($pdo->query("PRAGMA table_info(exposed_cves)") as $col) {
        $cols[$col['name']] = $col;
    }
    check('migración: sin snapshot_id', !isset($cols['snapshot_id']));
    check('migración: PK cve_id', isset($cols['cve_id']) && (int)$cols['cve_id']['pk'] === 1);
    check('migración: columnas nuevas', isset($cols['fingerprint'], $cols['first_seen_at'], $cols['last_seen_at']));

    $rows = $pdo->query("SELECT cve_id, severity, exposed_machines, fingerprint, description FROM exposed_cves ORDER BY cve_id")->fetchAll();
    check('migración: una fila por CVE', count($rows) === 3, 'filas=' . count($rows));
    check('migración: se queda el dato más reciente',
        $rows[0]['severity'] === 'critical'
        && (int)$rows[0]['exposed_machines'] === 99
        && $rows[0]['fingerprint'] === 'fp-nueva'
        && $rows[0]['description'] === 'A nueva');
    check('migración: conserva los CVE exclusivos',
        $rows[1]['cve_id'] === 'CVE-2026-0002' && $rows[2]['cve_id'] === 'CVE-2026-0003');

    // Idempotencia: la migración está guardada por la ausencia de snapshot_id,
    // así que tras la primera pasada no se vuelve a ejecutar.
    $cols = [];
    foreach ($pdo->query("PRAGMA table_info(exposed_cves)") as $col) {
        $cols[$col['name']] = true;
    }
    check('migración: el guard no la repetiría', !isset($cols['snapshot_id']));
    $again = (int)$pdo->query("SELECT COUNT(*) AS c FROM exposed_cves")->fetch()['c'];
    check('migración: filas intactas', $again === 3);
} finally {
    $pdo = null;
    if (is_file($path)) {
        @unlink($path);
    }
}

echo "\n" . ($total - $fail) . "/{$total} pruebas correctas\n";
echo $fail === 0 ? "OK\n" : "FALLOS: {$fail}\n";
exit($fail === 0 ? 0 : 1);
