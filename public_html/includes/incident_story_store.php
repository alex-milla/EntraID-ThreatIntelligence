<?php
/**
 * IncidentStoryStore — almacén del triaje asistido de incidencias Defender XDR.
 *
 * Base independiente (INCIDENT_STORY_DB_PATH, por defecto
 * storage/incident_story.sqlite) con tres tablas:
 *
 *  · casos      caso normalizado + versión pseudonimizada + mapeo + triaje IA
 *  · decisiones decisión humana registrada (auditoría de cada caso)
 *  · (el mapeo viaja en casos.mapping_json: nunca se envía al proveedor IA
 *    ni se pinta en la interfaz de triaje)
 *
 * Sustituye a los ficheros mappings/{id}.json y triajes-AAAA-MM.jsonl de la
 * especificación para seguir la convención del resto de módulos del proyecto.
 */

declare(strict_types=1);

final class IncidentStoryStore
{
    /** Clasificaciones válidas del recurso incident de Microsoft Graph. */
    public const CLASSIFICATIONS = [
        'unknown'                       => 'Desconocida (unknown)',
        'falsePositive'                 => 'Falso positivo (falsePositive)',
        'truePositive'                  => 'Verdadero positivo (truePositive)',
        'informationalExpectedActivity' => 'Actividad esperada (informationalExpectedActivity)',
    ];

    /** Determinaciones válidas del recurso incident de Microsoft Graph. */
    public const DETERMINATIONS = [
        'NotAvailable', 'Malware', 'Phishing', 'UnwantedSoftware', 'Other',
        'CompromisedAccount', 'SecurityPersonnel', 'SecurityTesting',
        'UserReportedPhishing', 'SuspiciousActivity', 'SuspiciousButExpected',
        'IncorrectAlert', 'ConfirmedActivity', 'LineOfBusinessApplication',
        'MaliciousUserActivity', 'Apt', 'ConfidentialInformation',
        'DataExfiltration', 'DataSpillage', 'DestructiveAttack',
        'DenialOfService', 'Fraud', 'InsiderThreat', 'PasswordAttack',
        'Ransomware', 'ValidAccounts',
    ];

    private PDO $pdo;

    public function __construct(?string $dbPath = null)
    {
        $path = $dbPath ?? (string)INCIDENT_STORY_DB_PATH;
        $dir = dirname($path);
        if (!is_dir($dir)) {
            @mkdir($dir, 0770, true);
        }

        $this->pdo = new PDO('sqlite:' . $path, null, null, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        $this->pdo->exec('PRAGMA journal_mode = WAL');
        $this->pdo->exec('PRAGMA busy_timeout = 5000');
        $this->pdo->exec('PRAGMA foreign_keys = ON');

        $this->ensureSchema();
    }

    private function ensureSchema(): void
    {
        $this->pdo->exec("CREATE TABLE IF NOT EXISTS casos (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            public_id          TEXT NOT NULL UNIQUE,
            formato_entrada    TEXT NOT NULL,
            origen             TEXT,
            story_hash         TEXT NOT NULL,
            incidencia_id      TEXT,
            incidencia_nombre  TEXT,
            severidad          TEXT,
            estado             TEXT,
            eventos_count      INTEGER NOT NULL DEFAULT 0,
            caso_json          TEXT NOT NULL,
            anon_json          TEXT NOT NULL,
            mapping_json       TEXT NOT NULL,
            warnings_json      TEXT,
            triage_json        TEXT,
            triage_verdict     TEXT,
            triage_model       TEXT,
            triage_profile     INTEGER,
            triage_at          TEXT,
            created_by         INTEGER,
            created_at         TEXT NOT NULL
        )");
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_story_hash ON casos(story_hash)');
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_story_created ON casos(created_at)');

        $this->pdo->exec("CREATE TABLE IF NOT EXISTS decisiones (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            caso_id        INTEGER NOT NULL REFERENCES casos(id) ON DELETE CASCADE,
            analista       TEXT NOT NULL,
            classification TEXT NOT NULL,
            determination  TEXT NOT NULL DEFAULT 'NotAvailable',
            justificacion  TEXT,
            veredicto_ia   TEXT,
            created_at     TEXT NOT NULL
        )");
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_story_decisions ON decisiones(caso_id)');
    }

    /* =====================================================================
     * Casos
     * ================================================================== */

    public static function newPublicId(): string
    {
        $hex = bin2hex(random_bytes(16));
        return substr($hex, 0, 8) . '-' . substr($hex, 8, 4) . '-' . substr($hex, 12, 4)
            . '-' . substr($hex, 16, 4) . '-' . substr($hex, 20, 12);
    }

    /**
     * Guarda un caso ya normalizado y pseudonimizado.
     *
     * @param array $caso      Modelo normalizado (con id_caso relleno aquí).
     * @param array $anon      Caso pseudonimizado.
     * @param array $mapping   Tabla de pseudónimos (nunca sale del servidor).
     * @param array $warnings  Avisos de la validación post-anonimización.
     * @return array{id:int, public_id:string, story_hash:string, duplicate:?int}
     */
    public function createCase(
        array $caso,
        array $anon,
        array $mapping,
        array $warnings,
        string $storyHash,
        string $formato,
        string $origen,
        ?int $userId = null
    ): array {
        $publicId = self::newPublicId();
        $caso['id_caso'] = $publicId;

        $dup = $this->findByHash($storyHash);
        $incidencia = is_array($caso['incidencia'] ?? null) ? $caso['incidencia'] : [];

        $stmt = $this->pdo->prepare(
            "INSERT INTO casos
             (public_id, formato_entrada, origen, story_hash, incidencia_id,
              incidencia_nombre, severidad, estado, eventos_count, caso_json,
              anon_json, mapping_json, warnings_json, created_by, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        );
        $stmt->execute([
            $publicId,
            $formato,
            $origen,
            $storyHash,
            self::str($incidencia['id_defender'] ?? null),
            self::str($incidencia['nombre'] ?? null),
            self::str($incidencia['severidad'] ?? null),
            self::str($incidencia['estado'] ?? null),
            count((array)($caso['eventos'] ?? [])),
            self::json($caso),
            self::json($anon),
            self::json($mapping),
            self::json($warnings),
            $userId,
            gmdate('c'),
        ]);

        return [
            'id'           => (int)$this->pdo->lastInsertId(),
            'public_id'    => $publicId,
            'story_hash'   => $storyHash,
            'duplicate'    => $dup !== null ? (int)$dup['id'] : null,
        ];
    }

    /** Caso completo con los JSON ya decodificados. */
    public function getCase(int $id): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM casos WHERE id = ?');
        $stmt->execute([$id]);
        $row = $stmt->fetch();
        return $row ? $this->hydrate($row) : null;
    }

    public function findByHash(string $hash): ?array
    {
        $stmt = $this->pdo->prepare('SELECT id FROM casos WHERE story_hash = ? ORDER BY id ASC LIMIT 1');
        $stmt->execute([$hash]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    /** @return array<int,array> Listado sin los JSON grandes. */
    public function listCases(int $limit = 300): array
    {
        $limit = max(1, min(2000, $limit));
        $rows = $this->pdo->query(
            "SELECT c.id, c.public_id, c.formato_entrada, c.origen, c.incidencia_id,
                    c.incidencia_nombre, c.severidad, c.estado, c.eventos_count,
                    c.triage_verdict, c.triage_at, c.created_at,
                    (SELECT d.classification FROM decisiones d
                      WHERE d.caso_id = c.id ORDER BY d.id DESC LIMIT 1) AS ultima_classification,
                    (SELECT d.determination FROM decisiones d
                      WHERE d.caso_id = c.id ORDER BY d.id DESC LIMIT 1) AS ultima_determination,
                    (SELECT COUNT(*) FROM decisiones d WHERE d.caso_id = c.id) AS decisiones_count
               FROM casos c
              ORDER BY c.id DESC
              LIMIT {$limit}"
        )->fetchAll();

        return $rows;
    }

    public function countCases(): int
    {
        return (int)$this->pdo->query('SELECT COUNT(*) FROM casos')->fetchColumn();
    }

    public function stats(): array
    {
        $casos = (int)$this->pdo->query('SELECT COUNT(*) FROM casos')->fetchColumn();
        $triage = (int)$this->pdo->query('SELECT COUNT(*) FROM casos WHERE triage_json IS NOT NULL')->fetchColumn();
        $decisiones = (int)$this->pdo->query('SELECT COUNT(*) FROM decisiones')->fetchColumn();
        $pendientes = (int)$this->pdo->query(
            'SELECT COUNT(*) FROM casos c WHERE NOT EXISTS (SELECT 1 FROM decisiones d WHERE d.caso_id = c.id)'
        )->fetchColumn();

        return [
            'casos'      => $casos,
            'triage'     => $triage,
            'decisiones' => $decisiones,
            'pendientes' => $pendientes,
        ];
    }

    public function deleteCase(int $id): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM casos WHERE id = ?');
        $stmt->execute([$id]);
    }

    /* =====================================================================
     * Triaje IA
     * ================================================================== */

    public function saveTriage(int $id, array $triage, ?string $model, ?int $profileId, ?string $rawContent = null): void
    {
        $verdict = self::str($triage['veredicto_asistido'] ?? null);
        $encoded = json_encode($triage, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($encoded === false || $encoded === '' || $encoded === 'null') {
            /* Nunca guardar un triaje vacío: si falla la serialización se
               conserva la respuesta original del modelo para poder verla. */
            $encoded = self::json([
                'veredicto_asistido' => $verdict,
                'resumen_ejecutivo'  => 'La respuesta del modelo no se pudo serializar.',
                'respuesta_original' => (string)($rawContent ?? ''),
            ]);
            if ($encoded === '{}') {
                /* Si hasta el fallback falla, se sanea la respuesta original. */
                $encoded = (string)json_encode(
                    [
                        'veredicto_asistido' => $verdict,
                        'resumen_ejecutivo'  => 'La respuesta del modelo no se pudo serializar.',
                        'respuesta_original' => (string)($rawContent ?? ''),
                    ],
                    JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
                );
            }
        }
        $stmt = $this->pdo->prepare(
            'UPDATE casos SET triage_json = ?, triage_verdict = ?, triage_model = ?,
                    triage_profile = ?, triage_at = ? WHERE id = ?'
        );
        $stmt->execute([
            $encoded,
            $verdict,
            self::str($model),
            $profileId,
            gmdate('c'),
            $id,
        ]);
    }

    /* =====================================================================
     * Decisiones humanas
     * ================================================================== */

    public function addDecision(
        int $casoId,
        string $analista,
        string $classification,
        string $determination,
        string $justificacion,
        ?string $veredictoIa
    ): int {
        $stmt = $this->pdo->prepare(
            'INSERT INTO decisiones
             (caso_id, analista, classification, determination, justificacion, veredicto_ia, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)'
        );
        $stmt->execute([
            $casoId,
            $analista,
            $classification,
            $determination,
            $justificacion,
            $veredictoIa,
            gmdate('c'),
        ]);
        return (int)$this->pdo->lastInsertId();
    }

    /** @return array<int,array> Decisiones del caso, la más reciente primero. */
    public function listDecisions(int $casoId): array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM decisiones WHERE caso_id = ? ORDER BY id DESC');
        $stmt->execute([$casoId]);
        return $stmt->fetchAll();
    }

    /* =====================================================================
     * Helpers
     * ================================================================== */

    private function hydrate(array $row): array
    {
        $row['caso']      = safe_json_decode((string)$row['caso_json'], []);
        $row['anon']      = safe_json_decode((string)$row['anon_json'], []);
        $row['mapping']   = safe_json_decode((string)$row['mapping_json'], []);
        $row['warnings']  = safe_json_decode((string)($row['warnings_json'] ?? ''), []);
        $row['triage']    = safe_json_decode((string)($row['triage_json'] ?? ''), null);
        return $row;
    }

    private static function json(mixed $value): string
    {
        return json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?: '{}';
    }

    private static function str(mixed $value): ?string
    {
        if ($value === null) {
            return null;
        }
        $s = trim((string)$value);
        return $s === '' ? null : $s;
    }
}
