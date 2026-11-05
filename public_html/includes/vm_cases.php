<?php
/**
 * VmCases — reglas puras del seguimiento de vulnerabilidades (v0.3.0).
 *
 * El origen de los casos es la importación MANUAL del CSV de Defender TVM.
 * Ese export es agregado por CVE: no identifica equipos, así que el ámbito de
 * seguimiento es empresa + CVE y los pares vendor:product son solo metadata.
 *
 * Este fichero no escribe en base de datos: concentra estados, prioridad,
 * plazos y decisiones de reimportación para poder probarlas en los smoke tests.
 */

declare(strict_types=1);

final class VmCases
{
    /** Estados del ciclo de remediación (claves estables en BD). */
    public const STATUSES = [
        'detected'             => 'Detectada',
        'in_review'            => 'En evaluación',
        'planned'              => 'Planificada',
        'assigned'             => 'Asignada',
        'in_progress'          => 'En curso',
        'mitigated'            => 'Mitigada (control compensatorio)',
        'pending_verification' => 'Pendiente de verificación',
        'resolved_verified'    => 'Corregida y verificada',
        'risk_accepted'        => 'Riesgo aceptado temporalmente',
        'false_positive'       => 'Falso positivo',
    ];

    /** Fuentes admitidas para un hallazgo local. */
    public const FINDING_SOURCES = [
        'manual'         => 'Registro manual',
        'defender-tvm'   => 'Defender TVM (CSV)',
        'reconocimiento' => 'Reconocimiento / inventario',
        'otro'           => 'Otra fuente',
    ];

    /** Estados que retiran el caso de la cola abierta. */
    public const CLOSED_STATUSES = ['resolved_verified', 'false_positive'];

    public const PRIORITIES = [
        'critical' => 'Crítica',
        'high'     => 'Alta',
        'medium'   => 'Media',
        'low'      => 'Baja',
    ];

    /** Plazos por defecto (días) si no hay configuración guardada. */
    public const DEFAULT_SLA = [
        'critical' => 14,
        'high'     => 30,
        'medium'   => 60,
        'low'      => 90,
    ];

    public const DUE_SOON_DAYS = 7;

    public static function isStatus(string $status): bool
    {
        return isset(self::STATUSES[$status]);
    }

    public static function isClosed(string $status): bool
    {
        return in_array($status, self::CLOSED_STATUSES, true);
    }

    public static function statusLabel(string $status): string
    {
        return self::STATUSES[$status] ?? $status;
    }

    public static function priorityLabel(?string $priority): string
    {
        if ($priority === null || $priority === '') {
            return 'Sin calcular';
        }
        return self::PRIORITIES[$priority] ?? ucfirst($priority);
    }

    /** Clave lógica del ámbito: no existe seguimiento por activo en el CSV. */
    public static function scopeKey(int $groupId, string $cveId): string
    {
        return $groupId . '|' . strtoupper(trim($cveId));
    }

    /**
     * Plazo configurable por empresa/instalación.
     * Se lee de `settings` (`vm_sla_<prioridad>`); si no existe, usa el default.
     */
    public static function slaDays(string $priority): int
    {
        $priority = self::isPriority($priority) ? $priority : 'medium';
        $default = self::DEFAULT_SLA[$priority] ?? 60;
        if (!function_exists('setting_get')) {
            return $default;
        }
        $value = setting_get('vm_sla_' . $priority, $default);
        $days = is_numeric($value) ? (int)$value : $default;
        return max(1, min(365, $days));
    }

    public static function isPriority(string $priority): bool
    {
        return isset(self::PRIORITIES[$priority]);
    }

    /**
     * Fecha objetivo: se calcula UNA vez al crear/priorizar el caso.
     * Nunca se recalcula silenciosamente al visualizar.
     */
    public static function dueDate(string $priority, string $baseDate = ''): string
    {
        $base = self::parseDate($baseDate) ?? new DateTimeImmutable('today');
        return $base->modify('+' . self::slaDays($priority) . ' days')->format('Y-m-d');
    }

    public static function parseDate(?string $value): ?DateTimeImmutable
    {
        $value = trim((string)$value);
        if ($value === '') {
            return null;
        }
        $date = DateTimeImmutable::createFromFormat('!Y-m-d', substr($value, 0, 10));
        if ($date instanceof DateTimeImmutable) {
            return $date;
        }
        $ts = strtotime($value);
        return $ts === false ? null : (new DateTimeImmutable())->setTimestamp($ts);
    }

    public static function daysUntil(?string $dueDate, string $today = ''): ?int
    {
        $due = self::parseDate($dueDate);
        if ($due === null) {
            return null;
        }
        $base = self::parseDate($today) ?? new DateTimeImmutable('today');
        $base = $base->setTime(0, 0, 0);
        $diff = $due->setTime(0, 0, 0)->getTimestamp() - $base->getTimestamp();
        return (int)floor($diff / 86400);
    }

    /**
     * Estado del plazo para la interfaz.
     * Devuelve: closed | exception_expired | expired | due_soon | ok | none
     */
    public static function deadlineState(?string $dueDate, string $status, ?string $acceptedUntil = null, string $today = ''): string
    {
        if (self::isClosed($status)) {
            return 'closed';
        }
        if ($status === 'risk_accepted') {
            $until = self::daysUntil($acceptedUntil, $today);
            if ($until !== null) {
                // Mientras la aceptación esté vigente, cubre la fecha objetivo.
                return $until < 0 ? 'exception_expired' : 'ok';
            }
        }
        $days = self::daysUntil($dueDate, $today);
        if ($days === null) {
            return 'none';
        }
        if ($days < 0) {
            return 'expired';
        }
        return $days <= self::DUE_SOON_DAYS ? 'due_soon' : 'ok';
    }

    /**
     * Factores de prioridad con su explicación. Solo usa datos disponibles:
     * los campos ausentes del CSV quedan como null/false y no generan motivos.
     *
     * @param array<string, mixed> $cve severity, cvss, epss, kev, has_exploit,
     *                                  has_alerts, has_known_threats, exposed_machines
     * @return array<string, mixed>
     */
    public static function priorityFactors(array $cve): array
    {
        $severity = strtolower(trim((string)($cve['severity'] ?? '')));
        $cvss = self::numberOrNull($cve['cvss'] ?? null);
        $epss = self::numberOrNull($cve['epss'] ?? null);
        $kev = !empty($cve['kev']) || !empty($cve['kev_id']);
        $exploit = !empty($cve['has_exploit']);
        $alerts = !empty($cve['has_alerts']);
        $threats = !empty($cve['has_known_threats']);
        $exposed = max(0, (int)($cve['exposed_machines'] ?? 0));

        $score = $cvss ?? 0.0;
        if ($epss !== null) {
            $score += min(3.0, $epss * 3);
        }
        if ($kev) {
            $score += 2.0;
        }
        if ($exploit) {
            $score += 1.0;
        }
        if ($alerts) {
            $score += 1.0;
        }
        if ($threats) {
            $score += 0.5;
        }
        if ($exposed >= 100) {
            $score += 1.0;
        } elseif ($exposed > 0) {
            $score += 0.5;
        }
        $score = round($score, 2);

        $ranks = ['low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4];
        $rank = 1;
        if (isset($ranks[$severity])) {
            $rank = max($rank, $ranks[$severity]);
        }
        if ($cvss !== null) {
            $rank = max($rank, $cvss >= 9.0 ? 4 : ($cvss >= 7.0 ? 3 : ($cvss >= 4.0 ? 2 : 1)));
        }
        if ($score >= 12.0) {
            $rank = max($rank, 4);
        } elseif ($score >= 9.0) {
            $rank = max($rank, 3);
        } elseif ($score >= 6.0) {
            $rank = max($rank, 2);
        }
        if ($kev) {
            $rank = max($rank, 3);
        }

        $priority = array_search($rank, $ranks, true) ?: 'low';

        $reasons = [];
        if (isset(self::PRIORITIES[$severity])) {
            $reasons[] = 'Severidad del CSV: ' . self::PRIORITIES[$severity];
        }
        if ($cvss !== null) {
            $reasons[] = 'CVSS: ' . number_format($cvss, 1);
        }
        if ($epss !== null) {
            $reasons[] = 'EPSS: ' . number_format($epss, 4);
        }
        if ($kev) {
            $reasons[] = 'En CISA KEV';
        }
        if ($exploit) {
            $reasons[] = 'Exploit público conocido';
        }
        if ($alerts) {
            $reasons[] = 'Alertas asociadas en TVM';
        }
        if ($threats) {
            $reasons[] = 'Amenazas conocidas según TVM';
        }
        if ($exposed > 0) {
            $reasons[] = $exposed . ' equipos expuestos (contador del CSV)';
        }

        return [
            'severity'         => $severity,
            'cvss'             => $cvss,
            'epss'             => $epss,
            'kev'              => $kev,
            'exploit'          => $exploit,
            'alerts'           => $alerts,
            'threats'          => $threats,
            'exposed_machines' => $exposed,
            'score'            => $score,
            'priority'         => $priority,
            'reasons'          => $reasons,
        ];
    }

    /**
     * Factores para un CVE asignado en «Mis CVE» (origen catálogo, sin TVM).
     * No inventa exposición, alertas ni amenazas: esos campos no existen fuera
     * de la importación del CSV.
     *
     * @param array<string, mixed> $cve severity, cvss/cvss_v3_score, epss,
     *                                kev/kev_id, has_exploit/exploit_total
     * @return array<string, mixed>
     */
    public static function factorsFromCatalog(array $cve): array
    {
        $cvss = $cve['cvss'] ?? null;
        if ($cvss === null || $cvss === '') {
            $cvss = $cve['cvss_v3_score'] ?? null;
        }
        if ($cvss === null || $cvss === '') {
            $cvss = $cve['cvss_v2_score'] ?? null;
        }

        return self::priorityFactors([
            'severity'          => (string)($cve['severity'] ?? ''),
            'cvss'              => $cvss,
            'epss'              => $cve['epss'] ?? null,
            'kev'               => !empty($cve['kev']) || !empty($cve['kev_id']),
            'has_exploit'       => !empty($cve['has_exploit']) || (int)($cve['exploit_total'] ?? 0) > 0,
            'has_alerts'        => false,
            'has_known_threats' => false,
            'exposed_machines'  => 0,
        ]);
    }

    /**
     * Decide qué hacer al importar un CVE respecto a un caso existente.
     *
     * REGLA CLAVE: una importación selecciona un subconjunto de CVEs. La
     * ausencia de un CVE en una importación NO cierra casos; esta función no
     * puede devolver nunca "close". Tampoco crea casos: eso es acción manual.
     *
     * @param string                    $importStatus    'done' | 'processing' | ...
     * @param array<string, mixed>|null $existingCase    fila de vm_cases
     * @param array<string, mixed>      $row             fila de cve_tvm_import_rows
     * @return array{action: string, event: ?string, observed_at: string, reason: string}
     */
    public static function reconcile(string $importStatus, ?array $existingCase, array $row, string $importCreatedAt = ''): array
    {
        $observedAt = self::observationDate($row, $importCreatedAt);

        if ($importStatus !== 'done') {
            return [
                'action'      => 'skip',
                'event'       => null,
                'observed_at' => $observedAt,
                'reason'      => 'La importación no está completa: no se toca el seguimiento.',
            ];
        }

        if ($existingCase === null || empty($existingCase['id'])) {
            return [
                'action'      => 'create',
                'event'       => null,
                'observed_at' => $observedAt,
                'reason'      => 'Primera observación de este CVE para la empresa.',
            ];
        }

        $status = (string)($existingCase['status'] ?? 'detected');
        $reobserved = self::isClosed($status);

        return [
            'action'      => 'observe',
            'event'       => $reobserved ? 'reobserved' : 'observed',
            'observed_at' => $observedAt,
            'reason'      => $reobserved
                ? 'El CVE reaparece en una importación nueva; el caso sigue cerrado hasta revisión.'
                : 'Nueva observación del mismo ámbito; solo se actualiza la última observación.',
        ];
    }

    /** Fecha de observación declarada por la fila importada. */
    public static function observationDate(array $row, string $fallback = ''): string
    {
        foreach (['updated_at', 'first_detected_at', 'published_at'] as $key) {
            $date = self::parseDate($row[$key] ?? null);
            if ($date !== null) {
                return $date->format('Y-m-d');
            }
        }
        $date = self::parseDate($fallback);
        return $date !== null ? $date->format('Y-m-d') : date('Y-m-d');
    }

    /**
     * Valida un cambio de caso. Devuelve null si es válido o el mensaje de error.
     *
     * @param array<string, mixed> $current               fila actual de vm_cases
     * @param array<string, mixed> $input                 campos enviados
     * @param bool                 $hasVerification       hay evidencia de verificación (nueva o guardada)
     */
    public static function validateUpdate(array $current, array $input, bool $hasVerification): ?string
    {
        $status = (string)($input['status'] ?? $current['status'] ?? 'detected');
        if (!self::isStatus($status)) {
            return 'Estado no reconocido.';
        }

        $priority = (string)($input['priority'] ?? '');
        if ($priority !== '' && !self::isPriority($priority)) {
            return 'Prioridad no reconocida.';
        }

        $due = trim((string)($input['due_date'] ?? ''));
        if ($due !== '' && self::parseDate($due) === null) {
            return 'La fecha objetivo no es válida.';
        }
        if ($due !== '' && !self::isSensibleDate($due)) {
            return 'La fecha objetivo está fuera de un rango razonable (revisa el año).';
        }

        if ($status === 'resolved_verified' && !$hasVerification) {
            return 'Para marcar «Corregida y verificada» hay que registrar comentario y referencia de verificación manual.';
        }

        if ($status === 'risk_accepted') {
            $reason = trim((string)($input['accepted_reason'] ?? ''));
            $until = trim((string)($input['accepted_until'] ?? ''));
            $approvedAt = trim((string)($input['accepted_approved_at'] ?? ''));
            if ($reason === '') {
                return 'El riesgo aceptado exige un motivo.';
            }
            $untilDate = self::parseDate($until);
            if ($untilDate === null) {
                return 'El riesgo aceptado exige una fecha de caducidad válida.';
            }
            if ($approvedAt !== '' && (self::parseDate($approvedAt) === null || !self::isSensibleDate($approvedAt))) {
                return 'La fecha de aprobación de la excepción no es válida.';
            }
            $today = new DateTimeImmutable('today');
            if ($untilDate < $today) {
                return 'La caducidad del riesgo aceptado debe ser hoy o posterior.';
            }
        }

        return null;
    }

    /**
     * Indicadores calculados sobre el conjunto realmente importado.
     * No se presenta como cobertura total: solo mide casos con seguimiento.
     *
     * @param array<int, array<string, mixed>> $cases
     * @return array<string, mixed>
     */
    public static function kpis(array $cases, string $today = ''): array
    {
        $today = $today !== '' ? $today : date('Y-m-d');
        $kpi = [
            'total'              => 0,
            'open'               => 0,
            'overdue'            => 0,
            'due_soon'           => 0,
            'resolved_verified'  => 0,
            'risk_accepted'      => 0,
            'exception_expired'  => 0,
            'by_status'          => array_fill_keys(array_keys(self::STATUSES), 0),
            'by_priority'        => array_fill_keys(array_keys(self::PRIORITIES), 0),
        ];

        foreach ($cases as $case) {
            $kpi['total']++;
            $status = (string)($case['status'] ?? 'detected');
            if (isset($kpi['by_status'][$status])) {
                $kpi['by_status'][$status]++;
            }
            $priority = (string)($case['priority'] ?? '');
            if (isset($kpi['by_priority'][$priority])) {
                $kpi['by_priority'][$priority]++;
            }

            if ($status === 'resolved_verified') {
                $kpi['resolved_verified']++;
            }
            if (self::isClosed($status)) {
                continue;
            }

            $kpi['open']++;
            if ($status === 'risk_accepted') {
                $kpi['risk_accepted']++;
            }

            $deadline = self::deadlineState(
                isset($case['due_date']) ? (string)$case['due_date'] : null,
                $status,
                isset($case['accepted_until']) ? (string)$case['accepted_until'] : null,
                $today
            );
            if ($deadline === 'exception_expired') {
                $kpi['exception_expired']++;
                $kpi['overdue']++;
            } elseif ($deadline === 'expired') {
                $kpi['overdue']++;
            } elseif ($deadline === 'due_soon') {
                $kpi['due_soon']++;
            }
        }

        return $kpi;
    }

    /**
     * Valida un hallazgo local. Devuelve null o el mensaje de error.
     * Los campos de activo/entorno/versión son opcionales: vacío = «sin datos».
     */
    public static function validateFinding(array $input): ?string
    {
        $status = (string)($input['status'] ?? 'detected');
        if (!self::isStatus($status)) {
            return 'Estado del hallazgo no reconocido.';
        }
        $source = (string)($input['source'] ?? 'manual');
        if (!isset(self::FINDING_SOURCES[$source])) {
            return 'Fuente del hallazgo no reconocida.';
        }

        $limits = [
            'asset_or_service' => 200,
            'environment'      => 120,
            'product'          => 200,
            'product_version'  => 120,
            'owner_name'       => 120,
            'notes'            => 4000,
        ];
        foreach ($limits as $field => $max) {
            $value = trim((string)($input[$field] ?? ''));
            $length = function_exists('mb_strlen') ? mb_strlen($value) : strlen($value);
            if ($length > $max) {
                return 'El campo «' . $field . '» supera el máximo de ' . $max . ' caracteres.';
            }
        }

        $first = trim((string)($input['first_detected_at'] ?? ''));
        $last = trim((string)($input['last_detected_at'] ?? ''));
        foreach (['primera detección' => $first, 'última detección' => $last] as $label => $value) {
            if ($value !== '' && (self::parseDate($value) === null || !self::isSensibleDate($value))) {
                return 'La fecha de ' . $label . ' no es válida.';
            }
        }
        if ($first !== '' && $last !== '') {
            $firstDate = self::parseDate($first);
            $lastDate = self::parseDate($last);
            if ($firstDate !== null && $lastDate !== null && $firstDate > $lastDate) {
                return 'La última detección no puede ser anterior a la primera.';
            }
        }

        return null;
    }

    /** Rango razonable de fechas (evita años absurdos tipo 1900/9999). */
    public static function isSensibleDate(?string $value): bool
    {
        $date = self::parseDate($value);
        if ($date === null) {
            return false;
        }
        $year = (int)$date->format('Y');
        return $year >= 2000 && $year <= ((int)date('Y') + 10);
    }

    public static function eventLabel(string $event): string    {
        return match ($event) {
            'created'         => 'Caso creado',
            'observed'        => 'Observado de nuevo',
            'reobserved'      => 'Reaparece tras cierre',
            'status'          => 'Cambio de estado',
            'priority'        => 'Cambio de prioridad',
            'assignee'        => 'Cambio de responsable',
            'due_date'        => 'Fecha objetivo',
            'due_date_extend' => 'Prórroga de fecha objetivo',
            'ticket'          => 'Ticket externo',
            'evidence'        => 'Evidencia registrada',
            'verification'    => 'Verificación manual',
            'reopened'        => 'Caso reabierto',
            'note'            => 'Nota',
            'finding_created' => 'Hallazgo añadido',
            'finding_updated' => 'Hallazgo actualizado',
            'evidence_pin'    => 'Nota fijada o desfijada',
            'ai_prompt'       => 'Playbook de IA lanzado',
            default           => $event,
        };
    }

    /**
     * Playbooks de remediación del caso (v0.3.22).
     *
     * Se definen en servidor para que el prompt que recibe el asistente no
     * dependa de un campo oculto del formulario y para poder auditar cuál se
     * lanzó. La vista pinta un botón por clave; el handler valida la clave y
     * redirige con el texto ya construido.
     *
     * @return array<string, array{icon: string, title: string, hint: string, text: string}>
     */
    public static function playbooks(string $cveId): array
    {
        $cveId = strtoupper(trim($cveId));
        if ($cveId === '') {
            $cveId = 'el CVE de este caso';
        }

        return [
            'patch' => [
                'icon'  => 'build',
                'title' => 'Plan de parcheo y rollback',
                'hint'  => 'Versiones/KB corregidas, despliegue, reinicio y vuelta atrás.',
                'text'  => 'Actúa como analista de vulnerabilidades senior. Para el CVE ' . $cveId . ' en esta organización, elabora un plan de remediación paso a paso: versiones o KB corregidas, orden de despliegue, ventana de mantenimiento, impacto de reinicio, comprobaciones previas y posteriores, y procedimiento de rollback. Incluye los comandos o pasos exactos cuando proceda y marca explícitamente lo que no puedas verificar.',
            ],
            'mitigate' => [
                'icon'  => 'shield',
                'title' => 'Mitigación sin parche',
                'hint'  => 'Controles compensatorios inmediatos y cómo comprobarlos.',
                'text'  => 'Para el CVE ' . $cveId . ' no es posible aplicar el parche a corto plazo. Propón mitigaciones y controles compensatorios inmediatos (firewall, GPO, registro, configuración del servicio, segmentación) indicando alcance, limitaciones y cómo verificar que están realmente aplicados.',
            ],
            'detect' => [
                'icon'  => 'search',
                'title' => 'Detección y verificación',
                'hint'  => 'KQL para Defender Hunting y/o script PowerShell de solo lectura.',
                'text'  => 'Genera mecanismos de detección y verificación para el CVE ' . $cveId . ': una consulta KQL para Defender Advanced Hunting y/o un script PowerShell de solo lectura que compruebe versión, archivo o configuración afectada. Indica cómo interpretar el resultado y qué evidencia adjuntar al cierre.',
            ],
            'executive' => [
                'icon'  => 'mail',
                'title' => 'Nota ejecutiva para el cliente',
                'hint'  => 'Riesgo, acción solicitada y plazo, sin jerga.',
                'text'  => 'Redacta una nota ejecutiva breve (máximo 200 palabras) sobre el CVE ' . $cveId . ': qué riesgo supone, a quién afecta, qué acción se solicita y en qué plazo. Sin jerga innecesaria y sin inventar datos que no consten.',
            ],
        ];
    }

    private static function numberOrNull(mixed $value): ?float
    {
        if (is_int($value) || is_float($value)) {
            return (float)$value;
        }
        $value = str_replace(',', '.', trim((string)$value));
        return is_numeric($value) ? (float)$value : null;
    }
}
