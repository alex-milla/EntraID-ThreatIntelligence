<?php
/**
 * remediation_workflow.php — máquina de estados y registro del ticket (CVE Desk, F0).
 *
 * Reglas:
 *   · Una tarea tiene SIEMPRE exactamente un estado del ciclo.
 *   · Todo cambio se escribe en `remediation_task_logs` (inmutable: la clase
 *     no expone actualizar ni borrar entradas).
 *   · `remediation_tasks.status` sigue siendo la columna que leen las vistas,
 *     métricas y el asistente. El workflow la mantiene sincronizada para no
 *     romper nada de lo que ya funcionaba.
 *   · La API estricta (`transition`) valida la máquina de estados. La ruta
 *     heredada (`recordLegacyChange`) conserva el comportamiento del
 *     formulario actual, pero deja rastro de todo.
 */

declare(strict_types=1);

final class RemediationWorkflow
{
    /** Estados del ciclo. */
    public const STATES = [
        'ticket_creado',
        'planificado',
        'en_curso',
        'bloqueado',
        'verificacion',
        'cerrado',
        'riesgo_aceptado',
    ];

    /** Tipos de entrada del registro. */
    public const LOG_TYPES = ['cambio_estado', 'retraso', 'bloqueo', 'nota', 'reapertura', 'riesgo'];

    public static function stateLabels(): array
    {
        return [
            'ticket_creado'  => 'Ticket creado',
            'planificado'    => 'Planificado',
            'en_curso'       => 'En curso',
            'bloqueado'      => 'Bloqueado',
            'verificacion'   => 'En verificación',
            'cerrado'        => 'Cerrado',
            'riesgo_aceptado'=> 'Riesgo aceptado',
        ];
    }

    public static function stateLabel(string $state): string
    {
        return self::stateLabels()[$state] ?? $state;
    }

    public static function stateClasses(): array
    {
        return [
            'ticket_creado'  => 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300',
            'planificado'    => 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
            'en_curso'       => 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
            'bloqueado'      => 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
            'verificacion'   => 'bg-violet-100 text-violet-700 dark:bg-violet-900/30 dark:text-violet-300',
            'cerrado'        => 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
            'riesgo_aceptado'=> 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400',
        ];
    }

    public static function logTypeLabels(): array
    {
        return [
            'cambio_estado' => 'Estado',
            'retraso'       => 'Retraso',
            'bloqueo'       => 'Bloqueo',
            'nota'          => 'Nota',
            'reapertura'    => 'Reapertura',
            'riesgo'        => 'Riesgo',
        ];
    }

    /** Traduce el status heredado al estado del ciclo. */
    public static function stateForStatus(string $status): string
    {
        return match ($status) {
            'open'           => 'ticket_creado',
            'in_progress'    => 'en_curso',
            'accepted'       => 'riesgo_aceptado',
            'patched',
            'mitigated',
            'false_positive'=> 'cerrado',
            default          => 'ticket_creado',
        };
    }

    /** Traduce el estado del ciclo al status heredado (para métricas y vistas). */
    public static function statusForState(string $state, string $resolucion = 'patched'): string
    {
        return match ($state) {
            'ticket_creado', 'planificado' => 'open',
            'en_curso', 'bloqueado', 'verificacion' => 'in_progress',
            'riesgo_aceptado' => 'accepted',
            'cerrado' => in_array($resolucion, ['patched', 'mitigated', 'false_positive'], true)
                ? $resolucion
                : 'patched',
            default => 'open',
        };
    }

    public static function normalizeState(string $state): string
    {
        return in_array($state, self::STATES, true) ? $state : 'ticket_creado';
    }

    /** Estado actual de una tarea (con backfill perezoso si falta). */
    public static function ensureState(int $taskId): string
    {
        $task = self::get($taskId);
        if ($task === null) {
            return '';
        }
        $state = trim((string)($task['estado'] ?? ''));
        if ($state === '') {
            $state = self::stateForStatus((string)($task['status'] ?? 'open'));
            Database::update(
                "UPDATE remediation_tasks
                 SET estado = ?, importado = COALESCE(NULLIF(importado, ''), created_at),
                     eta_original = COALESCE(NULLIF(eta_original, ''), due_at),
                     eta_actual = COALESCE(NULLIF(eta_actual, ''), eta_original, due_at)
                 WHERE id = ?",
                [$state, $taskId]
            );
        }
        return self::normalizeState($state);
    }

    /**
     * Transiciones permitidas desde un estado. La UI de acciones (F2) pinta
     * solo estas; la API las valida.
     *
     * @return array<string,array{label:string,to:string,requires:string[]}>
     */
    public static function transitions(string $state): array
    {
        $close = ['label' => 'Cerrar CVE', 'to' => 'cerrado', 'requires' => ['evidencia']];
        $risk  = ['label' => 'Aceptar riesgo', 'to' => 'riesgo_aceptado', 'requires' => ['justificacion', 'caducidad']];

        return match (self::normalizeState($state)) {
            'ticket_creado' => [
                'planificar'     => ['label' => 'Planificar', 'to' => 'planificado', 'requires' => ['ventana_parcheo']],
                'cerrar'         => $close,
                'aceptar_riesgo' => $risk,
            ],
            'planificado' => [
                'iniciar'        => ['label' => 'Iniciar parcheo', 'to' => 'en_curso', 'requires' => []],
                'cerrar'         => $close,
                'aceptar_riesgo' => $risk,
            ],
            'en_curso' => [
                'bloquear'          => ['label' => 'Registrar bloqueo', 'to' => 'bloqueado', 'requires' => ['motivo']],
                'pasar_verificacion'=> ['label' => 'Pasar a verificación', 'to' => 'verificacion', 'requires' => []],
                'cerrar'            => $close,
                'aceptar_riesgo'    => $risk,
            ],
            'bloqueado' => [
                'reactivar'      => ['label' => 'Reactivar', 'to' => 'en_curso', 'requires' => []],
                'aceptar_riesgo' => $risk,
            ],
            'verificacion' => [
                'cerrar'               => $close,
                'verificacion_fallida' => ['label' => 'Verificación fallida', 'to' => 'en_curso', 'requires' => ['motivo']],
                'aceptar_riesgo'       => $risk,
            ],
            'cerrado' => [
                'reabrir' => ['label' => 'Reabrir', 'to' => 'ticket_creado', 'requires' => []],
            ],
            'riesgo_aceptado' => [
                'cancelar_riesgo' => ['label' => 'Cancelar aceptación', 'to' => 'ticket_creado', 'requires' => []],
                'reabrir'         => ['label' => 'Reabrir', 'to' => 'ticket_creado', 'requires' => []],
            ],
            default => [],
        };
    }

    public static function get(int $taskId): ?array
    {
        if ($taskId <= 0) {
            return null;
        }
        return Database::fetchOne("SELECT * FROM remediation_tasks WHERE id = ?", [$taskId]);
    }

    /**
     * Inicializa el ciclo de una tarea recién creada y deja la primera entrada.
     * Idempotente: si ya tiene estado, no duplica el alta.
     */
    public static function initTask(
        int $taskId,
        string $status = 'open',
        ?string $dueAt = null,
        int $userId = 0,
        string $entry = 'Alta de la tarea'
    ): void {
        $task = self::get($taskId);
        if ($task === null) {
            return;
        }
        $state = self::normalizeState((string)($task['estado'] ?? ''));
        $current = trim((string)($task['estado'] ?? ''));
        $imported = (string)($task['importado'] ?? '');
        if ($state === '' || $current === '') {
            $state = self::stateForStatus($status);
        }

        Database::update(
            "UPDATE remediation_tasks
             SET estado = ?, importado = COALESCE(NULLIF(importado, ''), datetime('now')),
                 eta_original = COALESCE(NULLIF(eta_original, ''), ?),
                 eta_actual = COALESCE(NULLIF(eta_actual, ''), ?, ?)
             WHERE id = ?",
            [$state, $dueAt, $dueAt, $dueAt, $taskId]
        );

        if ($current === '') {
            self::addLog($taskId, 'cambio_estado', $entry, 0, '', $state, $userId);
        }
    }

    /**
     * Cambio de estado desde el formulario heredado. No impone la máquina
     * estricta (para no romper el flujo actual), pero sincroniza `estado`,
     * traduce `status` y escribe el registro.
     *
     * @param array{nota?:string,evidencia?:string,exception_until?:string} $context
     * @return array{ok:bool,error:string,state:string}
     */
    public static function recordLegacyChange(
        int $taskId,
        string $fromStatus,
        string $toStatus,
        array $context = [],
        int $userId = 0
    ): array {
        $task = self::get($taskId);
        if ($task === null) {
            return ['ok' => false, 'error' => 'La tarea no existe.', 'state' => ''];
        }

        $fromState = self::normalizeState((string)($task['estado'] ?? ''));
        if (trim((string)($task['estado'] ?? '')) === '') {
            $fromState = self::stateForStatus($fromStatus);
        }
        $toState = self::stateForStatus($toStatus);

        if ($toState === $fromState && $fromStatus === (string)($task['status'] ?? '')) {
            return ['ok' => true, 'error' => '', 'state' => $fromState];
        }

        $resolved = in_array($toStatus, ['patched', 'mitigated', 'accepted', 'false_positive'], true);
        $fields = [
            'estado = ?',
            'status = ?',
            'bloqueado_desde = NULL',
        ];
        $params = [$toState, $toStatus];

        if ($toStatus === 'accepted') {
            $just = trim((string)($context['nota'] ?? ''));
            if ($just === '') {
                $just = 'Aceptación registrada desde la ficha (sin justificación escrita).';
            }
            $until = trim((string)($context['exception_until'] ?? ''));
            if ($until === '' || strtotime($until) === false) {
                $until = date('Y-m-d', strtotime('+30 days'));
            }
            // La caducidad de la ficha heredada no se recorta: se respeta lo
            // que el usuario ya venía guardando. La API estricta sí exige ≤90.
            Database::query(
                "INSERT INTO remediation_risk_acceptances
                 (task_id, justificacion, caducidad, aprobado_por, estado)
                 VALUES (?, ?, ?, ?, 'vigente')",
                [$taskId, $just, $until, $userId > 0 ? $userId : null]
            );
            $fields[] = 'exception_until = ?';
            $params[] = $until;
        } elseif ($toState !== 'riesgo_aceptado') {
            $fields[] = 'exception_until = NULL';
        }

        if ($resolved || $toStatus === 'accepted') {
            $fields[] = "resolved_at = COALESCE(NULLIF(resolved_at, ''), datetime('now'))";
            $fields[] = 'cierre_actor_id = ?';
            $params[] = $userId > 0 ? $userId : null;
        } else {
            // Reabrir o volver a un estado vivo limpia la fecha de resolución.
            $fields[] = 'resolved_at = NULL';
        }

        $params[] = $taskId;
        Database::query(
            "UPDATE remediation_tasks SET " . implode(', ', $fields) . " WHERE id = ?",
            $params
        );

        $text = trim((string)($context['nota'] ?? ''));
        if ($text === '') {
            $text = 'Cambio de ' . self::stateLabel($fromState) . ' a ' . self::stateLabel($toState) . '.';
        }
        $logType = 'cambio_estado';
        if ($toStatus === 'accepted') {
            $logType = 'riesgo';
        } elseif (in_array($fromState, ['cerrado', 'riesgo_aceptado'], true) && $toState === 'ticket_creado') {
            $logType = 'reapertura';
        }
        self::addLog(
            $taskId,
            $logType,
            $text,
            0,
            $fromState,
            $toState,
            $userId
        );

        return ['ok' => true, 'error' => '', 'state' => $toState];
    }

    /**
     * API estricta: valida la transición y aplica sus efectos.
     *
     * @return array{ok:bool,error:string,state:string}
     */
    public static function transition(int $taskId, string $action, array $payload = [], int $userId = 0): array
    {
        $task = self::get($taskId);
        if ($task === null) {
            return ['ok' => false, 'error' => 'La tarea no existe.', 'state' => ''];
        }
        $state = self::ensureState($taskId);
        $transitions = self::transitions($state);
        if (!isset($transitions[$action])) {
            return [
                'ok'    => false,
                'error' => 'La acción «' . $action . '» no es válida desde «' . self::stateLabel($state) . '».',
                'state' => $state,
            ];
        }
        $def = $transitions[$action];

        foreach ($def['requires'] as $field) {
            if (trim((string)($payload[$field] ?? '')) === '') {
                return ['ok' => false, 'error' => 'Falta el campo obligatorio: ' . $field . '.', 'state' => $state];
            }
        }

        switch ($action) {
            case 'planificar':
                $ventana = trim((string)$payload['ventana_parcheo']);
                Database::update(
                    "UPDATE remediation_tasks
                     SET estado = 'planificado', ventana_parcheo = ?, status = 'open',
                         responsable_user_id = COALESCE(?, responsable_user_id), updated_at = datetime('now')
                     WHERE id = ?",
                    [$ventana, (int)($payload['responsable_user_id'] ?? 0) ?: null, $taskId]
                );
                self::addLog($taskId, 'cambio_estado', 'Planificado: ' . $ventana, 0, $state, 'planificado', $userId);
                return ['ok' => true, 'error' => '', 'state' => 'planificado'];

            case 'iniciar':
                Database::update(
                    "UPDATE remediation_tasks SET estado = 'en_curso', status = 'in_progress', updated_at = datetime('now') WHERE id = ?",
                    [$taskId]
                );
                self::addLog($taskId, 'cambio_estado', 'Parcheo iniciado', 0, $state, 'en_curso', $userId);
                return ['ok' => true, 'error' => '', 'state' => 'en_curso'];

            case 'bloquear':
                return self::addEntry($taskId, 'bloqueo', (string)$payload['motivo'], (int)($payload['impacto_dias'] ?? 0), $userId);

            case 'reactivar':
                Database::update(
                    "UPDATE remediation_tasks
                     SET estado = 'en_curso', status = 'in_progress', bloqueado_desde = NULL, updated_at = datetime('now')
                     WHERE id = ?",
                    [$taskId]
                );
                self::addLog($taskId, 'cambio_estado', 'Bloqueo reactivado', 0, 'bloqueado', 'en_curso', $userId);
                return ['ok' => true, 'error' => '', 'state' => 'en_curso'];

            case 'pasar_verificacion':
                Database::update(
                    "UPDATE remediation_tasks SET estado = 'verificacion', updated_at = datetime('now') WHERE id = ?",
                    [$taskId]
                );
                self::addLog($taskId, 'cambio_estado', 'Pendiente de verificación', 0, $state, 'verificacion', $userId);
                return ['ok' => true, 'error' => '', 'state' => 'verificacion'];

            case 'verificacion_fallida':
                $motivo = trim((string)$payload['motivo']);
                Database::update(
                    "UPDATE remediation_tasks SET estado = 'en_curso', status = 'in_progress', updated_at = datetime('now') WHERE id = ?",
                    [$taskId]
                );
                self::addLog($taskId, 'cambio_estado', 'Verificación fallida: ' . $motivo, 0, 'verificacion', 'en_curso', $userId);
                if ((int)($payload['impacto_dias'] ?? 0) > 0) {
                    self::shiftEta($taskId, (int)$payload['impacto_dias']);
                    self::addLog($taskId, 'retraso', $motivo, (int)$payload['impacto_dias'], '', '', $userId);
                }
                return ['ok' => true, 'error' => '', 'state' => 'en_curso'];

            case 'cerrar':
                $evidencia = trim((string)$payload['evidencia']);
                $resolucion = (string)($payload['resolucion'] ?? 'patched');
                if (!in_array($resolucion, ['patched', 'mitigated', 'false_positive'], true)) {
                    $resolucion = 'patched';
                }
                Database::update(
                    "UPDATE remediation_tasks
                     SET estado = 'cerrado', status = ?, evidence = ?, resolved_at = datetime('now'),
                         cierre_actor_id = ?, bloqueado_desde = NULL, updated_at = datetime('now')
                     WHERE id = ?",
                    [$resolucion, $evidencia, $userId > 0 ? $userId : null, $taskId]
                );
                self::addLog(
                    $taskId,
                    'cambio_estado',
                    'Cierre con evidencia: ' . $evidencia,
                    0,
                    $state,
                    'cerrado',
                    $userId
                );
                return ['ok' => true, 'error' => '', 'state' => 'cerrado'];

            case 'aceptar_riesgo':
                return self::acceptRisk(
                    $taskId,
                    (string)$payload['justificacion'],
                    (string)$payload['caducidad'],
                    $userId,
                    isset($payload['segundo_aprobador']) ? (int)$payload['segundo_aprobador'] : null
                );

            case 'cancelar_riesgo':
                return self::cancelRisk($taskId, $userId);

            case 'reabrir':
                Database::update(
                    "UPDATE remediation_tasks
                     SET estado = 'ticket_creado', status = 'open', resolved_at = NULL,
                         exception_until = NULL, bloqueado_desde = NULL, updated_at = datetime('now')
                     WHERE id = ?",
                    [$taskId]
                );
                self::addLog($taskId, 'reapertura', 'Tarea reabierta', 0, $state, 'ticket_creado', $userId);
                return ['ok' => true, 'error' => '', 'state' => 'ticket_creado'];
        }

        return ['ok' => false, 'error' => 'Acción no soportada.', 'state' => $state];
    }

    /**
     * Incidencia tipificada: retraso, bloqueo o nota. Retraso y bloqueo
     * desplazan la ETA; el bloqueo además congela el ticket.
     *
     * @return array{ok:bool,error:string,state:string}
     */
    public static function addEntry(
        int $taskId,
        string $tipo,
        string $texto,
        int $impactoDias = 0,
        int $userId = 0
    ): array {
        $task = self::get($taskId);
        if ($task === null) {
            return ['ok' => false, 'error' => 'La tarea no existe.', 'state' => ''];
        }
        if (!in_array($tipo, ['retraso', 'bloqueo', 'nota'], true)) {
            return ['ok' => false, 'error' => 'Tipo de entrada no válido.', 'state' => self::ensureState($taskId)];
        }
        $state = self::ensureState($taskId);
        if (in_array($state, ['cerrado', 'riesgo_aceptado'], true)) {
            return [
                'ok'    => false,
                'error' => 'Un ticket cerrado o con riesgo aceptado no admite incidencias. Reábrelo primero.',
                'state' => $state,
            ];
        }
        if ($tipo === 'bloqueo' && $state !== 'en_curso') {
            return [
                'ok'    => false,
                'error' => 'Solo se puede bloquear un ticket «En curso».',
                'state' => $state,
            ];
        }
        $texto = trim($texto);
        if ($texto === '') {
            return ['ok' => false, 'error' => 'El texto del registro es obligatorio.', 'state' => $state];
        }
        $impactoDias = max(0, min(365, $impactoDias));

        if ($tipo === 'retraso' || $tipo === 'bloqueo') {
            if ($impactoDias <= 0) {
                return ['ok' => false, 'error' => 'Indica los días de impacto (1 o más).', 'state' => $state];
            }
            self::shiftEta($taskId, $impactoDias);
        }

        if ($tipo === 'bloqueo') {
            Database::update(
                "UPDATE remediation_tasks
                 SET estado = 'bloqueado', status = 'in_progress', bloqueado_desde = datetime('now'),
                     updated_at = datetime('now')
                 WHERE id = ?",
                [$taskId]
            );
            self::addLog($taskId, 'bloqueo', $texto, $impactoDias, $state, 'bloqueado', $userId);
            return ['ok' => true, 'error' => '', 'state' => 'bloqueado'];
        }

        self::addLog($taskId, $tipo, $texto, $impactoDias, '', '', $userId);
        return ['ok' => true, 'error' => '', 'state' => $state];
    }

    /**
     * Aceptación de riesgo con justificación, caducidad ≤ 90 días y doble
     * aprobación para CVSS ≥ 9.
     *
     * @return array{ok:bool,error:string,state:string}
     */
    public static function acceptRisk(
        int $taskId,
        string $justificacion,
        string $caducidad,
        int $userId = 0,
        ?int $segundoAprobador = null
    ): array {
        $task = self::get($taskId);
        if ($task === null) {
            return ['ok' => false, 'error' => 'La tarea no existe.', 'state' => ''];
        }
        if (self::ensureState($taskId) === 'cerrado') {
            return ['ok' => false, 'error' => 'Una tarea cerrada no puede aceptar riesgo; reábrela primero.', 'state' => 'cerrado'];
        }
        $justificacion = trim($justificacion);
        if ($justificacion === '') {
            return ['ok' => false, 'error' => 'La justificación es obligatoria.', 'state' => self::ensureState($taskId)];
        }
        $caducidad = trim($caducidad);
        $ts = strtotime($caducidad);
        if ($ts === false) {
            return ['ok' => false, 'error' => 'La caducidad no es una fecha válida.', 'state' => self::ensureState($taskId)];
        }
        $hoy = strtotime(date('Y-m-d'));
        if ($ts < $hoy) {
            return ['ok' => false, 'error' => 'La caducidad no puede estar en el pasado.', 'state' => self::ensureState($taskId)];
        }
        if ($ts > strtotime('+90 days', $hoy)) {
            return ['ok' => false, 'error' => 'La caducidad no puede superar 90 días.', 'state' => self::ensureState($taskId)];
        }

        $cvss = (float)($task['cvss'] ?? 0);
        if ($cvss >= 9.0 && ($segundoAprobador === null || $segundoAprobador <= 0)) {
            return [
                'ok'    => false,
                'error' => 'CVSS ≥ 9: la aceptación exige un segundo aprobador.',
                'state' => self::ensureState($taskId),
            ];
        }

        $fromState = self::ensureState($taskId);

        Database::query(
            "INSERT INTO remediation_risk_acceptances
             (task_id, justificacion, caducidad, aprobado_por, segundo_aprobador, estado)
             VALUES (?, ?, ?, ?, ?, 'vigente')",
            [
                $taskId,
                $justificacion,
                date('Y-m-d', $ts),
                $userId > 0 ? $userId : null,
                $segundoAprobador !== null && $segundoAprobador > 0 ? $segundoAprobador : null,
            ]
        );

        Database::update(
            "UPDATE remediation_tasks
             SET estado = 'riesgo_aceptado', status = 'accepted', exception_until = ?,
                 resolved_at = COALESCE(NULLIF(resolved_at, ''), datetime('now')),
                 cierre_actor_id = ?, updated_at = datetime('now')
             WHERE id = ?",
            [date('Y-m-d', $ts), $userId > 0 ? $userId : null, $taskId]
        );
        self::addLog(
            $taskId,
            'riesgo',
            $justificacion . ' (caduca ' . date('d/m/Y', $ts) . ')',
            0,
            $fromState,
            'riesgo_aceptado',
            $userId
        );

        return ['ok' => true, 'error' => '', 'state' => 'riesgo_aceptado'];
    }

    /** Cancela la aceptación vigente y devuelve la tarea a la cola. */
    public static function cancelRisk(int $taskId, int $userId = 0): array
    {
        $task = self::get($taskId);
        if ($task === null) {
            return ['ok' => false, 'error' => 'La tarea no existe.', 'state' => ''];
        }
        Database::query(
            "UPDATE remediation_risk_acceptances
             SET estado = 'cancelada', cancelled_at = datetime('now')
             WHERE task_id = ? AND estado = 'vigente'",
            [$taskId]
        );
        Database::update(
            "UPDATE remediation_tasks
             SET estado = 'ticket_creado', status = 'open', exception_until = NULL,
                 resolved_at = NULL, bloqueado_desde = NULL, updated_at = datetime('now')
             WHERE id = ?",
            [$taskId]
        );
        self::addLog($taskId, 'reapertura', 'Aceptación de riesgo cancelada; vuelve a la cola', 0, 'riesgo_aceptado', 'ticket_creado', $userId);
        return ['ok' => true, 'error' => '', 'state' => 'ticket_creado'];
    }

    /**
     * Caduca las aceptaciones vencidas y devuelve sus tareas a la cola.
     * Se llama de forma perezosa al abrir el módulo (idempotente).
     */
    public static function expireRisks(): int
    {
        $expired = 0;
        $rows = Database::fetchAll(
            "SELECT a.id, a.task_id, t.estado
             FROM remediation_risk_acceptances a
             JOIN remediation_tasks t ON t.id = a.task_id
             WHERE a.estado = 'vigente' AND a.caducidad IS NOT NULL AND a.caducidad < date('now')"
        );
        foreach ($rows as $row) {
            $taskId = (int)$row['task_id'];
            Database::update(
                "UPDATE remediation_risk_acceptances SET estado = 'caducada', cancelled_at = datetime('now') WHERE id = ?",
                [(int)$row['id']]
            );
            Database::update(
                "UPDATE remediation_tasks
                 SET estado = 'ticket_creado', status = 'open', exception_until = NULL,
                     resolved_at = NULL, bloqueado_desde = NULL, updated_at = datetime('now')
                 WHERE id = ?",
                [$taskId]
            );
            self::addLog($taskId, 'reapertura', 'La aceptación de riesgo caducó; la tarea vuelve a la cola', 0, 'riesgo_aceptado', 'ticket_creado', 0);
            $expired++;
        }

        // Tareas antiguas con exception_until y sin aceptación formal.
        $legacy = Database::fetchAll(
            "SELECT id FROM remediation_tasks
             WHERE estado = 'riesgo_aceptado' AND exception_until IS NOT NULL AND exception_until < date('now')
               AND id NOT IN (SELECT task_id FROM remediation_risk_acceptances WHERE estado = 'vigente')"
        );
        foreach ($legacy as $row) {
            $taskId = (int)$row['id'];
            Database::update(
                "UPDATE remediation_tasks
                 SET estado = 'ticket_creado', status = 'open', exception_until = NULL,
                     resolved_at = NULL, updated_at = datetime('now')
                 WHERE id = ?",
                [$taskId]
            );
            self::addLog($taskId, 'reapertura', 'La excepción caducó; la tarea vuelve a la cola', 0, 'riesgo_aceptado', 'ticket_creado', 0);
            $expired++;
        }

        return $expired;
    }

    /** Registro cronológico de una tarea (más reciente primero). */
    public static function logFor(int $taskId, int $limit = 50): array
    {
        if ($taskId <= 0) {
            return [];
        }
        return Database::fetchAll(
            "SELECT * FROM remediation_task_logs WHERE task_id = ? ORDER BY id DESC LIMIT " . max(1, min(200, $limit)),
            [$taskId]
        );
    }

    public static function authorName(?int $userId): string
    {
        if ($userId === null || $userId <= 0) {
            return 'Sistema';
        }
        $user = Database::fetchOne(
            "SELECT display_name, username FROM users WHERE id = ?",
            [$userId]
        );
        if ($user === null) {
            return 'Usuario #' . $userId;
        }
        $name = trim((string)($user['display_name'] ?? ''));
        return $name !== '' ? $name : (string)($user['username'] ?? ('Usuario #' . $userId));
    }

    /** Suma días a la ETA y a `due_at` (compatibilidad con la UI actual). */
    private static function shiftEta(int $taskId, int $days): void
    {
        if ($days === 0) {
            return;
        }
        $task = self::get($taskId);
        if ($task === null) {
            return;
        }
        $base = trim((string)($task['eta_actual'] ?? ''));
        if ($base === '') {
            $base = trim((string)($task['eta_original'] ?? ''));
        }
        if ($base === '') {
            $base = trim((string)($task['due_at'] ?? ''));
        }
        if ($base === '' || strtotime($base) === false) {
            $base = date('Y-m-d');
        }
        $new = date('Y-m-d', strtotime($base . ' +' . $days . ' days'));
        Database::update(
            "UPDATE remediation_tasks SET eta_actual = ?, due_at = ?, updated_at = datetime('now') WHERE id = ?",
            [$new, $new, $taskId]
        );
    }

    /** Escribe una entrada inmutable en el registro. */
    private static function addLog(
        int $taskId,
        string $tipo,
        string $texto,
        int $impactoDias,
        string $origen,
        string $destino,
        int $userId
    ): void {
        Database::query(
            "INSERT INTO remediation_task_logs
             (task_id, tipo, texto, impacto_dias, estado_origen, estado_destino, autor_id, autor)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                $taskId,
                in_array($tipo, self::LOG_TYPES, true) ? $tipo : 'nota',
                $texto !== '' ? truncate($texto, 2000) : null,
                max(0, $impactoDias),
                $origen !== '' ? $origen : null,
                $destino !== '' ? $destino : null,
                $userId > 0 ? $userId : null,
                self::authorName($userId),
            ]
        );
    }
}
