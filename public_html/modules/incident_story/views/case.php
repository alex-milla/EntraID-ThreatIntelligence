<?php
/**
 * Vista detalle — Incidentes Story.
 *
 * @var Module_IncidentStory $module
 * @var array $case
 * @var array $eventos
 * @var int $eventosTotal
 * @var array $decisions
 * @var array $profiles
 * @var int|null $defaultProfileId
 * @var bool $llmConfigured
 * @var array $classifications
 * @var array $determinations
 * @var array|null $notice
 */

$base = base_url('modules/incident_story');
$caso = is_array($case['caso'] ?? null) ? $case['caso'] : [];
$incidencia = is_array($caso['incidencia'] ?? null) ? $caso['incidencia'] : [];
$triage = is_array($case['triage'] ?? null) ? $case['triage'] : [];
$warnings = is_array($case['warnings'] ?? null) ? $case['warnings'] : [];
$decisionActual = $decisions[0] ?? null;

$list = static function (mixed $value): array {
    if (is_string($value)) {
        $value = trim($value);
        return $value === '' ? [] : [$value];
    }
    if (!is_array($value)) {
        return [];
    }
    return array_values(array_filter(array_map(
        static fn($v) => is_scalar($v) ? trim((string)$v) : '',
        $value
    ), static fn($v) => $v !== ''));
};
$fmtDate = static fn(?string $date): string => $date === null || trim($date) === ''
    ? '—'
    : str_replace('T', ' ', substr(trim($date), 0, 19));
$json = static fn(mixed $value): string => (string)json_encode(
    $value,
    JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
);

$sev = strtolower((string)($incidencia['severidad'] ?? ''));
$sevClass = in_array($sev, ['high', 'critical'], true)
    ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'
    : ($sev === 'medium'
        ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300'
        : 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300');

$verdict = strtolower(trim((string)($triage['veredicto_asistido'] ?? '')));
$verdictClass = match ($verdict) {
    'benigna'    => 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
    'sospechosa' => 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
    'ataque'     => 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
    default      => 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300',
};
$decisionLabel = static fn(?string $classification): string => match ((string)$classification) {
    'truePositive'                  => 'Verdadero positivo',
    'falsePositive'                 => 'Falso positivo',
    'informationalExpectedActivity' => 'Actividad esperada',
    'unknown'                       => 'Desconocida',
    default                         => '—',
};
$suggestion = is_array($triage['clasificacion_defender_sugerida'] ?? null)
    ? $triage['clasificacion_defender_sugerida']
    : [];
$analistaActual = Auth::user();
$analistaDefault = $analistaActual !== null
    ? (trim((string)($analistaActual['display_name'] ?? '')) ?: (string)$analistaActual['username'])
    : '';
$inputClass = 'w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-sm focus:ring-2 focus:ring-brand-500 outline-none';
?>

<?php if (!empty($notice) && is_array($notice)): ?>
    <div class="alert alert-<?= e((string)($notice['type'] ?? 'info')) ?>" role="status">
        <?= e((string)($notice['text'] ?? '')) ?>
    </div>
<?php endif; ?>

<div class="mb-6">
    <a href="<?= e($base) ?>" class="text-xs text-brand-500 hover:underline">← Volver a Incidentes Story</a>
    <div class="flex items-start justify-between gap-3 mt-3 flex-wrap">
        <div class="min-w-0">
            <h1 class="text-xl font-bold">
                <?= e((string)($incidencia['nombre'] ?? 'Caso #' . (int)$case['id'])) ?>
            </h1>
            <p class="text-xs text-ink-soft mt-1">
                <?= e($case['public_id'] ?? '') ?>
                <?php if (!empty($incidencia['id_defender'])): ?> · Incidencia <?= e((string)$incidencia['id_defender']) ?><?php endif; ?>
                · <?= e((string)($case['formato_entrada'] ?? '')) ?>
                · <?= e($fmtDate($case['created_at'] ?? null)) ?>
            </p>
        </div>
        <div class="flex items-center gap-2 flex-wrap">
            <span class="inline-flex px-3 py-1 text-xs rounded-full <?= $sevClass ?>">
                <?= e($incidencia['severidad'] ?? 'Severidad —') ?>
            </span>
            <?php if ($verdict !== ''): ?>
                <span class="inline-flex px-3 py-1 text-xs rounded-full <?= $verdictClass ?>">
                    IA: <?= e(ucfirst($verdict)) ?>
                </span>
            <?php endif; ?>
            <?php if ($decisionActual !== null): ?>
                <span class="inline-flex px-3 py-1 text-xs rounded-full bg-brand-100 text-brand-700 dark:bg-brand-900/30 dark:text-brand-300">
                    Decisión: <?= e($decisionLabel((string)$decisionActual['classification'])) ?>
                </span>
            <?php endif; ?>
        </div>
    </div>
</div>

<?php if ($warnings !== []): ?>
    <div class="alert alert-warning" role="alert">
        <strong>Revisión manual recomendada antes de enviar a la IA:</strong>
        <ul class="mt-1 list-disc list-inside text-xs">
            <?php foreach ($warnings as $w): ?>
                <li><?= e((string)$w) ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
<?php endif; ?>

<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <!-- Columna izquierda: evidencia -->
    <div class="lg:col-span-2 space-y-6">
        <div class="card p-5">
            <h2 class="text-sm font-semibold mb-4">Incidencia y evidencia</h2>
            <dl class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3 text-sm">
                <div><dt class="text-xs text-ink-muted">Nombre</dt><dd class="mt-0.5"><?= e((string)($incidencia['nombre'] ?? '—')) ?></dd></div>
                <div><dt class="text-xs text-ink-muted">Severidad</dt><dd class="mt-0.5"><?= e((string)($incidencia['severidad'] ?? '—')) ?></dd></div>
                <div><dt class="text-xs text-ink-muted">Estado</dt><dd class="mt-0.5"><?= e((string)($incidencia['estado'] ?? '—')) ?></dd></div>
                <div><dt class="text-xs text-ink-muted">Clasificación actual en Defender</dt><dd class="mt-0.5"><?= e((string)($incidencia['clasificacion_actual'] ?? '—')) ?></dd></div>
                <div><dt class="text-xs text-ink-muted">Origen</dt><dd class="mt-0.5"><?= e((string)($case['origen'] ?? '—')) ?></dd></div>
                <div><dt class="text-xs text-ink-muted">Hash del story</dt><dd class="mt-0.5 font-mono text-xs break-all"><?= e(substr((string)($case['story_hash'] ?? ''), 0, 24)) ?>…</dd></div>
                <div><dt class="text-xs text-ink-muted">Eventos</dt><dd class="mt-0.5"><?= number_format((float)$eventosTotal, 0, ',', '.') ?></dd></div>
                <div><dt class="text-xs text-ink-muted">Técnicas MITRE</dt><dd class="mt-0.5"><?= e($list($incidencia['tecnicas_mitre'] ?? []) === [] ? '—' : implode(', ', $list($incidencia['tecnicas_mitre'] ?? []))) ?></dd></div>
            </dl>

            <?php $alertas = is_array($incidencia['alertas'] ?? null) ? $incidencia['alertas'] : []; ?>
            <?php if ($alertas !== []): ?>
                <div class="mt-4 border-t border-line-subtle pt-3">
                    <p class="text-xs text-ink-muted mb-2">Alertas del story (<?= count($alertas) ?>)</p>
                    <div class="flex flex-wrap gap-1.5">
                        <?php foreach ($alertas as $al): ?>
                            <span class="inline-flex px-2 py-0.5 text-xs rounded-full bg-muted text-ink-muted">
                                <?= e((string)($al['nombre'] ?? $al['title'] ?? 'Alerta')) ?>
                                <?php if (!empty($al['severidad'])): ?> · <?= e((string)$al['severidad']) ?><?php endif; ?>
                            </span>
                        <?php endforeach; ?>
                    </div>
                </div>
            <?php endif; ?>
        </div>

        <div class="card p-5">
            <div class="flex items-center justify-between gap-3 mb-4">
                <h2 class="text-sm font-semibold">Eventos normalizados</h2>
                <span class="text-xs text-ink-muted">
                    <?= count($eventos) ?> de <?= number_format((float)$eventosTotal, 0, ',', '.') ?>
                </span>
            </div>
            <?php if ($eventos === []): ?>
                <p class="text-sm text-ink-muted">No se han podido extraer eventos estructurados. Revisa el texto crudo del caso.</p>
            <?php else: ?>
                <div class="overflow-x-auto">
                    <table class="data-table w-full text-xs">
                        <thead>
                            <tr>
                                <th>Hora</th>
                                <th>Proceso</th>
                                <th>Usuario / equipo</th>
                                <th>Detalle</th>
                            </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($eventos as $ev): ?>
                            <tr>
                                <td class="whitespace-nowrap align-top"><?= e($fmtDate($ev['timestamp'] ?? null)) ?></td>
                                <td class="align-top">
                                    <strong><?= e((string)($ev['proceso'] ?? '—')) ?></strong>
                                    <div class="text-ink-muted">
                                        PID <?= e((string)($ev['pid'] ?? '—')) ?>
                                        <?php if (!empty($ev['pid_padre'])): ?> · PPID <?= e((string)$ev['pid_padre']) ?><?php endif; ?>
                                    </div>
                                </td>
                                <td class="align-top">
                                    <?= e((string)($ev['usuario'] ?? '—')) ?>
                                    <?php if (!empty($ev['equipo'])): ?>
                                        <div class="text-ink-muted"><?= e((string)$ev['equipo']) ?></div>
                                    <?php endif; ?>
                                    <?php if (!empty($ev['integridad'])): ?>
                                        <div class="text-ink-muted">Integridad: <?= e((string)$ev['integridad']) ?></div>
                                    <?php endif; ?>
                                </td>
                                <td class="align-top">
                                    <?php if (!empty($ev['command_line'])): ?>
                                        <details>
                                            <summary class="cursor-pointer text-brand-600 dark:text-brand-300">Command line</summary>
                                            <pre class="mt-1 whitespace-pre-wrap break-all font-mono text-[11px]"><?= e((string)$ev['command_line']) ?></pre>
                                        </details>
                                    <?php endif; ?>
                                    <?php if (!empty($ev['image_path'])): ?>
                                        <div class="text-ink-muted break-all"><?= e((string)$ev['image_path']) ?></div>
                                    <?php endif; ?>
                                    <?php if (!empty($ev['sha1'])): ?>
                                        <div class="text-ink-muted font-mono break-all">SHA1 <?= e((string)$ev['sha1']) ?></div>
                                    <?php endif; ?>
                                    <?php if (!empty($ev['script_content'])): ?>
                                        <details class="mt-1">
                                            <summary class="cursor-pointer text-brand-600 dark:text-brand-300">Script (<?= number_format((float)strlen((string)$ev['script_content']), 0, ',', '.') ?> caracteres)</summary>
                                            <pre class="mt-1 whitespace-pre-wrap break-all font-mono text-[11px] max-h-64 overflow-auto"><?= e((string)$ev['script_content']) ?></pre>
                                        </details>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
                <?php if ($eventosTotal > count($eventos)): ?>
                    <p class="text-xs text-ink-muted mt-3">
                        Se muestran los primeros <?= count($eventos) ?> eventos; el caso completo queda guardado
                        y se envía íntegro (hasta el límite de prompt) al triaje.
                    </p>
                <?php endif; ?>
            <?php endif; ?>
        </div>

        <div class="card p-5">
            <h2 class="text-sm font-semibold mb-3">Datos para auditoría</h2>
            <details>
                <summary class="cursor-pointer text-sm text-brand-600 dark:text-brand-300">Caso normalizado (JSON)</summary>
                <pre class="mt-2 whitespace-pre-wrap break-all font-mono text-[11px] max-h-96 overflow-auto"><?= e($json($caso)) ?></pre>
            </details>
            <details class="mt-3">
                <summary class="cursor-pointer text-sm text-brand-600 dark:text-brand-300">Evidencia pseudonimizada enviada a la IA (JSON)</summary>
                <pre class="mt-2 whitespace-pre-wrap break-all font-mono text-[11px] max-h-96 overflow-auto"><?= e($json($case['anon'] ?? [])) ?></pre>
            </details>
            <p class="mt-3 text-[11px] text-ink-soft">
                La tabla de mapeo de pseudónimos no se muestra aquí. Solo se conserva en el servidor
                para una re-identificación autorizada.
            </p>
        </div>
    </div>

    <!-- Columna derecha: triaje y decisión -->
    <div class="space-y-6">
        <div class="card p-5">
            <div class="flex items-center justify-between gap-2 mb-3">
                <h2 class="text-sm font-semibold">Triaje asistido por IA</h2>
                <?php if ($verdict !== ''): ?>
                    <span class="inline-flex px-2 py-0.5 text-xs rounded-full <?= $verdictClass ?>">
                        <?= e(ucfirst($verdict)) ?>
                    </span>
                <?php endif; ?>
            </div>

            <?php if (!$llmConfigured): ?>
                <div class="alert alert-warning" role="status">
                    No hay proveedor de IA configurado. Configúralo en
                    <a class="underline" href="<?= e(base_url('admin/apis')) ?>">Admin → APIs</a>
                    o selecciona un perfil con clave.
                </div>
            <?php endif; ?>

            <?php if ($triage === []): ?>
                <p class="text-sm text-ink-muted">
                    Aún no hay veredicto asistido. La evidencia pseudonimizada se enviará al
                    proveedor de IA seleccionado.
                </p>
            <?php else: ?>
                <?php if (isset($triage['respuesta_original'])): ?>
                    <div class="alert alert-warning" role="status">La IA no devolvió JSON válido. Respuesta original:</div>
                    <pre class="whitespace-pre-wrap break-all font-mono text-[11px] max-h-64 overflow-auto"><?= e((string)$triage['respuesta_original']) ?></pre>
                <?php else: ?>
                    <div class="space-y-3 text-sm">
                        <?php if (!empty($triage['confianza_pct'])): ?>
                            <p class="text-xs text-ink-muted">Confianza: <strong><?= (int)$triage['confianza_pct'] ?>%</strong></p>
                        <?php endif; ?>
                        <?php if (!empty($triage['resumen_ejecutivo'])): ?>
                            <div>
                                <p class="text-xs text-ink-muted">Resumen ejecutivo</p>
                                <p class="mt-0.5 whitespace-pre-line"><?= e((string)$triage['resumen_ejecutivo']) ?></p>
                            </div>
                        <?php endif; ?>
                        <?php if (!empty($triage['cadena_de_eventos'])): ?>
                            <div>
                                <p class="text-xs text-ink-muted">Cadena de eventos</p>
                                <p class="mt-0.5 whitespace-pre-line"><?= e((string)$triage['cadena_de_eventos']) ?></p>
                            </div>
                        <?php endif; ?>
                        <?php if (!empty($triage['hipotesis_principal'])): ?>
                            <div>
                                <p class="text-xs text-ink-muted">Hipótesis principal</p>
                                <p class="mt-0.5 whitespace-pre-line"><?= e((string)$triage['hipotesis_principal']) ?></p>
                            </div>
                        <?php endif; ?>
                        <?php foreach ([
                            'tecnicas_attck'      => 'Técnicas ATT&CK',
                            'indicadores_benignos'=> 'Indicadores benignos',
                            'indicadores_maliciosos' => 'Indicadores maliciosos',
                            'datos_faltantes'     => 'Datos faltantes',
                            'acciones_recomendadas' => 'Acciones recomendadas',
                            'preguntas_para_el_analista' => 'Preguntas para el analista',
                        ] as $field => $label): ?>
                            <?php $items = $list($triage[$field] ?? []); ?>
                            <?php if ($items !== []): ?>
                                <div>
                                    <p class="text-xs text-ink-muted"><?= e($label) ?></p>
                                    <ul class="mt-0.5 list-disc list-inside space-y-0.5">
                                        <?php foreach ($items as $item): ?>
                                            <li><?= e($item) ?></li>
                                        <?php endforeach; ?>
                                    </ul>
                                </div>
                            <?php endif; ?>
                        <?php endforeach; ?>
                        <?php if ($suggestion !== []): ?>
                            <div class="border-t border-line-subtle pt-3">
                                <p class="text-xs text-ink-muted">Clasificación sugerida en Defender</p>
                                <p class="mt-0.5">
                                    <?= e((string)($suggestion['classification'] ?? '—')) ?>
                                    · <?= e((string)($suggestion['determination'] ?? '—')) ?>
                                </p>
                            </div>
                        <?php endif; ?>
                        <p class="text-[11px] text-ink-soft">
                            Veredicto asistido: <?= e((string)($case['triage_model'] ?? 'modelo desconocido')) ?>
                            · <?= e($fmtDate($case['triage_at'] ?? null)) ?>.
                            No es definitivo; la decisión final se registra abajo.
                        </p>
                    </div>
                <?php endif; ?>
            <?php endif; ?>

            <form method="POST" action="<?= e($base . '/case/' . (int)$case['id'] . '/triage') ?>" class="mt-4 space-y-3 border-t border-line-subtle pt-4">
                <?= Csrf::field() ?>
                <div>
                    <label for="profile-id" class="block text-xs font-medium text-ink-muted mb-1">
                        Perfil de IA
                    </label>
                    <select id="profile-id" name="profile_id" class="<?= e($inputClass) ?>">
                        <option value="">Predeterminado</option>
                        <?php foreach ($profiles as $profile): ?>
                            <option value="<?= (int)$profile['id'] ?>"
                                <?= (int)($defaultProfileId ?? 0) === (int)$profile['id'] ? 'selected' : '' ?>>
                                <?= e((string)$profile['name']) ?>
                                <?php if (!empty($profile['provider'])): ?> (<?= e((string)$profile['provider']) ?>)<?php endif; ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <button type="submit" class="btn w-full" <?= $llmConfigured ? '' : 'disabled' ?>>
                    <?= icon('psychology', 18) ?> <?= $triage === [] ? 'Analizar con IA' : 'Repetir triaje' ?>
                </button>
                <p class="text-[11px] text-ink-soft">
                    Se envía solo la evidencia pseudonimizada. Consume cuota del proveedor.
                </p>
            </form>
        </div>

        <div class="card p-5">
            <h2 class="text-sm font-semibold mb-3">Decisión humana</h2>

            <?php if ($decisionActual !== null): ?>
                <div class="rounded-lg border border-line-subtle p-3 mb-4 text-sm">
                    <p class="font-medium">
                        <?= e($decisionLabel((string)$decisionActual['classification'])) ?>
                        · <?= e((string)$decisionActual['determination']) ?>
                    </p>
                    <?php if (!empty($decisionActual['justificacion'])): ?>
                        <p class="text-xs text-ink-muted mt-1 whitespace-pre-line"><?= e((string)$decisionActual['justificacion']) ?></p>
                    <?php endif; ?>
                    <p class="text-[11px] text-ink-soft mt-2">
                        <?= e((string)$decisionActual['analista']) ?> · <?= e($fmtDate($decisionActual['created_at'] ?? null)) ?>
                    </p>
                </div>
            <?php endif; ?>

            <form method="POST" action="<?= e($base . '/case/' . (int)$case['id'] . '/decision') ?>" class="space-y-3">
                <?= Csrf::field() ?>
                <div>
                    <label for="analista" class="block text-xs font-medium text-ink-muted mb-1">Analista</label>
                    <input id="analista" type="text" name="analista" maxlength="190"
                           value="<?= e($analistaDefault) ?>" class="<?= e($inputClass) ?>" required>
                </div>
                <div>
                    <label for="classification" class="block text-xs font-medium text-ink-muted mb-1">Clasificación</label>
                    <select id="classification" name="classification" class="<?= e($inputClass) ?>" required>
                        <?php foreach ($classifications as $key => $label): ?>
                            <option value="<?= e($key) ?>"><?= e($label) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div>
                    <label for="determination" class="block text-xs font-medium text-ink-muted mb-1">Determinación</label>
                    <select id="determination" name="determination" class="<?= e($inputClass) ?>">
                        <?php foreach ($determinations as $det): ?>
                            <option value="<?= e($det) ?>"><?= e($det) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div>
                    <label for="justificacion" class="block text-xs font-medium text-ink-muted mb-1">
                        Justificación
                    </label>
                    <textarea id="justificacion" name="justificacion" rows="3" class="<?= e($inputClass) ?>"
                              placeholder="Obligatoria si la decisión contradice el veredicto de la IA."></textarea>
                </div>
                <button type="submit" class="btn w-full">
                    <?= icon('verified', 18) ?> Registrar decisión
                </button>
            </form>

            <?php if (count($decisions) > 1): ?>
                <details class="mt-4">
                    <summary class="cursor-pointer text-xs text-brand-600 dark:text-brand-300">
                        Historial de decisiones (<?= count($decisions) ?>)
                    </summary>
                    <ul class="mt-2 space-y-2 text-xs">
                        <?php foreach (array_slice($decisions, 1) as $d): ?>
                            <li class="border-t border-line-subtle pt-2">
                                <strong><?= e($decisionLabel((string)$d['classification'])) ?></strong>
                                · <?= e((string)$d['determination']) ?>
                                · <?= e((string)$d['analista']) ?>
                                · <?= e($fmtDate($d['created_at'] ?? null)) ?>
                                <?php if (!empty($d['justificacion'])): ?>
                                    <div class="text-ink-muted mt-0.5"><?= e((string)$d['justificacion']) ?></div>
                                <?php endif; ?>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                </details>
            <?php endif; ?>
        </div>

        <?php if (Auth::isAdmin()): ?>
            <div class="card p-5">
                <h2 class="text-sm font-semibold mb-2">Eliminar caso</h2>
                <p class="text-xs text-ink-muted mb-3">
                    Se borran el caso, su evidencia y todas sus decisiones. No se puede deshacer.
                </p>
                <form method="POST" action="<?= e($base . '/case/' . (int)$case['id'] . '/delete') ?>"
                      data-confirm="¿Eliminar este caso y todas sus decisiones?">
                    <?= Csrf::field() ?>
                    <button type="submit" class="btn btn-outline text-danger">
                        <?= icon('delete', 18) ?> Eliminar caso
                    </button>
                </form>
            </div>
        <?php endif; ?>
    </div>
</div>
