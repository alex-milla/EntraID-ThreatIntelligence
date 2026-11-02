<?php
/**
 * Vista índice — Incidentes Story.
 *
 * @var Module_IncidentStory $module
 * @var array $cases
 * @var array $stats
 * @var array $formats
 * @var array|null $notice
 */

$base = base_url('modules/incident_story');
$fmt = static fn(int|float $n): string => number_format((float)$n, 0, ',', '.');
$short = static fn(?string $date): string => $date === null || trim($date) === ''
    ? '—'
    : substr(str_replace('T', ' ', trim($date)), 0, 16);

$verdictClass = static function (?string $verdict): string {
    return match (strtolower(trim((string)$verdict))) {
        'benigna'    => 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
        'sospechosa' => 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
        'ataque'     => 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
        default      => 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300',
    };
};
$decisionLabel = static fn(?string $classification): string => match ((string)$classification) {
    'truePositive'                  => 'Verdadero positivo',
    'falsePositive'                 => 'Falso positivo',
    'informationalExpectedActivity' => 'Actividad esperada',
    'unknown'                       => 'Desconocida',
    default                         => '',
};
?>

<?php if (!empty($notice) && is_array($notice)): ?>
    <div class="alert alert-<?= e((string)($notice['type'] ?? 'info')) ?>" role="status">
        <?= e((string)($notice['text'] ?? '')) ?>
    </div>
<?php endif; ?>

<div class="page-header">
    <h1>Incidentes Story</h1>
    <p class="subtitle">
        Triaje asistido de incidencias de Defender XDR sin necesidad de licencia ni permisos de Graph:
        pega el story del portal o sube su JSON, pseudonimiza la evidencia y obtén un veredicto
        de apoyo. La decisión final siempre la registra un analista.
    </p>
    <span class="spacer"></span>
    <a class="btn" href="<?= e($base . '/new') ?>">
        <?= icon('add', 18) ?> Nuevo caso
    </a>
</div>

<div class="alert alert-info" role="status">
    La evidencia se pseudonimiza antes de salir al proveedor de IA (usuarios, equipos,
    dominios internos e IPs privadas). La tabla de mapeo se guarda solo en este servidor
    y no se muestra en la interfaz de triaje.
</div>

<div class="stat-strip mt-4">
    <div class="stat">
        <span class="stat-ico"><?= icon('description', 18) ?></span>
        <div>
            <div class="stat-num"><?= $fmt((int)($stats['casos'] ?? 0)) ?></div>
            <div class="stat-label">Casos analizados</div>
        </div>
    </div>
    <div class="stat">
        <span class="stat-ico ok"><?= icon('psychology', 18) ?></span>
        <div>
            <div class="stat-num"><?= $fmt((int)($stats['triage'] ?? 0)) ?></div>
            <div class="stat-label">Con triaje IA</div>
        </div>
    </div>
    <div class="stat">
        <span class="stat-ico ok"><?= icon('verified', 18) ?></span>
        <div>
            <div class="stat-num"><?= $fmt((int)($stats['decisiones'] ?? 0)) ?></div>
            <div class="stat-label">Decisiones humanas</div>
        </div>
    </div>
    <div class="stat">
        <span class="stat-ico warn"><?= icon('pending_actions', 18) ?></span>
        <div>
            <div class="stat-num"><?= $fmt((int)($stats['pendientes'] ?? 0)) ?></div>
            <div class="stat-label">Pendientes de decisión</div>
        </div>
    </div>
</div>

<?php if ($cases === []): ?>
    <div class="card mt-6">
        <h2>Todavía no hay casos</h2>
        <p class="text-sm text-ink-muted">
            Crea el primero pegando la historia de la incidencia (texto del portal) o subiendo
            el JSON del story capturado con las dev tools, el export de Graph o un resultado de
            Advanced Hunting.
        </p>
        <a class="btn" href="<?= e($base . '/new') ?>">
            <?= icon('add', 18) ?> Analizar el primer story
        </a>
    </div>
<?php else: ?>
    <div class="card p-0 mt-6 overflow-hidden">
        <div class="overflow-x-auto">
            <table class="data-table w-full">
                <thead>
                    <tr>
                        <th>Caso</th>
                        <th class="col-secondary">Formato</th>
                        <th>Eventos</th>
                        <th>Triaje IA</th>
                        <th>Decisión</th>
                        <th class="col-secondary">Creado</th>
                        <th class="text-right">Acciones</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($cases as $case):
                    $id = (int)$case['id'];
                    $nombre = trim((string)($case['incidencia_nombre'] ?? ''));
                    ?>
                    <tr>
                        <td>
                            <strong><?= e($nombre !== '' ? $nombre : ('Caso #' . $id)) ?></strong>
                            <div class="text-xs text-ink-muted">
                                <?php if (!empty($case['incidencia_id'])): ?>
                                    Incidencia <?= e((string)$case['incidencia_id']) ?> ·
                                <?php endif; ?>
                                <?= e((string)($case['public_id'] ?? '')) ?>
                                <?php if (!empty($case['severidad'])): ?>
                                    · Severidad: <?= e((string)$case['severidad']) ?>
                                <?php endif; ?>
                            </div>
                        </td>
                        <td class="col-secondary text-xs text-ink-muted">
                            <?= e($formats[(string)$case['formato_entrada']] ?? (string)$case['formato_entrada']) ?>
                        </td>
                        <td class="whitespace-nowrap"><?= $fmt((int)$case['eventos_count']) ?></td>
                        <td class="whitespace-nowrap">
                            <?php if (!empty($case['triage_verdict'])): ?>
                                <span class="inline-flex px-2 py-0.5 text-xs rounded-full <?= $verdictClass((string)$case['triage_verdict']) ?>">
                                    <?= e(ucfirst((string)$case['triage_verdict'])) ?>
                                </span>
                            <?php else: ?>
                                <span class="text-ink-muted text-xs">Sin triaje</span>
                            <?php endif; ?>
                        </td>
                        <td class="whitespace-nowrap">
                            <?php if (!empty($case['ultima_classification'])): ?>
                                <span class="inline-flex px-2 py-0.5 text-xs rounded-full bg-brand-100 text-brand-700 dark:bg-brand-900/30 dark:text-brand-300">
                                    <?= e($decisionLabel((string)$case['ultima_classification'])) ?>
                                </span>
                                <?php if ((int)($case['decisiones_count'] ?? 0) > 1): ?>
                                    <span class="text-xs text-ink-muted">×<?= (int)$case['decisiones_count'] ?></span>
                                <?php endif; ?>
                            <?php else: ?>
                                <span class="text-ink-muted text-xs">Pendiente</span>
                            <?php endif; ?>
                        </td>
                        <td class="col-secondary whitespace-nowrap text-xs"><?= e($short($case['created_at'] ?? null)) ?></td>
                        <td class="text-right whitespace-nowrap">
                            <a class="btn-tiny btn-outline btn" href="<?= e($base . '/case/' . $id) ?>">
                                <?= icon('visibility', 16) ?> Ver caso
                            </a>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
<?php endif; ?>
