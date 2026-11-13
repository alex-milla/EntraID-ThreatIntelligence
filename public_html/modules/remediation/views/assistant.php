<?php
/**
 * Vista: asistente IA de remediación.
 * Variables compartidas: $org, $selectedOrgId, $selectedTask, $cveData,
 * $cveQuery, $cveContext, $chats, $chat, $messages, $llmConfigured,
 * $profiles, $taskProfileId.
 */

$modUrl = base_url('modules/remediation');
$promptText = trim((string)($prompt ?? ''));
$assistantUrl = $modUrl . '?tab=assistant&org=' . $selectedOrgId
    . ($selectedTask !== null ? '&task=' . (int)$selectedTask['id'] : '')
    . ($cveQuery !== '' ? '&cve=' . urlencode($cveQuery) : '');
$contextCve = $selectedTask !== null ? (string)$selectedTask['cve_id'] : ($cveQuery !== '');
$defaultProfile = $taskProfileId > 0 ? $taskProfileId : (int)($profiles[0]['id'] ?? 0);
$quickPrompts = array_values(llm_prompt_group('remediation.quick.'));
if ($quickPrompts === []) {
    $quickPrompts = [
        'Plan de implementación paso a paso, con verificación y rollback.',
        '¿Cómo compruebo que el parche está realmente aplicado en los equipos?',
        '¿Qué controles CIS o medidas de hardening reducen la exposición?',
        '¿Qué evidencia debo adjuntar para cerrar la tarea?',
        '¿Qué riesgos tiene aplicar el parche y cómo hago el rollback?',
    ];
}

// Guardar plan: vale tanto con tarea seleccionada como en conversaciones
// de CVE (el servidor crea la tarea de Remediation si falta).
$chatCve = ($chat !== null && (string)($chat['context_type'] ?? '') === 'cve')
    ? strtoupper(trim((string)($chat['context_ref'] ?? '')))
    : '';
$planCve = $chatCve !== '' ? $chatCve : $cveQuery;
$canSavePlan = $selectedTask !== null || $planCve !== '';
// Última pregunta del usuario (para el botón «Reintentar» del error).
$lastQuestion = '';
foreach (array_reverse($messages ?? []) as $msg) {
    if (($msg['role'] ?? '') === 'user') {
        $lastQuestion = (string)($msg['content'] ?? '');
        break;
    }
}
?>
<div class="grid grid-cols-1 lg:grid-cols-4 gap-5">

    <aside class="lg:col-span-1 space-y-4">
        <div class="card p-4">
            <p class="text-[10px] font-semibold uppercase tracking-wide text-ink-soft">Contexto</p>
            <p class="text-sm font-semibold mt-1"><?= e((string)$org['name']) ?></p>
            <p class="text-[11px] text-ink-muted mt-0.5">
                <?= $org['kind'] === 'tenant' ? 'Tenant vinculado a Defender' : 'Organización manual' ?>
            </p>

            <?php if ($selectedTask !== null): ?>
                <div class="mt-3 px-3 py-2 rounded-lg bg-muted/60">
                    <p class="font-mono text-xs font-semibold"><?= e((string)$selectedTask['cve_id']) ?></p>
                    <p class="text-[11px] text-ink-muted truncate mt-0.5"><?= e((string)($selectedTask['title'] ?? '')) ?></p>
                    <a href="<?= e($modUrl . '?tab=tasks&org=' . $selectedOrgId . '&task=' . (int)$selectedTask['id']) ?>"
                       class="inline-block mt-1 text-[11px] text-primary hover:underline">Ver tarea</a>
                    <button type="button" id="btn-suggest"
                            class="block mt-1 text-[11px] text-primary hover:underline text-left">Proponer datos (KB, versión, verificación)</button>
                </div>
            <?php elseif ($cveQuery !== ''): ?>
                <div class="mt-3 px-3 py-2 rounded-lg bg-muted/60">
                    <p class="font-mono text-xs font-semibold"><?= e($cveQuery) ?></p>
                    <p class="text-[11px] text-ink-muted mt-0.5">
                        <?= $cveContext !== null ? e((string)($cveContext['catalog']['severity'] ?? '')) : 'Sin datos locales del CVE' ?>
                    </p>
                </div>
                <label class="block mt-3">
                    <span class="block text-[10px] font-semibold uppercase tracking-wide text-ink-soft mb-1">Cambiar CVE</span>
                    <input type="text" id="assistant-cve" value="<?= e($cveQuery) ?>" placeholder="CVE-2024-38063"
                           class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-surface text-ink text-xs font-mono">
                </label>
            <?php else: ?>
                <label class="block mt-3">
                    <span class="block text-[10px] font-semibold uppercase tracking-wide text-ink-soft mb-1">CVE (opcional)</span>
                    <input type="text" id="assistant-cve" placeholder="CVE-2024-38063"
                           class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs font-mono">
                </label>
                <p class="text-[10px] text-ink-soft mt-1">Sin CVE, el asistente responde sobre procesos, controles y hardening.</p>
            <?php endif; ?>
        </div>

        <div class="card overflow-hidden">
            <div class="px-4 py-3 border-b border-line flex items-center justify-between">
                <h2 class="text-sm font-semibold">Conversaciones</h2>
                <a href="<?= e($assistantUrl) ?>" class="text-[11px] text-primary hover:underline">Nueva</a>
            </div>
            <?php if ($chats === []): ?>
                <p class="px-4 py-5 text-xs text-ink-muted text-center">Aún no hay conversaciones.</p>
            <?php else: ?>
                <div class="max-h-64 overflow-y-auto divide-y divide-line-subtle">
                    <?php foreach ($chats as $item): ?>
                        <div class="flex items-start gap-1 px-2 py-1.5 <?= $chat !== null && (int)$chat['id'] === (int)$item['id'] ? 'bg-brand-50 dark:bg-brand-950/40' : '' ?>">
                            <a href="<?= e($modUrl . '?tab=assistant&org=' . $selectedOrgId . '&chat=' . (int)$item['id']) ?>"
                               class="min-w-0 flex-1 px-2 py-1 rounded hover:bg-muted">
                                <span class="block text-xs truncate"><?= e((string)($item['title'] ?? 'Conversación')) ?></span>
                                <span class="block text-[10px] text-ink-soft mt-0.5"><?= e(format_date((string)$item['updated_at'], 'd/m/Y H:i')) ?></span>
                            </a>
                            <form method="POST" action="<?= base_url('modules/remediation/chats/delete') ?>"
                                  data-confirm="¿Eliminar esta conversación?" data-confirm-danger>
                                <?= Csrf::field() ?>
                                <input type="hidden" name="id" value="<?= (int)$item['id'] ?>">
                                <button type="submit" title="Eliminar" class="px-1.5 py-1 text-ink-soft hover:text-red-500">×</button>
                            </form>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>

        <?php if (!$llmConfigured): ?>
            <div class="px-4 py-3 rounded-xl bg-warning-bg text-xs text-warning">
                La IA no está configurada.
                <?php if (!empty($isAdmin)): ?>
                    <a href="<?= base_url('admin/apis') ?>" class="underline">Configúrala en Admin → APIs</a>.
                <?php else: ?>
                    Pide al administrador que la configure en Admin → APIs.
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </aside>

    <section class="lg:col-span-3 card flex flex-col h-[calc(100vh-230px)] min-h-[540px] overflow-hidden">
        <div class="px-4 py-3 border-b border-line flex items-center justify-between gap-3 flex-wrap">
            <div class="min-w-0">
                <h2 class="text-sm font-semibold truncate">
                    <?= $selectedTask !== null ? 'Asistente · ' . e((string)$selectedTask['cve_id']) : ($cveQuery !== '' ? 'Asistente · ' . e($cveQuery) : 'Asistente de remediación') ?>
                </h2>
                <p class="text-[11px] text-ink-muted">Implementación, controles, verificación, rollback y hardening.</p>
            </div>
            <?php if (count($profiles) > 1): ?>
                <label class="flex items-center gap-1.5 text-[11px] text-ink-muted">
                    Perfil IA
                    <select id="assistant-profile" class="px-2 py-1 rounded-lg border border-line-strong bg-input text-ink text-[11px]">
                        <option value="0">Predeterminado de la tarea</option>
                        <?php foreach ($profiles as $profile): ?>
                            <option value="<?= (int)$profile['id'] ?>" <?= (int)$profile['id'] === $defaultProfile ? 'selected' : '' ?>>
                                <?= e((string)$profile['name']) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </label>
            <?php endif; ?>
        </div>

        <?php if (!empty($assistantSmall)): ?>
            <div class="px-4 py-2 border-b border-line bg-warning-bg text-[11px] text-warning flex items-start gap-2">
                <i class="material-icons icon-14 shrink-0" aria-hidden="true">info</i>
                <span>
                    El perfil de la tarea es <strong><?= e((string)($assistantProfileName ?: 'un modelo local pequeño')) ?></strong>,
                    un modelo pequeño: sirve para resumir o extraer datos, pero para <strong>planes de remediación</strong>
                    conviene un perfil con más capacidad.
                    <a href="<?= base_url('admin/apis') ?>" class="underline">Cambiar el perfil de la tarea</a>
                    o elige otro en el desplegable de arriba.
                </span>
            </div>
        <?php endif; ?>

        <div id="chat-messages" class="flex-1 overflow-y-auto px-4 py-4 space-y-4">
            <?php if ($messages === []): ?>
                <div class="max-w-xl mx-auto text-center py-8">
                    <p class="text-sm font-semibold">Pregunta por la remediación de este CVE</p>
                    <p class="text-xs text-ink-muted mt-1">
                        El asistente recibe el contexto de la organización<?= $contextCve ? ', del CVE' : '' ?><?= $selectedTask !== null ? ' y de la tarea' : '' ?>.
                        No se envían datos de otros tenants.
                    </p>
                    <div class="mt-4 flex flex-wrap justify-center gap-2">
                        <?php foreach ($quickPrompts as $prompt): ?>
                            <button type="button" data-prompt="<?= e($prompt) ?>"
                                    class="quick-prompt px-3 py-1.5 rounded-full border border-line-strong text-[11px] text-ink-muted hover:bg-muted">
                                <?= e($prompt) ?>
                            </button>
                        <?php endforeach; ?>
                    </div>
                </div>
            <?php else: ?>
                <?php foreach ($messages as $message): ?>
                    <?php $isUser = ($message['role'] ?? '') === 'user'; ?>
                    <div class="flex <?= $isUser ? 'justify-end' : 'justify-start' ?>">
                        <div class="max-w-[85%] rounded-xl px-3.5 py-2.5 <?= $isUser ? 'bg-brand-500 text-white' : 'bg-gray-50 dark:bg-gray-800/70 text-gray-800 dark:text-gray-100' ?>">
                            <div class="text-[10px] uppercase tracking-wide <?= $isUser ? 'text-white/70' : 'text-gray-400' ?> mb-1">
                                <?= $isUser ? 'Tú' : 'Asistente' ?><?= !$isUser && !empty($message['model']) ? ' · ' . e((string)$message['model']) : '' ?>
                            </div>
                            <?php if ($isUser): ?>
                                <div class="text-xs leading-relaxed whitespace-pre-wrap break-words"><?= e((string)$message['content']) ?></div>
                            <?php else: ?>
                                <div class="md-body text-xs leading-relaxed break-words"><?= render_ai_markdown((string)$message['content']) ?></div>
                                <div class="mt-2 flex items-center gap-3">
                                    <?php if ($canSavePlan): ?>
                                        <button type="button" class="save-plan text-[10px] underline opacity-70 hover:opacity-100"
                                                data-content="<?= e((string)$message['content']) ?>">Guardar como plan</button>
                                    <?php endif; ?>
                                    <button type="button" class="copy-md text-[10px] underline opacity-70 hover:opacity-100"
                                            data-content="<?= e((string)$message['content']) ?>">Copiar</button>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>

            <?php if ($chat !== null && in_array((string)($chat['status'] ?? ''), ['pending', 'running'], true)): ?>
                <div class="flex justify-start">
                    <div class="max-w-[85%] rounded-xl px-3.5 py-2.5 bg-gray-50 dark:bg-gray-800/70 text-xs text-ink-muted">
                        <span class="inline-flex items-center gap-2">
                            <span class="spinner"></span> Pensando… <span id="pending-elapsed">0 s</span>
                        </span>
                        <p class="mt-1 text-[11px]" id="pending-note">La IA está generando la respuesta en segundo plano; puedes seguir navegando.</p>
                    </div>
                </div>
            <?php elseif ($chat !== null && (string)($chat['status'] ?? '') === 'error'): ?>
                <div class="flex justify-start">
                    <div class="max-w-[85%] rounded-xl px-3.5 py-2.5 bg-danger-bg text-xs text-danger">
                        <strong>No se pudo generar la respuesta.</strong>
                        <p class="mt-1 break-words"><?= e((string)($chat['last_error'] ?? 'Error desconocido.')) ?></p>
                        <div class="mt-2 flex items-center gap-3">
                            <?php if ($lastQuestion !== ''): ?>
                                <button type="button" id="retry-ask" data-question="<?= e($lastQuestion) ?>"
                                        class="px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-[11px] font-medium rounded-lg">Reintentar</button>
                            <?php endif; ?>
                            <span class="text-[11px]">o prueba con otro perfil de IA.</span>
                        </div>
                    </div>
                </div>
            <?php endif; ?>
        </div>

        <div id="suggest-panel" class="hidden border-t border-line p-3 bg-muted/40">
            <p class="text-xs font-semibold">Datos propuestos por la IA
                <span class="font-normal text-ink-soft">(revísalos antes de guardar; no se escribe nada sin tu confirmación)</span>
            </p>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-2 mt-2">
                <label class="block text-[11px] text-ink-muted">KB/parche
                    <input type="text" id="sug-kb" autocomplete="off"
                           class="mt-1 w-full px-2 py-1.5 rounded-lg border border-line-strong bg-surface text-xs font-mono">
                </label>
                <label class="block text-[11px] text-ink-muted">Versión corregida
                    <input type="text" id="sug-version" autocomplete="off"
                           class="mt-1 w-full px-2 py-1.5 rounded-lg border border-line-strong bg-surface text-xs font-mono">
                </label>
            </div>
            <label class="block text-[11px] text-ink-muted mt-2">Notas (verificación y rollback)
                <textarea id="sug-notes" rows="4"
                          class="mt-1 w-full px-2 py-1.5 rounded-lg border border-line-strong bg-surface text-xs"></textarea>
            </label>
            <p id="sug-missing" class="text-[11px] text-amber-600 dark:text-amber-400 mt-2"></p>
            <div class="flex items-center gap-2 mt-2">
                <button type="button" id="sug-save"
                        class="px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-medium rounded-lg">Guardar en la tarea</button>
                <button type="button" id="sug-cancel"
                        class="px-3 py-1.5 border border-line text-xs rounded-lg hover:bg-muted">Cancelar</button>
                <span id="sug-status" class="text-[11px] text-ink-soft"></span>
            </div>
        </div>

        <div class="border-t border-line p-3">
            <input type="hidden" name="csrf_token" value="<?= e(Csrf::token()) ?>">
            <div class="flex items-end gap-2">
                <textarea id="assistant-input" rows="2" placeholder="Escribe tu pregunta… (Enter para enviar, Shift+Enter para nueva línea)"
                          class="flex-1 resize-none px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-sm focus:ring-2 focus:ring-brand-500 outline-none"><?= e($promptText) ?></textarea>
                <button type="button" id="assistant-send"
                        class="px-4 py-2.5 bg-brand-500 hover:bg-brand-600 disabled:opacity-50 text-white text-sm font-medium rounded-lg">
                    Enviar
                </button>
            </div>
            <div class="flex items-center justify-between gap-2 mt-1.5">
                <p class="text-[10px] text-ink-soft">La IA puede equivocarse. Verifica versiones, KB y pasos antes de aplicarlos.</p>
                <button type="button" id="assistant-clear" class="text-[10px] text-ink-soft hover:text-gray-600">Limpiar</button>
            </div>
        </div>
    </section>
</div>

<style>
    .md-body h1, .md-body h2, .md-body h3, .md-body h4, .md-body h5, .md-body h6 {
        font-weight: 600; line-height: 1.3; margin: 0.85rem 0 0.35rem;
    }
    .md-body h1 { font-size: 1.05rem; }
    .md-body h2 { font-size: 1rem; }
    .md-body h3 { font-size: 0.95rem; }
    .md-body h4, .md-body h5, .md-body h6 { font-size: 0.9rem; }
    .md-body p { margin: 0.4rem 0; }
    .md-body ul, .md-body ol { margin: 0.4rem 0 0.4rem 1.1rem; }
    .md-body ul { list-style: disc; }
    .md-body ol { list-style: decimal; }
    .md-body li { margin: 0.15rem 0; }
    .md-body li > ul, .md-body li > ol { margin: 0.2rem 0 0.2rem 1rem; }
    .md-body code {
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        background: rgba(127, 127, 127, 0.16); padding: 0.1rem 0.3rem; border-radius: 0.25rem;
        font-size: 0.9em;
    }
    .md-body pre {
        background: rgba(127, 127, 127, 0.12); padding: 0.6rem 0.75rem; border-radius: 0.5rem;
        overflow-x: auto; margin: 0.5rem 0;
    }
    .md-body pre code { background: none; padding: 0; }
    .md-body hr { border: 0; border-top: 1px solid rgba(127, 127, 127, 0.3); margin: 0.8rem 0; }
    .md-body strong { font-weight: 600; }
    .md-body blockquote {
        border-left: 3px solid rgba(127, 127, 127, 0.4); padding-left: 0.6rem;
        margin: 0.5rem 0; opacity: 0.9;
    }
    .md-body a { text-decoration: underline; }
    .md-body table { border-collapse: collapse; margin: 0.5rem 0; width: 100%; }
    .md-body th, .md-body td { border: 1px solid rgba(127, 127, 127, 0.3); padding: 0.25rem 0.4rem; text-align: left; }
</style>

<script>
(function () {
    var ASK_URL = <?= json_encode($modUrl . '/ask') ?>;
    var PLAN_URL = <?= json_encode($modUrl . '/tasks/plan') ?>;
    var TASK_ID = <?= $selectedTask !== null ? (int)$selectedTask['id'] : 0 ?>;
    var ORG_ID = <?= (int)$selectedOrgId ?>;
    var CHAT_ID = <?= $chat !== null ? (int)$chat['id'] : 0 ?>;
    var CAN_SAVE_PLAN = <?= $canSavePlan ? 'true' : 'false' ?>;
    var PLAN_CVE = <?= json_encode($planCve) ?>;
    var CHAT_URL = <?= json_encode($assistantUrl) ?>;
    var messagesEl = document.getElementById('chat-messages');
    var inputEl = document.getElementById('assistant-input');
    var sendEl = document.getElementById('assistant-send');
    var profileEl = document.getElementById('assistant-profile');
    var cveEl = document.getElementById('assistant-cve');
    var firstMessage = CHAT_ID === 0;

    // --- Consulta en segundo plano: sondeo del estado ---
    var CHAT_STATUS_URL = <?= json_encode($modUrl . '/ask-status/' . ($chat !== null ? (int)$chat['id'] : 0)) ?>;
    var CHAT_PENDING = <?= ($chat !== null && in_array((string)($chat['status'] ?? ''), ['pending', 'running'], true)) ? 'true' : 'false' ?>;

    if (CHAT_PENDING) {
        var startedAt = Date.now();
        var pendingWarned = false;
        var elapsedEl = document.getElementById('pending-elapsed');
        var elapsedTimer = setInterval(function () {
            if (elapsedEl) { elapsedEl.textContent = Math.round((Date.now() - startedAt) / 1000) + ' s'; }
        }, 1000);
        var statusTimer = setInterval(function () {
            fetch(CHAT_STATUS_URL, { headers: { 'X-Requested-With': 'XMLHttpRequest' }, credentials: 'same-origin' })
                .then(function (r) { return r.json(); })
                .then(function (st) {
                    if (!st || !st.success) { return; }
                    if (st.status === 'done' || st.status === 'error') {
                        clearInterval(statusTimer);
                        clearInterval(elapsedTimer);
                        window.location.reload();
                        return;
                    }
                    // Watchdog: si a los 20 s sigue «pending», el worker no arrancó.
                    if (!pendingWarned && st.status === 'pending' && (Date.now() - startedAt) > 20000) {
                        pendingWarned = true;
                        var note = document.getElementById('pending-note');
                        if (note) {
                            note.textContent = 'El servidor no parece haber lanzado el trabajo en segundo plano. '
                                + 'Si sigue así, vuelve a enviar la pregunta.';
                            note.classList.add('text-amber-600', 'dark:text-amber-400');
                        }
                    }
                })
                .catch(function () { /* se reintenta en el siguiente tick */ });
        }, 3000);
    }

    var retryAskEl = document.getElementById('retry-ask');
    if (retryAskEl) {
        retryAskEl.addEventListener('click', function () {
            var q = retryAskEl.getAttribute('data-question') || '';
            if (q !== '') { inputEl.value = q; }
            send();
        });
    }

    function bubble(role, text) {
        var wrap = document.createElement('div');
        wrap.className = 'flex ' + (role === 'user' ? 'justify-end' : 'justify-start');
        var box = document.createElement('div');
        box.className = 'max-w-[85%] rounded-xl px-3.5 py-2.5 ' + (role === 'user'
            ? 'bg-brand-500 text-white'
            : 'bg-gray-50 dark:bg-gray-800/70 text-gray-800 dark:text-gray-100');
        var meta = document.createElement('div');
        meta.className = 'text-[10px] uppercase tracking-wide mb-1 ' + (role === 'user' ? 'text-white/70' : 'text-gray-400');
        meta.textContent = role === 'user' ? 'Tú' : 'Asistente';
        var body = document.createElement('div');
        body.className = 'text-xs leading-relaxed break-words' + (role === 'user' ? ' whitespace-pre-wrap' : '');
        body.textContent = text;
        box.appendChild(meta);
        box.appendChild(body);
        wrap.appendChild(box);
        messagesEl.appendChild(wrap);
        messagesEl.scrollTop = messagesEl.scrollHeight;
        return { wrap: wrap, box: box, body: body };
    }

    function setBusy(busy) {
        sendEl.disabled = busy;
        sendEl.textContent = busy ? 'Pensando…' : 'Enviar';
    }

    function send() {
        var question = (inputEl.value || '').trim();
        if (question === '') return;

        // Si había un estado vacío con prompts, lo retiramos.
        var empty = messagesEl.querySelector('.max-w-xl');
        if (empty) messagesEl.innerHTML = '';

        bubble('user', question);
        inputEl.value = '';
        var thinking = bubble('assistant', 'Pensando…');
        setBusy(true);

        var payload = {
            org_id: ORG_ID,
            task_id: TASK_ID,
            chat_id: CHAT_ID,
            question: question,
            profile_id: profileEl ? parseInt(profileEl.value || '0', 10) : 0
        };
        if (cveEl && cveEl.value.trim() !== '') payload.cve_id = cveEl.value.trim();

        api('POST', ASK_URL, payload).then(function (res) {
            if (!res || !res.success) {
                throw new Error((res && res.error) ? res.error : 'Error de la IA');
            }
            if (res.pending || firstMessage) {
                window.location.href = CHAT_URL + '&chat=' + encodeURIComponent(res.chat_id);
                return;
            }
            if (res.content_html) {
                thinking.body.classList.add('md-body');
                thinking.body.innerHTML = res.content_html;
            } else {
                thinking.body.classList.add('whitespace-pre-wrap');
                thinking.body.textContent = res.content || '';
            }
            if (CAN_SAVE_PLAN) {
                var save = document.createElement('button');
                save.type = 'button';
                save.className = 'save-plan mt-2 text-[10px] underline opacity-70 hover:opacity-100';
                save.textContent = 'Guardar como plan';
                save.setAttribute('data-content', res.content || '');
                save.onclick = function () { savePlan(save); };
                thinking.box.appendChild(save);
            }
            var copy = document.createElement('button');
            copy.type = 'button';
            copy.className = 'copy-md mt-2 ml-3 text-[10px] underline opacity-70 hover:opacity-100';
            copy.textContent = 'Copiar';
            copy.setAttribute('data-content', res.content || '');
            thinking.box.appendChild(copy);
            messagesEl.scrollTop = messagesEl.scrollHeight;
        }).catch(function (err) {
            thinking.body.textContent = 'Error: ' + err.message;
            thinking.body.classList.add('text-red-500');
        }).finally(function () {
            setBusy(false);
            inputEl.focus();
        });
    }

    function savePlan(btn) {
        var content = btn.getAttribute('data-content') || '';
        if (!content || !CAN_SAVE_PLAN) return;
        api('POST', PLAN_URL, {
            task_id: TASK_ID,
            chat_id: CHAT_ID,
            org_id: ORG_ID,
            cve_id: PLAN_CVE,
            content: content
        }).then(function (res) {
            if (res && res.success) {
                btn.textContent = 'Plan guardado ✓';
                btn.disabled = true;
            } else {
                appAlert((res && res.error) ? res.error : 'No se pudo guardar el plan.');
            }
        }).catch(function (err) {
            appAlert('No se pudo guardar el plan: ' + err.message);
        });
    }

    function copyFallback(text, btn) {
        var area = document.createElement('textarea');
        area.value = text;
        area.style.position = 'fixed';
        area.style.opacity = '0';
        document.body.appendChild(area);
        area.select();
        var ok = false;
        try { ok = document.execCommand('copy'); } catch (err) { ok = false; }
        document.body.removeChild(area);
        btn.textContent = ok ? 'Copiado ✓' : 'No se pudo copiar';
        setTimeout(function () { btn.textContent = 'Copiar'; }, 1600);
    }

    document.addEventListener('click', function (event) {
        var btn = event.target.closest('.copy-md');
        if (!btn) { return; }
        var text = btn.getAttribute('data-content') || '';
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(function () {
                btn.textContent = 'Copiado ✓';
                setTimeout(function () { btn.textContent = 'Copiar'; }, 1600);
            }, function () {
                copyFallback(text, btn);
            });
            return;
        }
        copyFallback(text, btn);
    });

    // --- Proponer y guardar los datos que faltan de la tarea (con revisión) ---
    var SUGGEST_URL = <?= json_encode($modUrl . '/tasks/suggest') ?>;
    var APPLY_URL = <?= json_encode($modUrl . '/tasks/apply') ?>;
    var TASK_NOTES = <?= json_encode((string)($selectedTask['notes'] ?? '')) ?>;
    var sugPanel = document.getElementById('suggest-panel');
    var sugStatus = document.getElementById('sug-status');

    function setSugStatus(text) {
        if (sugStatus) { sugStatus.textContent = text || ''; }
    }

    function suggestTaskData() {
        if (!sugPanel) { return; }
        sugPanel.classList.remove('hidden');
        setSugStatus('Consultando a la IA…');
        api('POST', SUGGEST_URL, {
            org_id: ORG_ID,
            task_id: TASK_ID,
            profile_id: profileEl ? parseInt(profileEl.value || '0', 10) : 0
        }).then(function (res) {
            if (!res || !res.success) {
                setSugStatus((res && res.error) ? res.error : 'No se pudieron proponer los datos.');
                return;
            }
            var f = res.fields || {};
            var kb = document.getElementById('sug-kb');
            var ver = document.getElementById('sug-version');
            var notes = document.getElementById('sug-notes');
            var missing = document.getElementById('sug-missing');
            if (kb) { kb.value = f.patch_kb || ''; }
            if (ver) { ver.value = f.fixed_version || ''; }
            var lines = [];
            if (f.verification) { lines.push('Verificación: ' + f.verification); }
            if (f.rollback) { lines.push('Rollback: ' + f.rollback); }
            if (notes) {
                notes.value = (TASK_NOTES ? TASK_NOTES + "\n\n" : '') + lines.join("\n");
            }
            if (missing) {
                missing.textContent = (f.missing && f.missing.length)
                    ? 'La IA no pudo confirmar: ' + f.missing.join(', ') + '.'
                    : '';
            }
            setSugStatus('Revisa y guarda lo que confirmes.');
        }).catch(function (err) {
            setSugStatus(err && err.message ? err.message : 'Error de conexión');
        });
    }

    function saveTaskData() {
        var kb = document.getElementById('sug-kb');
        var ver = document.getElementById('sug-version');
        var notes = document.getElementById('sug-notes');
        setSugStatus('Guardando…');
        api('POST', APPLY_URL, {
            org_id: ORG_ID,
            task_id: TASK_ID,
            patch_kb: kb ? kb.value : '',
            fixed_version: ver ? ver.value : '',
            notes: notes ? notes.value : ''
        }).then(function (res) {
            if (!res || !res.success) {
                setSugStatus((res && res.error) ? res.error : 'No se pudo guardar.');
                return;
            }
            toast(res.message || 'Datos guardados', 'success');
            window.location.reload();
        }).catch(function (err) {
            setSugStatus(err && err.message ? err.message : 'Error de conexión');
        });
    }

    var btnSuggest = document.getElementById('btn-suggest');
    if (btnSuggest) { btnSuggest.addEventListener('click', suggestTaskData); }
    var sugSave = document.getElementById('sug-save');
    if (sugSave) { sugSave.addEventListener('click', saveTaskData); }
    var sugCancel = document.getElementById('sug-cancel');
    if (sugCancel) {
        sugCancel.addEventListener('click', function () {
            if (sugPanel) { sugPanel.classList.add('hidden'); }
            setSugStatus('');
        });
    }

    sendEl.addEventListener('click', send);
    inputEl.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            send();
        }
    });

    document.querySelectorAll('.save-plan').forEach(function (btn) {
        btn.addEventListener('click', function () { savePlan(btn); });
    });
    document.querySelectorAll('.quick-prompt').forEach(function (btn) {
        btn.addEventListener('click', function () {
            inputEl.value = btn.getAttribute('data-prompt') || '';
            inputEl.focus();
        });
    });

    var clearEl = document.getElementById('assistant-clear');
    if (clearEl) {
        clearEl.addEventListener('click', function () {
            window.location.href = CHAT_URL;
        });
    }

    inputEl.focus();
})();
</script>
