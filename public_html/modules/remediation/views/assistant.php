<?php
/**
 * Vista: asistente IA de remediación.
 * Variables compartidas: $org, $selectedOrgId, $selectedTask, $cveData,
 * $cveQuery, $cveContext, $chats, $chat, $messages, $llmConfigured,
 * $profiles, $taskProfileId.
 */

$modUrl = base_url('modules/remediation');
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
                            <div class="text-xs leading-relaxed whitespace-pre-wrap break-words"><?= e((string)$message['content']) ?></div>
                            <?php if (!$isUser && $selectedTask !== null): ?>
                                <button type="button" class="save-plan mt-2 text-[10px] underline opacity-70 hover:opacity-100"
                                        data-content="<?= e((string)$message['content']) ?>">Guardar como plan</button>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <div class="border-t border-line p-3">
            <input type="hidden" name="csrf_token" value="<?= e(Csrf::token()) ?>">
            <div class="flex items-end gap-2">
                <textarea id="assistant-input" rows="2" placeholder="Escribe tu pregunta… (Enter para enviar, Shift+Enter para nueva línea)"
                          class="flex-1 resize-none px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-sm focus:ring-2 focus:ring-brand-500 outline-none"></textarea>
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

<script>
(function () {
    var ASK_URL = <?= json_encode($modUrl . '/ask') ?>;
    var PLAN_URL = <?= json_encode($modUrl . '/tasks/plan') ?>;
    var TASK_ID = <?= $selectedTask !== null ? (int)$selectedTask['id'] : 0 ?>;
    var ORG_ID = <?= (int)$selectedOrgId ?>;
    var CHAT_ID = <?= $chat !== null ? (int)$chat['id'] : 0 ?>;
    var CHAT_URL = <?= json_encode($assistantUrl) ?>;
    var messagesEl = document.getElementById('chat-messages');
    var inputEl = document.getElementById('assistant-input');
    var sendEl = document.getElementById('assistant-send');
    var profileEl = document.getElementById('assistant-profile');
    var cveEl = document.getElementById('assistant-cve');
    var firstMessage = CHAT_ID === 0;

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
        body.className = 'text-xs leading-relaxed whitespace-pre-wrap break-words';
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
            if (firstMessage) {
                window.location.href = CHAT_URL + '&chat=' + encodeURIComponent(res.chat_id);
                return;
            }
            if (res.content_html) {
                thinking.body.innerHTML = res.content_html;
            } else {
                thinking.body.textContent = res.content || '';
            }
            if (TASK_ID > 0) {
                var save = document.createElement('button');
                save.type = 'button';
                save.className = 'save-plan mt-2 text-[10px] underline opacity-70 hover:opacity-100';
                save.textContent = 'Guardar como plan';
                save.setAttribute('data-content', res.content || '');
                save.onclick = function () { savePlan(save); };
                thinking.box.appendChild(save);
            }
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
        if (!content || TASK_ID <= 0) return;
        api('POST', PLAN_URL, { task_id: TASK_ID, content: content }).then(function (res) {
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
