<?php
/**
 * Partial: modal de edición de una plantilla de prompt.
 * Requiere: $prompts (array de llm_prompts_all()).
 */
$__prompts = [];
foreach (($prompts ?? []) as $key => $p) {
    $__prompts[(string)$key] = [
        'key'         => (string)$key,
        'label'       => (string)($p['label'] ?? ''),
        'description' => (string)($p['description'] ?? ''),
        'text'        => (string)($p['text'] ?? ''),
        'is_locked'   => !empty($p['is_locked']),
        'edited'      => !empty($p['edited']),
    ];
}
$__json = json_encode($__prompts, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
?>
<div id="prompt-modal" class="tdl-modal-overlay" hidden>
    <div class="tdl-modal" role="dialog" aria-modal="true" aria-labelledby="prompt-modal-title">
        <div class="tdl-modal-head">
            <?= icon('edit_note', 20) ?>
            <span id="prompt-modal-title">Editar prompt</span>
            <button type="button" class="icon-btn ml-auto" data-prompt-close aria-label="Cerrar">
                <?= icon('close', 18) ?>
            </button>
        </div>

        <div class="tdl-modal-body">
            <p id="prompt-modal-desc" class="text-xs text-ink-muted mt-0 mb-2"></p>
            <p id="prompt-modal-key" class="text-[11px] text-ink-soft mono mt-0 mb-3"></p>

            <form method="POST" action="<?= base_url('admin/prompts/save') ?>" id="prompt-save-form">
                <input type="hidden" name="key" id="prompt-key-save" value="">
                <label for="prompt-template" class="block text-xs font-medium text-ink-muted mb-1">Texto del prompt</label>
                <textarea id="prompt-template" name="template" rows="14"
                          class="w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-sm mono focus:ring-2 focus:ring-brand-500 outline-none"
                          spellcheck="false"></textarea>
                <p class="text-[11px] text-ink-soft mt-1 mb-0">
                    <span id="prompt-chars">0</span> caracteres · máximo 20.000
                </p>
                <div class="flex items-center gap-3 mt-4 flex-wrap">
                    <button type="submit" class="btn">
                        <?= icon('save', 16) ?>
                        Guardar
                    </button>
                    <button type="button" class="btn btn-outline" data-prompt-close>Cancelar</button>
                </div>
            </form>

            <form method="POST" action="<?= base_url('admin/prompts/reset') ?>" id="prompt-reset-form" class="mt-3 pt-3 border-t border-line-subtle">
                <input type="hidden" name="key" id="prompt-key-reset" value="">
                <button type="submit" class="btn btn-small btn-outline"
                        data-confirm="¿Restaurar el texto original de este prompt? Se perderá la personalización."
                        data-confirm-title="Restaurar prompt"
                        data-confirm-ok="Restaurar">
                    <?= icon('restart_alt', 16) ?>
                    Restaurar original
                </button>
            </form>
        </div>
    </div>
</div>

<script>
(function () {
    'use strict';
    var PROMPTS = <?= $__json ?>;
    var modal = document.getElementById('prompt-modal');
    if (!modal) { return; }

    var titleEl = document.getElementById('prompt-modal-title');
    var descEl = document.getElementById('prompt-modal-desc');
    var keyEl = document.getElementById('prompt-modal-key');
    var textEl = document.getElementById('prompt-template');
    var charsEl = document.getElementById('prompt-chars');
    var saveKey = document.getElementById('prompt-key-save');
    var resetKey = document.getElementById('prompt-key-reset');
    var lastFocus = null;

    function countChars() {
        if (charsEl) { charsEl.textContent = String(textEl.value.length); }
    }

    function openModal(key) {
        var p = PROMPTS[key];
        if (!p || p.is_locked) { return; }
        lastFocus = document.activeElement;
        titleEl.textContent = p.label || 'Editar prompt';
        descEl.textContent = p.description || '';
        keyEl.textContent = p.key;
        textEl.value = p.text || '';
        saveKey.value = key;
        resetKey.value = key;
        countChars();
        modal.hidden = false;
        document.body.classList.add('overflow-hidden');
        setTimeout(function () { textEl.focus(); textEl.setSelectionRange(0, 0); }, 40);
    }

    function closeModal() {
        modal.hidden = true;
        document.body.classList.remove('overflow-hidden');
        if (lastFocus && typeof lastFocus.focus === 'function') { lastFocus.focus(); }
    }

    document.addEventListener('click', function (ev) {
        var trigger = ev.target.closest ? ev.target.closest('[data-prompt-edit]') : null;
        if (trigger) {
            ev.preventDefault();
            openModal(trigger.getAttribute('data-prompt-edit'));
            return;
        }
        if (ev.target.closest && ev.target.closest('[data-prompt-close]')) {
            ev.preventDefault();
            closeModal();
            return;
        }
        if (ev.target === modal) { closeModal(); }
    });

    document.addEventListener('keydown', function (ev) {
        if (ev.key === 'Escape' && !modal.hidden) { closeModal(); }
    });

    textEl.addEventListener('input', countChars);
})();
</script>
