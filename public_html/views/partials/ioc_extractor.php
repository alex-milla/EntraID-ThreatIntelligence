<?php
/**
 * Asistente global de extracción y exportación de IOCs.
 *
 * Se incluye una vez en el layout (footer) y se abre desde cualquier botón
 * de exportación mediante IOCExtractor.open({...}).
 */
?>
<div id="iocz-modal" class="hidden fixed inset-0 z-[60] no-print" role="dialog" aria-modal="true"
     aria-label="Asistente de extracción y exportación de IOCs"
     data-base="<?= e(base_url('modules/export')) ?>">
    <div class="absolute inset-0 bg-black/50" onclick="IOCExtractor.close()"></div>
    <div class="relative mx-auto my-6 w-[calc(100%-1.5rem)] max-w-5xl card shadow-2xl flex flex-col"
         style="max-height: calc(100vh - 3rem);">
        <div class="flex items-start justify-between gap-3 px-5 py-3 border-b border-line">
            <div class="min-w-0">
                <h2 class="text-sm font-semibold">Asistente de IOCs</h2>
                <p class="text-[11px] text-ink-muted mt-0.5">Extrae, revisa y exporta con el formato que necesitas.</p>
            </div>
            <button type="button" onclick="IOCExtractor.close()"
                    class="shrink-0 text-xs text-ink-soft hover:text-gray-600" aria-label="Cerrar">Cerrar ✕</button>
        </div>

        <div class="px-5 py-2 border-b border-line flex items-center gap-1 flex-wrap">
            <?php foreach (['1 · Origen', '2 · Extraídos', '3 · Clasificación', '4 · Exportación'] as $i => $label): ?>
                <span id="iocz-nav-<?= $i + 1 ?>"
                      class="px-2 py-0.5 rounded-full text-[10px] font-medium <?= $i === 0 ? 'bg-brand-500 text-white' : 'bg-muted text-ink-muted' ?>">
                    <?= e($label) ?>
                </span>
                <?php if ($i < 3): ?><span class="text-[10px] text-ink-soft">›</span><?php endif; ?>
            <?php endforeach; ?>
        </div>

        <div class="overflow-y-auto px-5 py-4 flex-1">
            <!-- PASO 1: Origen -->
            <section id="iocz-step-1">
                <label class="block text-xs font-semibold mb-1">¿De dónde extraemos?</label>
                <select id="iocz-source"
                        class="w-full max-w-sm px-2.5 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                    <option value="u42">Publicaciones de Unit 42</option>
                    <option value="tenant">IOCs del catálogo (tenant)</option>
                    <option value="text">Texto pegado</option>
                </select>

                <div id="iocz-src-u42" class="mt-3">
                    <div class="flex items-center gap-2 flex-wrap">
                        <input type="text" id="iocz-article-q" placeholder="Buscar por título o fichero…"
                               class="flex-1 min-w-[14rem] px-2.5 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                        <button type="button" onclick="IOCExtractor.searchArticles()"
                                class="px-2.5 py-1.5 border border-line-strong text-xs rounded-lg hover:bg-muted">Buscar</button>
                    </div>
                    <p id="iocz-selected-label" class="text-[11px] text-ink-muted mt-2"></p>
                    <div id="iocz-article-list" class="mt-2 max-h-56 overflow-y-auto border border-line rounded-lg divide-y divide-line-subtle"></div>
                </div>

                <div id="iocz-src-tenant" class="hidden mt-3 text-xs text-ink-muted">
                    Se usarán los IOCs del tenant con los filtros que tenías aplicados en la pantalla de exportación.
                </div>

                <div id="iocz-src-text" class="hidden mt-3">
                    <textarea id="iocz-text" rows="9" placeholder="Pega aquí el informe, log o lista de IOCs…"
                              class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs mono"></textarea>
                </div>

                <div class="mt-4 flex items-center gap-2">
                    <button type="button" onclick="IOCExtractor.extract()" id="iocz-extract"
                            class="px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-medium rounded-lg">
                        Extraer IOCs
                    </button>
                    <span id="iocz-error" class="text-xs text-danger"></span>
                </div>
            </section>

            <!-- PASO 2: Extraídos -->
            <section id="iocz-step-2" class="hidden">
                <div class="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2" id="iocz-stats"></div>
                <p class="text-[11px] text-ink-soft mt-3">
                    Duplicados se cuentan antes de unificar por tipo y valor. Después puedes corregir tipo y descripción.
                </p>
                <div class="mt-4 flex items-center gap-2 flex-wrap">
                    <button type="button" onclick="IOCExtractor.copyValues()"
                            class="px-2.5 py-1 border border-line-strong text-xs rounded-lg hover:bg-muted">Copiar IOCs</button>
                    <button type="button" onclick="IOCExtractor.quickExport('txt')"
                            class="px-2.5 py-1 border border-line-strong text-xs rounded-lg hover:bg-muted">Exportar TXT</button>
                    <button type="button" onclick="IOCExtractor.go(3)"
                            class="px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-medium rounded-lg">
                        Continuar a Clasificación →
                    </button>
                </div>
            </section>

            <!-- PASO 3: Clasificación -->
            <section id="iocz-step-3" class="hidden">
                <div class="flex items-center gap-1 flex-wrap" id="iocz-tabs"></div>

                <div class="mt-3 flex items-center gap-2 flex-wrap p-2 rounded-lg bg-muted/40">
                    <input type="text" id="iocz-bulk-desc" placeholder="Descripción para los indicadores…"
                           class="flex-1 min-w-[12rem] px-2 py-1 rounded-lg border border-line-strong bg-input text-ink text-xs">
                    <select id="iocz-bulk-scope"
                            class="px-2 py-1 rounded-lg border border-line-strong bg-input text-ink text-xs">
                        <option value="all">Todos los indicadores</option>
                        <option value="filtered">Solo el filtro actual</option>
                    </select>
                    <label class="flex items-center gap-1 text-[11px] text-ink">
                        <input type="checkbox" id="iocz-bulk-empty" checked class="rounded border-line-strong text-brand-500">
                        Solo los vacíos
                    </label>
                    <button type="button" onclick="IOCExtractor.applyBulkDesc()"
                            class="px-2.5 py-1 border border-line-strong text-xs rounded-lg hover:bg-muted">Aplicar</button>
                </div>

                <div class="mt-3 flex items-center gap-2 flex-wrap">
                    <button type="button" onclick="IOCExtractor.saveCorrections()"
                            class="px-2.5 py-1 border border-green-300 text-green-700 text-xs rounded-lg hover:bg-green-50 dark:hover:bg-green-900/20">
                        Guardar correcciones
                    </button>
                    <span class="text-[11px] text-ink-soft">Los cambios se guardan en la publicación de Unit 42.</span>
                </div>

                <div class="mt-2 overflow-x-auto border border-line rounded-lg">
                    <table class="w-full text-xs">
                        <thead class="bg-muted/50">
                            <tr>
                                <th class="px-2 py-1.5 text-left">#</th>
                                <th class="px-2 py-1.5 text-left">Tipo</th>
                                <th class="px-2 py-1.5 text-left">Valor</th>
                                <th class="px-2 py-1.5 text-left">Descripción</th>
                                <th class="px-2 py-1.5 text-left">Acciones</th>
                            </tr>
                        </thead>
                        <tbody id="iocz-tbody" class="divide-y divide-line-subtle"></tbody>
                    </table>
                </div>

                <div class="mt-4 flex items-center gap-2 flex-wrap">
                    <button type="button" onclick="IOCExtractor.toExport('csv')"
                            class="px-2.5 py-1 border border-line-strong text-xs rounded-lg hover:bg-muted">Exportar CSV</button>
                    <button type="button" onclick="IOCExtractor.toExport('misp')"
                            class="px-2.5 py-1 border border-line-strong text-xs rounded-lg hover:bg-muted">Exportar MISP</button>
                    <button type="button" onclick="IOCExtractor.toExport('stix')"
                            class="px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-medium rounded-lg">
                        Exportar a STIX 2.1
                    </button>
                    <button type="button" onclick="IOCExtractor.go(2)" class="px-2.5 py-1 text-xs text-ink-soft hover:text-brand-600">← Atrás</button>
                </div>
            </section>

            <!-- PASO 4: Exportación -->
            <section id="iocz-step-4" class="hidden">
                <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    <label class="block">
                        <span class="block text-[10px] font-semibold uppercase tracking-wide text-ink-soft mb-1">Formato de salida</span>
                        <select id="iocz-cfg-format" class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                            <option value="split">Separado por tipo (recomendado)</option>
                            <option value="merged">Archivo único combinado</option>
                        </select>
                    </label>
                    <label class="block">
                        <span class="block text-[10px] font-semibold uppercase tracking-wide text-ink-soft mb-1">Nombre de la fuente</span>
                        <input type="text" id="iocz-cfg-source" value="EntraID TI" class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                    </label>
                    <label class="block">
                        <span class="block text-[10px] font-semibold uppercase tracking-wide text-ink-soft mb-1">Actor de amenaza</span>
                        <input type="text" id="iocz-cfg-actor" placeholder="Ej: APT28" class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                    </label>
                    <label class="block">
                        <span class="block text-[10px] font-semibold uppercase tracking-wide text-ink-soft mb-1">Etiquetas (separadas por coma)</span>
                        <input type="text" id="iocz-cfg-tags" placeholder="c2, ransomware" class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                    </label>
                    <label class="block">
                        <span class="block text-[10px] font-semibold uppercase tracking-wide text-ink-soft mb-1">Tipo de indicador (STIX)</span>
                        <select id="iocz-cfg-indicator" class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                            <option value="malicious-activity">malicious-activity</option>
                            <option value="anomalous-activity">anomalous-activity</option>
                            <option value="attribution">attribution</option>
                            <option value="compromised">compromised</option>
                            <option value="benign">benign</option>
                            <option value="unknown">unknown</option>
                        </select>
                    </label>
                    <label class="block">
                        <span class="block text-[10px] font-semibold uppercase tracking-wide text-ink-soft mb-1">Confianza (0-100)</span>
                        <input type="number" id="iocz-cfg-confidence" min="0" max="100" value="75" class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                    </label>
                    <label class="block">
                        <span class="block text-[10px] font-semibold uppercase tracking-wide text-ink-soft mb-1">TLP</span>
                        <select id="iocz-cfg-tlp" class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                            <option value="white">TLP:WHITE</option>
                            <option value="green" selected>TLP:GREEN</option>
                            <option value="amber">TLP:AMBER</option>
                            <option value="red">TLP:RED</option>
                        </select>
                    </label>
                    <label class="block">
                        <span class="block text-[10px] font-semibold uppercase tracking-wide text-ink-soft mb-1">Validez (días)</span>
                        <input type="number" id="iocz-cfg-days" min="1" max="3650" value="365" class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                    </label>
                    <label class="block">
                        <span class="block text-[10px] font-semibold uppercase tracking-wide text-ink-soft mb-1">Dirección IP (MISP)</span>
                        <select id="iocz-cfg-ipdir" class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                            <option value="ip-dst">ip-dst</option>
                            <option value="ip-src">ip-src</option>
                            <option value="both">Ambas</option>
                        </select>
                    </label>
                </div>

                <div class="mt-4 flex items-center gap-2 flex-wrap">
                    <button type="button" onclick="IOCExtractor.generate()" id="iocz-generate"
                            class="px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-medium rounded-lg">
                        Generar ficheros
                    </button>
                    <button type="button" onclick="IOCExtractor.go(3)" class="px-2.5 py-1 text-xs text-ink-soft hover:text-brand-600">← Atrás</button>
                    <span id="iocz-generate-msg" class="text-xs text-ink-muted"></span>
                </div>

                <div id="iocz-results" class="mt-4 space-y-2"></div>
            </section>
        </div>
    </div>
</div>
