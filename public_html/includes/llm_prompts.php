<?php
/**
 * llm_prompts.php — Registro central de prompts editables.
 *
 * El CATÁLOGO (este fichero) es la fuente de verdad: qué prompts existen y
 * cuál es su texto por defecto. La tabla `llm_prompts` solo guarda las
 * personalizaciones hechas desde la interfaz.
 *
 * Garantías:
 *   · Sin fila en la tabla → se usa el valor por defecto del código.
 *   · Prompt bloqueado (is_locked) → siempre el valor por defecto, aunque
 *     alguien inserte una fila a mano en la base de datos.
 *   · Si la tabla no existe o falla → valor por defecto (nunca rompe).
 *
 * Uso:
 *   $system = llm_prompt('cve.report.system', 'Eres un analista…');
 *   $text   = llm_prompt('cve.item.intro', 'Analiza el CVE {cve_id}…', ['{cve_id}' => $id]);
 */

declare(strict_types=1);

if (!function_exists('llm_prompts_catalog')) {
    /**
     * Catálogo de prompts: clave => metadatos y texto por defecto.
     *
     * @return array<string,array{scope:string,scope_label:string,label:string,description:string,is_locked:bool,default:string}>
     */
    function llm_prompts_catalog(): array
    {
        static $catalog = null;
        if (is_array($catalog)) {
            return $catalog;
        }

        $catalog = [
            // ====================================================
            // Análisis IA (módulo LLM)
            // ====================================================
            'llm.analysis.tenant.system' => [
                'scope'       => 'ia',
                'scope_label' => 'Análisis IA',
                'label'       => 'Análisis del tenant · rol del asistente',
                'description' => 'Rol y reglas del análisis libre sobre los datos de un tenant.',
                'is_locked'   => false,
                'default'     => 'Eres un analista de ciberseguridad senior. Responde SIEMPRE en español y en Markdown. '
                    . 'Básate EXCLUSIVAMENTE en los datos del tenant que se te proporcionan; no inventes cifras ni hechos. '
                    . 'Si falta información, dilo explícitamente. Sé concreto, prioriza y propón acciones.',
            ],
            'llm.analysis.profile.system' => [
                'scope'       => 'ia',
                'scope_label' => 'Análisis IA',
                'label'       => 'Perfil de amenaza · rol del asistente',
                'description' => 'Rol y reglas del análisis de un intel profile (actor o herramienta).',
                'is_locked'   => false,
                'default'     => 'Eres un analista de threat intelligence senior. Responde SIEMPRE en español y en Markdown, '
                    . 'basándote EXCLUSIVAMENTE en los datos del perfil; no inventes. Sé concreto y accionable.',
            ],
            'llm.analysis.indicators.system' => [
                'scope'       => 'ia',
                'scope_label' => 'Análisis IA',
                'label'       => 'Indicadores · rol del asistente',
                'description' => 'Rol y reglas del análisis de indicadores (IOCs).',
                'is_locked'   => false,
                'default'     => 'Eres un analista de threat intelligence senior. Responde SIEMPRE en español y en Markdown, '
                    . 'basándote EXCLUSIVAMENTE en los indicadores proporcionados; no inventes.',
            ],
            'llm.analysis.article.system' => [
                'scope'       => 'ia',
                'scope_label' => 'Análisis IA',
                'label'       => 'Artículo TI · rol del asistente',
                'description' => 'Rol y reglas del análisis de un artículo de threat intelligence.',
                'is_locked'   => false,
                'default'     => 'Eres un analista de threat intelligence senior. Responde SIEMPRE en español y en Markdown. '
                    . 'Usa EXCLUSIVAMENTE la información del artículo proporcionado; no inventes datos. Si algo no consta, dilo.',
            ],
            'llm.analysis.article.defang' => [
                'scope'       => 'ia',
                'scope_label' => 'Análisis IA',
                'label'       => 'Artículo TI · instrucción de defanging',
                'description' => 'Se añade al análisis de artículos cuando se pide ofuscar IPs y dominios.',
                'is_locked'   => false,
                'default'     => 'IMPORTANTE: al listar direcciones IP y dominios, ofusca el ÚLTIMO punto como "[.]" '
                    . '(defanging) para que el texto sea seguro de publicar.',
            ],
            'llm.analysis.incident.system' => [
                'scope'       => 'ia',
                'scope_label' => 'Análisis IA',
                'label'       => 'Incidente · rol del asistente',
                'description' => 'Rol y reglas del informe de un incidente de Defender.',
                'is_locked'   => false,
                'default'     => 'Eres un analista de ciberseguridad senior de un SOC. Responde SIEMPRE en español y en Markdown, '
                    . 'basándote EXCLUSIVAMENTE en los datos del incidente que se te dan; no inventes.',
            ],
            'llm.analysis.incident.format' => [
                'scope'       => 'ia',
                'scope_label' => 'Análisis IA',
                'label'       => 'Incidente · estructura del informe',
                'description' => 'Estructura fija que espera el informe de incidente. No editable.',
                'is_locked'   => true,
                'default'     => 'Estructura la respuesta con: 1) Resumen ejecutivo; 2) Naturaleza y vector (mapea las técnicas MITRE); '
                    . '3) Impacto potencial; 4) Indicadores (IoCs) relevantes; 5) Acciones recomendadas priorizadas (3-5). '
                    . 'Sé concreto y accionable.',
            ],
            'llm.analysis.report.system' => [
                'scope'       => 'ia',
                'scope_label' => 'Análisis IA',
                'label'       => 'Resumen de reporte · rol del asistente',
                'description' => 'Convierte los datos de un reporte en un resumen ejecutivo narrativo.',
                'is_locked'   => false,
                'default'     => 'Eres un analista de ciberseguridad que escribe informes ejecutivos. Convierte los datos técnicos '
                    . 'en un resumen narrativo profesional en español, destacando los hallazgos más relevantes y el estado '
                    . 'general de la seguridad.',
            ],
            'llm.ioc.classify.system' => [
                'scope'       => 'ia',
                'scope_label' => 'Análisis IA',
                'label'       => 'Clasificación de IOCs · rol del asistente',
                'description' => 'Cómo clasificar los indicadores (tipo de amenaza, confianza y descripción).',
                'is_locked'   => false,
                'default'     => 'Eres un analista de threat intelligence. Clasifica cada IOC en: tipo de amenaza '
                    . '(malware, phishing, C2, etc.), nivel de confianza (alta/media/baja) y una breve descripción.',
            ],
            'llm.ioc.classify.format' => [
                'scope'       => 'ia',
                'scope_label' => 'Análisis IA',
                'label'       => 'Clasificación de IOCs · formato de salida',
                'description' => 'El clasificador espera un array JSON. No editable.',
                'is_locked'   => true,
                'default'     => 'Responde en formato JSON array.',
            ],
            'llm.ioc.extract.system' => [
                'scope'       => 'ia',
                'scope_label' => 'Análisis IA',
                'label'       => 'Extracción de IOCs · contrato JSON',
                'description' => 'Define la forma exacta del JSON que espera el extractor. No editable.',
                'is_locked'   => true,
                'default'     => 'Eres un analista de threat intelligence. A partir del texto (artículo o correo), devuelve '
                    . 'EXCLUSIVAMENTE un JSON válido con esta forma: '
                    . '{"resumen":"...","iocs":[{"tipo":"ipv4-addr|domain-name|url|file|email-addr|otro","valor":"..."}],'
                    . '"recomendaciones":"..."}. No inventes IOCs; si no hay, deja el array vacío. Responde en español.',
            ],
            'llm.article.translate.system' => [
                'scope'       => 'ia',
                'scope_label' => 'Análisis IA',
                'label'       => 'Traducción de artículos · rol del asistente',
                'description' => 'Reglas de traducción al español de un artículo (conserva Markdown y términos técnicos).',
                'is_locked'   => false,
                'default'     => 'Eres un traductor profesional especializado en ciberseguridad. Traduce al ESPAÑOL (de España) '
                    . 'el artículo que se te proporciona. Reglas: conserva el formato Markdown y la estructura (títulos, listas, '
                    . 'tablas); NO traduzcas indicadores técnicos ni términos que deban permanecer literales (direcciones IP, '
                    . 'dominios, URLs, hashes, nombres de malware/actores, comandos, código, identificadores CVE/MITRE); '
                    . 'no añadas ni omitas información; no resumas. Devuelve ÚNICAMENTE la traducción en Markdown, '
                    . 'sin comentarios adicionales.',
            ],

            // ====================================================
            // Informes IA de CVE
            // ====================================================
            'cve.report.system' => [
                'scope'       => 'cve',
                'scope_label' => 'Informes IA de CVE',
                'label'       => 'Informe de varios CVEs · prompt de sistema',
                'description' => 'Rol base del analista para los informes con IA de varios CVEs.',
                'is_locked'   => false,
                'default'     => 'Eres un analista sénior de ciberseguridad especializado en vulnerabilidades, explotación '
                    . 'y respuesta a incidentes. Escribes en español, con precisión técnica y sin inventar datos.',
            ],
            'cve.report.intro' => [
                'scope'       => 'cve',
                'scope_label' => 'Informes IA de CVE',
                'label'       => 'Informe de varios CVEs · rol y enfoque',
                'description' => 'Introducción del análisis: a quién va dirigido y con qué enfoque.',
                'is_locked'   => false,
                'default'     => 'Eres un analista de seguridad sénior. Usando SOLO la información proporcionada, redacta '
                    . 'un análisis BREVE para un responsable técnico.',
            ],
            'cve.report.format' => [
                'scope'       => 'cve',
                'scope_label' => 'Informes IA de CVE',
                'label'       => 'Informe de varios CVEs · contrato de formato',
                'description' => 'Secciones numeradas y formato de viñetas que el informe necesita para renderizarse. No editable.',
                'is_locked'   => true,
                'default'     => <<<'TXT'
Devuelve EXACTAMENTE estas cuatro secciones, cada una empezando por su encabezado numerado:

1. Evaluación del riesgo
2. Escenarios de ataque
3. Mitigación
4. Resumen ejecutivo

Formato obligatorio:
- Usa SOLO viñetas, una por línea, empezando por "- ".
- Máximo 4 viñetas por sección.
- Cada viñeta debe ocupar una sola línea y tener 20 palabras como máximo.
- No escribas párrafos, introducciones ni conclusiones fuera de las cuatro secciones.
- No repitas CVSS, EPSS, KEV, fechas ni la descripción literal: ya aparecen en el informe.
- La descripción del CVE ya se muestra en el informe; no la reescribas, resumes ni traduzcas.
- No incluyas URLs ni enlaces: las referencias se muestran aparte.
- Sin Markdown (nada de **, #, `), sin emojis, sin tablas.
- Español técnico y directo. Si un dato es desconocido, escribe una viñeta con "Desconocido".
- Si hay varios CVEs, prioriza los de mayor riesgo y no repitas lo mismo.

Contenido esperado:
1. Naturaleza, componente afectado, precondiciones, impacto CIA y señal KEV/EPSS/exploits.
2. Escenario realista: entrada, autenticación, privilegios y consecuencia.
3. Acciones concretas: parche, mitigación temporal y detección.
4. Riesgo de negocio, probabilidad y urgencia (2-3 viñetas).
TXT,
            ],
            'cve.item.system' => [
                'scope'       => 'cve',
                'scope_label' => 'Informes IA de CVE',
                'label'       => 'Análisis individual de CVE · prompt de sistema',
                'description' => 'Rol base del analista para el análisis extendido de un único CVE.',
                'is_locked'   => false,
                'default'     => 'Eres un analista sénior de ciberseguridad especializado en vulnerabilidades, explotación, '
                    . 'gestión de parches y respuesta. Analizas un único CVE por respuesta, escribes en español con '
                    . 'precisión técnica y no inventas datos.',
            ],
            'cve.item.intro' => [
                'scope'       => 'cve',
                'scope_label' => 'Informes IA de CVE',
                'label'       => 'Análisis individual de CVE · rol y enfoque',
                'description' => 'Introducción del análisis. Puedes usar {cve_id} como marcador del identificador.',
                'is_locked'   => false,
                'default'     => 'Analiza ÚNICAMENTE el CVE {cve_id}. No mezcles datos de otros CVEs. Redacta un análisis '
                    . 'extendido para el equipo que va a remediarlo, usando SOLO los datos aportados.',
            ],
            'cve.item.format' => [
                'scope'       => 'cve',
                'scope_label' => 'Informes IA de CVE',
                'label'       => 'Análisis individual de CVE · contrato de formato',
                'description' => 'Secciones numeradas y reglas que el análisis individual necesita. No editable.',
                'is_locked'   => true,
                'default'     => <<<'TXT'
Devuelve EXACTAMENTE estas seis secciones, cada una empezando por su encabezado numerado:

1. Naturaleza y alcance
2. Evaluación de riesgo
3. Escenarios de ataque
4. Impacto y probabilidad
5. Mitigación y parcheo
6. Detección, verificación y prioridad

Formato obligatorio:
- Usa SOLO viñetas, una por línea, empezando por "- ".
- Entre 3 y 5 viñetas por sección.
- Cada viñeta debe ocupar una sola línea y tener 25 palabras como máximo.
- No escribas párrafos, introducciones ni conclusiones fuera de las seis secciones.
- No repitas la descripción literal ni los datos CVSS/EPSS/KEV: ya aparecen en el informe; aporta análisis.
- No inventes KB, versiones, productos ni URLs. Si un dato no consta, escribe "Desconocido".
- En mitigación, distingue parche oficial, mitigación temporal y verificación.
- Usa las etiquetas/origen solo para contextualizar al equipo responsable; no inventes datos sobre ellas.
- Sin Markdown (nada de **, #, `), sin emojis, sin tablas. Español técnico y directo.
TXT,
            ],
            'cve.translate.system' => [
                'scope'       => 'cve',
                'scope_label' => 'Informes IA de CVE',
                'label'       => 'Traducción de CVE · prompt de sistema',
                'description' => 'Rol del traductor de descripciones y acciones de CISA.',
                'is_locked'   => false,
                'default'     => 'Eres un traductor técnico especializado en ciberseguridad. Traduces al español manteniendo '
                    . 'en inglés los términos técnicos y nombres propios (RCE, buffer overflow, heap, checksum, kernel, '
                    . 'privilege escalation, CISA, KEV, BOD 26-04, etc.). No añades información ni opiniones.',
            ],
            'cve.translate.rules' => [
                'scope'       => 'cve',
                'scope_label' => 'Informes IA de CVE',
                'label'       => 'Traducción de CVE · contrato de salida',
                'description' => 'Claves exactas que el traductor debe devolver. No editable.',
                'is_locked'   => true,
                'default'     => "Traduce al español los textos de cada bloque.\n\n"
                    . "Reglas:\n"
                    . "- Devuelve EXACTAMENTE un bloque por CVE, con las mismas claves que recibe, sin nada más:\n"
                    . "CVE: CVE-AAAA-NNNN\n"
                    . "DESCRIPCION_ES: ... (solo si el bloque tenía DESCRIPCION)\n"
                    . "ACCION_KEV_ES: ... (solo si el bloque tenía ACCION_KEV)\n"
                    . "- Mantén los términos técnicos y nombres propios en inglés cuando sea lo habitual.\n"
                    . "- No inventes datos ni añadas URLs.\n"
                    . "- No resumas: traduce el contenido completo.",
            ],

            // ====================================================
            // Remediación
            // ====================================================
            'remediation.assistant.system' => [
                'scope'       => 'remediation',
                'scope_label' => 'Remediación',
                'label'       => 'Asistente de remediación · prompt de sistema',
                'description' => 'Rol del asistente que propone planes de parcheo y hardening.',
                'is_locked'   => false,
                'default'     => 'Eres un ingeniero sénior de vulnerabilidades, gestión de parches y hardening (CIS Benchmarks). '
                    . 'Respondes en español, con precisión técnica y pasos concretos. Distingue siempre entre implementación, '
                    . 'verificación y rollback. Mantén en inglés los términos técnicos habituales (RCE, KB, GPO, WAF, etc.). '
                    . 'No inventes versiones, KB ni URLs: si falta información, dilo. No repitas el contexto; ve al grano.',
            ],
            'remediation.quick.1' => [
                'scope'       => 'remediation',
                'scope_label' => 'Remediación',
                'label'       => 'Pregunta rápida 1',
                'description' => 'Botón de pregunta rápida del asistente de remediación.',
                'is_locked'   => false,
                'default'     => 'Plan de implementación paso a paso, con verificación y rollback.',
            ],
            'remediation.quick.2' => [
                'scope'       => 'remediation',
                'scope_label' => 'Remediación',
                'label'       => 'Pregunta rápida 2',
                'description' => 'Botón de pregunta rápida del asistente de remediación.',
                'is_locked'   => false,
                'default'     => '¿Cómo compruebo que el parche está realmente aplicado en los equipos?',
            ],
            'remediation.quick.3' => [
                'scope'       => 'remediation',
                'scope_label' => 'Remediación',
                'label'       => 'Pregunta rápida 3',
                'description' => 'Botón de pregunta rápida del asistente de remediación.',
                'is_locked'   => false,
                'default'     => '¿Qué controles CIS o medidas de hardening reducen la exposición?',
            ],
            'remediation.quick.4' => [
                'scope'       => 'remediation',
                'scope_label' => 'Remediación',
                'label'       => 'Pregunta rápida 4',
                'description' => 'Botón de pregunta rápida del asistente de remediación.',
                'is_locked'   => false,
                'default'     => '¿Qué evidencia debo adjuntar para cerrar la tarea?',
            ],
            'remediation.quick.5' => [
                'scope'       => 'remediation',
                'scope_label' => 'Remediación',
                'label'       => 'Pregunta rápida 5',
                'description' => 'Botón de pregunta rápida del asistente de remediación.',
                'is_locked'   => false,
                'default'     => '¿Qué riesgos tiene aplicar el parche y cómo hago el rollback?',
            ],
        ];

        return $catalog;
    }
}

if (!class_exists('LlmPromptStore')) {
    /**
     * Acceso a las personalizaciones guardadas en `llm_prompts`.
     */
    final class LlmPromptStore
    {
        /** @var array<string,string>|null */
        private static ?array $cache = null;

        private static function load(): void
        {
            if (self::$cache !== null) {
                return;
            }
            self::$cache = [];
            try {
                foreach (Database::fetchAll('SELECT key, template FROM llm_prompts') as $row) {
                    self::$cache[(string)$row['key']] = (string)$row['template'];
                }
            } catch (Throwable $e) {
                // Sin tabla (instalación antigua) → todo por defecto.
                self::$cache = [];
            }
        }

        public static function custom(string $key): ?string
        {
            $catalog = llm_prompts_catalog();
            if (isset($catalog[$key]) && !empty($catalog[$key]['is_locked'])) {
                return null; // los contratos siempre usan el texto del código
            }
            self::load();
            $value = self::$cache[$key] ?? null;
            return ($value !== null && trim($value) !== '') ? $value : null;
        }

        public static function set(string $key, string $template, ?int $userId = null): array
        {
            $catalog = llm_prompts_catalog();
            if (!isset($catalog[$key])) {
                return ['ok' => false, 'error' => 'Prompt desconocido.'];
            }
            if (!empty($catalog[$key]['is_locked'])) {
                return ['ok' => false, 'error' => 'Este prompt es un contrato de formato y no se puede editar.'];
            }
            $template = trim($template);
            if ($template === '') {
                return ['ok' => false, 'error' => 'El prompt no puede estar vacío.'];
            }
            $length = function_exists('mb_strlen') ? mb_strlen($template) : strlen($template);
            if ($length > 20000) {
                return ['ok' => false, 'error' => 'El prompt es demasiado largo (máximo 20.000 caracteres).'];
            }            try {
                Database::query(
                    "INSERT INTO llm_prompts (key, template, updated_at, updated_by)
                     VALUES (?, ?, datetime('now'), ?)
                     ON CONFLICT(key) DO UPDATE SET
                        template = excluded.template,
                        updated_at = datetime('now'),
                        updated_by = excluded.updated_by",
                    [$key, $template, $userId]
                );
            } catch (Throwable $e) {
                return ['ok' => false, 'error' => 'No se pudo guardar: ' . $e->getMessage()];
            }
            self::$cache = null;
            return ['ok' => true, 'error' => ''];
        }

        public static function reset(string $key): array
        {
            if (!isset(llm_prompts_catalog()[$key])) {
                return ['ok' => false, 'error' => 'Prompt desconocido.'];
            }
            try {
                Database::query('DELETE FROM llm_prompts WHERE key = ?', [$key]);
            } catch (Throwable $e) {
                return ['ok' => false, 'error' => 'No se pudo restaurar: ' . $e->getMessage()];
            }
            self::$cache = null;
            return ['ok' => true, 'error' => ''];
        }

        /**
         * Catálogo con el estado real de cada prompt.
         *
         * @return array<string,array<string,mixed>>
         */
        public static function all(): array
        {
            self::load();
            $out = [];
            foreach (llm_prompts_catalog() as $key => $meta) {
                $custom = self::custom($key);
                $out[$key] = $meta + [
                    'key'    => $key,
                    'custom' => $custom,
                    'text'   => $custom ?? (string)$meta['default'],
                    'edited' => $custom !== null,
                ];
            }
            return $out;
        }
    }
}

if (!function_exists('llm_prompt')) {
    /**
     * Texto efectivo de un prompt (personalización o valor por defecto).
     *
     * @param array<string,string> $vars Marcadores a sustituir (p. ej. ['{cve_id}' => 'CVE-2026-1']).
     */
    function llm_prompt(string $key, string $default = '', array $vars = []): string
    {
        $custom = LlmPromptStore::custom($key);
        $text = $custom ?? $default;
        if ($vars !== []) {
            $text = strtr($text, $vars);
        }
        return $text;
    }
}

if (!function_exists('llm_prompt_group')) {
    /**
     * Prompts de un grupo (prefijo de clave) con su texto efectivo.
     *
     * @return array<string,string> clave => texto
     */
    function llm_prompt_group(string $prefix): array
    {
        $out = [];
        foreach (llm_prompts_catalog() as $key => $meta) {
            if (str_starts_with($key, $prefix)) {
                $out[$key] = llm_prompt($key, (string)$meta['default']);
            }
        }
        return $out;
    }
}

if (!function_exists('llm_prompt_save')) {
    function llm_prompt_save(string $key, string $template, ?int $userId = null): array
    {
        return LlmPromptStore::set($key, $template, $userId);
    }
}

if (!function_exists('llm_prompt_reset')) {
    function llm_prompt_reset(string $key): array
    {
        return LlmPromptStore::reset($key);
    }
}

if (!function_exists('llm_prompts_all')) {
    function llm_prompts_all(): array
    {
        return LlmPromptStore::all();
    }
}
