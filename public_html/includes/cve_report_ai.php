<?php
/**
 * CveReportAi — informes de CVE con formato «SploitScan» y evaluación con IA.
 *
 * Recopila los datos del catálogo local (NVD, KEV y EPSS), calcula la
 * prioridad de parcheo y dibuja el informe en texto plano con cajas, tal y
 * como hace SploitScan en terminal. La sección final la genera el módulo LLM
 * configurado en Admin → APIs.
 *
 * Los textos están centralizados en labels() para poder traducirlos cuando
 * la aplicación sea bilingüe.
 */

declare(strict_types=1);

final class CveReportAi
{
    /** Máximo de CVEs por informe (evita prompts gigantes y llamadas eternas). */
    public const MAX_CVES = 20;
    /** Máximo de referencias que se listan por CVE. */
    public const MAX_REFS = 20;
    /** Umbrales de la prioridad (idénticos a SploitScan). */
    public const PRIORITY_CVSS_THRESHOLD = 6.0;
    public const PRIORITY_EPSS_THRESHOLD = 0.2;

    // ============================================================
    // Textos (preparado para i18n)
    // ============================================================

    private static function labels(): array
    {
        return [
            'sec_info'       => '🔍 Información de la vulnerabilidad',
            'sec_epss'       => '♾️ Puntuación EPSS',
            'sec_kev'        => '🛡️ Catálogo CISA KEV',
            'sec_exploits'   => '💣 Exploits públicos (Total: %d)',
            'sec_refs'       => '📚 Más referencias',
            'sec_priority'   => '⚠️ Prioridad de parcheo',
            'sec_ai'         => '🤖 Evaluación de riesgo con IA',
            'no_data'        => '❌ Sin datos disponibles.',
            'published'      => 'Publicado',
            'score'          => 'Puntuación',
            'vector'         => 'Vector',
            'description'    => 'Descripción',
            'epss'           => 'EPSS',
            'kev_listed'     => 'En el catálogo KEV de CISA.',
            'kev_not_listed' => '❌ No figura en el catálogo CISA KEV.',
            'kev_added'      => 'Añadido',
            'kev_due'        => 'Vencimiento',
            'kev_ransomware' => 'Ransomware',
            'github'         => 'GitHub',
            'github_none'    => '❌ Sin exploits conocidos en el catálogo local.',
            'other'          => 'Otros',
            'packetstorm'    => 'PacketStorm',
            'priority'       => 'Prioridad',
            'priority_none'  => '❌ Sin datos suficientes para calcular la prioridad.',
            'refs_none'      => '❌ No hay más referencias.',
            'refs_more'      => '… y %d referencias más',
            'ai_error'       => '❌ No se pudo generar la evaluación con IA: %s',
            'ai_pending'     => '⏳ Evaluación con IA pendiente.',
            'ai_local'       => 'ℹ️ Informe generado en modo solo datos (sin IA). Las secciones anteriores salen del catálogo local.',
            'unknown'        => 'Desconocido',
            'yes'            => 'Sí',
            'no'             => 'No',
        ];
    }

    private static function severityLabel(string $severity): string
    {
        $map = [
            'Critical' => 'CRÍTICO',
            'High'     => 'ALTO',
            'Medium'   => 'MEDIO',
            'Low'      => 'BAJO',
            'None'     => 'NINGUNO',
        ];
        return $map[$severity] ?? strtoupper($severity);
    }

    // ============================================================
    // Entrada: validación de los CVE
    // ============================================================

    /**
     * Normaliza y valida una lista de CVE introducida por el usuario.
     * Admite arrays o texto separado por comas, espacios o punto y coma.
     *
     * @return string[] CVE-AAAA-NNNN únicos y en mayúsculas (máx. $max).
     */
    public static function normalizeCveIds(mixed $raw, int $max = self::MAX_CVES): array
    {
        $max = max(1, $max);
        $parts = [];
        if (is_array($raw)) {
            foreach ($raw as $item) {
                if (!is_scalar($item)) {
                    continue;
                }
                $parts[] = (string)$item;
            }
        } else {
            $parts = preg_split('/[\s,;]+/', (string)$raw) ?: [];
        }

        $ids = [];
        foreach ($parts as $part) {
            $id = strtoupper(trim($part));
            if ($id === '' || !preg_match('/^CVE-\d{4}-\d{4,7}$/', $id)) {
                continue;
            }
            $ids[$id] = true;
            if (count($ids) >= $max) {
                break;
            }
        }

        return array_keys($ids);
    }

    // ============================================================
    // Tags por CVE (v0.2.8.1)
    // ============================================================

    /**
     * Normaliza una lista de tags: texto libre separado por comas, punto y coma
     * o saltos de línea, o un array. Elimina duplicados sin distinguir mayúsculas.
     *
     * @return string[]
     */
    public static function normalizeTags(mixed $raw, int $max = 10): array
    {
        $parts = [];
        if (is_array($raw)) {
            foreach ($raw as $item) {
                if (is_scalar($item)) {
                    $parts[] = (string)$item;
                }
            }
        } else {
            $parts = preg_split('/[,;\n]+/u', (string)$raw) ?: [];
        }

        $tags = [];
        $seen = [];
        foreach ($parts as $part) {
            $tag = trim((string)$part);
            $tag = ltrim($tag, "# \t");
            $tag = preg_replace('/\s+/u', ' ', $tag) ?? $tag;
            $tag = preg_replace('/[\x00-\x1F\x7F]/u', '', $tag) ?? $tag;
            if ($tag === '') {
                continue;
            }
            $tag = function_exists('mb_substr')
                ? mb_substr($tag, 0, 40, 'UTF-8')
                : substr($tag, 0, 40);
            $key = function_exists('mb_strtolower')
                ? mb_strtolower($tag, 'UTF-8')
                : strtolower($tag);
            if (isset($seen[$key])) {
                continue;
            }
            $seen[$key] = true;
            $tags[] = $tag;
            if (count($tags) >= max(1, $max)) {
                break;
            }
        }

        return $tags;
    }

    /** Serializa tags para SQLite (o null si no hay). */
    public static function tagsJson(array $tags): ?string
    {
        $tags = self::normalizeTags($tags);
        if ($tags === []) {
            return null;
        }
        $json = json_encode($tags, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        return $json !== false ? $json : null;
    }

    /**
     * Decodifica tags guardados como JSON (o texto separado por comas en datos
     * antiguos) y los normaliza.
     *
     * @return string[]
     */
    public static function decodeTags(?string $json): array
    {
        $raw = trim((string)$json);
        if ($raw === '') {
            return [];
        }
        $decoded = json_decode($raw, true);
        if (is_array($decoded)) {
            return self::normalizeTags($decoded);
        }
        return self::normalizeTags($raw);
    }

    // ============================================================
    // Datos del catálogo local
    // ============================================================

    /**
     * Recopila los datos de cada CVE desde cve.sqlite.
     *
     * @param string[] $cveIds
     * @return array<int,array<string,mixed>>
     */
    public static function buildData(array $cveIds): array
    {
        $items = [];
        foreach ($cveIds as $cveId) {
            $row = CveDatabase::fetchOne("SELECT * FROM cve_catalog WHERE cve_id = ?", [$cveId]);
            if ($row === null) {
                continue;
            }

            $epssRow = CveDatabase::fetchOne(
                "SELECT epss, percentile, score_date FROM cve_epss WHERE cve_id = ?",
                [$cveId]
            );
            $kevRow = CveDatabase::fetchOne("SELECT * FROM cve_kev WHERE cve_id = ?", [$cveId]);

            $github = [];
            $others = [];
            foreach (self::normalizeReferences($row['references_json'] ?? '') as $url) {
                $host = strtolower((string)parse_url($url, PHP_URL_HOST));
                if ($host === 'github.com' || $host === 'www.github.com') {
                    $github[] = $url;
                } else {
                    $others[] = $url;
                }
            }
            $github = array_values(array_unique($github));
            $others = array_values(array_unique($others));

            $cvss = null;
            if (isset($row['cvss_v3_score']) && $row['cvss_v3_score'] !== null) {
                $cvss = (float)$row['cvss_v3_score'];
            } elseif (isset($row['cvss_v2_score']) && $row['cvss_v2_score'] !== null) {
                $cvss = (float)$row['cvss_v2_score'];
            }

            $epss = null;
            if ($epssRow !== null && $epssRow['epss'] !== null) {
                $epss = (float)$epssRow['epss'];
            }

            $isKev = $kevRow !== null;
            $kevAction = trim((string)($kevRow['required_action'] ?? ''));
            $kevActionEs = '';
            $cachedActionEs = self::cleanTranslatedText((string)($kevRow['required_action_es'] ?? ''));
            if ($cachedActionEs !== '' && hash_equals((string)($kevRow['required_action_es_hash'] ?? ''), sha1($kevAction))) {
                $kevActionEs = $cachedActionEs;
            }

            $description = trim((string)($row['description'] ?? ''));
            $descriptionEs = '';
            $cachedEs = self::cleanTranslatedText((string)($row['description_es'] ?? ''));
            if ($cachedEs !== '' && hash_equals((string)($row['description_es_hash'] ?? ''), sha1($description))) {
                $descriptionEs = $cachedEs;
            } elseif (str_starts_with(strtolower((string)($row['description_lang'] ?? '')), 'es')) {
                $descriptionEs = $description;
            }

            $items[] = [
                'cve_id'          => (string)$row['cve_id'],
                'description'     => $description,
                'description_es'  => $descriptionEs,
                'description_lang'=> (string)($row['description_lang'] ?? ''),
                'published_at'    => self::shortDate((string)($row['published_at'] ?? '')),
                'severity'        => (string)($row['severity'] ?? ''),
                'cvss'            => $cvss,
                'vector'          => (string)($row['cvss_v3_vector'] ?? ''),
                'nvd_url'         => (string)($row['nvd_url'] ?? ''),
                'epss'            => $epss,
                'epss_percentile' => $epssRow !== null && $epssRow['percentile'] !== null ? (float)$epssRow['percentile'] : null,
                'epss_date'       => (string)($epssRow['score_date'] ?? ''),
                'kev'             => $isKev,
                'kev_added'       => self::shortDate((string)($kevRow['date_added'] ?? '')),
                'kev_due'         => self::shortDate((string)($kevRow['due_date'] ?? '')),
                'kev_ransomware'  => (string)($kevRow['known_ransomware'] ?? ''),
                'kev_action'      => trim((string)($kevRow['required_action'] ?? '')),
                'kev_action_es'   => $kevActionEs,
                'kev_name'        => trim((string)($kevRow['vulnerability_name'] ?? '')),
                'github'          => $github,
                'references'      => $others,
                'priority'        => self::calculatePriority($cvss, $epss, $isKev, $github !== []),
            ];
        }

        return $items;
    }

    /**
     * Prioridad de parcheo A+ / A / B / C / D (fórmula de SploitScan).
     * A+ si está en KEV; A si CVSS ≥ 6 y EPSS ≥ 0,2; B si CVSS ≥ 6; C si
     * EPSS ≥ 0,2; D en el resto. Con exploits públicos sube dos niveles.
     */
    public static function calculatePriority(?float $cvss, ?float $epss, bool $kev, bool $hasExploits): ?string
    {
        if ($cvss === null && $epss === null && !$kev && !$hasExploits) {
            return null;
        }

        $cvssVal = $cvss ?? 0.0;
        $epssVal = $epss ?? 0.0;

        if ($kev) {
            $grade = 'A+';
        } elseif ($cvssVal >= self::PRIORITY_CVSS_THRESHOLD && $epssVal >= self::PRIORITY_EPSS_THRESHOLD) {
            $grade = 'A';
        } elseif ($cvssVal >= self::PRIORITY_CVSS_THRESHOLD) {
            $grade = 'B';
        } elseif ($epssVal >= self::PRIORITY_EPSS_THRESHOLD) {
            $grade = 'C';
        } else {
            $grade = 'D';
        }

        if ($hasExploits && $grade !== 'A+') {
            $order = ['D', 'C', 'B', 'A', 'A+'];
            $pos = array_search($grade, $order, true);
            $grade = $order[min(($pos === false ? 0 : (int)$pos) + 2, 4)];
        }

        return $grade;
    }

    /**
     * Extrae URLs válidas de references_json (admite strings u objetos NVD).
     *
     * @return string[]
     */
    private static function normalizeReferences(mixed $json): array
    {
        $data = is_array($json) ? $json : safe_json_decode((string)$json, []);
        if (!is_array($data)) {
            return [];
        }

        $urls = [];
        foreach ($data as $item) {
            $url = '';
            if (is_string($item)) {
                $url = $item;
            } elseif (is_array($item)) {
                $url = (string)($item['url'] ?? '');
            }
            $url = trim($url);
            if ($url === '' || !preg_match('#^https?://#i', $url)) {
                continue;
            }
            $urls[$url] = true;
        }

        return array_keys($urls);
    }

    // ============================================================
    // Render del informe
    // ============================================================

    /**
     * Dibuja el informe completo en texto plano.
     *
     * @param array<int,array<string,mixed>> $items
     */
    public static function renderReport(array $items, ?string $aiText = null, string $aiError = '', bool $localOnly = false): string
    {
        $L = self::labels();
        $blocks = [];

        // Cabecera general del documento (útil cuando hay varios CVEs).
        $innerWidth = 60;
        $blocks[] = '╔' . str_repeat('═', $innerWidth) . '╗';
        $blocks[] = '║' . str_pad(' INFORME DE VULNERABILIDADES', $innerWidth, ' ', STR_PAD_RIGHT) . '║';
        $blocks[] = '║' . str_pad(' EntraID Threat Intelligence', $innerWidth, ' ', STR_PAD_RIGHT) . '║';
        $blocks[] = '╚' . str_repeat('═', $innerWidth) . '╝';
        $blocks[] = '';

        foreach ($items as $item) {
            $blocks = array_merge($blocks, self::cveBox($item, $L));
        }

        $blocks = array_merge($blocks, self::aiBox($aiText, $aiError, $localOnly));

        return rtrim(implode("\n", $blocks)) . "\n";
    }

    /**
     * @param array<string,mixed> $item
     * @param array<string,string> $L
     * @return string[]
     */
    private static function cveBox(array $item, array $L): array
    {
        $cveId = (string)$item['cve_id'];
        $out = self::headerBox($cveId);

        // --- Información de la vulnerabilidad ---
        $lines = [];
        if ($item['published_at'] !== '') {
            $lines[] = '├ ' . self::padLabel($L['published']) . $item['published_at'];
        }
        if ($item['cvss'] !== null) {
            $severity = self::severityLabel((string)$item['severity']);
            $lines[] = '├ ' . self::padLabel($L['score'])
                . number_format((float)$item['cvss'], 1, '.', '')
                . ($severity !== '' ? ' (' . $severity . ')' : '');
        }
        if ($item['vector'] !== '') {
            foreach (self::wrapLines((string)$item['vector'], 100, 16) as $i => $line) {
                $lines[] = ($i === 0 ? '├ ' . self::padLabel($L['vector']) : str_repeat(' ', 16)) . $line;
            }
        }

        $description = self::cleanText((string)$item['description']);
        if ($description === '') {
            $description = $L['unknown'];
        }
        $descLines = self::wrapLines($description, 100, 16);
        $labelsPad = '└ ' . self::padLabel($L['description']);
        if ($descLines === []) {
            $lines[] = $labelsPad . $L['unknown'];
        } else {
            $lines[] = $labelsPad . array_shift($descLines);
            foreach ($descLines as $line) {
                $lines[] = str_repeat(' ', 16) . $line;
            }
        }
        $out = array_merge($out, self::section($L['sec_info'], $lines, $L));

        // --- EPSS ---
        $lines = [];
        if ($item['epss'] !== null) {
            $lines[] = '└ ' . self::padLabel($L['epss'])
                . number_format((float)$item['epss'] * 100, 2, '.', '') . '% de probabilidad de explotación.';
        } else {
            $lines[] = '└ ❌ Sin puntuación EPSS disponible.';
        }
        $out = array_merge($out, self::section($L['sec_epss'], $lines, $L));

        // --- CISA KEV ---
        $lines = [];
        if (!empty($item['kev'])) {
            $lines[] = '├ ' . $L['kev_listed'];
            if ($item['kev_added'] !== '') {
                $lines[] = '├ ' . self::padLabel($L['kev_added']) . $item['kev_added'];
            }
            if ($item['kev_due'] !== '') {
                $lines[] = '├ ' . self::padLabel($L['kev_due']) . $item['kev_due'];
            }
            $ransom = strcasecmp((string)$item['kev_ransomware'], 'Known') === 0;
            $lines[] = '└ ' . self::padLabel($L['kev_ransomware']) . ($ransom ? $L['yes'] : $L['no']);
        } else {
            $lines[] = '└ ' . $L['kev_not_listed'];
        }
        $out = array_merge($out, self::section($L['sec_kev'], $lines, $L));

        // --- Exploits públicos (referencias GitHub del propio CVE) ---
        $github = is_array($item['github']) ? $item['github'] : [];
        $total = count($github);
        $lines = [];
        $lines[] = '├ ' . $L['github'];
        if ($total === 0) {
            $lines[] = '│  └ ' . $L['github_none'];
        } else {
            $i = 0;
            foreach ($github as $url) {
                $i++;
                $lines[] = '│  ' . ($i === $total ? '└' : '├') . ' ' . $url;
            }
        }
        $lines[] = '│';
        $lines[] = '└ ' . $L['other'];
        $lines[] = '   └ ' . $L['packetstorm'] . ': ' . self::packetStormUrl($cveId);
        $out = array_merge($out, self::section(sprintf($L['sec_exploits'], $total), $lines, $L));

        // --- Más referencias ---
        $refs = is_array($item['references']) ? $item['references'] : [];
        $lines = [];
        if ($refs === []) {
            $lines[] = '└ ' . $L['refs_none'];
        } else {
            $shown = array_slice($refs, 0, self::MAX_REFS);
            $last = count($shown) - 1;
            foreach ($shown as $i => $url) {
                $lines[] = ($i === $last && count($refs) <= self::MAX_REFS ? '└' : '├') . ' ' . $url;
            }
            if (count($refs) > self::MAX_REFS) {
                $lines[] = '└ ' . sprintf($L['refs_more'], count($refs) - self::MAX_REFS);
            }
        }
        $out = array_merge($out, self::section($L['sec_refs'], $lines, $L));

        // --- Prioridad de parcheo ---
        $lines = [];
        if (!empty($item['priority'])) {
            $lines[] = '└ ' . self::padLabel($L['priority']) . (string)$item['priority'];
        } else {
            $lines[] = '└ ' . $L['priority_none'];
        }
        $out = array_merge($out, self::section($L['sec_priority'], $lines, $L));

        return $out;
    }

    /**
     * @param array<string,string> $L
     * @return string[]
     */
    private static function section(string $title, array $lines, array $L): array
    {
        $out = ['┌───[ ' . $title . ' ]', '|'];
        if ($lines === []) {
            $lines = ['└ ' . $L['no_data']];
        }
        foreach ($lines as $line) {
            $out[] = $line;
        }
        $out[] = '';
        return $out;
    }

    /**
     * @return string[]
     */
    private static function headerBox(string $cveId): array
    {
        $text = ' CVE ID: ' . $cveId . ' ';
        $line = str_repeat('═', self::textLength($text));
        return ['╔' . $line . '╗', '║' . $text . '║', '╚' . $line . '╝', ''];
    }

    /**
     * Bloque final con la evaluación de la IA.
     *
     * @return string[]
     */
    private static function aiBox(?string $aiText, string $aiError, bool $localOnly = false): array
    {
        $L = self::labels();
        $out = ['┌───[ ' . $L['sec_ai'] . ' ]', '|'];

        if ($localOnly) {
            foreach (self::wrapLines($L['ai_local'], 94, 2) as $line) {
                $out[] = '| ' . $line;
            }
        } elseif ($aiText !== null && trim($aiText) !== '') {
            foreach (self::formatAiText($aiText) as $line) {
                $out[] = $line;
            }
        } elseif ($aiError !== '') {
            $message = sprintf($L['ai_error'], $aiError);
            foreach (self::wrapLines($message, 94, 2) as $line) {
                $out[] = '| ' . $line;
            }
        } else {
            $out[] = '| ' . $L['ai_pending'];
        }

        $out[] = '└────────────────────────────────────────';
        $out[] = '';
        return $out;
    }

    /**
     * Adapta el texto del LLM al formato de caja: encabezados numerados con
     * subrayado y párrafos con sangría «| ».
     *
     * @return string[]
     */
    private static function formatAiText(string $text): array
    {
        $text = str_replace(["\r\n", "\r"], "\n", $text);
        // Acepta también encabezados numerados separados por una sola línea.
        $text = preg_replace('/\n(?=[1-4]\.\s)/u', "\n\n", $text) ?? $text;
        $paragraphs = preg_split('/\n{2,}/', trim($text)) ?: [];
        $out = [];

        foreach ($paragraphs as $paragraph) {
            $paragraph = trim($paragraph);
            if ($paragraph === '') {
                continue;
            }
            $lines = preg_split('/\n/', $paragraph) ?: [];
            $first = trim((string)($lines[0] ?? ''));

            if (preg_match('/^[1-4]\.\s+\S/u', $first) && count($lines) > 1) {
                foreach (self::wrapLines($first, 96, 2) as $line) {
                    $out[] = '| ' . $line;
                }
                $out[] = '| ' . str_repeat('-', min(60, max(10, self::textLength($first) + 1)));
                $rest = implode(' ', array_map('trim', array_slice($lines, 1)));
                foreach (self::wrapLines($rest, 96, 2) as $line) {
                    $out[] = '| ' . $line;
                }
            } else {
                $joined = implode(' ', array_map('trim', $lines));
                foreach (self::wrapLines($joined, 96, 2) as $line) {
                    $out[] = '| ' . $line;
                }
            }
            $out[] = '|';
        }

        if ($out !== [] && end($out) === '|') {
            array_pop($out);
        }
        return $out;
    }

    // ============================================================
    // Utilidades de formato
    // ============================================================

    private static function padLabel(string $label): string
    {
        $text = $label . ':';
        $pad = 14 - self::textLength($text);
        return $text . str_repeat(' ', max(0, $pad));
    }

    /**
     * Longitud en caracteres (no bytes). mbstring es opcional en el hosting.
     */
    private static function textLength(string $text): int
    {
        if (function_exists('mb_strlen')) {
            return mb_strlen($text, 'UTF-8');
        }
        $count = preg_match_all('/./us', $text);
        return $count === false ? strlen($text) : $count;
    }

    private static function packetStormUrl(string $cveId): string
    {
        return 'https://packetstormsecurity.com/search/?q=' . rawurlencode($cveId);
    }

    private static function shortDate(string $value): string
    {
        $value = trim($value);
        if (preg_match('/^(\d{4}-\d{2}-\d{2})/', $value, $m)) {
            return $m[1];
        }
        return '';
    }

    private static function cleanText(string $text): string
    {
        $text = str_replace(["\r\n", "\r", "\t"], ' ', $text);
        $text = preg_replace('/\s+/u', ' ', $text) ?? '';
        return trim($text);
    }

    /**
     * Word-wrap multibyte que preserva palabras (sin dependencias externas).
     *
     * @return string[]
     */
    private static function wrapLines(string $text, int $width, int $indent = 0): array
    {
        $text = self::cleanText($text);
        if ($text === '') {
            return [];
        }

        $available = max(20, $width - $indent);
        $words = preg_split('/ /u', $text) ?: [];
        $lines = [];
        $current = '';

        foreach ($words as $word) {
            if ($current === '') {
                $current = $word;
                continue;
            }
            if (self::textLength($current . ' ' . $word) <= $available) {
                $current .= ' ' . $word;
            } else {
                $lines[] = $current;
                $current = $word;
            }
        }
        if ($current !== '') {
            $lines[] = $current;
        }

        return $lines;
    }

    // ============================================================
    // Prompt de IA
    // ============================================================

    public static function systemPrompt(): string
    {
        return 'Eres un analista sénior de ciberseguridad especializado en vulnerabilidades, '
            . 'explotación y respuesta a incidentes. Escribes en español, con precisión técnica '
            . 'y sin inventar datos.';
    }

    /**
     * Traduce y cachea en español la descripción del CVE y la acción requerida
     * por CISA. Se ejecuta una sola vez por CVE y se reutiliza en informes futuros.
     *
     * @param array<int,array<string,mixed>> $items
     */
    public static function ensureSpanishTexts(array &$items, ?int $profileId = null): void
    {
        $pending = [];
        foreach ($items as $index => $item) {
            $description = trim((string)($item['description'] ?? ''));
            $action = trim((string)($item['kev_action'] ?? ''));
            $needDescription = $description !== '' && trim((string)($item['description_es'] ?? '')) === '';
            $needAction = $action !== '' && trim((string)($item['kev_action_es'] ?? '')) === '';
            if (!$needDescription && !$needAction) {
                continue;
            }
            $pending[$index] = [
                'item'         => $item,
                'description'  => $needDescription,
                'action'       => $needAction,
            ];
        }

        if ($pending === [] || !class_exists('Module_Llm')) {
            return;
        }

        $blocks = [];
        foreach ($pending as $entry) {
            $block = 'CVE: ' . $entry['item']['cve_id'];
            if ($entry['description']) {
                $block .= "\nDESCRIPCION: " . truncate((string)$entry['item']['description'], 1200);
            }
            if ($entry['action']) {
                $block .= "\nACCION_KEV: " . truncate((string)$entry['item']['kev_action'], 1200);
            }
            $blocks[] = $block;
        }

        $system = 'Eres un traductor técnico especializado en ciberseguridad. Traduces al español '
            . 'manteniendo en inglés los términos técnicos y nombres propios (RCE, buffer overflow, heap, '
            . 'checksum, kernel, privilege escalation, CISA, KEV, BOD 26-04, etc.). No añades información ni opiniones.';

        $prompt = "Traduce al español los textos de cada bloque.\n\n"
            . "Reglas:\n"
            . "- Devuelve EXACTAMENTE un bloque por CVE, con las mismas claves que recibe, sin nada más:\n"
            . "CVE: CVE-AAAA-NNNN\n"
            . "DESCRIPCION_ES: ... (solo si el bloque tenía DESCRIPCION)\n"
            . "ACCION_KEV_ES: ... (solo si el bloque tenía ACCION_KEV)\n"
            . "- Mantén los términos técnicos y nombres propios en inglés cuando sea lo habitual.\n"
            . "- No inventes datos ni añadas URLs.\n"
            . "- No resumas: traduce el contenido completo.\n\n"
            . "TEXTOS:\n" . implode("\n\n", $blocks);

        $maxTokens = min(4000, max(800, 600 * count($pending)));
        $started = microtime(true);

        try {
            $llm = new Module_Llm();
            $result = $llm->chat(
                $system,
                $prompt,
                ['max_tokens' => $maxTokens, 'temperature' => 0.1],
                $profileId
            );
        } catch (Throwable $e) {
            app_log('warning', 'cve_ai', 'No se pudieron traducir los textos', ['error' => $e->getMessage()]);
            return;
        }

        if (empty($result['success'])) {
            app_log('warning', 'cve_ai', 'Traducción de textos fallida', [
                'error' => (string)($result['error'] ?? ''),
            ]);
            return;
        }

        $text = (string)($result['content'] ?? '');
        $chunks = preg_split('/(?:^|\n)\s*CVE:\s*/i', "\n" . $text) ?: [];
        array_shift($chunks);

        $translatedDescriptions = 0;
        $translatedActions = 0;

        foreach ($chunks as $chunk) {
            if (!preg_match('/^(CVE-\d{4}-\d{4,7})/i', trim($chunk), $m)) {
                continue;
            }
            $cveId = strtoupper($m[1]);

            $descriptionEs = null;
            if (preg_match('/DESCRIPCION_ES:\s*(.+?)(?=\n\s*ACCION_KEV_ES:|\z)/is', $chunk, $dm)) {
                $descriptionEs = self::cleanTranslatedText($dm[1]);
            }
            $actionEs = null;
            if (preg_match('/ACCION_KEV_ES:\s*(.+?)(?=\n\s*DESCRIPCION_ES:|\z)/is', $chunk, $am)) {
                $actionEs = self::cleanTranslatedText($am[1]);
            }

            $sourceDescription = '';
            $sourceAction = '';
            foreach ($items as &$item) {
                if ((string)$item['cve_id'] !== $cveId) {
                    continue;
                }
                if ($descriptionEs !== null && $descriptionEs !== '') {
                    $sourceDescription = (string)$item['description'];
                    $item['description_es'] = $descriptionEs;
                }
                if ($actionEs !== null && $actionEs !== '') {
                    $sourceAction = (string)$item['kev_action'];
                    $item['kev_action_es'] = $actionEs;
                }
                break;
            }
            unset($item);

            if ($sourceDescription !== '' && $descriptionEs !== null && $descriptionEs !== '') {
                CveDatabase::query(
                    "UPDATE cve_catalog SET description_es = ?, description_es_hash = ? WHERE cve_id = ?",
                    [$descriptionEs, sha1($sourceDescription), $cveId]
                );
                $translatedDescriptions++;
            }

            if ($sourceAction !== '' && $actionEs !== null && $actionEs !== '') {
                CveDatabase::query(
                    "UPDATE cve_kev SET required_action_es = ?, required_action_es_hash = ? WHERE cve_id = ?",
                    [$actionEs, sha1($sourceAction), $cveId]
                );
                $translatedActions++;
            }
        }

        app_log(
            ($translatedDescriptions + $translatedActions) > 0 ? 'info' : 'warning',
            'cve_ai',
            'Traducción de textos',
            [
                'requested'    => count($pending),
                'descriptions' => $translatedDescriptions,
                'actions'      => $translatedActions,
                'ms'           => (int)round((microtime(true) - $started) * 1000),
            ]
        );
    }

    /**
     * Compila los datos en texto plano y construye el prompt de 4 secciones.
     *
     * @param array<int,array<string,mixed>> $items
     * @param array<string,mixed>|null       $defender Snapshot de exposición de Defender.
     */
    public static function userPrompt(array $items, ?array $defender = null): string
    {
        $data = [];
        foreach ($items as $item) {
            $data[] = 'CVE: ' . $item['cve_id'];
            $data[] = 'Publicado: ' . ($item['published_at'] !== '' ? $item['published_at'] : 'Desconocido');
            $data[] = 'Puntuación CVSS: ' . ($item['cvss'] !== null
                ? number_format((float)$item['cvss'], 1, '.', '') . ' (' . self::severityLabel((string)$item['severity']) . ')'
                : 'Desconocida');
            $data[] = 'Vector: ' . ($item['vector'] !== '' ? $item['vector'] : 'Desconocido');
            $descriptionForPrompt = (string)($item['description_es'] ?? '') !== ''
                ? (string)$item['description_es']
                : (string)($item['description'] ?? '');
            $data[] = 'Descripción: ' . ($descriptionForPrompt !== '' ? truncate($descriptionForPrompt, 1200) : 'Desconocida');
            $data[] = 'EPSS: ' . ($item['epss'] !== null
                ? number_format((float)$item['epss'] * 100, 2, '.', '') . '%'
                : 'Desconocido');
            $kev = 'No';
            if (!empty($item['kev'])) {
                $kev = 'Sí';
                if ($item['kev_added'] !== '') {
                    $kev .= ' (añadido ' . $item['kev_added'] . ')';
                }
                if (strcasecmp((string)$item['kev_ransomware'], 'Known') === 0) {
                    $kev .= '; ransomware conocido';
                }
            }
            $data[] = 'CISA KEV: ' . $kev;
            if (!empty($item['kev']) && $item['kev_action'] !== '') {
                $actionForPrompt = trim((string)($item['kev_action_es'] ?? '')) !== ''
                    ? (string)$item['kev_action_es']
                    : (string)$item['kev_action'];
                $data[] = 'Acción requerida (CISA): ' . $actionForPrompt;
            }
            $github = is_array($item['github']) ? $item['github'] : [];
            $data[] = 'Exploits públicos en GitHub: ' . count($github)
                . ($github !== [] ? ' — ' . implode(', ', array_slice($github, 0, 10)) : '');
            $data[] = 'Prioridad calculada: ' . (!empty($item['priority']) ? $item['priority'] : 'Sin datos');
            $refs = is_array($item['references']) ? array_slice($item['references'], 0, 8) : [];
            if ($refs !== []) {
                $data[] = 'Referencias: ' . implode(', ', $refs);
            }
            $data[] = '';
        }

        $exposureLines = [];
        if (is_array($defender) && !empty($defender['cves']) && is_array($defender['cves'])) {
            foreach ($defender['cves'] as $cveId => $ctx) {
                if (!is_array($ctx)) {
                    continue;
                }
                $line = 'CVE ' . $cveId . ': ' . (int)($ctx['machine_total'] ?? 0) . ' equipos afectados';
                if (!empty($ctx['public_exploit'])) {
                    $line .= '; exploit público';
                }
                if (!empty($ctx['exploit_verified'])) {
                    $line .= ' verificado';
                }
                if (!empty($ctx['products']) && is_array($ctx['products'])) {
                    $line .= '; productos: ' . implode(', ', array_slice($ctx['products'], 0, 4));
                }
                $exposureLines[] = $line;
            }
        }

        return "Eres un analista de seguridad sénior. Usando SOLO la información proporcionada, "
            . "redacta un análisis BREVE para un responsable técnico. Devuelve EXACTAMENTE estas "
            . "cuatro secciones, cada una empezando por su encabezado numerado:\n\n"
            . "1. Evaluación del riesgo\n"
            . "2. Escenarios de ataque\n"
            . "3. Mitigación\n"
            . "4. Resumen ejecutivo\n\n"
            . "Formato obligatorio:\n"
            . "- Usa SOLO viñetas, una por línea, empezando por \"- \".\n"
            . "- Máximo 4 viñetas por sección.\n"
            . "- Cada viñeta debe ocupar una sola línea y tener 20 palabras como máximo.\n"
            . "- No escribas párrafos, introducciones ni conclusiones fuera de las cuatro secciones.\n"
            . "- No repitas CVSS, EPSS, KEV, fechas ni la descripción literal: ya aparecen en el informe.\n"
            . "- La descripción del CVE ya se muestra en el informe; no la reescribas, resumes ni traduzcas.\n"
            . "- No incluyas URLs ni enlaces: las referencias se muestran aparte.\n"
            . "- Sin Markdown (nada de **, #, `), sin emojis, sin tablas.\n"
            . "- Español técnico y directo. Si un dato es desconocido, escribe una viñeta con \"Desconocido\".\n"
            . "- Si hay varios CVEs, prioriza los de mayor riesgo y no repitas lo mismo.\n\n"
            . "Contenido esperado:\n"
            . "1. Naturaleza, componente afectado, precondiciones, impacto CIA y señal KEV/EPSS/exploits.\n"
            . "2. Escenario realista: entrada, autenticación, privilegios y consecuencia.\n"
            . "3. Acciones concretas: parche, mitigación temporal y detección.\n"
            . "4. Riesgo de negocio, probabilidad y urgencia (2-3 viñetas).\n\n"
            . ($exposureLines !== []
                ? "EXPOSICIÓN EN TU ENTORNO (Defender):\n" . implode("\n", $exposureLines) . "\n"
                    . "- Usa la exposición real para priorizar; no inventes equipos ni datos.\n\n"
                : '')
            . "DATOS DE LOS CVEs:\n" . implode("\n", $data);
    }

    /**
     * Prompt del análisis extendido de UN único CVE (v0.2.8.1).
     *
     * @param array<string,mixed>      $item
     * @param array<string,mixed>|null $defenderCve Exposición concreta del CVE.
     * @param string[]                 $tags
     */
    public static function itemPrompt(array $item, ?array $defenderCve = null, array $tags = [], string $groupName = ''): string
    {
        $cveId = (string)($item['cve_id'] ?? '');
        $description = trim((string)($item['description_es'] ?? ''));
        if ($description === '') {
            $description = trim((string)($item['description'] ?? ''));
        }
        $kevAction = trim((string)($item['kev_action_es'] ?? ''));
        if ($kevAction === '') {
            $kevAction = trim((string)($item['kev_action'] ?? ''));
        }

        $lines = [];
        $lines[] = 'CVE: ' . $cveId;
        $lines[] = 'Publicado: ' . (!empty($item['published_at']) ? (string)$item['published_at'] : 'Desconocido');
        $lines[] = 'CVSS: ' . ($item['cvss'] !== null
            ? number_format((float)$item['cvss'], 1, '.', '') . ' (' . self::severityLabel((string)($item['severity'] ?? '')) . ')'
            : 'Desconocido');
        $lines[] = 'Vector: ' . (!empty($item['vector']) ? (string)$item['vector'] : 'Desconocido');
        $lines[] = 'EPSS: ' . ($item['epss'] !== null
            ? number_format((float)$item['epss'] * 100, 2, '.', '') . '%'
            : 'Desconocido');
        $kev = 'No';
        if (!empty($item['kev'])) {
            $kev = 'Sí';
            if (!empty($item['kev_added'])) {
                $kev .= ' (añadido ' . (string)$item['kev_added'] . ')';
            }
            if (!empty($item['kev_due'])) {
                $kev .= '; vence ' . (string)$item['kev_due'];
            }
            if (strcasecmp((string)($item['kev_ransomware'] ?? ''), 'Known') === 0) {
                $kev .= '; ransomware conocido';
            }
        }
        $lines[] = 'CISA KEV: ' . $kev;
        if ($kevAction !== '') {
            $lines[] = 'Acción requerida (CISA): ' . truncate($kevAction, 1200);
        }
        $lines[] = 'Descripción: ' . ($description !== '' ? truncate($description, 1500) : 'Desconocida');
        $lines[] = 'Prioridad calculada: ' . (!empty($item['priority']) ? (string)$item['priority'] : 'Sin datos');
        $lines[] = 'Etiquetas/origen: ' . ($tags !== [] ? implode(', ', $tags) : 'Sin definir');
        if ($groupName !== '') {
            $lines[] = 'Grupo asignado: ' . $groupName;
        }

        $github = is_array($item['github'] ?? null) ? $item['github'] : [];
        if ($github !== []) {
            $lines[] = 'Exploits públicos en GitHub: ' . implode(', ', array_slice($github, 0, 8));
        }
        $refs = is_array($item['references'] ?? null) ? array_slice($item['references'], 0, 8) : [];
        if ($refs !== []) {
            $lines[] = 'Referencias: ' . implode(', ', $refs);
        }

        $exposureLines = [];
        if (is_array($defenderCve)) {
            $exposureLines[] = 'Equipos afectados: ' . (int)($defenderCve['machine_total'] ?? 0);
            if (!empty($defenderCve['products']) && is_array($defenderCve['products'])) {
                $exposureLines[] = 'Productos expuestos: ' . implode(', ', array_slice($defenderCve['products'], 0, 6));
            }
            if (!empty($defenderCve['public_exploit'])) {
                $exposureLines[] = 'Exploit público detectado en el entorno.';
            }
            if (!empty($defenderCve['exploit_verified'])) {
                $exposureLines[] = 'Exploit verificado en el entorno.';
            }
            if (!empty($defenderCve['machines']) && is_array($defenderCve['machines'])) {
                $machines = [];
                foreach (array_slice($defenderCve['machines'], 0, 8) as $machine) {
                    $label = trim((string)($machine['name'] ?? ''));
                    if (!empty($machine['os'])) {
                        $label .= ' (' . (string)$machine['os'] . ')';
                    }
                    if (!empty($machine['exposure'])) {
                        $label .= ' [' . (string)$machine['exposure'] . ']';
                    }
                    if ($label !== '') {
                        $machines[] = $label;
                    }
                }
                if ($machines !== []) {
                    $exposureLines[] = 'Equipos: ' . implode('; ', $machines);
                }
            }
        }

        return "Analiza ÚNICAMENTE el CVE " . $cveId . ". No mezcles datos de otros CVEs. "
            . "Redacta un análisis extendido para el equipo que va a remediarlo, usando SOLO los datos aportados. "
            . "Devuelve EXACTAMENTE estas seis secciones, cada una empezando por su encabezado numerado:\n\n"
            . "1. Naturaleza y alcance\n"
            . "2. Evaluación de riesgo\n"
            . "3. Escenarios de ataque\n"
            . "4. Impacto y probabilidad\n"
            . "5. Mitigación y parcheo\n"
            . "6. Detección, verificación y prioridad\n\n"
            . "Formato obligatorio:\n"
            . "- Usa SOLO viñetas, una por línea, empezando por \"- \".\n"
            . "- Entre 3 y 5 viñetas por sección.\n"
            . "- Cada viñeta debe ocupar una sola línea y tener 25 palabras como máximo.\n"
            . "- No escribas párrafos, introducciones ni conclusiones fuera de las seis secciones.\n"
            . "- No repitas la descripción literal ni los datos CVSS/EPSS/KEV: ya aparecen en el informe; aporta análisis.\n"
            . "- No inventes KB, versiones, productos ni URLs. Si un dato no consta, escribe \"Desconocido\".\n"
            . "- En mitigación, distingue parche oficial, mitigación temporal y verificación.\n"
            . "- Usa las etiquetas/origen solo para contextualizar al equipo responsable; no inventes datos sobre ellas.\n"
            . "- Sin Markdown (nada de **, #, `), sin emojis, sin tablas. Español técnico y directo.\n\n"
            . ($exposureLines !== []
                ? "EXPOSICIÓN EN TU ENTORNO (Defender):\n" . implode("\n", $exposureLines) . "\n\n"
                : "EXPOSICIÓN EN TU ENTORNO (Defender): sin datos para este CVE.\n\n")
            . "DATOS DEL CVE:\n" . implode("\n", $lines);
    }

    /**
     * System prompt del análisis individual.
     */
    public static function itemSystemPrompt(): string
    {
        return 'Eres un analista sénior de ciberseguridad especializado en vulnerabilidades, '
            . 'explotación, gestión de parches y respuesta. Analizas un único CVE por respuesta, '
            . 'escribes en español con precisión técnica y no inventas datos.';
    }

    /**
     * Convierte la respuesta de la IA en secciones con viñetas.
     * Tolera que el modelo ignore el formato y devuelva prosa.
     *
     * @return array<int,array{title:string,bullets:string[],paragraphs:string[]}>
     */
    public static function parseAiSections(?string $text): array
    {
        $text = trim((string)$text);
        if ($text === '') {
            return [];
        }

        $text = str_replace(["\r\n", "\r"], "\n", $text);
        $text = preg_replace('/\*\*(.+?)\*\*/u', '$1', $text) ?? $text;
        $text = preg_replace('/^#{1,6}\s*/m', '', $text) ?? $text;
        $text = str_replace('`', '', $text);

        $parts = preg_split('/(?=^\s*\d{1,2}\.\s+\S)/mu', $text) ?: [];
        $sections = [];

        foreach ($parts as $part) {
            $part = trim($part);
            if ($part === '') {
                continue;
            }

            $lines = preg_split('/\n/', $part) ?: [];
            $title = trim((string)array_shift($lines));
            $title = preg_replace('/^\d{1,2}\.\s*/u', '', $title) ?? $title;

            $bullets = [];
            $paragraphs = [];
            $buffer = '';

            foreach ($lines as $line) {
                $line = trim($line);
                if ($line === '') {
                    if ($buffer !== '') {
                        $paragraphs[] = $buffer;
                        $buffer = '';
                    }
                    continue;
                }
                if (preg_match('/^[-•*]\s+(.+)$/u', $line, $m)
                    || preg_match('/^\d+[.)]\s+(.+)$/u', $line, $m)) {
                    if ($buffer !== '') {
                        $paragraphs[] = $buffer;
                        $buffer = '';
                    }
                    $bullets[] = trim($m[1]);
                    continue;
                }
                $buffer .= ($buffer !== '' ? ' ' : '') . $line;
            }
            if ($buffer !== '') {
                $paragraphs[] = $buffer;
            }

            // Si el modelo ignoró las viñetas, partir las frases para no mostrar parrafadas.
            if ($bullets === [] && $paragraphs !== []) {
                foreach ($paragraphs as $paragraph) {
                    foreach (self::splitSentences($paragraph) as $sentence) {
                        $bullets[] = $sentence;
                    }
                }
                $paragraphs = [];
            }

            $bullets = array_slice($bullets, 0, 6);
            $paragraphs = array_slice($paragraphs, 0, 2);

            if ($title !== '') {
                $sections[] = [
                    'title'      => $title,
                    'bullets'    => $bullets,
                    'paragraphs' => $paragraphs,
                ];
            }
        }

        if ($sections === []) {
            $bullets = [];
            foreach (preg_split('/\n/', $text) ?: [] as $line) {
                $line = trim($line);
                if ($line === '') {
                    continue;
                }
                $bullets[] = preg_replace('/^[-•*]\s*/u', '', $line) ?? $line;
            }
            if ($bullets !== []) {
                $sections[] = [
                    'title'      => 'Análisis',
                    'bullets'    => array_slice($bullets, 0, 6),
                    'paragraphs' => [],
                ];
            }
        }

        return $sections;
    }

    /**
     * Recupera el texto de IA de un informe antiguo guardado en formato ASCII.
     */
    public static function extractAiTextFromContent(?string $content): string
    {
        $content = (string)$content;
        if ($content === '') {
            return '';
        }

        $lines = preg_split('/\r\n|\n|\r/', $content) ?: [];
        $started = false;
        $raw = [];

        foreach ($lines as $line) {
            if (!$started) {
                if (str_contains($line, 'Evaluación de riesgo con IA')) {
                    $started = true;
                }
                continue;
            }
            if (str_starts_with($line, '└')) {
                break;
            }
            if (str_starts_with($line, '| ')) {
                $raw[] = substr($line, 2);
            } elseif (trim($line) === '|') {
                $raw[] = '';
            }
        }

        $result = [];
        $buffer = '';
        foreach ($raw as $line) {
            $line = trim($line);
            if ($line === '') {
                if ($buffer !== '') {
                    $result[] = $buffer;
                    $buffer = '';
                }
                $result[] = '';
                continue;
            }
            if (preg_match('/^-{3,}$/', $line)) {
                continue;
            }
            if (preg_match('/^[1-4]\.\s+\S/u', $line)) {
                if ($buffer !== '') {
                    $result[] = $buffer;
                    $buffer = '';
                }
                $result[] = $line;
                continue;
            }
            $buffer .= ($buffer !== '' ? ' ' : '') . $line;
        }
        if ($buffer !== '') {
            $result[] = $buffer;
        }

        return trim(implode("\n", $result));
    }

    /**
     * Limpia restos de Markdown que algunos modelos añaden a las traducciones
     * (asteriscos, backticks, saltos de línea) y deja un texto plano.
     */
    public static function cleanTranslatedText(string $text): string
    {
        $text = preg_replace('/\*\*(.+?)\*\*/u', '$1', $text) ?? $text;
        $text = str_replace(['`', '*'], '', $text);
        $text = preg_replace('/\s+/u', ' ', $text) ?? $text;
        return trim($text);
    }

    /**
     * @return string[]
     */
    private static function splitSentences(string $text): array
    {
        $text = trim(preg_replace('/\s+/u', ' ', $text) ?? '');
        if ($text === '') {
            return [];
        }
        $parts = preg_split('/(?<=[.!?])\s+/u', $text) ?: [];
        $out = [];
        foreach ($parts as $part) {
            $part = trim($part);
            if ($part !== '') {
                $out[] = $part;
            }
        }
        return array_slice($out, 0, 6);
    }

    // ============================================================
    // Ejecución del trabajo (worker)
    // ============================================================

    /**
     * Procesa un informe pendiente a partir de su token (vía worker/CLI).
     */
    public static function runPending(string $token): array
    {
        $row = CveDatabase::fetchOne(
            "SELECT id FROM cve_ai_reports WHERE token = ? AND status IN ('pending','running') LIMIT 1",
            [$token]
        );
        if ($row === null) {
            return ['success' => false, 'error' => 'Informe no encontrado o ya procesado.'];
        }
        return self::runById((int)$row['id']);
    }

    /**
     * Crea las filas de análisis por CVE que falten y conserva tags/estado de
     * las existentes. Se ejecuta antes de generar el informe.
     *
     * @param array<int,array<string,mixed>> $items
     */
    private static function ensureAiItems(int $reportId, array $items, ?string $reportTagsJson, int $defaultGroupId = 0): void
    {
        $existing = [];
        foreach (CveDatabase::fetchAll(
            "SELECT id, cve_id, tags FROM cve_ai_report_items WHERE report_id = ?",
            [$reportId]
        ) as $row) {
            $existing[(string)$row['cve_id']] = $row;
        }

        $position = 0;
        foreach ($items as $item) {
            $cveId = (string)($item['cve_id'] ?? '');
            if ($cveId === '') {
                continue;
            }
            if (!isset($existing[$cveId])) {
                CveDatabase::insert(
                    "INSERT INTO cve_ai_report_items (report_id, cve_id, position, tags, group_id, status)
                     VALUES (?, ?, ?, ?, ?, 'pending')",
                    [$reportId, $cveId, $position, $reportTagsJson, $defaultGroupId > 0 ? $defaultGroupId : null]
                );
            } else {
                $row = $existing[$cveId];
                if (trim((string)($row['tags'] ?? '')) === '' && $reportTagsJson !== null) {
                    CveDatabase::update(
                        "UPDATE cve_ai_report_items SET tags = ? WHERE id = ?",
                        [$reportTagsJson, (int)$row['id']]
                    );
                }
                CveDatabase::update(
                    "UPDATE cve_ai_report_items SET position = ? WHERE id = ?",
                    [$position, (int)$row['id']]
                );
            }
            $position++;
        }

        CveDatabase::update(
            "UPDATE cve_ai_reports SET total_items = ? WHERE id = ?",
            [count($items), $reportId]
        );
    }

    /**
     * Genera un análisis extendido por cada CVE pendiente. Cada llamada es
     * independiente: un fallo en un CVE no impide analizar los demás.
     *
     * @param array<string,mixed>            $row
     * @param array<int,array<string,mixed>> $items
     * @return array<string,mixed>
     */
    private static function runExtendedItems(int $reportId, array $row, array $items, int $profileId, float $started): array
    {
        $defender = null;
        if (!empty($row['defender_json'])) {
            $decoded = safe_json_decode((string)$row['defender_json'], null);
            if (is_array($decoded)) {
                $defender = $decoded;
            }
        }

        $itemRows = [];
        foreach (CveDatabase::fetchAll(
            "SELECT * FROM cve_ai_report_items WHERE report_id = ?",
            [$reportId]
        ) as $itemRow) {
            $itemRows[(string)$itemRow['cve_id']] = $itemRow;
        }

        $done = 0;
        foreach ($itemRows as $itemRow) {
            if ((string)$itemRow['status'] === 'done') {
                $done++;
            }
        }
        CveDatabase::update(
            "UPDATE cve_ai_reports SET processed_items = ? WHERE id = ?",
            [$done, $reportId]
        );

        $failed = 0;
        $model = '';
        $total = count($items);
        $llm = null;

        foreach ($items as $item) {
            $current = CveDatabase::fetchOne("SELECT status FROM cve_ai_reports WHERE id = ?", [$reportId]);
            if ($current === null || (string)$current['status'] !== 'running') {
                return [
                    'success' => false,
                    'id'      => $reportId,
                    'status'  => 'canceled',
                    'error'   => 'El informe se canceló durante la generación.',
                ];
            }

            $cveId = (string)($item['cve_id'] ?? '');
            $itemRow = $itemRows[$cveId] ?? null;
            if ($itemRow === null) {
                continue;
            }
            if ((string)$itemRow['status'] === 'done') {
                continue;
            }

            CveDatabase::update(
                "UPDATE cve_ai_report_items
                 SET status = 'running', started_at = datetime('now'), ai_error = NULL
                 WHERE id = ?",
                [(int)$itemRow['id']]
            );
            $itemStarted = microtime(true);

            try {
                if (!class_exists('Module_Llm')) {
                    throw new RuntimeException('El módulo de IA no está activo. Actívalo en Admin → Módulos.');
                }
                if ($llm === null) {
                    $llm = new Module_Llm();
                }
                if (!$llm->isConfigured($profileId > 0 ? $profileId : null)) {
                    throw new RuntimeException('La IA no está configurada. Revisa Admin → APIs.');
                }

                $tags = self::decodeTags((string)($itemRow['tags'] ?? ''));
                $groupName = '';
                if (!empty($itemRow['group_id'])) {
                    $group = CveDatabase::fetchOne(
                        "SELECT name FROM software_groups WHERE id = ?",
                        [(int)$itemRow['group_id']]
                    );
                    $groupName = (string)($group['name'] ?? '');
                }
                $defenderCve = ($defender !== null && isset($defender['cves'][$cveId]) && is_array($defender['cves'][$cveId]))
                    ? $defender['cves'][$cveId]
                    : null;

                $result = $llm->chat(
                    self::itemSystemPrompt(),
                    self::itemPrompt($item, $defenderCve, $tags, $groupName),
                    ['max_tokens' => 1500, 'temperature' => 0.2],
                    $profileId > 0 ? $profileId : null
                );
                if (empty($result['success'])) {
                    throw new RuntimeException((string)($result['error'] ?? 'Error desconocido del proveedor de IA.'));
                }
                $content = trim((string)($result['content'] ?? ''));
                if ($content === '') {
                    throw new RuntimeException('La IA devolvió una respuesta vacía.');
                }

                $sections = self::parseAiSections($content);
                $sectionsJson = json_encode(
                    $sections,
                    JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
                );
                CveDatabase::update(
                    "UPDATE cve_ai_report_items
                     SET status = 'done', ai_text = ?, sections_json = ?, ai_model = ?, ai_error = NULL,
                         finished_at = datetime('now'), updated_at = datetime('now')
                     WHERE id = ?",
                    [
                        $content,
                        $sectionsJson !== false ? $sectionsJson : null,
                        (string)($result['model'] ?? ''),
                        (int)$itemRow['id'],
                    ]
                );
                $model = (string)($result['model'] ?? '');
                $done++;
                app_log('info', 'cve_ai', 'CVE analizado', [
                    'id'   => $reportId,
                    'cve'  => $cveId,
                    'ms'   => (int)round((microtime(true) - $itemStarted) * 1000),
                ]);
            } catch (Throwable $e) {
                $aiError = $e->getMessage();
                if (stripos($aiError, 'curl_init') !== false || stripos($aiError, 'curl extension') !== false) {
                    $aiError = 'La extensión cURL de PHP no está disponible en el servidor; no se puede llamar a la IA.';
                }
                CveDatabase::update(
                    "UPDATE cve_ai_report_items
                     SET status = 'error', ai_error = ?, finished_at = datetime('now'), updated_at = datetime('now')
                     WHERE id = ?",
                    [substr($aiError, 0, 2000), (int)$itemRow['id']]
                );
                $failed++;
                app_log('error', 'cve_ai', 'Error analizando CVE', [
                    'id'    => $reportId,
                    'cve'   => $cveId,
                    'error' => $aiError,
                ]);
            }

            CveDatabase::update(
                "UPDATE cve_ai_reports SET processed_items = ?, ai_model = ? WHERE id = ? AND status = 'running'",
                [$done + $failed, $model !== '' ? $model : null, $reportId]
            );
        }

        $status = $done > 0 ? 'done' : 'error';
        $error = '';
        if ($failed > 0) {
            $error = $failed . ' de ' . $total . ' análisis fallaron. Puedes reintentarlos individualmente.';
        } elseif ($done === 0) {
            $error = 'No se pudo analizar ningún CVE.';
        }

        $saved = CveDatabase::update(
            "UPDATE cve_ai_reports
             SET ai_text = NULL, content_text = NULL, status = ?, ai_error = ?, ai_model = ?,
                 ai_duration_ms = ?, processed_items = ?, total_items = ?,
                 finished_at = datetime('now'), updated_at = datetime('now'), token = NULL
             WHERE id = ? AND status = 'running'",
            [
                $status,
                $error !== '' ? substr($error, 0, 2000) : null,
                $model !== '' ? $model : null,
                (int)round((microtime(true) - $started) * 1000),
                $done + $failed,
                $total,
                $reportId,
            ]
        );
        if ($saved === 0) {
            app_log('info', 'cve_ai', 'Resultado descartado (informe cancelado o eliminado)', ['id' => $reportId]);
            return [
                'success' => false,
                'id'      => $reportId,
                'status'  => 'canceled',
                'error'   => 'El informe se canceló durante la generación.',
            ];
        }

        app_log('info', 'cve_ai', 'Informe extendido finalizado', [
            'id'     => $reportId,
            'status' => $status,
            'done'   => $done,
            'failed' => $failed,
        ]);

        return [
            'success' => $status === 'done',
            'id'      => $reportId,
            'status'  => $status,
            'error'   => $error !== '' ? $error : null,
        ];
    }

    /**
     * Ejecuta un informe concreto. Reclama la fila de forma atómica para que
     * un doble clic (o el worker y la web a la vez) no lo genere dos veces.
     */
    public static function runById(int $id): array
    {
        $row = CveDatabase::fetchOne("SELECT * FROM cve_ai_reports WHERE id = ?", [$id]);
        if ($row === null) {
            return ['success' => false, 'status' => 'missing', 'error' => 'Informe no encontrado.'];
        }

        $claimed = CveDatabase::update(
            "UPDATE cve_ai_reports
             SET status = 'running', started_at = datetime('now')
             WHERE id = ? AND status = 'pending'",
            [$id]
        );
        if ($claimed === 0) {
            $status = (string)($row['status'] ?? 'pending');
            return [
                'success' => $status === 'done',
                'id'      => $id,
                'status'  => $status,
                'error'   => $status === 'error' ? (string)($row['ai_error'] ?? '') : null,
                'running' => in_array($status, ['pending', 'running'], true),
            ];
        }

        // Si el proxy corta la conexión, el trabajo termina igualmente.
        if (function_exists('ignore_user_abort')) {
            @ignore_user_abort(true);
        }
        @set_time_limit(0);

        $started = microtime(true);
        $noAi = !empty($row['no_ai']);
        $mode = ((string)($row['mode'] ?? 'extended')) === 'summary' ? 'summary' : 'extended';
        app_log('info', 'cve_ai', 'Informe IA iniciado', [
            'id'    => $id,
            'no_ai' => $noAi,
            'cves'  => (string)($row['cve_ids'] ?? ''),
        ]);

        try {
            if ($mode === 'extended') {
                // Evita mostrar un análisis global antiguo mientras se generan los individuales.
                CveDatabase::update(
                    "UPDATE cve_ai_reports SET ai_text = NULL, content_text = NULL WHERE id = ?",
                    [$id]
                );
            }

            $ids = safe_json_decode((string)($row['cve_ids'] ?? ''), []);
            if (!is_array($ids) || $ids === []) {
                throw new RuntimeException('La lista de CVEs del informe está vacía.');
            }

            $items = self::buildData($ids);
            if ($items === []) {
                throw new RuntimeException('Ninguno de los CVEs está en el catálogo local.');
            }

            $profileId = (int)($row['ai_profile_id'] ?? 0);
            $aiText = null;
            $aiError = '';
            $model = '';
            $localOnly = $noAi;

            // Si no hay ningún dato relevante, no se gasta una llamada a la IA.
            if (!$localOnly) {
                $hasFacts = false;
                foreach ($items as $item) {
                    if ($item['cvss'] !== null || $item['epss'] !== null || !empty($item['kev'])
                        || (string)$item['description'] !== '' || !empty($item['github'])) {
                        $hasFacts = true;
                        break;
                    }
                }
                if (!$hasFacts) {
                    $localOnly = true;
                    app_log('warning', 'cve_ai', 'Sin datos relevantes: se omite la IA', ['id' => $id]);
                }
            }

            // Descripción: se traduce una sola vez por CVE y se cachea en el catálogo.
            if (!$localOnly) {
                self::ensureSpanishTexts($items, $profileId > 0 ? $profileId : null);
            }

            $dataJson = json_encode($items, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
            CveDatabase::query(
                "UPDATE cve_ai_reports SET data_json = ? WHERE id = ?",
                [$dataJson !== false ? $dataJson : null, $id]
            );

            $reportTagsJson = self::tagsJson(self::decodeTags((string)($row['tags'] ?? '')));
            self::ensureAiItems($id, $items, $reportTagsJson, (int)($row['group_id'] ?? 0));

            // Análisis extendido: una llamada independiente por CVE.
            if (!$localOnly && $mode === 'extended') {
                return self::runExtendedItems($id, $row, $items, $profileId, $started);
            }

            if ($localOnly) {
                $model = 'local';
            } else {
                $llmStarted = microtime(true);
                try {
                    if (!class_exists('Module_Llm')) {
                        throw new RuntimeException('El módulo de IA no está activo. Actívalo en Admin → Módulos.');
                    }
                    $defender = null;
                    if (!empty($row['defender_json'])) {
                        $decodedDefender = safe_json_decode((string)$row['defender_json'], null);
                        if (is_array($decodedDefender)) {
                            $defender = $decodedDefender;
                        }
                    }
                    $llm = new Module_Llm();
                    $result = $llm->chat(
                        self::systemPrompt(),
                        self::userPrompt($items, $defender),
                        ['max_tokens' => 1200, 'temperature' => 0.2],
                        $profileId > 0 ? $profileId : null
                    );
                    if (!empty($result['success'])) {
                        $aiText = trim((string)($result['content'] ?? ''));
                        $model = (string)($result['model'] ?? '');
                        if ($aiText === '') {
                            $aiError = 'La IA devolvió una respuesta vacía.';
                            $aiText = null;
                        }
                    } else {
                        $aiError = (string)($result['error'] ?? 'Error desconocido del proveedor de IA.');
                    }
                } catch (Throwable $e) {
                    $aiError = $e->getMessage();
                }

                if (stripos($aiError, 'curl_init') !== false || stripos($aiError, 'curl extension') !== false) {
                    $aiError = 'La extensión cURL de PHP no está disponible en el servidor; no se puede llamar a la IA.';
                }

                app_log($aiText !== null ? 'info' : 'error', 'cve_ai', $aiText !== null ? 'IA respondió' : 'IA falló', [
                    'id'    => $id,
                    'model' => $model,
                    'ms'    => (int)round((microtime(true) - $llmStarted) * 1000),
                    'chars' => $aiText !== null ? strlen($aiText) : 0,
                    'error' => $aiText !== null ? null : $aiError,
                ]);
            }

            $status = ($localOnly || $aiText !== null) ? 'done' : 'error';
            $durationMs = (int)round((microtime(true) - $started) * 1000);

            $saved = CveDatabase::update(
                "UPDATE cve_ai_reports
                 SET ai_text = ?, content_text = NULL, status = ?, ai_error = ?, ai_model = ?,
                     ai_duration_ms = ?, finished_at = datetime('now'), updated_at = datetime('now'), token = NULL
                 WHERE id = ? AND status = 'running'",
                [
                    $aiText,
                    $status,
                    $aiError !== '' ? substr($aiError, 0, 2000) : null,
                    $model !== '' ? $model : null,
                    $durationMs,
                    $id,
                ]
            );

            if ($saved === 0) {
                // El informe se canceló o se eliminó mientras la IA trabajaba.
                app_log('info', 'cve_ai', 'Resultado descartado (informe cancelado o eliminado)', ['id' => $id]);
                return [
                    'success' => false,
                    'id'      => $id,
                    'status'  => 'canceled',
                    'error'   => 'El informe se canceló durante la generación.',
                ];
            }

            // Modo resumen o solo datos: los CVEs no tienen análisis propio.
            if ($localOnly || $mode === 'summary') {
                CveDatabase::query(
                    "UPDATE cve_ai_report_items
                     SET status = 'skipped', ai_error = NULL,
                         finished_at = datetime('now'), updated_at = datetime('now')
                     WHERE report_id = ? AND status <> 'done'",
                    [$id]
                );
                CveDatabase::update(
                    "UPDATE cve_ai_reports SET processed_items = total_items WHERE id = ?",
                    [$id]
                );
            }

            app_log('info', 'cve_ai', 'Informe IA finalizado', [
                'id'     => $id,
                'status' => $status,
                'no_ai'  => $localOnly,
                'ms'     => $durationMs,
            ]);

            return [
                'success' => $status === 'done',
                'id'      => $id,
                'status'  => $status,
                'error'   => $aiError !== '' ? $aiError : null,
            ];
        } catch (Throwable $e) {
            $failed = CveDatabase::update(
                "UPDATE cve_ai_reports
                 SET status = 'error', ai_error = ?, finished_at = datetime('now'), token = NULL
                 WHERE id = ? AND status = 'running'",
                [substr($e->getMessage(), 0, 2000), $id]
            );
            app_log('error', 'cve_ai', 'Error generando el informe', ['id' => $id, 'error' => $e->getMessage()]);
            return [
                'success' => false,
                'id'      => $id,
                'status'  => $failed === 0 ? 'canceled' : 'error',
                'error'   => $failed === 0 ? 'El informe se canceló durante la generación.' : $e->getMessage(),
            ];
        }
    }

    /**
     * URL absoluta de la app (misma lógica que CveSync para proxies/CDN).
     */
    public static function baseUrl(): string
    {
        $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || (strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https');

        $base = rtrim(base_url(''), '/');
        if (preg_match('#^https?://#i', $base)) {
            if ($isHttps && str_starts_with(strtolower($base), 'http://')) {
                $base = 'https://' . substr($base, 7);
            }
            return $base;
        }

        $scheme = $isHttps ? 'https' : 'http';
        $host = (string)($_SERVER['HTTP_HOST'] ?? '');
        return $host !== '' ? $scheme . '://' . $host : '';
    }
}
