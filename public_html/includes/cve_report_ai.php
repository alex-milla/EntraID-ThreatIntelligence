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
     * @return string[] CVE-AAAA-NNNN únicos y en mayúsculas (máx. MAX_CVES).
     */
    public static function normalizeCveIds(mixed $raw): array
    {
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
            if (count($ids) >= self::MAX_CVES) {
                break;
            }
        }

        return array_keys($ids);
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

            $items[] = [
                'cve_id'          => (string)$row['cve_id'],
                'description'     => trim((string)($row['description'] ?? '')),
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
     * Compila los datos en texto plano y construye el prompt de 4 secciones.
     *
     * @param array<int,array<string,mixed>> $items
     */
    public static function userPrompt(array $items): string
    {
        $data = [];
        foreach ($items as $item) {
            $data[] = 'CVE: ' . $item['cve_id'];
            $data[] = 'Publicado: ' . ($item['published_at'] !== '' ? $item['published_at'] : 'Desconocido');
            $data[] = 'Puntuación CVSS: ' . ($item['cvss'] !== null
                ? number_format((float)$item['cvss'], 1, '.', '') . ' (' . self::severityLabel((string)$item['severity']) . ')'
                : 'Desconocida');
            $data[] = 'Vector: ' . ($item['vector'] !== '' ? $item['vector'] : 'Desconocido');
            $data[] = 'Descripción: ' . ($item['description'] !== '' ? truncate($item['description'], 1500) : 'Desconocida');
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
                $data[] = 'Acción requerida (CISA): ' . $item['kev_action'];
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
            . "- No incluyas URLs ni enlaces: las referencias se muestran aparte.\n"
            . "- Sin Markdown (nada de **, #, `), sin emojis, sin tablas.\n"
            . "- Español técnico y directo. Si un dato es desconocido, escribe una viñeta con \"Desconocido\".\n"
            . "- Si hay varios CVEs, prioriza los de mayor riesgo y no repitas lo mismo.\n\n"
            . "Contenido esperado:\n"
            . "1. Naturaleza, componente afectado, precondiciones, impacto CIA y señal KEV/EPSS/exploits.\n"
            . "2. Un escenario realista: entrada, autenticación, privilegios y consecuencia.\n"
            . "3. Acciones concretas: parche, mitigación temporal y detección.\n"
            . "4. Riesgo de negocio, probabilidad y urgencia (2-3 viñetas).\n\n"
            . "DATOS DE LOS CVEs:\n" . implode("\n", $data);
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

        $parts = preg_split('/(?=^\s*[1-4]\.\s+\S)/mu', $text) ?: [];
        $sections = [];

        foreach ($parts as $part) {
            $part = trim($part);
            if ($part === '') {
                continue;
            }

            $lines = preg_split('/\n/', $part) ?: [];
            $title = trim((string)array_shift($lines));
            $title = preg_replace('/^[1-4]\.\s*/u', '', $title) ?? $title;

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
        app_log('info', 'cve_ai', 'Informe IA iniciado', [
            'id'    => $id,
            'no_ai' => $noAi,
            'cves'  => (string)($row['cve_ids'] ?? ''),
        ]);

        try {
            $ids = safe_json_decode((string)($row['cve_ids'] ?? ''), []);
            if (!is_array($ids) || $ids === []) {
                throw new RuntimeException('La lista de CVEs del informe está vacía.');
            }

            $items = self::buildData($ids);
            if ($items === []) {
                throw new RuntimeException('Ninguno de los CVEs está en el catálogo local.');
            }

            $dataJson = json_encode($items, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
            CveDatabase::query(
                "UPDATE cve_ai_reports SET data_json = ? WHERE id = ?",
                [$dataJson !== false ? $dataJson : null, $id]
            );

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

            if ($localOnly) {
                $model = 'local';
            } else {
                $llmStarted = microtime(true);
                try {
                    if (!class_exists('Module_Llm')) {
                        throw new RuntimeException('El módulo de IA no está activo. Actívalo en Admin → Módulos.');
                    }
                    $llm = new Module_Llm();
                    $result = $llm->chat(
                        self::systemPrompt(),
                        self::userPrompt($items),
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

            CveDatabase::query(
                "UPDATE cve_ai_reports
                 SET ai_text = ?, content_text = NULL, status = ?, ai_error = ?, ai_model = ?,
                     ai_duration_ms = ?, finished_at = datetime('now'), token = NULL
                 WHERE id = ?",
                [
                    $aiText,
                    $status,
                    $aiError !== '' ? substr($aiError, 0, 2000) : null,
                    $model !== '' ? $model : null,
                    $durationMs,
                    $id,
                ]
            );

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
            CveDatabase::query(
                "UPDATE cve_ai_reports
                 SET status = 'error', ai_error = ?, finished_at = datetime('now'), token = NULL
                 WHERE id = ?",
                [substr($e->getMessage(), 0, 2000), $id]
            );
            app_log('error', 'cve_ai', 'Error generando el informe', ['id' => $id, 'error' => $e->getMessage()]);
            return ['success' => false, 'id' => $id, 'status' => 'error', 'error' => $e->getMessage()];
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
