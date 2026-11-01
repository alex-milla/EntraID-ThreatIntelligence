<?php
/**
 * markdown.php — Pruebas del renderizado de Markdown de la IA (v0.3.5).
 *
 *   php tools/smoke/markdown.php
 *
 * Verifica el helper compartido render_ai_markdown(): formato, fences y
 * seguridad (HTML crudo y enlaces peligrosos escapados).
 */

declare(strict_types=1);

require dirname(__DIR__, 2) . '/public_html/config/bootstrap.php';

$fail = 0;
$total = 0;

function check(string $label, bool $ok, string $detail = ''): void
{
    global $fail, $total;
    $total++;
    if ($ok) {
        echo "OK   {$label}\n";
        return;
    }
    $fail++;
    echo "FALLO {$label}" . ($detail !== '' ? ' — ' . $detail : '') . "\n";
}

$render = static fn(string $md): string => render_ai_markdown($md);

check('Markdown: vacío devuelve vacío', $render('') === '');

$h3 = $render('### Análisis de Riesgo');
check('Markdown: título h3', str_contains($h3, '<h3') && str_contains($h3, 'Análisis de Riesgo'), $h3);

$bold = $render('**Vulnerabilidad:** RCE');
check('Markdown: negrita', str_contains($bold, '<strong>Vulnerabilidad:</strong>'), $bold);

$italic = $render('Esto es *cursiva*');
check('Markdown: cursiva', str_contains($italic, '<em>cursiva</em>'), $italic);

$inline = $render('Ejecuta `sudo systemctl status`');
check('Markdown: código inline', str_contains($inline, '<code>sudo systemctl status</code>'), $inline);

$ul = $render("- uno\n- dos");
check('Markdown: lista con viñetas', str_contains($ul, '<ul>') && substr_count($ul, '<li>') === 2, $ul);

$ol = $render("1. uno\n2. dos");
check('Markdown: lista numerada', str_contains($ol, '<ol>') && substr_count($ol, '<li>') === 2, $ol);

$hr = $render("texto\n\n---\n\nmás");
check('Markdown: separador', str_contains($hr, '<hr'), $hr);

$link = $render('[NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-1111)');
check('Markdown: enlace', str_contains($link, 'href="https://nvd.nist.gov/vuln/detail/CVE-2026-1111"'), $link);
check('Markdown: enlace abre en pestaña nueva', str_contains($link, 'target="_blank"') && str_contains($link, 'rel="noopener noreferrer"'), $link);

$code = $render("Ejemplo de comando:\n\n```bash\nls -la\n```");
check('Markdown: bloque de código', str_contains($code, '<pre><code class="language-bash">') && str_contains($code, 'ls -la'), $code);

$fenced = $render("```markdown\n### Plan\n- paso 1\n```");
check('Markdown: fence global se normaliza', !str_contains($fenced, 'language-markdown') && str_contains($fenced, '<h3'), $fenced);

$prose = $render("Introducción breve:\n\n```markdown\n### Informe\ncontenido\n```");
check('Markdown: fence markdown embebido se renderiza', !str_contains($prose, 'language-markdown') && str_contains($prose, '<h3'), $prose);

$table = $render("| CVE | Severidad |\n|---|---|\n| CVE-2026-1111 | Alta |");
check('Markdown: tabla', str_contains($table, '<table>') && str_contains($table, '<th>'), $table);

$xss = $render('<script>alert(1)</script>');
check('Seguridad: script escapado', !str_contains($xss, '<script') && str_contains($xss, 'alert(1)'), $xss);

$img = $render('<img src=x onerror=alert(1)>');
check('Seguridad: HTML crudo no se inyecta', !str_contains($img, '<img'), $img);

$js = $render('[pulsa](javascript:alert(1))');
check('Seguridad: enlace javascript neutralizado', !str_contains($js, 'href="javascript:'), $js);

$safeLink = $render('[ok](https://example.com/?a=1&b=2)');
check('Seguridad: query string conservada', str_contains($safeLink, 'https://example.com/?a=1&amp;b=2') || str_contains($safeLink, 'https://example.com/?a=1&b=2'), $safeLink);

echo PHP_EOL . ($fail === 0 ? 'RESULTADO: OK (' . $total . ' comprobaciones)' : "RESULTADO: {$fail} de {$total} fallidas") . PHP_EOL;
exit($fail === 0 ? 0 : 1);
