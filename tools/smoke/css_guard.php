<?php
/**
 * Guardia de CSS: comprueba que las clases usadas en las vistas nuevas están
 * en algún fichero CSS compilado del proyecto (tw.css, app.css, ui.css…).
 *
 * Motivo: Tailwind se compila con `tools/tailwind/build.ps1` escaneando
 * public_html de forma recursiva. Si se añade una vista sin recompilar, el
 * navegador recibe clases inexistentes y el layout se rompe (v0.4.28.8).
 */

if (!function_exists('smoke_css_missing_classes')) {
    /**
     * @param array<int,string> $files   rutas relativas a public_html
     * @param array<int,string> $extra   clases que se asignan desde JS/PHP
     * @return array<int,string> clases ausentes
     */
    function smoke_css_missing_classes(array $files, array $extra = []): array
    {
        $root = dirname(__DIR__, 2) . '/public_html';
        $css = '';
        foreach (['tw.css', 'app.css', 'ui.css', 'fonts.css', 'print.css'] as $file) {
            $css .= (string)@file_get_contents($root . '/assets/css/' . $file);
        }

        $tokens = [];
        foreach ($files as $file) {
            $src = (string)@file_get_contents($root . '/' . $file);
            if (!preg_match_all('/class\s*=\s*"([^"<]*)"/s', $src, $m)) {
                continue;
            }
            foreach ($m[1] as $raw) {
                foreach (preg_split('/\s+/', trim($raw)) ?: [] as $class) {
                    // u42-* e iocz-* son hooks de JS, no clases de estilo.
                    if (preg_match('/^(?:u42-|iocz-)/', $class)) {
                        continue;
                    }
                    if (preg_match('/^[a-z][a-zA-Z0-9:\-\[\]\/\.\%\(\)\_]*$/', $class)) {
                        $tokens[$class] = true;
                    }
                }
            }
        }
        foreach ($extra as $class) {
            $tokens[$class] = true;
        }

        $missing = [];
        foreach (array_keys($tokens) as $class) {
            $needle = addcslashes($class, ':/.[]()%');
            if (!str_contains($css, $needle)) {
                $missing[] = $class;
            }
        }
        sort($missing);
        return $missing;
    }
}
