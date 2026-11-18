<?php
/**
 * exposed_priority.php — Prioridad de remediación determinista (v0.4.26.2).
 *
 * Convierte los datos del export de Defender TVM en un **tier de remediación**
 * con su motivo y su ventana, siguiendo la práctica recomendada:
 *
 *   · CVSS es severidad técnica, no prioridad (FIRST CVSS v4.0).
 *   · La explotación confirmada (CISA KEV), las alertas activas y el EPSS
 *     (probabilidad a 30 días) pesan más que la severidad.
 *   · La exposición real del tenant (`Exposed Machines`) decide el alcance.
 *   · Los tiers se nombran como los resultados de CISA SSVC
 *     (Immediate / Out-of-cycle / Scheduled / Defer) y cada uno tiene una
 *     ventana distinta, como pide NIST SP 800-40 r4.
 *
 * Es puro: no consulta red ni base de datos. Los umbrales se pasan por opciones
 * (la aplicación los lee de `settings`).
 */

declare(strict_types=1);

if (!class_exists('ExposedPriority')) {
    final class ExposedPriority
    {
        public const TIERS = [
            'p1' => ['label' => 'P1 · Immediate',    'ssvc' => 'act',        'window' => '24-72 h'],
            'p2' => ['label' => 'P2 · Out-of-cycle', 'ssvc' => 'attend',     'window' => '7-15 días'],
            'p3' => ['label' => 'P3 · Scheduled',    'ssvc' => 'track_star', 'window' => 'ciclo mensual'],
            'p4' => ['label' => 'P4 · Defer',        'ssvc' => 'track',      'window' => 'backlog'],
        ];

        /** Umbrales por defecto (sobrescribibles desde settings). */
        public static function defaults(): array
        {
            return [
                'p1_machines' => 50,
                'p2_machines' => 10,
                'epss_p1'     => 0.5,
                'epss_p2'     => 0.1,
            ];
        }

        /**
         * Clasifica una fila de `exposed_cves` (o del grupo).
         *
         * @param array<string,mixed> $row
         * @param array<string,mixed> $options
         * @return array{tier:string,label:string,ssvc:string,window:string,reason:string,exception:bool}
         */
        public static function classify(array $row, array $options = []): array
        {
            $opts = array_merge(self::defaults(), $options);
            $p1Machines = max(1, (int)$opts['p1_machines']);
            $p2Machines = max(1, (int)$opts['p2_machines']);
            $epssP1 = (float)$opts['epss_p1'];
            $epssP2 = (float)$opts['epss_p2'];

            $machines = (int)($row['exposed_machines'] ?? 0);
            $epss = $row['epss'] !== null ? (float)$row['epss'] : null;
            $severity = strtolower((string)($row['severity'] ?? ''));
            $exploit = (int)($row['has_exploit'] ?? 0) === 1;
            $alerts = (int)($row['has_alerts'] ?? 0) === 1;
            $threats = (int)($row['has_known_threats'] ?? 0) === 1;
            $kev = (int)($row['is_kev'] ?? $row['kev'] ?? 0) === 1;
            $status = (string)($row['tvm_status'] ?? '');

            $tier = 'p4';
            $reason = 'sin exposición registrada o severidad baja';

            if ($kev) {
                $tier = 'p1';
                $reason = 'CISA KEV: explotación confirmada';
            } elseif ($alerts) {
                $tier = 'p1';
                $reason = 'alerta activa asociada en Defender';
            } elseif ($exploit && $machines >= $p1Machines) {
                $tier = 'p1';
                $reason = 'exploit disponible en ' . $machines . ' equipos';
            } elseif ($epss !== null && $epss >= $epssP1 && $machines > 0) {
                $tier = 'p1';
                $reason = 'EPSS ' . number_format($epss, 2) . ' con ' . $machines . ' equipos expuestos';
            } elseif ($exploit) {
                $tier = 'p2';
                $reason = 'exploit disponible';
            } elseif ($severity === 'critical' && $machines >= $p2Machines) {
                $tier = 'p2';
                $reason = 'crítica en ' . $machines . ' equipos';
            } elseif ($threats) {
                $tier = 'p2';
                $reason = 'amenazas conocidas asociadas';
            } elseif ($epss !== null && $epss >= $epssP2 && $machines > 0) {
                $tier = 'p2';
                $reason = 'EPSS ' . number_format($epss, 2) . ' con exposición';
            } elseif (in_array($severity, ['critical', 'high', 'medium'], true) && $machines > 0) {
                $tier = 'p3';
                $reason = self::severityLabel($severity) . ' en ' . $machines . ' equipos';
            } elseif ($machines > 0) {
                $tier = 'p3';
                $reason = 'severidad baja con ' . $machines . ' equipos';
            }

            $meta = self::TIERS[$tier];
            return [
                'tier'      => $tier,
                'label'     => $meta['label'],
                'ssvc'      => $meta['ssvc'],
                'window'    => $meta['window'],
                'reason'    => $reason,
                'exception' => in_array($status, ['UnderException', 'PartialException'], true),
            ];
        }

        /** Orden de trabajo: P1 primero. */
        public static function rank(string $tier): int
        {
            return match ($tier) {
                'p1' => 0,
                'p2' => 1,
                'p3' => 2,
                default => 3,
            };
        }

        /**
         * Trocea la descripción de Defender en sus bloques habituales y extrae
         * la versión de corrección si aparece (marcada como inferida).
         *
         * @return array{summary:string,impact:string,remediation:string,fix:string}
         */
        public static function describe(string $description): array
        {
            $text = trim(preg_replace('/\s+/u', ' ', $description) ?? $description);
            $text = trim(str_replace('Generated by AI', '', $text));

            $out = ['summary' => '', 'impact' => '', 'remediation' => '', 'fix' => ''];
            if ($text === '') {
                return $out;
            }

            $pattern = '/\b(Summary:|Impact:|Remediation:|AdditionalInformation:)/i';
            $parts = preg_split($pattern, $text, -1, PREG_SPLIT_DELIM_CAPTURE) ?: [];
            $current = 'summary';
            $buffer = ['summary' => '', 'impact' => '', 'remediation' => '', 'additional' => ''];
            foreach ($parts as $part) {
                $trimmed = trim($part);
                if ($trimmed === '') {
                    continue;
                }
                $lower = strtolower($trimmed);
                if ($lower === 'summary:') {
                    $current = 'summary';
                    continue;
                }
                if ($lower === 'impact:') {
                    $current = 'impact';
                    continue;
                }
                if ($lower === 'remediation:') {
                    $current = 'remediation';
                    continue;
                }
                if ($lower === 'additionalinformation:') {
                    $current = 'additional';
                    continue;
                }
                $buffer[$current] = trim($buffer[$current] . ' ' . $trimmed);
            }

            $out['summary'] = self::sentences($buffer['summary'] !== '' ? $buffer['summary'] : $text, 2);
            $out['impact'] = self::sentences($buffer['impact'], 2);
            $out['remediation'] = self::sentences($buffer['remediation'], 2);

            if (preg_match(
                '/(?:fixed in|upgrade to|update to|updated to|versions? prior to|prior to version'
                . '|actualizar a|actualiza a|actualizaci[oó]n a)\s+v?([0-9][0-9A-Za-z.\-]{2,})/iu',
                $text,
                $m
            ) === 1) {
                $out['fix'] = trim($m[1], '.-');
            }

            return $out;
        }

        /** Etiqueta castellana de severidad para los motivos. */
        private static function severityLabel(string $severity): string
        {
            return match ($severity) {
                'critical' => 'crítica',
                'high'     => 'alta',
                'medium'   => 'media',
                'low'      => 'baja',
                default    => 'informativa',
            };
        }

        /** Primeras N frases (sin cortar palabras a la mitad). */
        public static function sentences(string $text, int $max = 2): string
        {
            $text = trim($text);
            if ($text === '' || $max <= 0) {
                return '';
            }
            $parts = preg_split('/(?<=[.!?])\s+/', $text) ?: [];
            $picked = array_slice($parts, 0, $max);
            $out = trim(implode(' ', $picked));
            if (count($parts) > $max) {
                $out .= ' […]';
            }
            return $out;
        }
    }
}
