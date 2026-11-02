<?php
/**
 * IncidentStoryParser — normaliza las cuatro entradas admitidas al modelo
 * interno `Caso` de la especificación (§5):
 *
 *  · texto_pegado       story copiado del portal ("Copiar historia")
 *  · story_json_portal  JSON interno story/timeline capturado con dev tools
 *  · graph_export       GET /security/incidents/{id}?$expand=alerts(...)
 *  · advanced_hunting   resultado de DeviceProcessEvents
 *
 * Todo el parsing es defensivo: los fallos son por-campo (nunca globales) y
 * lo no reconocido se conserva en `texto_crudo` o en `extra`. Los topes de
 * profundidad/nodos/eventos protegen de ficheros malformados.
 *
 * Uso:
 *   $out = IncidentStoryParser::parse($contenido, $formatoOpcional);
 *   $out['formato_entrada'] // sabor detectado
 *   $out['caso']            // modelo normalizado
 */

declare(strict_types=1);

final class IncidentStoryParser
{
    public const FORMATS = [
        'texto_pegado'      => 'Texto pegado',
        'story_json_portal' => 'Story JSON del portal',
        'graph_export'      => 'Export Microsoft Graph',
        'advanced_hunting'  => 'Advanced Hunting (DeviceProcessEvents)',
    ];

    private const RESERVED_PATH_SEGMENTS = [
        'users', 'windows', 'program', 'programs', 'programdata', 'appdata',
        'local', 'locallow', 'roaming', 'temp', 'tmp', 'system32', 'syswow64',
        'documents', 'desktop', 'downloads', 'public', 'default', 'all users',
        'perflogs', 'boot', 'recovery', 'system volume information',
    ];

    private static int $nodeCount = 0;

    /**
     * @return array{formato_entrada:string, caso:array}
     */
    public static function parse(string $content, ?string $format = null): array
    {
        $content = self::stripBom(trim($content));
        if ($content === '') {
            throw new InvalidArgumentException('No hay contenido que analizar.');
        }

        $looksJson = in_array($content[0], ['{', '['], true);

        if ($format === 'texto_pegado' || ($format === null && !$looksJson)) {
            return ['formato_entrada' => 'texto_pegado', 'caso' => self::parseText($content)];
        }

        $data = json_decode($content, true);
        if (!is_array($data)) {
            /* .jsonc guardado con comentarios o comas finales. */
            $cleaned = self::stripJsonComments($content);
            $data = json_decode($cleaned, true);
        }
        if (!is_array($data)) {
            $err = json_last_error_msg();
            if ($format === null) {
                /* Un pegado que empieza por llave pero no es JSON válido:
                   se trata como texto para no perder la evidencia. */
                return ['formato_entrada' => 'texto_pegado', 'caso' => self::parseText($content)];
            }
            throw new InvalidArgumentException('El JSON no es válido: ' . $err);
        }

        $format = $format ?? self::detectJsonFormat($data);
        if (!isset(self::FORMATS[$format])) {
            throw new InvalidArgumentException('Formato de entrada no soportado.');
        }

        $caso = match ($format) {
            'graph_export'     => self::parseGraph($data),
            'advanced_hunting' => self::parseAdvancedHunting($data),
            default            => self::parseStoryJson($data),
        };

        return ['formato_entrada' => $format, 'caso' => $caso];
    }

    public static function detectJsonFormat(array $data): string
    {
        $results = $data['Results'] ?? $data['results'] ?? null;
        if (is_array($results) && array_is_list($results)) {
            foreach (array_slice($results, 0, 3) as $row) {
                if (is_array($row) && self::looksLikeHuntingRow($row)) {
                    return 'advanced_hunting';
                }
            }
        }

        if (isset($data['alerts']) && is_array($data['alerts'])) {
            return 'graph_export';
        }
        if (isset($data['@odata.context']) && is_string($data['@odata.context'])
            && str_contains(strtolower($data['@odata.context']), 'security')) {
            return 'graph_export';
        }
        if (array_is_list($data) && isset($data[0]) && is_array($data[0])) {
            if (isset($data[0]['alerts'])) {
                return 'graph_export';
            }
            if (self::looksLikeHuntingRow($data[0])) {
                return 'advanced_hunting';
            }
        }

        return 'story_json_portal';
    }

    /* =====================================================================
     * Texto pegado (§3.1 / §6.1)
     * ================================================================== */

    public static function parseText(string $text): array
    {
        $text = str_replace(["\r\n", "\r"], "\n", $text);
        $lines = explode("\n", $text);

        $blocks = [];
        $current = null;
        $headerRe = '/^\s*(\d{1,2}\/\d{1,2}\/\d{4})\s+(\d{1,2}:\d{2}:\d{2})\s*([AP]M)?\s*$/i';

        foreach ($lines as $line) {
            if (preg_match($headerRe, $line, $m)) {
                if ($current !== null) {
                    $blocks[] = $current;
                }
                $current = [
                    'timestamp' => self::parseUsDate($m[1] . ' ' . $m[2] . ' ' . ($m[3] ?? '')),
                    'lines'     => [],
                ];
                continue;
            }
            if ($current === null) {
                if (trim($line) === '') {
                    continue;
                }
                $current = ['timestamp' => null, 'lines' => []];
            }
            $current['lines'][] = $line;
        }
        if ($current !== null) {
            $blocks[] = $current;
        }

        $eventos = [];
        $alertas = [];
        $orden = 0;

        foreach ($blocks as $block) {
            $ev = self::blankEvent($orden++);
            $ev['timestamp'] = $block['timestamp'];
            $raw = [];
            $lastField = null;

            foreach ($block['lines'] as $line) {
                $trimmed = trim($line);
                if ($trimmed === '') {
                    continue;
                }

                if (preg_match('/^\[(\d+)\]\s+(\S+)(?:\s+(.*))?$/', $trimmed, $m)) {
                    $ev['pid'] = (int)$m[1];
                    $ev['proceso'] = self::baseName($m[2]);
                    $args = trim((string)($m[3] ?? ''));
                    if ($args !== '') {
                        $ev['command_line'] = trim($m[2] . ' ' . $args);
                    }
                    $lastField = 'command_line';
                    continue;
                }

                if (preg_match('/^Command line\s+(.*)$/i', $trimmed, $m)) {
                    $ev['command_line'] = trim($m[1]);
                    $lastField = 'command_line';
                    continue;
                }

                if (preg_match('/^Process id\s+(\d+)\s*$/i', $trimmed, $m)) {
                    $ev['pid'] = (int)$m[1];
                    $lastField = null;
                    continue;
                }

                if (preg_match('/^Parent process id\s+(\d+)\s*$/i', $trimmed, $m)) {
                    $ev['pid_padre'] = (int)$m[1];
                    $lastField = null;
                    continue;
                }

                if (preg_match('/^Execution details\s+(.*)$/i', $trimmed, $m)) {
                    if (preg_match('/Token elevation:\s*([^,]+)/i', $m[1], $em)) {
                        $ev['elevacion_token'] = trim($em[1]);
                    }
                    if (preg_match('/Integrity level:\s*([^,]+)/i', $m[1], $im)) {
                        $ev['integridad'] = trim($im[1]);
                    }
                    $lastField = null;
                    continue;
                }

                if (preg_match('/^Image file path\s+(.*)$/i', $trimmed, $m)) {
                    $ev['image_path'] = trim($m[1]);
                    $lastField = null;
                    continue;
                }

                if (preg_match('/^Image file SHA1\s+([a-f0-9]{40})/i', $trimmed, $m)) {
                    $ev['sha1'] = strtolower($m[1]);
                    $lastField = null;
                    continue;
                }

                if (preg_match('/^Image file SHA256\s+([a-f0-9]{64})/i', $trimmed, $m)) {
                    $ev['sha256'] = strtolower($m[1]);
                    $lastField = null;
                    continue;
                }

                if (preg_match('/^Image file (creation|last modification) time\s+(.*)$/i', $trimmed, $m)) {
                    $raw[] = $trimmed;
                    $lastField = null;
                    continue;
                }

                if (preg_match('/^PE metadata\s+(.*)$/i', $trimmed, $m)) {
                    $raw[] = $trimmed;
                    $lastField = null;
                    continue;
                }

                if (preg_match('/^User\s+(.+)$/i', $trimmed, $m)) {
                    $ev['usuario'] = trim($m[1]);
                    $lastField = null;
                    continue;
                }

                if (preg_match('/^Content SHA256\s+([a-f0-9]{64})/i', $trimmed, $m)) {
                    $ev['script_sha256'] = strtolower($m[1]);
                    $lastField = null;
                    continue;
                }

                if (preg_match('/^Content\s*(.*)$/i', $trimmed, $m)) {
                    $ev['script_content'] = trim($m[1]);
                    $lastField = 'script_content';
                    continue;
                }

                if (preg_match('/executed a script/i', $trimmed)) {
                    $raw[] = $trimmed;
                    $lastField = 'script_content';
                    continue;
                }

                if (preg_match('/^(.+?)\s+(New\s+)?Detected\s+(Informational|Low|Medium|High|Critical)\s*$/i', $trimmed, $m)) {
                    $name = trim($m[1]);
                    $sev = ucfirst(strtolower($m[3]));
                    $ev['alerta'] = $name . ' (' . $sev . ')';
                    $alertas[$name . '|' . $sev] = [
                        'id_alerta'       => null,
                        'nombre'          => $name,
                        'severidad'       => $sev,
                        'fuente_deteccion'=> null,
                        'eventos'         => [],
                    ];
                    $lastField = null;
                    continue;
                }

                /* Continuación de un campo multilínea (script o command line). */
                if ($lastField === 'script_content') {
                    $ev['script_content'] = trim((string)$ev['script_content'] . "\n" . $trimmed);
                    continue;
                }
                if ($lastField === 'command_line') {
                    $ev['command_line'] = trim((string)$ev['command_line'] . ' ' . $trimmed);
                    continue;
                }

                $raw[] = $trimmed;
            }

            $ev['texto_crudo'] = trim(implode("\n", $block['lines']));
            if ($raw !== []) {
                $ev['texto_crudo'] = trim($ev['texto_crudo'] . "\n" . implode("\n", $raw));
            }
            $eventos[] = $ev;
        }

        $primerAlerta = $alertas !== [] ? array_values($alertas)[0] : null;

        return self::finalize([
            'formato_entrada' => 'texto_pegado',
            'incidencia'      => [
                'id_defender'          => null,
                'nombre'               => $primerAlerta !== null ? (string)$primerAlerta['nombre'] : 'Story pegado',
                'severidad'            => self::maxSeverity(array_column($alertas, 'severidad')),
                'estado'               => null,
                'clasificacion_actual' => null,
                'tecnicas_mitre'       => [],
                'alertas'              => array_values($alertas),
            ],
            'extra' => [],
        ], $eventos);
    }

    /* =====================================================================
     * Story JSON del portal (§3.2 / §6.2)
     * ================================================================== */

    public static function parseStoryJson(array $data): array
    {
        self::$nodeCount = 0;
        $eventos = [];

        $walk = function ($node, ?int $parentPid, int $depth) use (&$walk, &$eventos): void {
            if (!is_array($node) || $depth > (defined('INCIDENT_STORY_MAX_DEPTH') ? INCIDENT_STORY_MAX_DEPTH : 200)) {
                return;
            }
            if (++self::$nodeCount > (defined('INCIDENT_STORY_MAX_NODES') ? INCIDENT_STORY_MAX_NODES : 20000)) {
                return;
            }

            if (!array_is_list($node)) {
                $ev = self::eventFromStoryNode($node, $parentPid);
                if ($ev !== null) {
                    $ev['orden'] = count($eventos) + 1;
                    $eventos[] = $ev;
                    if ($ev['pid'] !== null) {
                        $parentPid = $ev['pid'];
                    }
                }
            }

            foreach ($node as $child) {
                if (is_array($child)) {
                    $walk($child, $parentPid, $depth + 1);
                }
            }
        };

        $walk($data, null, 0);

        return self::finalize([
            'formato_entrada' => 'story_json_portal',
            'incidencia'      => [
                'id_defender'          => null,
                'nombre'               => 'Story JSON del portal',
                'severidad'            => self::maxSeverity(array_column($eventos, 'severidad_evento')),
                'estado'               => null,
                'clasificacion_actual' => null,
                'tecnicas_mitre'       => [],
                'alertas'              => [],
            ],
            'extra' => [],
        ], $eventos);
    }

    private static function eventFromStoryNode(array $node, ?int $parentPid): ?array
    {
        $flat = [];
        foreach ($node as $key => $value) {
            if (is_scalar($value)) {
                $flat[self::normKey((string)$key)] = $value;
            }
        }

        $pid   = self::intOrNull(self::first($flat, ['processid', 'pid', 'processidentifier']));
        $cmd   = self::first($flat, ['processcommandline', 'commandline', 'cmdline', 'command']);
        $image = self::first($flat, ['imagefilepath', 'imagefilename', 'processpath', 'filepath']);
        $name  = self::first($flat, ['processname', 'processfilename', 'filename', 'imagefilename', 'imagename']);
        $ts    = self::first($flat, ['timestamp', 'eventtime', 'processcreationtime', 'createdtime',
                                     'creationtime', 'detectiontime', 'lasteventtime', 'lastseen', 'firstseen']);
        $ppid  = self::intOrNull(self::first($flat, ['parentprocessid', 'initiatingprocessid', 'ppid']));
        $user  = self::first($flat, ['accountname', 'username', 'user', 'username', 'upn', 'accountupn']);
        $domain= self::first($flat, ['accountdomain', 'domainname', 'domain', 'netbiosdomain']);
        $host  = self::first($flat, ['devicename', 'deviceDnsName', 'computerdnsname', 'machinename', 'hostname', 'host']);
        $sha1  = self::first($flat, ['sha1', 'filesha1', 'imagefilesha1']);
        $sha256= self::first($flat, ['sha256', 'filesha256', 'imagefilesha256']);
        $script= self::first($flat, ['scriptcontent', 'scriptblocktext', 'scripttext', 'powershellscript']);
        $scriptHash = self::first($flat, ['scriptsha256', 'contentsha256']);
        $elev  = self::first($flat, ['tokenelevation', 'elevationtoken']);
        $integ = self::first($flat, ['integritylevel']);

        if ($pid === null && $cmd === null && $name === null && $image === null) {
            return null;
        }

        $ev = self::blankEvent(0);
        $ev['timestamp'] = self::normalizeTimestamp($ts);
        $ev['pid'] = $pid;
        $ev['pid_padre'] = $ppid ?? $parentPid;
        $ev['proceso'] = $name !== null ? self::baseName((string)$name) : self::processFromCommand((string)($cmd ?? ''));
        $ev['command_line'] = $cmd !== null ? trim((string)$cmd) : null;
        $ev['image_path'] = $image !== null ? trim((string)$image) : null;
        $ev['sha1'] = is_string($sha1) && preg_match('/^[a-f0-9]{40}$/i', $sha1) ? strtolower($sha1) : null;
        $ev['sha256'] = is_string($sha256) && preg_match('/^[a-f0-9]{64}$/i', $sha256) ? strtolower($sha256) : null;
        $ev['usuario'] = self::userString($domain, $user);
        $ev['equipo'] = $host !== null ? trim((string)$host) : null;
        $ev['elevacion_token'] = $elev !== null ? trim((string)$elev) : null;
        $ev['integridad'] = $integ !== null ? trim((string)$integ) : null;
        $ev['script_content'] = $script !== null ? (string)$script : null;
        $ev['script_sha256'] = is_string($scriptHash) && preg_match('/^[a-f0-9]{64}$/i', $scriptHash) ? strtolower($scriptHash) : null;
        $ev['texto_crudo'] = null;
        $ev['relacion'] = $ev['pid_padre'] !== null ? 'hijo_de' : 'evento_aislado';

        return $ev;
    }

    /* =====================================================================
     * Export Microsoft Graph (§3.3 / §6.3)
     * ================================================================== */

    public static function parseGraph(array $data): array
    {
        if (array_is_list($data)) {
            $data = is_array($data[0] ?? null) ? $data[0] : [];
        }

        $incident = $data;
        $alertsRaw = is_array($incident['alerts'] ?? null) ? $incident['alerts'] : [];
        if ($alertsRaw === [] && isset($incident['value']) && is_array($incident['value'])) {
            $alertsRaw = $incident['value'];
        }

        $eventos = [];
        $alertas = [];
        $extraEvidence = [];

        foreach ($alertsRaw as $alert) {
            if (!is_array($alert)) {
                continue;
            }
            $alertId = self::scalar($alert['id'] ?? $alert['alertId'] ?? null);
            $alertName = self::scalar($alert['title'] ?? $alert['displayName'] ?? $alert['alertDisplayName'] ?? null);
            $alertSev = self::scalar($alert['severity'] ?? null);
            $alertSource = self::scalar($alert['serviceSource'] ?? $alert['detectionSource'] ?? null);

            $evidences = [];
            if (is_array($alert['evidence'] ?? null)) {
                $evidences = $alert['evidence'];
            }
            if (is_array($alert['evidence'] ?? null) && isset($alert['evidence']['evidence'])) {
                $evidences = $alert['evidence']['evidence'];
            }

            foreach ($evidences as $evidence) {
                if (!is_array($evidence)) {
                    continue;
                }
                $type = strtolower((string)($evidence['@odata.type'] ?? $evidence['kind'] ?? $evidence['evidenceType'] ?? ''));
                $type = trim(str_replace('#microsoft.graph.security.', '', $type));

                if (str_contains($type, 'process') || isset($evidence['processCommandLine'])) {
                    $ev = self::eventFromGraphEvidence($evidence);
                    if ($ev !== null) {
                        $ev['orden'] = count($eventos) + 1;
                        $eventos[] = $ev;
                        continue;
                    }
                }

                $compact = self::compactGraphEvidence($evidence, $type);
                if ($compact !== [] && count($extraEvidence) < 300) {
                    $extraEvidence[] = $compact;
                }
            }

            if ($alertName !== null) {
                $alertas[$alertName . '|' . (string)$alertSev] = [
                    'id_alerta'        => $alertId,
                    'nombre'           => $alertName,
                    'severidad'        => $alertSev,
                    'fuente_deteccion' => $alertSource,
                    'eventos'          => [],
                ];
            }
        }

        /* Evidencias a nivel de incidencia (algunos exports las traen así). */
        if (is_array($incident['evidence'] ?? null)) {
            foreach ($incident['evidence'] as $evidence) {
                if (!is_array($evidence)) {
                    continue;
                }
                $type = strtolower((string)($evidence['@odata.type'] ?? $evidence['kind'] ?? ''));
                $type = trim(str_replace('#microsoft.graph.security.', '', $type));
                if (str_contains($type, 'process') || isset($evidence['processCommandLine'])) {
                    $ev = self::eventFromGraphEvidence($evidence);
                    if ($ev !== null) {
                        $ev['orden'] = count($eventos) + 1;
                        $eventos[] = $ev;
                    }
                }
            }
        }

        $mitre = $incident['mitreTechniques'] ?? null;
        if (!is_array($mitre)) {
            $mitre = [];
            foreach ($alertsRaw as $alert) {
                if (is_array($alert) && is_array($alert['mitreTechniques'] ?? null)) {
                    $mitre = array_merge($mitre, $alert['mitreTechniques']);
                }
            }
        }

        return self::finalize([
            'formato_entrada' => 'graph_export',
            'incidencia'      => [
                'id_defender'          => self::scalar($incident['incidentId'] ?? $incident['id'] ?? null),
                'nombre'               => self::scalar($incident['displayName'] ?? $incident['title'] ?? null),
                'severidad'            => self::scalar($incident['severity'] ?? null),
                'estado'               => self::scalar($incident['status'] ?? null),
                'clasificacion_actual' => self::scalar($incident['classification'] ?? null),
                'tecnicas_mitre'       => array_values(array_unique(array_map(
                    'strval',
                    array_filter($mitre, static fn($v) => is_scalar($v))
                ))),
                'alertas'              => array_values($alertas),
            ],
            'extra' => $extraEvidence !== [] ? ['evidencias_graph' => $extraEvidence] : [],
        ], $eventos);
    }

    private static function eventFromGraphEvidence(array $evidence): ?array
    {
        $file = is_array($evidence['fileDetails'] ?? null) ? $evidence['fileDetails'] : [];
        $image = is_array($evidence['imageFile'] ?? null) ? $evidence['imageFile'] : [];
        $parent = is_array($evidence['parentProcess'] ?? null) ? $evidence['parentProcess'] : [];
        $account = is_array($evidence['userAccount'] ?? null) ? $evidence['userAccount'] : [];
        $machine = is_array($evidence['machine'] ?? null) ? $evidence['machine'] : [];

        $cmd = self::scalar($evidence['processCommandLine'] ?? $evidence['commandLine'] ?? null);
        $fileName = self::scalar($file['fileName'] ?? $image['fileName'] ?? $evidence['fileName'] ?? null);
        $filePath = self::scalar($file['filePath'] ?? $image['filePath'] ?? $evidence['filePath'] ?? null);
        $pid = self::intOrNull($evidence['processId'] ?? $evidence['processID'] ?? null);
        $ppid = self::intOrNull($parent['processId'] ?? $evidence['parentProcessId'] ?? null);

        if ($cmd === null && $fileName === null && $pid === null) {
            return null;
        }

        $ev = self::blankEvent(0);
        $ev['timestamp'] = self::normalizeTimestamp(
            $evidence['processCreationTime'] ?? $evidence['createdDateTime'] ?? null
        );
        $ev['pid'] = $pid;
        $ev['pid_padre'] = $ppid;
        $ev['proceso'] = $fileName !== null ? self::baseName($fileName) : self::processFromCommand((string)$cmd);
        $ev['command_line'] = $cmd;
        $ev['image_path'] = $filePath;
        $ev['sha1'] = self::hashOrNull($file['sha1'] ?? $image['sha1'] ?? null, 40);
        $ev['sha256'] = self::hashOrNull($file['sha256'] ?? $image['sha256'] ?? null, 64);
        $ev['usuario'] = self::userString(
            self::scalar($account['domainName'] ?? $account['accountDomain'] ?? null),
            self::scalar($account['accountName'] ?? $account['userPrincipalName'] ?? null)
        );
        $ev['equipo'] = self::scalar($machine['deviceDnsName'] ?? $evidence['deviceDnsName'] ?? null);
        $ev['elevacion_token'] = null;
        $ev['integridad'] = self::scalar($evidence['integrityLevel'] ?? $evidence['processIntegrityLevel'] ?? null);
        $ev['script_content'] = null;
        $ev['script_sha256'] = null;
        $ev['texto_crudo'] = null;
        $ev['relacion'] = $ppid !== null ? 'hijo_de' : 'evento_aislado';

        return $ev;
    }

    private static function compactGraphEvidence(array $evidence, string $type): array
    {
        $out = ['tipo' => $type !== '' ? $type : 'evidence'];
        $map = [
            'ipAddress'        => 'ip',
            'url'              => 'url',
            'deviceDnsName'    => 'equipo',
            'accountName'      => 'cuenta',
            'registryKey'      => 'clave_registro',
            'registryValueName'=> 'valor_registro',
            'fileName'         => 'fichero',
            'filePath'         => 'ruta',
        ];
        foreach ($map as $key => $label) {
            if (isset($evidence[$key]) && is_scalar($evidence[$key])) {
                $out[$label] = (string)$evidence[$key];
            }
        }
        if (isset($evidence['userAccount']) && is_array($evidence['userAccount'])) {
            $name = self::userString(
                self::scalar($evidence['userAccount']['domainName'] ?? null),
                self::scalar($evidence['userAccount']['accountName'] ?? null)
            );
            if ($name !== null) {
                $out['cuenta'] = $name;
            }
        }
        if (isset($evidence['fileDetails']) && is_array($evidence['fileDetails'])) {
            $out['fichero'] = self::scalar($evidence['fileDetails']['fileName'] ?? null) ?? $out['fichero'] ?? null;
            $out['ruta'] = self::scalar($evidence['fileDetails']['filePath'] ?? null) ?? $out['ruta'] ?? null;
        }
        return array_filter($out, static fn($v) => $v !== null && $v !== '');
    }

    /* =====================================================================
     * Advanced Hunting — DeviceProcessEvents (§3.3 / §6.3)
     * ================================================================== */

    public static function parseAdvancedHunting(array $data): array
    {
        $rows = $data['Results'] ?? $data['results'] ?? (array_is_list($data) ? $data : []);

        $eventos = [];
        foreach ($rows as $row) {
            if (!is_array($row)) {
                continue;
            }
            $flat = [];
            foreach ($row as $key => $value) {
                if (is_scalar($value)) {
                    $flat[self::normKey((string)$key)] = $value;
                }
            }

            $cmd = self::first($flat, ['processcommandline']);
            $fileName = self::first($flat, ['filename', 'processfilename']);
            if ($cmd === null && $fileName === null) {
                continue;
            }

            $ev = self::blankEvent(count($eventos) + 1);
            $ev['timestamp'] = self::normalizeTimestamp(self::first($flat, ['timestamp', 'eventtime']));
            $ev['pid'] = self::intOrNull(self::first($flat, ['processid']));
            $ev['pid_padre'] = self::intOrNull(self::first($flat, ['initiatingprocessid', 'parentprocessid']));
            $ev['proceso'] = $fileName !== null
                ? self::baseName((string)$fileName)
                : self::processFromCommand((string)$cmd);
            $ev['command_line'] = $cmd !== null ? trim((string)$cmd) : null;

            $folder = self::first($flat, ['folderpath']);
            $ev['image_path'] = ($folder !== null && $fileName !== null)
                ? rtrim((string)$folder, '\\/') . '\\' . (string)$fileName
                : self::first($flat, ['filepath']);
            $ev['sha1'] = self::hashOrNull(self::first($flat, ['sha1']), 40);
            $ev['sha256'] = self::hashOrNull(self::first($flat, ['sha256']), 64);
            $ev['usuario'] = self::userString(
                self::scalar(self::first($flat, ['accountdomain', 'accountdomainname'])),
                self::scalar(self::first($flat, ['accountname', 'accountupn']))
            );
            $ev['equipo'] = self::scalar(self::first($flat, ['devicename']));
            $ev['elevacion_token'] = self::scalar(self::first($flat, ['tokenelevation', 'processelevationtype']));
            $ev['integridad'] = self::scalar(self::first($flat, ['processintegritylevel']));
            $ev['script_content'] = null;
            $ev['script_sha256'] = null;
            $ev['texto_crudo'] = null;
            $ev['relacion'] = $ev['pid_padre'] !== null ? 'hijo_de' : 'evento_aislado';

            $eventos[] = $ev;
        }

        return self::finalize([
            'formato_entrada' => 'advanced_hunting',
            'incidencia'      => [
                'id_defender'          => null,
                'nombre'               => 'DeviceProcessEvents',
                'severidad'            => null,
                'estado'               => null,
                'clasificacion_actual' => null,
                'tecnicas_mitre'       => [],
                'alertas'              => [],
            ],
            'extra' => [],
        ], $eventos);
    }

    private static function looksLikeHuntingRow(array $row): bool
    {
        $norm = array_map(static fn($k) => self::normKey((string)$k), array_keys($row));
        return in_array('initiatingprocessid', $norm, true)
            || in_array('processcommandline', $norm, true)
            || (in_array('devicename', $norm, true) && in_array('timestamp', $norm, true));
    }

    /* =====================================================================
     * Finalización y utilidades
     * ================================================================== */

    private static function finalize(array $caso, array $eventos): array
    {
        /* Orden estable por timestamp cuando exista; los nulos al final. */
        foreach ($eventos as $i => &$ev) {
            $ev['_i'] = $i;
        }
        unset($ev);
        usort($eventos, static function (array $a, array $b): int {
            $ta = $a['timestamp'] ?? null;
            $tb = $b['timestamp'] ?? null;
            if ($ta === null && $tb === null) {
                return ($a['_i'] ?? 0) <=> ($b['_i'] ?? 0);
            }
            if ($ta === null) {
                return 1;
            }
            if ($tb === null) {
                return -1;
            }
            return [$ta, $a['_i'] ?? 0] <=> [$tb, $b['_i'] ?? 0];
        });
        $eventos = array_slice($eventos, 0, defined('INCIDENT_STORY_MAX_EVENTS') ? INCIDENT_STORY_MAX_EVENTS : 5000);
        foreach ($eventos as $i => &$ev) {
            unset($ev['_i']);
            $ev['orden'] = $i + 1;
        }
        unset($ev);

        $usuarios = [];
        $equipos = [];
        $dominios = [];
        foreach ($eventos as $ev) {
            if (!empty($ev['usuario'])) {
                $usuarios[self::normKey((string)$ev['usuario'])] = (string)$ev['usuario'];
                $parts = explode('\\', (string)$ev['usuario'], 2);
                if (count($parts) === 2 && $parts[0] !== '') {
                    $dominios[self::normKey($parts[0])] = $parts[0];
                }
            }
            if (!empty($ev['equipo'])) {
                $equipos[self::normKey((string)$ev['equipo'])] = (string)$ev['equipo'];
            }
            if (!empty($ev['image_path']) && preg_match('/^\\\\\\\\([^\\\\]+)/', (string)$ev['image_path'], $m)) {
                $equipos[self::normKey($m[1])] = $m[1];
            }
        }

        $incidencia = $caso['incidencia'];
        if (empty($incidencia['alertas'])) {
            $incidencia['alertas'] = [];
        }

        $caso['incidencia'] = $incidencia;
        $caso['eventos'] = $eventos;
        $caso['usuarios'] = array_values($usuarios);
        $caso['equipos'] = array_values($equipos);
        $caso['dominios'] = array_values($dominios);
        $caso['extra'] = is_array($caso['extra'] ?? null) ? $caso['extra'] : [];

        return $caso;
    }

    private static function blankEvent(int $orden): array
    {
        return [
            'orden'           => $orden,
            'timestamp'      => null,
            'pid'            => null,
            'pid_padre'      => null,
            'proceso'        => null,
            'command_line'   => null,
            'image_path'     => null,
            'sha1'           => null,
            'sha256'         => null,
            'usuario'        => null,
            'equipo'         => null,
            'elevacion_token'=> null,
            'integridad'     => null,
            'script_content' => null,
            'script_sha256'  => null,
            'texto_crudo'    => null,
            'relacion'       => 'evento_aislado',
            'alerta'         => null,
            'severidad_evento'=> null,
        ];
    }

    /** Normaliza una fecha del story a ISO 8601 (UTC asumido). */
    public static function normalizeTimestamp(mixed $value): ?string
    {
        if ($value === null || $value === '') {
            return null;
        }
        if (is_int($value) || is_float($value) || (is_string($value) && ctype_digit($value))) {
            $n = (int)$value;
            if ($n > 100000000000) {
                $n = (int)floor($n / 1000);
            }
            if ($n > 0) {
                return gmdate('Y-m-d\TH:i:s', $n);
            }
        }
        if (!is_string($value)) {
            return null;
        }
        $value = trim($value);
        if ($value === '') {
            return null;
        }
        if (preg_match('/\/Date\((-?\d+)([+-]\d{4})?\)\//', $value, $m)) {
            $n = (int)floor((int)$m[1] / 1000);
            return gmdate('Y-m-d\TH:i:s', $n);
        }
        $parsed = self::parseUsDate($value);
        if ($parsed !== null) {
            return $parsed;
        }
        $ts = strtotime($value);
        if ($ts === false) {
            return null;
        }
        return gmdate('Y-m-d\TH:i:s', $ts);
    }

    private static function parseUsDate(string $value): ?string
    {
        $value = trim($value);
        $formats = ['m/d/Y g:i:s A', 'm/d/Y G:i:s', 'm/d/Y g:i:s', 'm/d/Y H:i:s', 'n/j/y g:i:s A', 'n/j/Y g:i:s A'];
        foreach ($formats as $fmt) {
            $dt = DateTimeImmutable::createFromFormat($fmt, $value);
            if ($dt instanceof DateTimeImmutable) {
                $errors = DateTimeImmutable::getLastErrors();
                if ($errors === false || ((int)$errors['warning_count'] === 0 && (int)$errors['error_count'] === 0)) {
                    return $dt->format('Y-m-d\TH:i:s');
                }
            }
        }
        return null;
    }

    private static function maxSeverity(array $severities): ?string
    {
        $rank = ['informational' => 1, 'low' => 2, 'medium' => 3, 'high' => 4, 'critical' => 5];
        $best = null;
        $bestRank = 0;
        foreach ($severities as $sev) {
            if (!is_string($sev) || $sev === '') {
                continue;
            }
            $r = $rank[strtolower($sev)] ?? 0;
            if ($r > $bestRank) {
                $bestRank = $r;
                $best = $sev;
            }
        }
        return $best;
    }

    private static function first(array $flat, array $keys): mixed
    {
        foreach ($keys as $key) {
            $k = self::normKey($key);
            if (array_key_exists($k, $flat) && $flat[$k] !== '' && $flat[$k] !== null) {
                return $flat[$k];
            }
        }
        return null;
    }

    private static function normKey(string $key): string
    {
        return strtolower(preg_replace('/[^a-z0-9]/i', '', $key) ?? $key);
    }

    private static function baseName(string $path): ?string
    {
        $path = trim($path);
        if ($path === '') {
            return null;
        }
        $base = preg_replace('/^.*[\\\\\/]/', '', $path);
        return $base !== '' ? (string)$base : null;
    }

    private static function processFromCommand(string $cmd): ?string
    {
        $cmd = trim($cmd);
        if ($cmd === '') {
            return null;
        }
        if (preg_match('/^"([^"]+)"/', $cmd, $m)) {
            return self::baseName($m[1]);
        }
        $token = preg_split('/\s+/', $cmd)[0] ?? '';
        return $token !== '' ? self::baseName($token) : null;
    }

    private static function userString(?string $domain, mixed $user): ?string
    {
        $user = self::scalar($user);
        if ($user === null) {
            return null;
        }
        $user = trim($user);
        if ($user === '') {
            return null;
        }
        if (str_contains($user, '\\') || str_contains($user, '@')) {
            return $user;
        }
        $domain = self::scalar($domain);
        return $domain !== null && trim($domain) !== '' ? trim($domain) . '\\' . $user : $user;
    }

    private static function scalar(mixed $value): ?string
    {
        if ($value === null || is_array($value) || is_object($value)) {
            return null;
        }
        $s = trim((string)$value);
        return $s === '' ? null : $s;
    }

    private static function intOrNull(mixed $value): ?int
    {
        if (is_int($value)) {
            return $value;
        }
        if (is_string($value) && preg_match('/^\d+$/', trim($value))) {
            return (int)$value;
        }
        if (is_float($value)) {
            return (int)$value;
        }
        return null;
    }

    private static function hashOrNull(mixed $value, int $len): ?string
    {
        if (!is_string($value)) {
            return null;
        }
        $value = strtolower(trim($value));
        return preg_match('/^[a-f0-9]{' . $len . '}$/', $value) ? $value : null;
    }

    private static function stripBom(string $s): string
    {
        return str_starts_with($s, "\xEF\xBB\xBF") ? substr($s, 3) : $s;
    }

    /** Quita comentarios // y /* *\/ y comas finales de un .jsonc. */
    private static function stripJsonComments(string $s): string
    {
        $out = '';
        $len = strlen($s);
        $inString = false;
        $escape = false;
        for ($i = 0; $i < $len; $i++) {
            $ch = $s[$i];
            if ($inString) {
                $out .= $ch;
                if ($escape) {
                    $escape = false;
                } elseif ($ch === '\\') {
                    $escape = true;
                } elseif ($ch === '"') {
                    $inString = false;
                }
                continue;
            }
            if ($ch === '"') {
                $inString = true;
                $out .= $ch;
                continue;
            }
            if ($ch === '/' && ($s[$i + 1] ?? '') === '/') {
                while ($i < $len && $s[$i] !== "\n") {
                    $i++;
                }
                $out .= "\n";
                continue;
            }
            if ($ch === '/' && ($s[$i + 1] ?? '') === '*') {
                $i += 2;
                while ($i < $len - 1 && !($s[$i] === '*' && $s[$i + 1] === '/')) {
                    $i++;
                }
                $i++;
                continue;
            }
            $out .= $ch;
        }
        return preg_replace('/,\s*([}\]])/', '$1', $out) ?? $out;
    }
}
