<?php
/**
 * Smoke test — módulo Incidentes Story (incident_story).
 *
 * Sin red y sin tocar las bases reales: usa una BD temporal para el store.
 * Uso: php tools/smoke/incident_story.php
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
    echo "FALLA {$label}" . ($detail !== '' ? "\n     {$detail}" : '') . "\n";
}

/* =====================================================================
 * 1. Registro del módulo y navegación
 * ================================================================== */

$module = ModuleManager::get('incident_story');
check('módulo registrado', $module instanceof Module_IncidentStory);
check('clave del módulo', $module !== null && $module->key() === 'incident_story');
check('nombre visible', $module !== null && $module->name() === 'Incidentes Story');
check('sin permisos Graph', $module !== null && $module->requiredPermissions() === []);
check('no sincronizable', $module !== null && $module->isSyncable() === false);

$nav = $module?->getNavItem();
check('grupo Seguridad', is_array($nav) && ($nav['group'] ?? '') === 'Seguridad');
check('etiqueta del menú', is_array($nav) && ($nav['label'] ?? '') === 'Incidentes Story');
check('ancla tras incidents', is_array($nav) && ($nav['after'] ?? '') === 'incidents');
check('rutas registradas (7)', $module !== null && count($module->routes()) === 7);

/* =====================================================================
 * 2. Parser — texto pegado
 * ================================================================== */

$story = <<<'TXT'
10/30/2026 8:10:38 AM
 [41544] powershell.exe -NoProfile -NoLogo -NonInteractive -Command "try { ..."
Command line powershell.exe -NoProfile -NoLogo -NonInteractive -Command "try { ..."
Process id 41544
Execution details Token elevation: Limited, Integrity level: Medium
Image file path C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Image file SHA1 a4f874f663d4b2e682bbae87fd121865a42dddbb
User DIBA\pinedarp
Sensitive information lookup New Detected Medium
 powershell.exe executed a script
Content try { [Console]::OutputEncoding = ...
Content SHA256 093918998c6da0ecee02bb50d010e6efbba30bea5e57c5b4796c7d6e553d17e4
TXT;

$out = IncidentStoryParser::parse($story);
$caso = $out['caso'];
check('texto: formato detectado', $out['formato_entrada'] === 'texto_pegado');
check('texto: un evento', count($caso['eventos']) === 1);
check('texto: timestamp ISO', ($caso['eventos'][0]['timestamp'] ?? '') === '2026-10-30T08:10:38');
check('texto: pid', ($caso['eventos'][0]['pid'] ?? null) === 41544);
check('texto: proceso', ($caso['eventos'][0]['proceso'] ?? '') === 'powershell.exe');
check('texto: usuario', ($caso['eventos'][0]['usuario'] ?? '') === 'DIBA\pinedarp');
check('texto: sha1', ($caso['eventos'][0]['sha1'] ?? '') === 'a4f874f663d4b2e682bbae87fd121865a42dddbb');
check('texto: script', str_contains((string)($caso['eventos'][0]['script_content'] ?? ''), 'Console'));
check('texto: script sha256', ($caso['eventos'][0]['script_sha256'] ?? '') === '093918998c6da0ecee02bb50d010e6efbba30bea5e57c5b4796c7d6e553d17e4');
check('texto: elevación', ($caso['eventos'][0]['elevacion_token'] ?? '') === 'Limited');
check('texto: integridad', ($caso['eventos'][0]['integridad'] ?? '') === 'Medium');
check('texto: alerta detectada', ($caso['incidencia']['alertas'][0]['nombre'] ?? '') === 'Sensitive information lookup');
check('texto: severidad alerta', ($caso['incidencia']['severidad'] ?? '') === 'Medium');
check('texto: dominios', in_array('DIBA', $caso['dominios'], true));
check('texto: texto crudo conservado', str_contains((string)($caso['eventos'][0]['texto_crudo'] ?? ''), 'Command line'));

/* =====================================================================
 * 3. Parser — story JSON del portal
 * ================================================================== */

$storyJson = [
    'ProcessId'          => 100,
    'ProcessCommandLine' => '"C:\\Windows\\explorer.exe"',
    'FileName'           => 'explorer.exe',
    'AccountName'        => 'pinedarp',
    'AccountDomain'      => 'DIBA',
    'EventTime'          => '2026-10-30T08:00:00Z',
    'Children'           => [[
        'ProcessId'          => 101,
        'ParentProcessId'    => 100,
        'ProcessCommandLine' => 'powershell.exe -enc SQBFAFgA',
        'FileName'           => 'powershell.exe',
        'ScriptContent'      => 'Write-Host "hola"',
        'EventTime'          => '2026-10-30T08:05:00Z',
        'AccountName'        => 'pinedarp',
        'AccountDomain'      => 'DIBA',
    ]],
];
$storyOut = IncidentStoryParser::parse(json_encode($storyJson), 'story_json_portal');
$storyCaso = $storyOut['caso'];
check('story JSON: dos eventos', count($storyCaso['eventos']) === 2);
check('story JSON: pid hijo', ($storyCaso['eventos'][1]['pid'] ?? null) === 101);
check('story JSON: ppid del hijo', ($storyCaso['eventos'][1]['pid_padre'] ?? null) === 100);
check('story JSON: relación hijo_de', ($storyCaso['eventos'][1]['relacion'] ?? '') === 'hijo_de');
check('story JSON: script', str_contains((string)($storyCaso['eventos'][1]['script_content'] ?? ''), 'Write-Host'));
check('story JSON: usuario compuesto', ($storyCaso['eventos'][0]['usuario'] ?? '') === 'DIBA\pinedarp');

/* JSONC con comentarios y coma final. */
$jsonc = "{\n // story\n \"ProcessId\": 7, \"ProcessCommandLine\": \"cmd.exe /c whoami\",\n}";
$jsoncOut = IncidentStoryParser::parse($jsonc, 'story_json_portal');
check('JSONC tolerante', count($jsoncOut['caso']['eventos']) === 1);

/* =====================================================================
 * 4. Parser — export Graph
 * ================================================================== */

$graph = [
    'id'          => '8483',
    'displayName' => 'Sensitive information lookup',
    'severity'    => 'medium',
    'status'      => 'new',
    'alerts'      => [[
        'id'            => 'alert-1',
        'title'         => 'Sensitive information lookup',
        'severity'      => 'Medium',
        'serviceSource' => 'Microsoft Defender for Endpoint',
        'evidence'      => [
            [
                '@odata.type'        => '#microsoft.graph.security.processEvidence',
                'processCommandLine' => 'powershell.exe -NoProfile -enc SQBFAFgA',
                'processCreationTime'=> '2026-10-30T08:10:38Z',
                'processId'          => 41544,
                'parentProcess'      => ['processId' => 4000],
                'fileDetails'        => [
                    'fileName' => 'powershell.exe',
                    'filePath' => 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
                    'sha1'     => 'a4f874f663d4b2e682bbae87fd121865a42dddbb',
                ],
                'userAccount'        => ['accountName' => 'pinedarp', 'domainName' => 'DIBA'],
                'machine'            => ['deviceDnsName' => 'DBPC1234'],
            ],
            [
                '@odata.type' => '#microsoft.graph.security.ipEvidence',
                'ipAddress'   => '10.0.0.198',
            ],
        ],
    ]],
];
$graphOut = IncidentStoryParser::parse(json_encode($graph));
$graphCaso = $graphOut['caso'];
check('graph: formato detectado', $graphOut['formato_entrada'] === 'graph_export');
check('graph: incidencia', ($graphCaso['incidencia']['id_defender'] ?? '') === '8483');
check('graph: un evento', count($graphCaso['eventos']) === 1);
check('graph: ppid', ($graphCaso['eventos'][0]['pid_padre'] ?? null) === 4000);
check('graph: usuario', ($graphCaso['eventos'][0]['usuario'] ?? '') === 'DIBA\pinedarp');
check('graph: equipo', ($graphCaso['eventos'][0]['equipo'] ?? '') === 'DBPC1234');
check('graph: evidencia extra (IP)', str_contains(json_encode($graphCaso['extra']) ?: '', '10.0.0.198'));

/* =====================================================================
 * 5. Parser — Advanced Hunting
 * ================================================================== */

$hunting = ['Results' => [[
    'Timestamp'                  => '2026-10-30T08:10:38Z',
    'ProcessId'                  => 41544,
    'ProcessCommandLine'         => 'powershell.exe -enc SQBFAFgA',
    'FileName'                   => 'powershell.exe',
    'FolderPath'                 => 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0',
    'SHA1'                       => 'a4f874f663d4b2e682bbae87fd121865a42dddbb',
    'AccountName'                => 'pinedarp',
    'AccountDomain'              => 'DIBA',
    'DeviceName'                 => 'DBPC1234',
    'InitiatingProcessId'        => 4000,
    'InitiatingProcessFileName'  => 'explorer.exe',
    'ProcessIntegrityLevel'      => 'Medium',
]]];
$huntOut = IncidentStoryParser::parse(json_encode($hunting));
$huntCaso = $huntOut['caso'];
check('AH: formato detectado', $huntOut['formato_entrada'] === 'advanced_hunting');
check('AH: un evento', count($huntCaso['eventos']) === 1);
check('AH: pid padre', ($huntCaso['eventos'][0]['pid_padre'] ?? null) === 4000);
check('AH: ruta compuesta', str_contains((string)($huntCaso['eventos'][0]['image_path'] ?? ''), 'powershell.exe'));

/* =====================================================================
 * 6. Anonimizador
 * ================================================================== */

$casoAnon = [
    'usuarios' => ['DIBA\pinedarp', 'DIBA\pinedarp2', 'SYSTEM'],
    'equipos'  => ['DBPC1234'],
    'dominios' => ['DIBA'],
    'eventos'  => [[
        'usuario'       => 'DIBA\pinedarp',
        'equipo'        => 'DBPC1234',
        'command_line'  => 'net use \\DBPC1234\c$ /user:DIBA\pinedarp2',
        'image_path'    => 'C:\Users\pinedarp\AppData\Roaming\x.exe',
        'texto_crudo'   => 'Conexión desde 10.0.0.198 a 8.8.8.8 por DIBA\pinedarp; ruta C:\Windows\System32',
        'script_content'=> '$u="DIBA\pinedarp"; $cuenta="usuario@diba.es"',
        'sha1'          => 'a4f874f663d4b2e682bbae87fd121865a42dddbb',
    ]],
    'extra' => [],
];

$anonimizador = new IncidentStoryAnonymizer(['diba.es']);
$anon = $anonimizador->anonymize($casoAnon);
$anonJson = json_encode($anon['caso'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '';
$mapping = $anon['mapping'];

check('anon: pinedarp fuera', !str_contains($anonJson, 'pinedarp'));
check('anon: DIBA fuera', !str_contains($anonJson, 'DIBA'));
check('anon: equipo fuera', !str_contains($anonJson, 'DBPC1234'));
check('anon: IP privada fuera', !str_contains($anonJson, '10.0.0.198'));
check('anon: IP pública intacta', str_contains($anonJson, '8.8.8.8'));
check('anon: hash intacto', str_contains($anonJson, 'a4f874f663d4b2e682bbae87fd121865a42dddbb'));
check('anon: ruta de sistema intacta', str_contains($anonJson, 'C:\\\\Windows\\\\System32') || str_contains($anonJson, 'C:\\Windows\\System32'));
check('anon: SYSTEM excluido', str_contains($anonJson, 'SYSTEM'));
check('anon: usuario correlado en script', str_contains($anonJson, 'Usu001'));
check('anon: usuario2 distinto', isset($mapping['usuarios']['pinedarp2']) && $mapping['usuarios']['pinedarp2'] === 'Usu002');
check('anon: usuario1', ($mapping['usuarios']['pinedarp'] ?? '') === 'Usu001');
check('anon: dominio netbios', ($mapping['dominios']['diba'] ?? '') === 'DOM001');
check('anon: dominio FQDN', ($mapping['dominios']['diba.es'] ?? '') === 'dom001.invalid');
check('anon: equipo', ($mapping['equipos']['DBPC1234'] ?? '') === 'DB0001');
check('anon: ip privada', ($mapping['ips']['10.0.0.198'] ?? '') === 'IPT001');
check('anon: UPN correlado', str_contains($anonJson, 'Usu001@dom001.invalid') || str_contains($anonJson, 'Usu003@dom001.invalid'));
check('anon: sin avisos de restos', $anon['warnings'] === [], implode(' | ', $anon['warnings']));

/* Un caso idéntico produce el mismo mapeo (determinismo). */
$anon2 = (new IncidentStoryAnonymizer(['diba.es']))->anonymize($casoAnon);
check('anon: determinista', $anon2['mapping'] === $mapping);

/* =====================================================================
 * 7. Store (BD temporal)
 * ================================================================== */

$tmp = sys_get_temp_dir() . '/incident_story_smoke_' . getmypid() . '.sqlite';
@unlink($tmp);
@unlink($tmp . '-wal');
@unlink($tmp . '-shm');

try {
    $store = new IncidentStoryStore($tmp);
    check('store: base creada', file_exists($tmp));

    $saved = $store->createCase(
        $caso,
        $anon['caso'],
        $mapping,
        [],
        hash('sha256', $story),
        'texto_pegado',
        'Smoke test'
    );
    check('store: id creado', $saved['id'] > 0);
    check('store: public_id uuid', (bool)preg_match('/^[a-f0-9]{8}-[a-f0-9]{4}-/', $saved['public_id']));
    check('store: sin duplicado en el primero', $saved['duplicate'] === null);

    $dup = $store->createCase($caso, $anon['caso'], $mapping, [], hash('sha256', $story), 'texto_pegado', 'Duplicado');
    check('store: detecta duplicado', $dup['duplicate'] === $saved['id']);
    $store->deleteCase($dup['id']);

    $loaded = $store->getCase($saved['id']);
    check('store: recupera caso', $loaded !== null && ($loaded['public_id'] ?? '') === $saved['public_id']);
    check('store: eventos_count', (int)($loaded['eventos_count'] ?? 0) === 1);
    check('store: mapping guardado', str_contains((string)($loaded['mapping_json'] ?? ''), 'Usu001'));

    $store->saveTriage($saved['id'], ['veredicto_asistido' => 'benigna', 'confianza_pct' => 70], 'test-model', null);
    $loaded = $store->getCase($saved['id']);
    check('store: triaje guardado', ($loaded['triage_verdict'] ?? '') === 'benigna');
    check('store: modelo guardado', ($loaded['triage_model'] ?? '') === 'test-model');

    $decisionId = $store->addDecision($saved['id'], 'analista', 'falsePositive', 'NotAvailable', 'Prueba', 'benigna');
    check('store: decisión creada', $decisionId > 0);
    $decisions = $store->listDecisions($saved['id']);
    check('store: decisión recuperada', count($decisions) === 1 && $decisions[0]['classification'] === 'falsePositive');

    $stats = $store->stats();
    check('store: stats casos', (int)$stats['casos'] === 1);
    check('store: stats decisiones', (int)$stats['decisiones'] === 1);

    $list = $store->listCases();
    check('store: listado', count($list) === 1 && (int)$list[0]['decisiones_count'] === 1);

    $store->deleteCase($saved['id']);
    check('store: borrado en cascada', $store->getCase($saved['id']) === null && $store->listDecisions($saved['id']) === []);
} finally {
    @unlink($tmp);
    @unlink($tmp . '-wal');
    @unlink($tmp . '-shm');
}

/* =====================================================================
 * 8. Parseo del JSON del LLM
 * ================================================================== */

$ai = Module_IncidentStory::parseAiJson("```json\n{\"veredicto_asistido\":\"sospechosa\",\"confianza_pct\":55}\n```");
check('IA: fences limpiados', is_array($ai) && ($ai['veredicto_asistido'] ?? '') === 'sospechosa');
$ai2 = Module_IncidentStory::parseAiJson('Aquí tienes: {"veredicto_asistido":"ataque"} fin');
check('IA: texto envolvente', is_array($ai2) && ($ai2['veredicto_asistido'] ?? '') === 'ataque');
check('IA: JSON inválido devuelve null', Module_IncidentStory::parseAiJson('sin json') === null);

/* =====================================================================
 * Resultado
 * ================================================================== */

echo "\n" . ($fail === 0 ? 'TODO OK' : 'FALLOS') . ": " . ($total - $fail) . "/{$total}\n";
exit($fail === 0 ? 0 : 1);
