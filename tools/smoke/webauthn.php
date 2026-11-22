<?php
/**
 * webauthn.php — Pruebas de los ayudantes puros de WebAuthn (v0.4.28.17).
 *
 *   php tools/smoke/webauthn.php
 *
 * No necesita navegador: valida base64url, CBOR, PEM COSE y DER de firmas.
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

/** @return mixed */
function invoke(string $method, array $args = [])
{
    $ref = new ReflectionMethod(WebAuthn::class, $method);
    $ref->setAccessible(true);
    return $ref->invokeArgs(null, $args);
}

// --- Estado por defecto ---------------------------------------------------
check('WebAuthn desactivado por defecto', WebAuthn::enabled() === false);
check('registrationOptions null si desactivado', WebAuthn::registrationOptions(1) === null);
check('authenticationOptions null si desactivado', WebAuthn::authenticationOptions('admin') === null);
check('forUser vacío si desactivado', WebAuthn::forUser(1) === []);

// --- base64url ------------------------------------------------------------
$bytes = "\x00\xff\x10\x80abc";
$encoded = WebAuthn::b64uEncode($bytes);
check('base64url sin padding', !str_contains($encoded, '=')
    && !str_contains($encoded, '+') && !str_contains($encoded, '/'), $encoded);
check('base64url round-trip', WebAuthn::b64uDecode($encoded) === $bytes);
check('base64url rechaza basura', WebAuthn::b64uDecode('@@@@') === '');

// --- CBOR -----------------------------------------------------------------
$cbor = hex2bin('a26161016162820203'); // {"a":1,"b":[2,3]}
$offset = 0;
$decoded = invoke('cborDecode', [$cbor, &$offset]);
check('CBOR map + array', is_array($decoded) && $decoded['a'] === 1
    && $decoded['b'] === [2, 3], json_encode($decoded));

$cborNeg = hex2bin('a12001'); // {"-1":1}
$offset = 0;
$decodedNeg = invoke('cborDecode', [$cborNeg, &$offset]);
check('CBOR clave negativa (COSE -1)', is_array($decodedNeg) && ($decodedNeg['-1'] ?? null) === 1,
    json_encode($decodedNeg));

$cborBytes = hex2bin('43010203'); // byte string de 3 bytes
$offset = 0;
check('CBOR byte string', invoke('cborDecode', [$cborBytes, &$offset]) === "\x01\x02\x03");

// --- COSE -> PEM (vector fijo generado con Node, sin depender de OpenSSL) --
$vectorX = 'wDij6qLMtMWdMVYlJHB8Wz9AVI1cAjbDAIy3t4YSVss';
$vectorY = 'tw1MlemgWv6vkZc6BJ8Pv3iVw98jaEK2lswX3xnOjMQ';
$expectedPem = "-----BEGIN PUBLIC KEY-----\n"
    . "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwDij6qLMtMWdMVYlJHB8Wz9AVI1c\n"
    . "AjbDAIy3t4YSVsu3DUyV6aBa/q+RlzoEnw+/eJXD3yNoQraWzBffGc6MxA==\n"
    . "-----END PUBLIC KEY-----\n";
$pem = invoke('pemFromCose', [WebAuthn::b64uDecode($vectorX), WebAuthn::b64uDecode($vectorY)]);
check('COSE -> PEM exacto', $pem === $expectedPem, $pem);
check('COSE -> PEM rechaza coordenadas cortas', invoke('pemFromCose', ['x', 'y']) === '');

// --- DER de firma (raw r||s -> DER, mismo vector) --------------------------
$raw = base64_decode('B8UeZvZkaxdJatKFEG5D0HRbGRQcApb1uKsfa5XrZC0ZZdXDkpsBlrj0LawW+YEnVQs9+YMYgToZC/i1GQ+6Sw==', true);
$der = base64_decode('MEQCIAfFHmb2ZGsXSWrShRBuQ9B0WxkUHAKW9birH2uV62QtAiAZZdXDkpsBlrj0LawW+YEnVQs9+YMYgToZC/i1GQ+6Sw==', true);
check('Firma raw de 64 bytes', strlen((string)$raw) === 64);
check('DER(raw) coincide con el vector', invoke('derSignature', [(string)$raw]) === $der);
check('DER rechaza firma corta', invoke('derSignature', [str_repeat("\x01", 32)]) === '');

echo PHP_EOL . ($fail === 0
    ? 'RESULTADO: OK (' . $total . ' comprobaciones)'
    : "RESULTADO: {$fail} de {$total} fallidas") . PHP_EOL;
exit($fail === 0 ? 0 : 1);
