<?php
/**
 * WebAuthn — passkeys como segundo factor OPCIONAL (v0.4.28.17).
 *
 * EXPERIMENTAL: solo se activa con WEBAUTHN_ENABLED=1 en .env. Con el valor
 * por defecto (0) ninguna ruta ni el login cambian. Soporta attestation
 * "none" y assertiones ES256 (COSE alg -7), que es lo que usan las passkeys
 * de iCloud/Google/Windows Hello. No se verifica la firma de atestación.
 */

declare(strict_types=1);

final class WebAuthn
{
    private const CHALLENGE_KEY = 'webauthn_challenge';
    private const CHALLENGE_TTL = 120;

    public static function enabled(): bool
    {
        return getenv('WEBAUTHN_ENABLED') === '1';
    }

    public static function rpId(): string
    {
        $configured = trim((string)getenv('WEBAUTHN_RP_ID'));
        if ($configured !== '') {
            return $configured;
        }
        return (string)(parse_url(APP_URL, PHP_URL_HOST) ?? '');
    }

    public static function origin(): string
    {
        return rtrim(APP_URL, '/');
    }

    public static function b64uEncode(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }

    public static function b64uDecode(string $value): string
    {
        $value = strtr($value, '-_', '+/');
        $value .= str_repeat('=', (4 - strlen($value) % 4) % 4);
        $decoded = base64_decode($value, true);
        return $decoded === false ? '' : $decoded;
    }

    /** Opciones para navigator.credentials.create(). */
    public static function registrationOptions(int $userId): ?array
    {
        if (!self::enabled()) {
            return null;
        }
        $user = Database::fetchOne("SELECT id, username, display_name FROM users WHERE id = ?", [$userId]);
        if (!$user) {
            return null;
        }
        $rows = Database::fetchAll(
            "SELECT credential_id, transports FROM webauthn_credentials WHERE user_id = ?",
            [$userId]
        );
        $exclude = [];
        foreach ($rows as $row) {
            $entry = ['type' => 'public-key', 'id' => (string)$row['credential_id']];
            if (!empty($row['transports'])) {
                $entry['transports'] = array_values((array)json_decode((string)$row['transports'], true));
            }
            $exclude[] = $entry;
        }

        return [
            'challenge' => self::newChallenge('create', $userId),
            'rp'        => ['name' => APP_NAME, 'id' => self::rpId()],
            'user'      => [
                'id'          => self::b64uEncode((string)$userId),
                'name'        => (string)$user['username'],
                'displayName' => (string)($user['display_name'] ?: $user['username']),
            ],
            'pubKeyCredParams' => [
                ['type' => 'public-key', 'alg' => -7],
                ['type' => 'public-key', 'alg' => -257],
            ],
            'authenticatorSelection' => [
                'authenticatorAttachment' => 'platform',
                'residentKey'             => 'preferred',
                'userVerification'        => 'preferred',
            ],
            'attestation'       => 'none',
            'timeout'           => 60000,
            'excludeCredentials' => $exclude,
        ];
    }

    /** Guarda la credencial resultante. $body es el objeto devuelto por el navegador. */
    public static function finishRegistration(int $userId, array $body): array
    {
        if (!self::enabled()) {
            return self::error('Passkeys desactivadas');
        }
        $challenge = self::consumeChallenge('create');
        if ($challenge === null || (int)($challenge['user_id'] ?? 0) !== $userId) {
            return self::error('Reto caducado; vuelve a intentarlo');
        }

        $clientB64 = (string)($body['response']['clientDataJSON'] ?? '');
        $clientRaw = self::b64uDecode($clientB64);
        $client = json_decode($clientRaw, true);
        if (!is_array($client) || ($client['type'] ?? '') !== 'webauthn.create'
            || !hash_equals($challenge['value'], (string)($client['challenge'] ?? ''))
            || !hash_equals(self::origin(), (string)($client['origin'] ?? ''))) {
            return self::error('Datos del cliente no válidos');
        }

        $attestationRaw = self::b64uDecode((string)($body['response']['attestationObject'] ?? ''));
        $offset = 0;
        $attestation = self::cborDecode($attestationRaw, $offset);
        if (!is_array($attestation) || !isset($attestation['authData']) || !is_string($attestation['authData'])) {
            return self::error('Attestation no válido');
        }

        $authData = $attestation['authData'];
        if (strlen($authData) < 55
            || !hash_equals(hash('sha256', self::rpId(), true), substr($authData, 0, 32))) {
            return self::error('RP ID no coincide');
        }
        $flags = ord($authData[32]);
        if (($flags & 0x40) === 0) {
            return self::error('La credencial no incluye datos públicos');
        }
        $pos = 37 + 16; // rpIdHash(32) + flags(1) + signCount(4) + AAGUID(16)
        $credIdLen = unpack('n', substr($authData, $pos, 2));
        if ($credIdLen === false) {
            return self::error('Longitud de credencial no válida');
        }
        $pos += 2;
        $credId = substr($authData, $pos, $credIdLen[1]);
        $pos += $credIdLen[1];
        $coseOffset = 0;
        $cose = self::cborDecode(substr($authData, $pos), $coseOffset);
        if ($credId === '' || !is_array($cose)
            || (int)($cose[3] ?? 0) !== -7 || (int)($cose[1] ?? 0) !== 2
            || !isset($cose[-2], $cose[-3]) || !is_string($cose[-2]) || !is_string($cose[-3])) {
            return self::error('Solo se admiten passkeys ES256');
        }

        $credentialId = self::b64uEncode($credId);
        if (($body['id'] ?? '') !== $credentialId
            && self::b64uDecode((string)($body['id'] ?? '')) !== $credId) {
            return self::error('ID de credencial no coincide');
        }
        try {
            Database::insert(
                "INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count, transports)
                 VALUES (?, ?, ?, ?, ?)",
                [
                    $userId,
                    $credentialId,
                    json_encode([
                        'alg' => -7,
                        'x'   => self::b64uEncode($cose[-2]),
                        'y'   => self::b64uEncode($cose[-3]),
                    ], JSON_THROW_ON_ERROR),
                    unpack('N', substr($authData, 33, 4))[1],
                    json_encode(array_values((array)($body['response']['transports'] ?? [])), JSON_THROW_ON_ERROR),
                ]
            );
        } catch (Throwable $e) {
            return self::error('No se pudo guardar la passkey');
        }
        log_activity('auth.webauthn_enrolled', ['user_id' => $userId], $userId);
        return ['success' => true];
    }

    /** Opciones para navigator.credentials.get(). */
    public static function authenticationOptions(?string $username): ?array
    {
        if (!self::enabled()) {
            return null;
        }
        $user = null;
        if ($username !== null && trim($username) !== '') {
            $name = trim($username);
            $user = Database::fetchOne(
                "SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1",
                [$name, $name]
            );
        }
        $allow = [];
        if ($user) {
            foreach (Database::fetchAll(
                "SELECT credential_id FROM webauthn_credentials WHERE user_id = ?",
                [(int)$user['id']]
            ) as $row) {
                $allow[] = ['type' => 'public-key', 'id' => (string)$row['credential_id']];
            }
        }
        return [
            'challenge'       => self::newChallenge('get', $user ? (int)$user['id'] : null),
            'rpId'            => self::rpId(),
            'allowCredentials' => $allow,
            'userVerification' => 'preferred',
            'timeout'          => 60000,
        ];
    }

    /** Verifica la aserción y, si es válida, inicia sesión. */
    public static function finishAuthentication(array $body): array
    {
        if (!self::enabled()) {
            return self::error('Passkeys desactivadas');
        }
        $id = (string)($body['id'] ?? '');
        $row = Database::fetchOne(
            "SELECT * FROM webauthn_credentials WHERE credential_id = ?",
            [$id]
        );
        if (!$row) {
            $decoded = self::b64uDecode($id);
            $row = $decoded === '' ? null : Database::fetchOne(
                "SELECT * FROM webauthn_credentials WHERE credential_id = ?",
                [self::b64uEncode($decoded)]
            );
        }
        if (!$row) {
            return self::error('Passkey no registrada');
        }

        $challenge = self::consumeChallenge('get');
        if ($challenge === null
            || (!empty($challenge['user_id']) && (int)$challenge['user_id'] !== (int)$row['user_id'])) {
            return self::error('Reto caducado; vuelve a intentarlo');
        }

        $clientRaw = self::b64uDecode((string)($body['response']['clientDataJSON'] ?? ''));
        $client = json_decode($clientRaw, true);
        if (!is_array($client) || ($client['type'] ?? '') !== 'webauthn.get'
            || !hash_equals($challenge['value'], (string)($client['challenge'] ?? ''))
            || !hash_equals(self::origin(), (string)($client['origin'] ?? ''))) {
            return self::error('Datos del cliente no válidos');
        }

        $authData = self::b64uDecode((string)($body['response']['authenticatorData'] ?? ''));
        if (strlen($authData) < 37
            || !hash_equals(hash('sha256', self::rpId(), true), substr($authData, 0, 32))
            || (ord($authData[32]) & 0x01) === 0) {
            return self::error('Autenticador no válido');
        }

        $key = json_decode((string)$row['public_key'], true);
        if (!is_array($key) || (int)($key['alg'] ?? 0) !== -7 || !isset($key['x'], $key['y'])) {
            return self::error('Clave no compatible');
        }
        $pem = self::pemFromCose(self::b64uDecode((string)$key['x']), self::b64uDecode((string)$key['y']));
        if ($pem === '') {
            return self::error('Clave no válida');
        }
        $signature = self::b64uDecode((string)($body['response']['signature'] ?? ''));
        $signed = $authData . hash('sha256', $clientRaw, true);
        $der = self::derSignature($signature);
        if ($der === '' || openssl_verify($signed, $der, $pem, OPENSSL_ALGO_SHA256) !== 1) {
            return self::error('Firma no válida');
        }

        $count = unpack('N', substr($authData, 33, 4));
        $newCount = $count === false ? 0 : (int)$count[1];
        $oldCount = (int)$row['sign_count'];
        if ($newCount > 0 && $newCount <= $oldCount) {
            return self::error('Contador de autenticador sospechoso');
        }
        Database::update(
            "UPDATE webauthn_credentials SET sign_count = ?, last_used_at = datetime('now') WHERE id = ?",
            [$newCount, $row['id']]
        );
        if (!Auth::loginById((int)$row['user_id'], 'webauthn')) {
            return self::error('No se pudo iniciar sesión');
        }
        return ['success' => true];
    }

    /** Lista las passkeys del usuario (para la UI, sin clave pública). */
    public static function forUser(int $userId): array
    {
        if (!self::enabled()) {
            return [];
        }
        $rows = Database::fetchAll(
            "SELECT id, credential_id, created_at, last_used_at FROM webauthn_credentials
             WHERE user_id = ? ORDER BY id",
            [$userId]
        );
        return array_map(static function (array $row): array {
            return [
                'id'         => (int)$row['id'],
                'label'      => substr((string)$row['credential_id'], 0, 12) . '…',
                'created_at' => (string)$row['created_at'],
                'last_used'  => $row['last_used_at'] ? (string)$row['last_used_at'] : null,
            ];
        }, $rows);
    }

    // --- Internos ---------------------------------------------------------

    private static function error(string $message): array
    {
        return ['success' => false, 'error' => $message];
    }

    private static function newChallenge(string $action, ?int $userId): string
    {
        $value = self::b64uEncode(random_bytes(32));
        $_SESSION[self::CHALLENGE_KEY] = [
            'value'    => $value,
            'action'   => $action,
            'user_id'  => $userId,
            'expires'  => time() + self::CHALLENGE_TTL,
        ];
        return $value;
    }

    private static function consumeChallenge(string $action): ?array
    {
        $stored = $_SESSION[self::CHALLENGE_KEY] ?? null;
        unset($_SESSION[self::CHALLENGE_KEY]);
        if (!is_array($stored) || ($stored['action'] ?? '') !== $action
            || (int)($stored['expires'] ?? 0) < time() || empty($stored['value'])) {
            return null;
        }
        return $stored;
    }

    /** Decodificador CBOR mínimo (major types 0,1,2,3,4,5 y 7 simple). */
    private static function cborDecode(string $buf, int &$offset)
    {
        if ($offset >= strlen($buf)) {
            return null;
        }
        $ib = ord($buf[$offset++]);
        $major = $ib >> 5;
        $ai = $ib & 0x1f;
        $val = 0;
        if ($ai < 24) {
            $val = $ai;
        } elseif ($ai === 24) {
            $val = ord($buf[$offset++] ?? "\x00");
        } elseif ($ai === 25) {
            $val = unpack('n', substr($buf, $offset, 2))[1];
            $offset += 2;
        } elseif ($ai === 26) {
            $val = unpack('N', substr($buf, $offset, 4))[1];
            $offset += 4;
        } elseif ($ai === 27) {
            $hi = unpack('N', substr($buf, $offset, 4))[1];
            $lo = unpack('N', substr($buf, $offset + 4, 4))[1];
            $val = $hi * 4294967296 + $lo;
            $offset += 8;
        } else {
            return null;
        }

        switch ($major) {
            case 0:
                return $val;
            case 1:
                return -1 - $val;
            case 2:
            case 3:
                $out = substr($buf, $offset, (int)$val);
                $offset += (int)$val;
                return $out;
            case 4:
                $out = [];
                for ($i = 0; $i < $val; $i++) {
                    $out[] = self::cborDecode($buf, $offset);
                }
                return $out;
            case 5:
                $out = [];
                for ($i = 0; $i < $val; $i++) {
                    $k = self::cborDecode($buf, $offset);
                    $out[(string)$k] = self::cborDecode($buf, $offset);
                }
                return $out;
            case 7:
                if ($ai === 20) {
                    return false;
                }
                if ($ai === 21) {
                    return true;
                }
                return null;
            default:
                return null;
        }
    }

    private static function derLen(int $length): string
    {
        if ($length < 128) {
            return chr($length);
        }
        $bytes = [];
        while ($length > 0) {
            array_unshift($bytes, $length & 0xff);
            $length >>= 8;
        }
        return chr(0x80 | count($bytes)) . implode('', array_map('chr', $bytes));
    }

    private static function derSeq(string $content): string
    {
        return "\x30" . self::derLen(strlen($content)) . $content;
    }

    private static function derInt(string $value): string
    {
        $value = ltrim($value, "\x00");
        if ($value === '') {
            $value = "\x00";
        }
        if ((ord($value[0]) & 0x80) !== 0) {
            $value = "\x00" . $value;
        }
        return "\x02" . self::derLen(strlen($value)) . $value;
    }

    private static function pemFromCose(string $x, string $y): string
    {
        if (strlen($x) !== 32 || strlen($y) !== 32) {
            return '';
        }
        $algorithm = self::derSeq(
            "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01"
            . "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"
        );
        $bitString = "\x00\x04" . $x . $y;
        $spki = self::derSeq($algorithm . "\x03" . self::derLen(strlen($bitString)) . $bitString);
        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($spki), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    /** WebAuthn firma r||s en crudo; OpenSSL espera INTEGER DER. */
    private static function derSignature(string $signature): string
    {
        if (strlen($signature) !== 64) {
            return '';
        }
        return self::derSeq(
            self::derInt(substr($signature, 0, 32))
            . self::derInt(substr($signature, 32, 32))
        );
    }
}
