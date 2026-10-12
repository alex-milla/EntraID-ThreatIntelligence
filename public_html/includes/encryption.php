<?php
/**
 * Encryption — cifrado AES-256-CBC para secretos en la base de datos.
 * Los client_secret de los tenants NUNCA se almacenan en texto plano.
 */

declare(strict_types=1);

class Encryption
{
    private const CIPHER = 'aes-256-cbc';
    private static ?string $key = null;

    /**
     * Inicializa la clave de cifrado desde la configuración.
     */
    private static function getKey(): string
    {
        if (self::$key !== null) {
            return self::$key;
        }

        $key = ENCRYPTION_KEY;
        if (empty($key)) {
            // Si no hay clave configurada, generar una y avisar
            if (APP_DEBUG) {
                // En debug, generar clave temporal (no persistente)
                self::$key = hash('sha256', SESSION_SECRET . 'encryption-fallback', true);
                return self::$key;
            }
            throw new RuntimeException(
                'ENCRYPTION_KEY no está configurada en .env. '
                . 'Genera una con: php -r "echo base64_encode(random_bytes(32));"'
            );
        }

        // La clave puede venir en base64 o como string raw
        $decoded = base64_decode($key, true);
        if ($decoded !== false && strlen($decoded) === 32) {
            self::$key = $decoded;
        } elseif (strlen($key) === 32) {
            self::$key = $key;
        } else {
            // Derivar clave de 32 bytes desde el string proporcionado
            self::$key = hash('sha256', $key, true);
        }

        return self::$key;
    }

    /**
     * Cifra un valor y devuelve ['encrypted' => base64, 'iv' => base64].
     */
    public static function encrypt(string $plaintext): array
    {
        $key = self::getKey();
        $iv = random_bytes(openssl_cipher_iv_length(self::CIPHER));
        $encrypted = openssl_encrypt($plaintext, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv);

        if ($encrypted === false) {
            throw new RuntimeException('Error al cifrar: ' . openssl_error_string());
        }

        return [
            'encrypted' => base64_encode($encrypted),
            'iv'        => base64_encode($iv),
        ];
    }

    /**
     * Descifra un valor usando el ciphertext y el IV en base64.
     */
    public static function decrypt(string $encryptedB64, string $ivB64): string
    {
        $key = self::getKey();
        $encrypted = base64_decode($encryptedB64, true);
        $iv = base64_decode($ivB64, true);

        if ($encrypted === false || $iv === false) {
            throw new RuntimeException('Datos de cifrado inválidos (base64)');
        }

        $decrypted = openssl_decrypt($encrypted, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv);

        if ($decrypted === false) {
            throw new RuntimeException('Error al descifrar: ' . openssl_error_string());
        }

        return $decrypted;
    }

    /**
     * Cifra un valor y devuelve un string combinado (iv:encrypted) en base64.
     * Útil para almacenar en una sola columna.
     */
    public static function encryptCombined(string $plaintext): string
    {
        $result = self::encrypt($plaintext);
        return $result['iv'] . ':' . $result['encrypted'];
    }

    /**
     * Descifra un string combinado (iv:encrypted).
     */
    public static function decryptCombined(string $combined): string
    {
        $parts = explode(':', $combined, 2);
        if (count($parts) !== 2) {
            throw new RuntimeException('Formato de cifrado combinado inválido');
        }
        return self::decrypt($parts[1], $parts[0]);
    }

    /**
     * Genera una clave de cifrado segura en base64 (para .env).
     */
    public static function generateKey(): string
    {
        return base64_encode(random_bytes(32));
    }

    /**
     * Hash seguro para contraseñas.
     * Argon2id si el hosting lo soporta; BCRYPT como fallback universal
     * (algunos hostings compartidos no compilan Argon2 o limitan la memoria).
     */
    public static function hashPassword(string $password): string
    {
        if (defined('PASSWORD_ARGON2ID')) {
            try {
                $hash = @password_hash($password, PASSWORD_ARGON2ID, [
                    'memory_cost' => 65536,
                    'time_cost'   => 4,
                    'threads'     => 1,
                ]);
                if (is_string($hash) && $hash !== '') {
                    return $hash;
                }
            } catch (Throwable $e) {
                // Argon2 falló en este entorno: usar bcrypt
            }
        }
        $hash = password_hash($password, PASSWORD_BCRYPT);
        if (!is_string($hash) || $hash === '') {
            throw new RuntimeException('No se pudo generar el hash de la contraseña');
        }
        return $hash;
    }

    /**
     * Verifica una contraseña contra su hash.
     */
    public static function verifyPassword(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    /**
     * Genera un token aleatorio seguro.
     */
    public static function randomToken(int $length = 32): string
    {
        return bin2hex(random_bytes($length));
    }

    /**
     * Genera un hash HMAC para firmas.
     */
    public static function hmac(string $data, ?string $key = null): string
    {
        return hash_hmac('sha256', $data, $key ?? self::getKey());
    }
}
