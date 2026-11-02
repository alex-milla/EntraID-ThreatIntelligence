<?php
/**
 * IncidentStoryAnonymizer — pseudonimización correlacionada (§7).
 *
 * Sustituye usuarios, equipos, dominios internos e IPs privadas por
 * pseudónimos estables dentro de un mismo caso:
 *
 *   DIBA\pinedarp      -> DOM001\Usu001
 *   usuario@diba.es    -> Usu002@dom001.invalid
 *   \\DBPC1234\c$      -> \\DB0001\c$
 *   10.0.0.198         -> IPT001
 *
 * El mismo original produce siempre el mismo pseudónimo. La tabla de mapeo
 * se devuelve aparte y nunca debe enviarse al proveedor de IA ni pintarse
 * en la interfaz de triaje.
 *
 * Se ejecuta SIEMPRE antes del triaje, sobre el Caso completo (incluidas
 * command lines y scripts embebidos). Tras sustituir, valida el resultado y
 * devuelve avisos honestos si quedan restos que el analista deba revisar.
 */

declare(strict_types=1);

final class IncidentStoryAnonymizer
{
    /** Usuarios universales que no identifican a una persona. */
    public const EXCLUDED_USERS = [
        'system', 'local service', 'network service', 'nt authority',
        'anonymous logon', 'everyone', 'authenticated users', 'network',
        'creator owner', 'trustedinstaller', 'defaultaccount', 'wdagutilityaccount',
        'public', 'default', 'default user', 'all users',
    ];

    /** Dominios públicos de terceros que no deben pseudonimizarse. */
    public const PUBLIC_DOMAINS = [
        'microsoft.com', 'microsoftonline.com', 'windows.com', 'windows.net',
        'office.com', 'office365.com', 'live.com', 'outlook.com', 'msn.com',
        'github.com', 'githubusercontent.com', 'google.com', 'gstatic.com',
        'amazon.com', 'amazonaws.com', 'cloudflare.com', 'akamai.net',
        'azure.com', 'azurewebsites.net', 'sharepoint.com', 'teams.microsoft.com',
        'bing.com', 'yahoo.com', 'apple.com', 'adobe.com', 'mozilla.org',
        'w3.org', 'schema.org', 'verisign.com', 'digicert.com', 'sectigo.com',
    ];

    /** Segmentos de ruta que nunca son un dominio NetBIOS. */
    private const PATH_SEGMENTS = [
        'users', 'windows', 'program', 'programs', 'programdata', 'appdata',
        'local', 'locallow', 'roaming', 'temp', 'tmp', 'system32', 'syswow64',
        'documents', 'desktop', 'downloads', 'public', 'default', 'all users',
        'perflogs', 'boot', 'recovery', 'system volume information', 'c$', 'admin$', 'ipc$',
    ];

    /** Extensiones que delatan un fichero, no un dominio. */
    private const FILE_EXTENSIONS = [
        'exe', 'dll', 'sys', 'ps1', 'psm1', 'txt', 'json', 'jsonc', 'log', 'dat',
        'tmp', 'bat', 'cmd', 'msi', 'zip', '7z', 'cab', 'etl', 'evtx', 'php',
        'html', 'htm', 'js', 'css', 'py', 'vbs', 'lnk', 'ini', 'xml', 'csv',
        'md', 'doc', 'docx', 'xls', 'xlsx', 'pdf', 'png', 'jpg', 'jpeg', 'gif',
        'ico', 'yml', 'yaml', 'config', 'manifest', 'mui', 'cpl', 'ocx', 'drv',
        'bin', 'img', 'iso', 'vhd', 'vhdx', 'db', 'sqlite', 'evtx', 'pdb',
    ];

    private array $users = [];        // clave normalizada => [original, pseudónimo]
    private array $hosts = [];        // clave normalizada => [original, pseudónimo]
    private array $domains = [];      // clave normalizada => [original, pseudónimo]
    private array $domainNumbers = [];// clave normalizada => número
    private array $ips = [];          // clave normalizada => [original, pseudónimo]
    private int $userSeq = 0;
    private int $hostSeq = 0;
    private int $domainSeq = 0;
    private int $ipSeq = 0;
    private array $clientDomains = [];
    private array $warnings = [];

    public function __construct(array $clientDomains = [])
    {
        $configured = defined('INCIDENT_STORY_CLIENT_DOMAINS') ? (string)INCIDENT_STORY_CLIENT_DOMAINS : '';
        foreach (array_merge($clientDomains, preg_split('/[,;\s]+/', $configured) ?: []) as $domain) {
            $domain = strtolower(trim((string)$domain, " \t\n\r\0\x0B."));
            if ($domain !== '' && str_contains($domain, '.')) {
                $this->clientDomains[$domain] = true;
            }
        }
    }

    /**
     * Pseudonimiza un caso completo.
     *
     * @return array{caso:array, mapping:array, warnings:array}
     */
    public function anonymize(array $caso): array
    {
        $this->reset();
        $this->collectFromCaso($caso);
        $this->collectFromCaso($caso, true);

        $anon = $this->walk($caso);
        $this->validate($anon);

        return [
            'caso'     => $anon,
            'mapping'  => [
                'usuarios' => $this->mapFor($this->users),
                'equipos'  => $this->mapFor($this->hosts),
                'dominios' => $this->mapFor($this->domains),
                'ips'      => $this->mapFor($this->ips),
            ],
            'warnings' => array_values(array_unique($this->warnings)),
        ];
    }

    /** @return array<string,mixed> */
    public function map(): array
    {
        return [
            'usuarios' => $this->mapFor($this->users),
            'equipos'  => $this->mapFor($this->hosts),
            'dominios' => $this->mapFor($this->domains),
            'ips'      => $this->mapFor($this->ips),
        ];
    }

    private function reset(): void
    {
        $this->users = [];
        $this->hosts = [];
        $this->domains = [];
        $this->domainNumbers = [];
        $this->ips = [];
        $this->userSeq = 0;
        $this->hostSeq = 0;
        $this->domainSeq = 0;
        $this->ipSeq = 0;
        $this->warnings = [];
    }

    /* =====================================================================
     * Recolección de entidades
     * ================================================================== */

    private function collectFromCaso(array $caso, bool $onlyText = false): void
    {
        if ($onlyText) {
            $this->walkStrings($caso, function (string $s): void {
                $this->collectFromText($s);
            });
            return;
        }

        foreach ((array)($caso['usuarios'] ?? []) as $user) {
            $this->registerUserString((string)$user);
        }
        foreach ((array)($caso['equipos'] ?? []) as $host) {
            $this->registerHost((string)$host);
        }
        foreach ((array)($caso['dominios'] ?? []) as $domain) {
            $this->registerDomain((string)$domain, !str_contains((string)$domain, '.'));
        }
        foreach ((array)($caso['eventos'] ?? []) as $ev) {
            if (!is_array($ev)) {
                continue;
            }
            if (!empty($ev['usuario'])) {
                $this->registerUserString((string)$ev['usuario']);
            }
            if (!empty($ev['equipo'])) {
                $this->registerHost((string)$ev['equipo']);
            }
            if (!empty($ev['image_path'])) {
                $this->collectFromText((string)$ev['image_path']);
            }
        }
    }

    private function collectFromText(string $text): void
    {
        if ($text === '') {
            return;
        }

        /* UPN / correo */
        if (preg_match_all('/\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/u', $text, $m, PREG_SET_ORDER)) {
            foreach ($m as $match) {
                $domain = strtolower($match[2]);
                if ($this->isPublicDomain($domain)) {
                    continue;
                }
                $this->registerDomain($domain, false);
                $this->registerUser($match[1]);
            }
        }

        /* DOMINIO\usuario (excluye rutas y letras de unidad) */
        if (preg_match_all('/(?<![A-Za-z0-9._-\x5c])([A-Za-z0-9._-]{2,})\x5c([A-Za-z0-9._$-]{1,})/u', $text, $m, PREG_SET_ORDER)) {
            foreach ($m as $match) {
                $domain = $match[1];
                if (!$this->looksLikeNetbios($domain)) {
                    continue;
                }
                $this->registerDomain($domain, true);
                $this->registerUser($match[2]);
            }
        }

        /* C:\Users\<nombre> y cualquier \Users\<nombre>\ (unidad, UNC, \\ dobles) */
        if (preg_match_all('/(?:[A-Za-z]:)?\x5c{1,2}Users\x5c{1,2}([^\x5c\/\s"\']+)/iu', $text, $m, PREG_SET_ORDER)) {
            foreach ($m as $match) {
                $this->registerUser($match[1]);
            }
        }

        /* UNC \\EQUIPO\recurso */
        if (preg_match_all('/\x5c\x5c([A-Za-z0-9._-]{2,})\x5c/u', $text, $m, PREG_SET_ORDER)) {
            foreach ($m as $match) {
                $this->registerHost($match[1]);
            }
        }

        /* IPs privadas RFC1918 */
        if (preg_match_all('/\b(?:(?:10)\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})|172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3})\.(?:\d{1,3})|192\.168\.(?:\d{1,3})\.(?:\d{1,3}))\b/u', $text, $m, PREG_SET_ORDER)) {
            foreach ($m as $match) {
                $this->registerIp($match[0]);
            }
        }

        /* Dominios internos declarados por configuración. */
        foreach (array_keys($this->clientDomains) as $domain) {
            if (stripos($text, $domain) !== false) {
                $this->registerDomain($domain, false);
            }
        }
    }

    private function registerUserString(string $user): void
    {
        $user = trim($user);
        if ($user === '') {
            return;
        }
        if (str_contains($user, '\\')) {
            [$domain, $name] = explode('\\', $user, 2);
            if ($this->looksLikeNetbios($domain)) {
                $this->registerDomain($domain, true);
            }
            $this->registerUser($name);
            return;
        }
        if (str_contains($user, '@')) {
            [$local, $domain] = explode('@', $user, 2);
            if (!$this->isPublicDomain($domain)) {
                $this->registerDomain($domain, false);
                $this->registerUser($local);
            }
            return;
        }
        $this->registerUser($user);
    }

    private function registerUser(string $name): ?string
    {
        $name = trim($name, " \t\n\r\0\x0B\"'");
        if ($name === '' || $this->isExcludedUser($name)) {
            return null;
        }
        $key = strtolower($name);
        if (!isset($this->users[$key])) {
            $this->userSeq++;
            $this->users[$key] = [
                'original'   => $name,
                'pseudonimo' => 'Usu' . str_pad((string)$this->userSeq, 3, '0', STR_PAD_LEFT),
            ];
        }
        return $this->users[$key]['pseudonimo'];
    }

    private function registerHost(string $host): ?string
    {
        $host = trim($host, " \t\n\r\0\x0B\\/\"'");
        if ($host === '' || !preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]{1,}$/', $host)) {
            return null;
        }
        if (in_array(strtolower($host), ['localhost', 'local', 'unknown'], true)) {
            return null;
        }
        $key = strtolower($host);
        if (!isset($this->hosts[$key])) {
            $this->hostSeq++;
            $this->hosts[$key] = [
                'original'   => $host,
                'pseudonimo' => 'DB' . str_pad((string)$this->hostSeq, 4, '0', STR_PAD_LEFT),
            ];
        }
        return $this->hosts[$key]['pseudonimo'];
    }

    private function registerDomain(string $domain, bool $netbios): ?string
    {
        $domain = strtolower(trim($domain, " \t\n\r\0\x0B."));
        if ($domain === '' || $this->isPublicDomain($domain)) {
            return null;
        }
        if ($netbios && !$this->looksLikeNetbios($domain)) {
            return null;
        }

        $key = $domain;
        if (!isset($this->domainNumbers[$key])) {
            /* Un FQDN diba.es reutiliza el número de su NetBIOS DIBA. */
            $first = explode('.', $domain)[0];
            if (str_contains($domain, '.') && isset($this->domainNumbers[$first])) {
                $this->domainNumbers[$key] = $this->domainNumbers[$first];
            } else {
                $this->domainSeq++;
                $this->domainNumbers[$key] = $this->domainSeq;
            }
        }

        $num = $this->domainNumbers[$key];
        $pseudo = str_contains($domain, '.')
            ? 'dom' . str_pad((string)$num, 3, '0', STR_PAD_LEFT) . '.invalid'
            : 'DOM' . str_pad((string)$num, 3, '0', STR_PAD_LEFT);

        if (!isset($this->domains[$key])) {
            $this->domains[$key] = ['original' => $domain, 'pseudonimo' => $pseudo];
        }
        return $pseudo;
    }

    private function registerIp(string $ip): ?string
    {
        if (!$this->isPrivateIp($ip)) {
            return null;
        }
        $key = strtolower($ip);
        if (!isset($this->ips[$key])) {
            $this->ipSeq++;
            $this->ips[$key] = [
                'original'   => $ip,
                'pseudonimo' => 'IPT' . str_pad((string)$this->ipSeq, 3, '0', STR_PAD_LEFT),
            ];
        }
        return $this->ips[$key]['pseudonimo'];
    }

    /* =====================================================================
     * Sustitución
     * ================================================================== */

    private function walk(mixed $value): mixed
    {
        if (is_array($value)) {
            $out = [];
            foreach ($value as $k => $v) {
                $out[$k] = $this->walk($v);
            }
            return $out;
        }
        if (is_string($value)) {
            return $this->replaceText($value);
        }
        return $value;
    }

    /** @param callable(string):void $fn */
    private function walkStrings(mixed $value, callable $fn): void
    {
        if (is_array($value)) {
            foreach ($value as $v) {
                $this->walkStrings($v, $fn);
            }
            return;
        }
        if (is_string($value) && $value !== '') {
            $fn($value);
        }
    }

    private function replaceText(string $text): string
    {
        /* 1. UPN / correo interno. */
        $text = preg_replace_callback(
            '/\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/u',
            function (array $m): string {
                $domain = strtolower($m[2]);
                if ($this->isPublicDomain($domain)) {
                    return $m[0];
                }
                $domainPseudo = $this->registerDomain($domain, false);
                $userPseudo = $this->registerUser($m[1]);
                if ($domainPseudo === null && $userPseudo === null) {
                    return $m[0];
                }
                return ($userPseudo ?? $m[1]) . '@' . ($domainPseudo ?? $m[2]);
            },
            $text
        ) ?? $text;

        /* 2. DOMINIO\usuario. */
        $text = preg_replace_callback(
            '/(?<![A-Za-z0-9._-\x5c])([A-Za-z0-9._-]{2,})\x5c([A-Za-z0-9._$-]{1,})/u',
            function (array $m): string {
                if (!$this->looksLikeNetbios($m[1])) {
                    return $m[0];
                }
                $domainPseudo = $this->registerDomain($m[1], true);
                $userPseudo = $this->registerUser($m[2]);
                if ($domainPseudo === null && $userPseudo === null) {
                    return $m[0];
                }
                return ($domainPseudo ?? $m[1]) . '\\' . ($userPseudo ?? $m[2]);
            },
            $text
        ) ?? $text;

        /* 3. Cualquier \Users\<nombre>\ (unidad, UNC, barras dobles). */
        $text = preg_replace_callback(
            '/((?:[A-Za-z]:)?\x5c{1,2}Users\x5c{1,2})([^\x5c\/\s"\']+)/iu',
            function (array $m): string {
                $pseudo = $this->registerUser($m[2]);
                return $m[1] . ($pseudo ?? $m[2]);
            },
            $text
        ) ?? $text;

        /* 4. UNC \\EQUIPO\recurso. */
        $text = preg_replace_callback(
            '/\x5c\x5c([A-Za-z0-9._-]{2,})\x5c/u',
            function (array $m): string {
                $pseudo = $this->registerHost($m[1]);
                return $pseudo !== null ? '\\\\' . $pseudo . '\\' : $m[0];
            },
            $text
        ) ?? $text;

        /* 5. IPs privadas. */
        $text = preg_replace_callback(
            '/\b(?:(?:10)\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})|172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3})\.(?:\d{1,3})|192\.168\.(?:\d{1,3})\.(?:\d{1,3}))\b/u',
            function (array $m): string {
                $pseudo = $this->registerIp($m[0]);
                return $pseudo ?? $m[0];
            },
            $text
        ) ?? $text;

        /* 6. Menciones sueltas de entidades ya conocidas (longitud desc.). */
        $literals = [];
        foreach ($this->users as $key => $data) {
            $literals[$data['original']] = $data['pseudonimo'];
        }
        foreach ($this->hosts as $key => $data) {
            $literals[$data['original']] = $data['pseudonimo'];
        }
        foreach ($this->domains as $key => $data) {
            $literals[$data['original']] = $data['pseudonimo'];
        }
        foreach ($this->ips as $key => $data) {
            $literals[$data['original']] = $data['pseudonimo'];
        }

        uksort($literals, static fn($a, $b) => strlen((string)$b) <=> strlen((string)$a));
        foreach ($literals as $original => $pseudo) {
            $pattern = '/(?<![\pL\pN._-])' . preg_quote((string)$original, '/') . '(?![\pL\pN._-])/iu';
            $text = preg_replace($pattern, str_replace(['\\', '$'], ['\\\\', '\\$'], $pseudo), $text) ?? $text;
        }

        return $text;
    }

    /* =====================================================================
     * Validación post-anonimización (§7.6)
     * ================================================================== */

    private function validate(array $anon): void
    {
        $suspicious = 0;
        $clientHits = 0;
        $privateIps = 0;
        $originalHits = 0;

        $originals = [];
        foreach ([$this->users, $this->hosts, $this->domains] as $map) {
            foreach ($map as $data) {
                if (strlen((string)$data['original']) >= 4) {
                    $originals[] = strtolower((string)$data['original']);
                }
            }
        }

        $this->walkStrings($anon, function (string $s) use (&$suspicious, &$clientHits, &$privateIps, &$originalHits, $originals): void {
            if (preg_match('/(?<![A-Za-z0-9._-\x5c])([A-Za-z0-9._-]{2,})\x5c([A-Za-z0-9._$-]{1,})/u', $s, $m)) {
                if (!preg_match('/^DOM\d{3}$/i', $m[1]) && $this->looksLikeNetbios($m[1])) {
                    $suspicious++;
                }
            }
            foreach (array_keys($this->clientDomains) as $domain) {
                if (stripos($s, $domain) !== false && !str_contains($s, 'dom')) {
                    $clientHits++;
                }
            }
            if (preg_match_all('/\b(?:(?:10)\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})|172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3})\.(?:\d{1,3})|192\.168\.(?:\d{1,3})\.(?:\d{1,3}))\b/u', $s)) {
                $privateIps++;
            }
            $low = strtolower($s);
            foreach ($originals as $original) {
                if (str_contains($low, $original)) {
                    $originalHits++;
                    break;
                }
            }
        });

        if ($suspicious > 0) {
            $this->warnings[] = 'Quedan posibles pares DOMINIO\\usuario sin pseudonimizar; revísalos antes de enviar a la IA.';
        }
        if ($clientHits > 0) {
            $this->warnings[] = 'Se detectan menciones a dominios internos configurados en el caso pseudonimizado.';
        }
        if ($privateIps > 0) {
            $this->warnings[] = 'Quedan IPs privadas RFC1918 sin pseudonimizar.';
        }
        if ($originalHits > 0) {
            $this->warnings[] = 'Algún nombre original detectado previamente sigue presente en el texto.';
        }
    }

    /* =====================================================================
     * Utilidades
     * ================================================================== */

    private function isExcludedUser(string $name): bool
    {
        $low = strtolower(trim($name));
        if ($low === '') {
            return true;
        }
        if (in_array($low, self::EXCLUDED_USERS, true)) {
            return true;
        }
        if (preg_match('/^s-1-5-(18|19|20)$/', $low)) {
            return true;
        }
        if (str_starts_with($low, 's-1-5-32-')) {
            return true;
        }
        return false;
    }

    private function isPublicDomain(string $domain): bool
    {
        $domain = strtolower(trim($domain, '.'));
        foreach (self::PUBLIC_DOMAINS as $public) {
            if ($domain === $public || str_ends_with($domain, '.' . $public)) {
                return true;
            }
        }
        /* Un dominio con extensión de fichero no es un dominio. */
        $ext = strtolower((string)pathinfo($domain, PATHINFO_EXTENSION));
        if ($ext !== '' && in_array($ext, self::FILE_EXTENSIONS, true)) {
            return true;
        }
        return false;
    }

    private function looksLikeNetbios(string $domain): bool
    {
        $domain = trim($domain);
        if ($domain === '' || strlen($domain) < 2 || strlen($domain) > 63) {
            return false;
        }
        if (preg_match('/^[A-Za-z]:$/', $domain)) {
            return false;
        }
        if (in_array(strtolower($domain), self::PATH_SEGMENTS, true)) {
            return false;
        }
        if ($this->isPublicDomain($domain)) {
            return false;
        }
        /* Solo letras, números, guion y punto; sin espacios ni símbolos raros. */
        return (bool)preg_match('/^[A-Za-z0-9._-]+$/', $domain);
    }

    private function isPrivateIp(string $ip): bool
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }
        $isPublic = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
        return !$isPublic || str_starts_with($ip, '169.254.');
    }

    private function mapFor(array $map): array
    {
        $out = [];
        foreach ($map as $data) {
            $out[(string)$data['original']] = (string)$data['pseudonimo'];
        }
        return $out;
    }
}
