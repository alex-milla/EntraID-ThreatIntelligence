<?php
/**
 * Alias de autocarga para CveZipReader: la clase vive en cve_list_feed.php,
 * pero el autoloader busca `cve_zip_reader.php` por el nombre de la clase.
 */

declare(strict_types=1);

require_once __DIR__ . '/cve_list_feed.php';
