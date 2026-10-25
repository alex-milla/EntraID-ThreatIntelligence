<?php
/**
 * Lista la navegación de módulos activos (CLI).
 * Uso: php tools/smoke/modules.php
 */

declare(strict_types=1);

require dirname(__DIR__, 2) . '/public_html/config/bootstrap.php';

foreach (ModuleManager::getNavigation() as $item) {
    echo $item['label'] . ' -> ' . $item['url'] . PHP_EOL;
}
