<?php
declare(strict_types=1);
namespace Piwik\Plugins\Soca;

require_once __DIR__ . '/vendor/autoload.php';

use Piwik\Common;
use Piwik\Db;
use Piwik\Plugin;

final class Soca extends Plugin
{
    public function registerEvents(): array
    {
        return ['Template.loginNav' => 'loginLink', 'Request.initAuthenticationObject' => 'checkSession'];
    }
    public function loginLink(&$html, $position): void
    {
        if ($position === 'bottom') { $html .= '<li><a href="index.php?module=Soca&amp;action=start">Sign in with SOCA</a></li>'; }
    }
    public function checkSession(): void { if (!Common::isPhpCliMode()) { (new Service())->enforceSession(); } }
    public function install(): void
    {
        $ticket = Common::prefixTable('soca_ticket'); $link = Common::prefixTable('soca_link'); $evidence = Common::prefixTable('soca_evidence');
        Db::exec("CREATE TABLE IF NOT EXISTS `$ticket` (state_hash CHAR(64) NOT NULL PRIMARY KEY, browser_hash CHAR(64) NOT NULL, revision CHAR(64) NOT NULL, expires BIGINT NOT NULL, INDEX expiry (expires)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        Db::exec("CREATE TABLE IF NOT EXISTS `$link` (identity_hash CHAR(64) NOT NULL PRIMARY KEY, user_id VARCHAR(100) NOT NULL, created_at BIGINT NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        Db::exec("CREATE TABLE IF NOT EXISTS `$evidence` (id INT NOT NULL PRIMARY KEY, payload TEXT NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    }
    public function deactivate(): void { (new Store())->purgeTickets(); }
    // Uninstall deliberately preserves account links. Permanent deletion is a documented operator action.
}
