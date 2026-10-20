<?php
declare(strict_types=1);
namespace Piwik\Plugins\Soca;
final class Menu extends \Piwik\Plugin\Menu
{
    public function configureAdminMenu(\Piwik\Menu\MenuAdmin $menu): void
    {
        if (\Piwik\Piwik::hasUserSuperUserAccess()) { $menu->addSystemItem('SOCA sign-in', $this->urlForAction('index'), 35); }
    }
}
