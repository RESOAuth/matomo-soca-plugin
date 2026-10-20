<?php
declare(strict_types=1);
namespace Piwik\Plugins\Soca;

use Piwik\Auth\Password;
use Piwik\Common;
use Piwik\Concurrency\Lock;
use Piwik\Container\StaticContainer;
use Piwik\Date;
use Piwik\Db;
use Piwik\Piwik;
use Piwik\Plugins\UsersManager\Model;
use Piwik\Plugins\UsersManager\UsersManager;
use Piwik\Plugins\UsersManager\Validators\Email;
use Piwik\Plugins\UsersManager\Validators\Login;
use Piwik\Session\SessionFingerprint;
use Piwik\Validators\BaseValidator;
use RESOAuth\Soca\Client;
use RESOAuth\SocaHost\Configuration;
use RESOAuth\SocaHost\Flow;
use RESOAuth\SocaHost\Identity;
use RuntimeException;

final class Service
{
    public function config(): array
    {
        return Configuration::load(['client_name' => 'Matomo Analytics'], [
            'redirect_uri' => '/index.php?module=Soca&action=callback', 'metadata_uri' => '/index.php?module=Soca&action=metadata', 'jwks_uri' => '/index.php?module=Soca&action=jwks',
        ]);
    }
    public function client(): Client { return new Client(Configuration::protocol($this->config())); }
    public function store(): Store { return new Store(); }
    public function flow(): Flow { $c = $this->config(); return new Flow(new Client(Configuration::protocol($c)), $this->store(), $c); }
    public function operator(): string { return Piwik::hasUserSuperUserAccess() ? (string)Piwik::getCurrentUserLogin() : ''; }
    public function eligible(string $uid): array
    {
        $c = $this->config(); $row = (new Model())->getUser($uid);
        $access = Common::prefixTable('access');
        $view = Db::fetchOne("SELECT COUNT(*) FROM `$access` WHERE login=? AND idsite=? AND access='view'", [$uid,(int)$c['site_id']]);
        $admin = Db::fetchOne("SELECT COUNT(*) FROM `$access` WHERE login=? AND access='admin'", [$uid]);
        if (!$row || $uid === 'anonymous' || !empty($row['superuser_access']) || !empty($row['invite_token']) || empty($row['password']) || !$view || $admin) { throw new RuntimeException('The linked local account is unavailable or is not an eligible viewer.'); }
        return $row;
    }
    public function account(array $claims): array
    {
        $c = $this->config(); $store = $this->store(); $hash = Identity::hash($c['issuer'], $claims['sub']);
        $uid = $store->linkedUid($hash); if ($uid !== null) { return $this->eligible($uid); }
        if (!$c['provision']) { throw new RuntimeException('No approved local account link exists.'); }
        if ($c['group_id'] !== 'view' || !ctype_digit((string)$c['site_id']) || (int)$c['site_id'] < 1) { throw new RuntimeException('Provisioning requires group_id=view and one explicit site_id.'); }
        $site = Db::fetchOne('SELECT idsite FROM ' . Common::prefixTable('site') . ' WHERE idsite=?', [(int)$c['site_id']]);
        if (!$site) { throw new RuntimeException('The configured site is unavailable.'); }
        foreach (['user','access','soca_link'] as $table) {
            $engine = Db::fetchRow('SHOW TABLE STATUS WHERE Name=?', [Common::prefixTable($table)]);
            if (strtoupper((string)($engine['Engine'] ?? '')) !== 'INNODB') { throw new RuntimeException('Atomic provisioning requires InnoDB user, access and link tables.'); }
        }
        $profile = Identity::profile($claims);
        if (!isset($profile['email'])) { throw new RuntimeException('A validated verified email is required to create a Matomo user.'); }
        $uid = Identity::generatedUid($hash);
        $lock = StaticContainer::getContainer()->make(Lock::class, ['namespace' => 'UsersManager']);
        $lock->execute('createUser', function () use ($uid, $profile, $hash, $c, $store): void {
            $model = new Model();
            BaseValidator::check('SOCA username', $uid, [new Login(false)]);
            BaseValidator::check('SOCA email', $profile['email'], [new Email(false)]);
            Db::get()->beginTransaction();
            try {
                if ($model->userExists($uid) || $model->getUserByEmail($profile['email'])) { throw new RuntimeException('Account or email collision requires administrator recovery.'); }
                $password = (new Password())->hash(UsersManager::getPasswordHash(base64_encode(random_bytes(64))));
                $model->addUser($uid, $password, $profile['email'], Date::now()->getDatetime());
                $model->addUserAccess($uid, 'view', [(int)$c['site_id']]);
                $store->link($hash, $uid); Db::get()->commit();
                $store->audit('account_provisioned', $hash);
            } catch (\Throwable $e) { Db::get()->rollBack(); throw $e; }
        });
        return $this->eligible($uid);
    }
    public function enforceSession(): void
    {
        $store = $this->store(); $marker = $store->get('soca.auth');
        if (!is_array($marker)) { return; }
        try {
            $c = $this->config();
            $valid = $c['enabled'] && !Configuration::emergencyDisabled() && hash_equals($this->flow()->revision(), (string)$marker['revision']) && time() < $marker['at'] + $c['session_max_age'];
            if ($valid) { $this->eligible($marker['uid']); return; }
        } catch (\Throwable) { /* A failed deployment closes SOCA sessions. */ }
        $store->remove('soca.auth'); (new SessionFingerprint())->clear();
        if (Configuration::emergencyDisabled()) { $store->purgeTickets(); }
    }
}
