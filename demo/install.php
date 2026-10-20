<?php
declare(strict_types=1);
// Disposable demo bootstrap. No outbound mail or newsletter actions are called.
if (getenv('SOCA_NATIVE_TESTS') !== '1') { throw new RuntimeException('Disposable demo only.'); }
define('PIWIK_DOCUMENT_ROOT','/var/www/html');define('PIWIK_INCLUDE_PATH',PIWIK_DOCUMENT_ROOT);
require PIWIK_INCLUDE_PATH . '/core/bootstrap.php';
// The native CLI environment requires a readable local configuration before init.
// Seed it through Matomo's INI writer, preserving PHP access protection and escaping.
if (!is_file(PIWIK_INCLUDE_PATH . '/config/config.ini.php')) {
    $deployment = json_decode(file_get_contents(getenv('SOCA_CONFIG_FILE')), true, 32, JSON_THROW_ON_ERROR);
    $host = parse_url($deployment['origin'], PHP_URL_HOST);
    $port = parse_url($deployment['origin'], PHP_URL_PORT);
    (new \Matomo\Ini\IniWriter())->writeToFile(PIWIK_INCLUDE_PATH . '/config/config.ini.php', [
        'database' => ['host' => 'db', 'username' => 'matomo', 'password' => trim(file_get_contents('/run/soca/db-password')), 'dbname' => 'matomo', 'tables_prefix' => 'matomo_', 'adapter' => 'PDO\\MYSQL', 'schema' => 'Mysql', 'type' => 'InnoDB', 'charset' => 'utf8mb4', 'collation' => 'utf8mb4_general_ci'],
        'General' => ['salt' => bin2hex(random_bytes(32)), 'trusted_hosts' => [$host . ($port ? ':' . $port : '')], 'installation_in_progress' => 1, 'enable_update_communication' => 0, 'enable_internet_features' => 0],
    ], "; <?php exit; ?>\n");
}
$environment=new \Piwik\Application\Environment('cli');$environment->init();
$config=\Piwik\Config::getInstance();
$config->database=['host'=>'db','username'=>'matomo','password'=>trim(file_get_contents('/run/soca/db-password')),'dbname'=>'matomo','tables_prefix'=>'matomo_','adapter'=>'PDO\\MYSQL','schema'=>'Mysql','type'=>'InnoDB','charset'=>'utf8mb4','collation'=>'utf8mb4_general_ci'];
$config->General['salt']=bin2hex(random_bytes(32));$deployment=json_decode(file_get_contents(getenv('SOCA_CONFIG_FILE')),true,32,JSON_THROW_ON_ERROR);$config->General['trusted_hosts']=[parse_url($deployment['origin'],PHP_URL_HOST).(parse_url($deployment['origin'],PHP_URL_PORT)?':'.parse_url($deployment['origin'],PHP_URL_PORT):'')];$config->General['enable_update_communication']=0;$config->General['enable_internet_features']=0;$config->forceSave();
\Piwik\Db::createDatabaseObject();\Piwik\DbHelper::createTables();\Piwik\DbHelper::createAnonymousUser();\Piwik\DbHelper::recordInstallVersion();
new \Piwik\Updater(); \Piwik\Updater::recordComponentSuccessfullyUpdated('core',\Piwik\Version::VERSION);
$model=new \Piwik\Plugins\UsersManager\Model();
$password=(new \Piwik\Auth\Password())->hash(\Piwik\Plugins\UsersManager\UsersManager::getPasswordHash(trim(file_get_contents('/run/soca/admin-password'))));
if (!$model->userExists('localadmin')) { $model->addUser('localadmin',$password,'localadmin@example.invalid',\Piwik\Date::now()->getDatetime()); } $model->setSuperUserAccess('localadmin',true);
\Piwik\Plugin\Manager::getInstance()->loadActivatedPlugins();
\Piwik\Plugin\Manager::getInstance()->installLoadedPlugins();
\Piwik\Access::doAsSuperUser(static function(): void { \Piwik\Plugins\SitesManager\API::getInstance()->addSite('SOCA demo','https://example.invalid'); });
\Piwik\Plugin\Manager::getInstance()->activatePlugin('Soca');
$config->General['installation_in_progress'] = 0; $config->forceSave();
echo "Matomo demo installed and SOCA activated. Credentials are in the ignored local secrets directory.\n";
