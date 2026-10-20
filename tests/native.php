<?php
declare(strict_types=1);
if (getenv('SOCA_NATIVE_TESTS') !== '1') { throw new RuntimeException('Disposable demo only.'); }
define('PIWIK_DOCUMENT_ROOT','/var/www/html');define('PIWIK_INCLUDE_PATH',PIWIK_DOCUMENT_ROOT);require PIWIK_INCLUDE_PATH.'/core/bootstrap.php';
$environment=new \Piwik\Application\Environment('cli');$environment->init();\Piwik\Plugin\Manager::getInstance()->loadActivatedPlugins();
require __DIR__.'/../vendor/autoload.php';
use Piwik\Plugins\Soca\{Service,Store};use RESOAuth\SocaHost\Identity;
$service=new Service();$store=new Store();$model=new \Piwik\Plugins\UsersManager\Model();$count=0;
function nativeCheck(bool $ok,string $name):void{global $count;++$count;if(!$ok){throw new RuntimeException($name);}}
function nativeDeny(callable $fn,string $name):void{try{$fn();}catch(Throwable){nativeCheck(true,$name);return;}nativeCheck(false,$name);}
$uid='soca_test_'.bin2hex(random_bytes(6));$sub='native-'.bin2hex(random_bytes(8));$hash=Identity::hash($service->config()['issuer'],$sub);
$configPath=tempnam('/tmp','soca-native-');$original=getenv('SOCA_CONFIG_FILE');$provisioned=null;
try{
 $password=(new \Piwik\Auth\Password())->hash(\Piwik\Plugins\UsersManager\UsersManager::getPasswordHash(base64_encode(random_bytes(64))));
 $model->addUser($uid,$password,'native-'.bin2hex(random_bytes(6)).'@example.com',\Piwik\Date::now()->getDatetime());$model->addUserAccess($uid,'view',[1]);
 nativeDeny(fn()=>$service->account(['sub'=>$sub,'email'=>$model->getUser($uid)['email'],'email_verified'=>true]),'Email must never select existing account');
 $store->link($hash,$uid);nativeCheck($service->account(['sub'=>$sub])['login']===$uid,'Explicit native identity link resolves');nativeDeny(fn()=>$store->link($hash,$uid),'Unique native identity constraint');
 $model->deleteUserAccess($uid);nativeDeny(fn()=>$service->account(['sub'=>$sub]),'Missing site access denies login');$model->addUserAccess($uid,'view',[1]);
 $model->setSuperUserAccess($uid,true);nativeDeny(fn()=>$service->account(['sub'=>$sub]),'Protected superuser denied');$model->setSuperUserAccess($uid,false);
 $state=hash('sha256',random_bytes(32));$store->putTicket($state,'browser','revision',time()+300);nativeCheck(!$store->consumeTicket($state,'copied','revision',time()),'Copied callback denied');nativeCheck($store->consumeTicket($state,'browser','revision',time()),'Native callback consumed');nativeCheck(!$store->consumeTicket($state,'browser','revision',time()),'Native replay denied');
 $deployment=json_decode(file_get_contents($original),true,32,JSON_THROW_ON_ERROR);$deployment['provision']=true;file_put_contents($configPath,json_encode($deployment,JSON_THROW_ON_ERROR));putenv('SOCA_CONFIG_FILE='.$configPath);
 $newSub='provision-'.bin2hex(random_bytes(8));$newHash=Identity::hash($service->config()['issuer'],$newSub);$provisioned=$service->account(['sub'=>$newSub,'email'=>'native-'.bin2hex(random_bytes(6)).'@example.com','email_verified'=>true]);
 nativeCheck(!$provisioned['superuser_access'],'Native provisioning creates non-superuser');nativeCheck($service->account(['sub'=>$newSub])['login']===$provisioned['login'],'Returning identity resolves stable native account');
 $store->unlink($newHash);$model->deleteUser($provisioned['login']);$provisioned=null;
 $store->unlink($hash);nativeCheck($model->userExists($uid),'Unlink preserves native account');
 echo "Matomo native host: $count assertions passed. No live provider login.\n";
}finally{putenv('SOCA_CONFIG_FILE='.$original);$store->unlink($hash);$model->deleteUser($uid);if($provisioned!==null){$model->deleteUser($provisioned['login']);}unlink($configPath);}
