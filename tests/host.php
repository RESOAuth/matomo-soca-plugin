<?php
declare(strict_types=1);
require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/Fixture.php';

use RESOAuth\Soca\Client;
use RESOAuth\Soca\Tests\Fixture;
use RESOAuth\SocaHost\{Configuration, Flow, Host, Identity};

final class TestHost implements Host
{
    public array $session = [];
    public array $proof = [];
    public array $audit = [];
    public PDO $db;
    public function __construct(string $path = ':memory:')
    {
        $this->db = new PDO('sqlite:' . $path, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $this->db->exec('PRAGMA busy_timeout=5000');
        $this->db->exec('CREATE TABLE IF NOT EXISTS ticket (state_hash TEXT PRIMARY KEY,browser_hash TEXT,revision TEXT,expires INTEGER)');
    }
    public function get(string $key): mixed { return $this->session[$key] ?? null; }
    public function set(string $key, mixed $value): void { $this->session[$key] = $value; }
    public function remove(string $key): void { unset($this->session[$key]); }
    public function putTicket(string $stateHash, string $browserHash, string $revision, int $expires): void { $this->db->prepare('INSERT INTO ticket VALUES (?,?,?,?)')->execute([$stateHash,$browserHash,$revision,$expires]); }
    public function consumeTicket(string $stateHash, string $browserHash, string $revision, int $now): bool
    {
        $q = $this->db->prepare('DELETE FROM ticket WHERE state_hash=? AND browser_hash=? AND revision=? AND expires>?');
        $q->execute([$stateHash,$browserHash,$revision,$now]); return $q->rowCount() === 1;
    }
    public function purgeTickets(): void { $this->db->exec('DELETE FROM ticket'); }
    public function evidence(): array { return $this->proof; }
    public function saveEvidence(array $evidence): void { $this->proof = $evidence; }
    public function audit(string $event, string $reference): void { $this->audit[] = [$event,$reference]; }
}
$count = 0;
function assertion(bool $condition, string $name): void { global $count; ++$count; if (!$condition) { throw new RuntimeException('FAILED: ' . $name); } }
function denied(callable $run, string $name): void { try { $run(); } catch (Throwable) { assertion(true, $name); return; } assertion(false, $name); }
function fixtureConfig(): array
{
    openssl_pkey_export(openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']), $pem);
    return ['issuer' => 'https://issuer.example.com','origin' => 'https://app.example.com','redirect_uri' => 'https://app.example.com/soca/callback','metadata_uri' => 'https://app.example.com/soca/metadata','jwks_uri' => 'https://app.example.com/soca/jwks','private_key_pem' => $pem,'allowed_domains' => ['example.com'],'_state_key' => random_bytes(32),'enabled' => false,'provision' => false,'group_id' => 'readers','site_id' => 'main','session_max_age' => 900];
}
function attachFixture(Fixture $fixture, Client $client, TestHost $host, string $url, array $config): array
{
    parse_str((string)parse_url($url, PHP_URL_QUERY), $query);
    $state = $query['state']; $hash = hash('sha256', $state); $sealed = base64_decode($host->session['soca.tx.' . $hash]);
    $plain = openssl_decrypt(substr($sealed,28),'aes-256-gcm',hash('sha256',$config['_state_key'],true),OPENSSL_RAW_DATA,substr($sealed,0,12),substr($sealed,12,16),$hash . $host->session['soca.browser']);
    $fixture->client = $client; $fixture->transaction = json_decode($plain,true,32,JSON_THROW_ON_ERROR); $fixture->consumed = false;
    assertion(!str_contains($host->session['soca.tx.' . $hash], $fixture->transaction['verifier']), 'verifier sealed in native session');
    return $fixture->query();
}
$config = fixtureConfig(); $fixture = new Fixture(); $client = new Client(Configuration::protocol($config), $fixture); $fixture->client=$client;
$host = new TestHost(); $flow = new Flow($client,$host,$config);
denied(fn() => $flow->begin(), 'disabled ordinary login');
denied(fn() => $flow->begin(true, 'operator'), 'test needs document evidence');
$flow->checkDocuments();
assertion($flow->status()['documents_checked'] && !$flow->status()['test_login_succeeded'], 'documents and login evidence separate');
denied(fn() => $flow->begin(true), 'test needs local operator');
$url = $flow->begin(true,'operator'); $query = attachFixture($fixture,$client,$host,$url,$config);
$localBefore = $host->session; $localBefore['native.uid']='operator'; $host->session['native.uid']='operator';
assertion($flow->complete($query,'operator') === ['test'=>true], 'candidate real protocol fixture login');
assertion($host->session['native.uid']==='operator' && $flow->status()['test_login_succeeded'], 'test preserves operator session');
denied(fn() => $flow->complete($query,'operator'), 'replayed callback rejected');
$enabled = $config; $enabled['enabled']=true; $enabledClient = new Client(Configuration::protocol($enabled),$fixture); $fixture->client=$enabledClient; $ordinary = new Flow($enabledClient,$host,$enabled);
assertion($ordinary->revision() === $flow->revision(), 'enabling does not stale candidate evidence');
$url = $ordinary->begin(); $query = attachFixture($fixture,$enabledClient,$host,$url,$enabled);
$other = new TestHost(); $other->session = $host->session; $other->session['soca.browser']=bin2hex(random_bytes(32)); $other->db=$host->db;
$copied = new Flow($enabledClient,$other,$enabled);
denied(fn() => $copied->complete($query), 'copied callback rejected by browser binding');
assertion($ordinary->complete($query)['claims']['sub']==='stable-subject','copied callback cannot consume original browser transaction');
$url1=$ordinary->begin(); $q1=attachFixture($fixture,$enabledClient,$host,$url1,$enabled); $tx1=$fixture->transaction;
$url2=$ordinary->begin(); $q2=attachFixture($fixture,$enabledClient,$host,$url2,$enabled); $tx2=$fixture->transaction;
$fixture->transaction=$tx1; $fixture->consumed=false; assertion(!$ordinary->complete($q1)['test'],'first parallel tab');
$fixture->transaction=$tx2; $fixture->consumed=false; assertion(!$ordinary->complete($q2)['test'],'second parallel tab');
$url=$ordinary->begin();$q=attachFixture($fixture,$enabledClient,$host,$url,$enabled);
$changed=$enabled;$changed['group_id']='other-readers';$changedFlow=new Flow($enabledClient,$host,$changed);
denied(fn()=>$changedFlow->complete($q),'privilege-policy revision invalidates pending callback');
$url=$flow->begin(true,'operator');$q=attachFixture($fixture,$client,$host,$url,$config);
denied(fn()=>$flow->complete($q,'different-operator'),'candidate bound to initiating operator');
$url=$ordinary->begin();$q=attachFixture($fixture,$enabledClient,$host,$url,$enabled);
$hash=hash('sha256',$q['state']);$sealed=$host->session['soca.tx.'.$hash];$sealed[20]=$sealed[20]==='A'?'B':'A';$host->session['soca.tx.'.$hash]=$sealed;
denied(fn()=>$ordinary->complete($q),'sealed transaction tampering rejected');
$url=$ordinary->begin();$q=attachFixture($fixture,$enabledClient,$host,$url,$enabled);$host->db->exec('UPDATE ticket SET expires=0');
denied(fn()=>$ordinary->complete($q),'expired callback rejected');
putenv('SOCA_EMERGENCY_DISABLE=unexpected-value');
denied(fn()=>$ordinary->begin(),'any non-empty emergency switch blocks login');
denied(fn()=>$flow->begin(true,'operator'),'emergency blocks test login');
assertion((int)$host->db->query('SELECT COUNT(*) FROM ticket')->fetchColumn()===0,'emergency purges shared pending transactions');putenv('SOCA_EMERGENCY_DISABLE');
assertion(Identity::hash('https://issuer.example.com','subject')!==Identity::hash('https://other.example.com','subject'),'issuer isolates subjects');
denied(fn()=>Identity::hash('https://issuer.example.com',''),'empty subject rejected');
denied(fn()=>Identity::profile(['name'=>"bad\nname"]),'profile control characters rejected');
assertion(!isset(Identity::profile(['email'=>'person@example.com','email_verified'=>'true'])['email']),'email_verified must be boolean');
assertion(!isset(Configuration::redacted($enabled)['_state_key']) && !isset(Configuration::redacted($enabled)['private_key_pem']),'effective configuration is redacted');
// Separate workers/DB connections share a single-use atomic DELETE ledger.
$path=tempnam(sys_get_temp_dir(),'soca-race-');$raceA=new TestHost($path);$raceB=new TestHost($path);
$raceA->putTicket('state','browser','revision',time()+300);
assertion($raceB->consumeTicket('state','browser','revision',time()),'another worker can consume');
assertion(!$raceA->consumeTicket('state','browser','revision',time()),'first worker sees shared consumption');
if (function_exists('pcntl_fork')) {
    $raceA->putTicket('concurrent','browser','revision',time()+300);$results=[];$children=[];
    for($i=0;$i<2;$i++) { $out=$path.'.'.$i;$pid=pcntl_fork();if($pid===0){$worker=new TestHost($path);file_put_contents($out,$worker->consumeTicket('concurrent','browser','revision',time())?'1':'0');exit(0);} $children[]=[$pid,$out]; }
    foreach($children as [$pid,$out]){pcntl_waitpid($pid,$status);$results[]=file_get_contents($out);unlink($out);}sort($results);assertion($results===['0','1'],'concurrent workers consume exactly once');
}
unlink($path);
echo "Host coordination: $count assertions passed. Protocol fixture, not a live provider login.\n";
