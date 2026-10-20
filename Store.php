<?php
declare(strict_types=1);
namespace Piwik\Plugins\Soca;

use Piwik\Common;
use Piwik\Db;
use Piwik\Log;
use Piwik\Session\SessionNamespace;
use RESOAuth\SocaHost\Host;

final class Store implements Host
{
    private ?SessionNamespace $session = null;
    private function session(): SessionNamespace { return $this->session ??= new SessionNamespace('Soca'); }
    public function get(string $key): mixed { return $this->session()->$key ?? null; }
    public function set(string $key, mixed $value): void { $this->session()->$key = $value; }
    public function remove(string $key): void { unset($this->session()->$key); }
    private function table(string $table): string { return Common::prefixTable('soca_' . $table); }
    public function putTicket(string $stateHash, string $browserHash, string $revision, int $expires): void
    {
        Db::query('DELETE FROM ' . $this->table('ticket') . ' WHERE expires < ?', [time()]);
        Db::query('INSERT INTO ' . $this->table('ticket') . ' (state_hash,browser_hash,revision,expires) VALUES (?,?,?,?)', [$stateHash,$browserHash,$revision,$expires]);
    }
    public function consumeTicket(string $stateHash, string $browserHash, string $revision, int $now): bool
    {
        return Db::query('DELETE FROM ' . $this->table('ticket') . ' WHERE state_hash=? AND browser_hash=? AND revision=? AND expires>?', [$stateHash,$browserHash,$revision,$now])->rowCount() === 1;
    }
    public function purgeTickets(): void { Db::query('DELETE FROM ' . $this->table('ticket')); }
    public function evidence(): array
    {
        $raw = Db::fetchOne('SELECT payload FROM ' . $this->table('evidence') . ' WHERE id=1');
        return $raw === false ? [] : json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
    }
    public function saveEvidence(array $evidence): void
    {
        Db::query('INSERT INTO ' . $this->table('evidence') . ' (id,payload) VALUES (1,?) ON DUPLICATE KEY UPDATE payload=VALUES(payload)', [json_encode($evidence, JSON_THROW_ON_ERROR)]);
    }
    public function audit(string $event, string $reference): void { Log::info('SOCA ' . $event . ' reference=' . $reference); }
    public function linkedUid(string $hash): ?string
    {
        $uid = Db::fetchOne('SELECT user_id FROM ' . $this->table('link') . ' WHERE identity_hash=?', [$hash]);
        return $uid === false ? null : (string)$uid;
    }
    public function link(string $hash, string $uid): void
    {
        Db::query('INSERT INTO ' . $this->table('link') . ' (identity_hash,user_id,created_at) VALUES (?,?,?)', [$hash,$uid,time()]);
        $this->audit('identity_linked', $hash);
    }
    public function unlink(string $hash): void
    {
        Db::query('DELETE FROM ' . $this->table('link') . ' WHERE identity_hash=?', [$hash]); $this->purgeTickets(); $this->audit('identity_unlinked', $hash);
    }
}
