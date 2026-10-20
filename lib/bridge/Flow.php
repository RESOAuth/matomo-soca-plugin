<?php
declare(strict_types=1);
namespace RESOAuth\SocaHost;

use RESOAuth\Soca\Client;
use RESOAuth\Soca\Policy;
use RuntimeException;

final class Flow
{
    public function __construct(private Client $client, private Host $host, private array $config) {}

    public function revision(): string { return Configuration::revision($this->client, $this->config); }

    private function available(): void
    {
        if (Configuration::emergencyDisabled()) {
            $this->host->purgeTickets();
            throw new RuntimeException('SSO is disabled by the deployment emergency switch.');
        }
    }

    public function checkDocuments(): array
    {
        $this->available();
        $result = $this->client->checkDocuments();
        $evidence = $this->host->evidence();
        if (($evidence['revision'] ?? '') !== $this->revision()) { $evidence = []; }
        $evidence['revision'] = $this->revision();
        $evidence['documents_at'] = time();
        $this->host->saveEvidence($evidence);
        $this->host->audit('documents_checked', $this->revision());
        return $result;
    }

    public function status(): array
    {
        $evidence = $this->host->evidence();
        $current = ($evidence['revision'] ?? '') === $this->revision();
        return [
            'revision' => $this->revision(), 'client_id' => $this->client->clientId(),
            'documents_checked' => $current && !empty($evidence['documents_at']),
            'test_login_succeeded' => $current && !empty($evidence['login_at']),
            'enabled' => ($this->config['enabled'] ?? false) && !Configuration::emergencyDisabled(),
            'emergency_disabled' => Configuration::emergencyDisabled(),
            'configuration' => Configuration::redacted($this->config),
        ];
    }

    public function begin(bool $test = false, string $operator = ''): string
    {
        $this->available();
        $status = $this->status();
        if ($test && $operator === '') { throw new RuntimeException('A locally authenticated operator is required.'); }
        if (!$status['documents_checked']) { throw new RuntimeException('Check the candidate public documents first.'); }
        if (!$test && (!$status['enabled'] || !$status['test_login_succeeded'])) {
            throw new RuntimeException('Ordinary SSO needs an enabled profile and a successful test for this revision.');
        }
        $binding = $this->host->get('soca.browser');
        if (!is_string($binding) || strlen($binding) !== 64) {
            $binding = bin2hex(random_bytes(32));
            $this->host->set('soca.browser', $binding);
        }
        $pending = $this->host->get('soca.pending') ?? [];
        if (!is_array($pending)) { $pending = []; }
        foreach ($pending as $key => $expiry) {
            if (!is_int($expiry) || $expiry <= time()) { $this->host->remove('soca.tx.' . $key); unset($pending[$key]); }
        }
        if (count($pending) >= 8) { throw new RuntimeException('Too many pending sign-ins. Finish a tab or wait five minutes.'); }
        $started = $this->client->start();
        $state = $started['state'];
        $transaction = $started['transaction'] + ['test' => $test, 'operator' => $operator];
        $hash = hash('sha256', $state);
        $this->host->putTicket($hash, hash('sha256', $binding), $this->revision(), time() + 300);
        $this->host->set('soca.tx.' . $hash, $this->encrypt($transaction, $hash . $binding));
        $pending[$hash] = time() + 300; $this->host->set('soca.pending', $pending);
        return $started['url'];
    }

    /** Consume before any network or account operation. Copied callbacks cannot consume another browser's ticket. */
    public function complete(array $query, string $currentOperator = ''): array
    {
        $this->available();
        $state = $query['state'] ?? null;
        if (!is_string($state) || strlen($state) < 32 || strlen($state) > 256) { throw new RuntimeException('Invalid callback state.'); }
        $hash = hash('sha256', $state);
        $binding = $this->host->get('soca.browser');
        $sealed = $this->host->get('soca.tx.' . $hash);
        if (!is_string($binding) || !is_string($sealed)) { throw new RuntimeException('No browser-bound transaction.'); }
        if (!$this->host->consumeTicket($hash, hash('sha256', $binding), $this->revision(), time())) {
            $this->host->remove('soca.tx.' . $hash);
            throw new RuntimeException('The transaction expired, changed or was already consumed.');
        }
        $this->host->remove('soca.tx.' . $hash);
        $pending = $this->host->get('soca.pending') ?? [];
        if (is_array($pending)) { unset($pending[$hash]); $this->host->set('soca.pending', $pending); }
        $transaction = $this->decrypt($sealed, $hash . $binding);
        if ($transaction['test'] && ($currentOperator === '' || !hash_equals($transaction['operator'], $currentOperator))) {
            throw new RuntimeException('The test must finish in the initiating operator session.');
        }
        if (!$transaction['test'] && !($this->config['enabled'] ?? false)) { throw new RuntimeException('SSO is disabled.'); }
        $claims = $this->client->complete($transaction, $query);
        Policy::assertAllowed($claims, $this->config);
        if ($transaction['test']) {
            $evidence = $this->host->evidence();
            if (($evidence['revision'] ?? '') !== $this->revision() || empty($evidence['documents_at'])) {
                throw new RuntimeException('Candidate document evidence changed.');
            }
            $evidence['login_at'] = time();
            $this->host->saveEvidence($evidence);
            $this->host->audit('test_login_succeeded', $this->revision());
            return ['test' => true];
        }
        return ['test' => false, 'claims' => $claims];
    }

    private function encrypt(array $value, string $associated): string
    {
        $iv = random_bytes(12);
        $cipher = openssl_encrypt(json_encode($value, JSON_THROW_ON_ERROR), 'aes-256-gcm', hash('sha256', $this->config['_state_key'], true), OPENSSL_RAW_DATA, $iv, $tag, $associated);
        if ($cipher === false) { throw new RuntimeException('Transaction encryption failed.'); }
        return base64_encode($iv . $tag . $cipher);
    }

    private function decrypt(string $value, string $associated): array
    {
        $raw = base64_decode($value, true);
        if ($raw === false || strlen($raw) < 29) { throw new RuntimeException('Invalid sealed transaction.'); }
        $plain = openssl_decrypt(substr($raw, 28), 'aes-256-gcm', hash('sha256', $this->config['_state_key'], true), OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, 12, 16), $associated);
        if ($plain === false) { throw new RuntimeException('Invalid transaction binding.'); }
        return json_decode($plain, true, 32, JSON_THROW_ON_ERROR);
    }
}
