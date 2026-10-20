<?php
declare(strict_types=1);
namespace RESOAuth\SocaHost;

use RESOAuth\Soca\Client;
use RESOAuth\Soca\Policy;
use RuntimeException;

final class Configuration
{
    /** The deployment file has absolute precedence. There are no database overrides. */
    public static function load(array $identity, array $paths): array
    {
        $file = getenv('SOCA_CONFIG_FILE') ?: '';
        if ($file === '' || !is_readable($file)) {
            throw new RuntimeException('Set SOCA_CONFIG_FILE to a readable deployment JSON file.');
        }
        $raw = file_get_contents($file);
        if ($raw === false || strlen($raw) > 65536) {
            throw new RuntimeException('The deployment configuration exceeds 65536 bytes.');
        }
        $data = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
        if (!is_array($data) || array_is_list($data)) {
            throw new RuntimeException('The deployment configuration must be a JSON object.');
        }
        $config = $data + $identity + [
            'issuer' => 'https://auth.resoauth.cloud', 'enabled' => false,
            'provision' => false, 'allowed_emails' => [], 'allowed_domains' => [],
            'denied_emails' => [], 'denied_domains' => [], 'session_max_age' => 900,
            'metadata_mode' => 'hosted', 'group_id' => '', 'site_id' => '',
        ];
        foreach (['enabled', 'provision'] as $key) {
            if (!is_bool($config[$key])) {
                throw new RuntimeException($key . ' must be a JSON boolean.');
            }
        }
        if (!is_int($config['session_max_age']) || $config['session_max_age'] < 60 || $config['session_max_age'] > 86400) {
            throw new RuntimeException('session_max_age must be an integer between 60 and 86400 seconds.');
        }
        $origin = rtrim((string)($config['origin'] ?? ''), '/');
        if (!preg_match('~^https://[^/?#@]+(?:/[^?#]*)?$~D', $origin) || str_contains($origin, '\\')) {
            throw new RuntimeException('origin must be the canonical HTTPS installation URL, including its path prefix.');
        }
        $config['client_uri'] ??= $origin;
        foreach ($paths as $key => $path) {
            $expected = $origin . $path;
            if (isset($config[$key]) && $config[$key] !== $expected) {
                throw new RuntimeException($key . ' must match the native host endpoint.');
            }
            $config[$key] = $expected;
        }
        foreach (['private_key_file', 'state_key_file'] as $key) {
            if (!isset($config[$key]) || !is_string($config[$key]) || !str_starts_with($config[$key], '/') || !is_readable($config[$key])) {
                throw new RuntimeException($key . ' must reference a readable absolute deployment secret file.');
            }
        }
        $config['private_key_pem'] = file_get_contents($config['private_key_file']);
        $config['_state_key'] = file_get_contents($config['state_key_file']);
        if (!is_string($config['_state_key']) || strlen($config['_state_key']) < 32 || strlen($config['_state_key']) > 4096) {
            throw new RuntimeException('state_key_file must contain between 32 and 4096 secret bytes.');
        }
        Policy::validate($config);
        return $config;
    }

    public static function protocol(array $config): array
    {
        foreach (['enabled', 'provision', 'group_id', 'site_id', 'session_max_age', 'private_key_file', 'state_key_file', '_state_key'] as $key) { unset($config[$key]); }
        return $config;
    }

    public static function emergencyDisabled(): bool
    {
        $value = getenv('SOCA_EMERGENCY_DISABLE');
        // Unknown non-empty values also disable SSO. An invalid switch cannot weaken recovery.
        return $value !== false && $value !== '' && $value !== '0';
    }

    public static function revision(Client $client, array $config): string
    {
        return hash('sha256', $client->revision() . json_encode([
            $config['provision'] ?? false, $config['group_id'] ?? '', $config['site_id'] ?? '',
            $config['session_max_age'] ?? 900, $config['allowed_emails'] ?? [], $config['allowed_domains'] ?? [],
            $config['denied_emails'] ?? [], $config['denied_domains'] ?? [], hash('sha256', $config['_state_key']),
        ], JSON_THROW_ON_ERROR));
    }

    public static function redacted(array $config): array
    {
        unset($config['private_key_pem'], $config['_state_key']);
        return $config + ['source' => 'deployment JSON, all fields locked'];
    }
}
