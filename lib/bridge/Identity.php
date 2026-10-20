<?php
declare(strict_types=1);
namespace RESOAuth\SocaHost;

use RuntimeException;

final class Identity
{
    public static function hash(string $issuer, string $subject): string
    {
        if ($issuer === '' || $subject === '' || strlen($subject) > 255 || str_contains($subject, "\0")) {
            throw new RuntimeException('Invalid issuer or subject.');
        }
        return hash('sha256', $issuer . "\0" . $subject);
    }
    public static function generatedUid(string $hash): string { return 'soca_' . substr($hash, 0, 24); }
    public static function profile(array $claims): array
    {
        $result = [];
        foreach (['name' => 255, 'given_name' => 100, 'family_name' => 100, 'preferred_username' => 100, 'email' => 254] as $field => $limit) {
            if (!isset($claims[$field])) { continue; }
            $value = $claims[$field];
            if (!is_string($value) || strlen($value) > $limit || preg_match('/[\x00-\x1f\x7f]/', $value)) {
                throw new RuntimeException('Invalid profile field: ' . $field);
            }
            if ($field === 'email' && (!filter_var($value, FILTER_VALIDATE_EMAIL) || ($claims['email_verified'] ?? null) !== true)) { continue; }
            $result[$field] = $value;
        }
        return $result;
    }
}
