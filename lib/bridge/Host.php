<?php
declare(strict_types=1);
namespace RESOAuth\SocaHost;

/** Native session plus a shared, atomic replay ledger. Never store tokens here. */
interface Host
{
    public function get(string $key): mixed;
    public function set(string $key, mixed $value): void;
    public function remove(string $key): void;
    public function putTicket(string $stateHash, string $browserHash, string $revision, int $expires): void;
    public function consumeTicket(string $stateHash, string $browserHash, string $revision, int $now): bool;
    public function purgeTickets(): void;
    public function evidence(): array;
    public function saveEvidence(array $evidence): void;
    public function audit(string $event, string $reference): void;
}
