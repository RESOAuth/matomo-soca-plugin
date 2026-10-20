<?php
declare(strict_types=1);
namespace Piwik\Plugins\Soca;

use Piwik\AuthResult;

/** Ephemeral adapter passed to the native initializer only after verified OIDC admission. */
final class VerifiedAuth extends \Piwik\Plugins\Login\Auth
{
    public function __construct(private string $uid) { parent::__construct(); $this->setLogin($uid); }
    public function authenticate(): AuthResult
    {
        (new Service())->eligible($this->uid);
        return new AuthResult(AuthResult::SUCCESS, $this->uid, bin2hex(random_bytes(32)));
    }
}
