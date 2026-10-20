<?php
declare(strict_types=1);
namespace Piwik\Plugins\Soca;

use Piwik\Nonce;
use Piwik\Piwik;
use Piwik\Session\SessionInitializer;
use Piwik\Url;
use RuntimeException;

final class Controller extends \Piwik\Plugin\ControllerAdmin
{
    public function metadata(): string { return $this->json((new Service())->client()->metadata(), true); }
    public function jwks(): string { return $this->json((new Service())->client()->jwks(), true); }
    public function start(): string
    {
        try {
            if (!\Piwik\ProxyHttp::isHttps()) { throw new RuntimeException('HTTPS is required.'); }
            if (Piwik::getCurrentUserLogin() !== 'anonymous') { throw new RuntimeException('A local session must not be replaced.'); }
            Url::redirectToUrl((new Service())->flow()->begin()); return '';
        } catch (\Throwable) { return $this->failure(); }
    }
    public function callback(): string
    {
        try {
            if (!\Piwik\ProxyHttp::isHttps()) { throw new RuntimeException('HTTPS is required.'); }
            $service = new Service();
            $result = $service->flow()->complete($_GET, $service->operator());
            if ($result['test']) { return $this->json(['test_login_succeeded' => true, 'operator_session_preserved' => true]); }
            if (Piwik::getCurrentUserLogin() !== 'anonymous') { throw new RuntimeException('A local session must not be replaced.'); }
            $account = $service->account($result['claims']);
            (new SessionInitializer())->initSession(new VerifiedAuth($account['login']));
            $service->store()->set('soca.auth', ['uid' => $account['login'], 'revision' => $service->flow()->revision(), 'at' => time()]);
            Url::redirectToUrl($service->config()['origin'] . '/index.php?module=CoreHome&action=index&idSite=' . (int)$service->config()['site_id']); return '';
        } catch (\Throwable) { return $this->failure(); }
    }
    public function index(): string
    {
        Piwik::checkUserHasSuperUserAccess(); $service = new Service(); $message = '';
        try {
            if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
                if (!Nonce::verifyNonce('Soca.actions', (string)($_POST['nonce'] ?? ''))) { throw new RuntimeException('Expired form.'); }
                if (($_POST['operation'] ?? '') === 'test') { if (!\Piwik\ProxyHttp::isHttps()) { throw new RuntimeException('HTTPS is required.'); } Url::redirectToUrl($service->flow()->begin(true, $service->operator())); return ''; }
                $service->flow()->checkDocuments(); $message = 'Public documents checked. Complete a real candidate test before enabling ordinary sign-in.';
            }
            $status = json_encode($service->flow()->status(), JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
        } catch (\Throwable) { $status = 'Configuration or document check failed. Use console soca:manage status/check for deployment diagnostics.'; }
        return $this->renderTemplate('index', ['status' => $status, 'message' => $message, 'socaNonce' => Nonce::getNonce('Soca.actions')]);
    }
    private function json(array $data, bool $public = false): string
    {
        header('Content-Type: application/json; charset=utf-8'); header('Cache-Control: ' . ($public ? 'public, max-age=300' : 'no-store'));
        return json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }
    private function failure(): string
    {
        http_response_code(403); $reference = bin2hex(random_bytes(8)); (new Store())->audit('login_rejected', $reference);
        return $this->json(['error' => 'SOCA could not complete this action. Check deployment configuration, candidate evidence, admission and account links.', 'reference' => $reference]);
    }
}
