<?php
declare(strict_types=1);
namespace Piwik\Plugins\Soca\Commands;

use Piwik\Plugins\Soca\Service;
use RESOAuth\SocaHost\Identity;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class Manage extends \Piwik\Plugin\ConsoleCommand
{
    private Service $service;
    protected function configure(): void
    {
        $this->setName('soca:manage')->setDescription('Inspect SOCA, check documents, invalidate transactions or approve identity links.');
        $this->addRequiredArgument('action', 'status|check|invalidate|link|unlink');
        foreach (['issuer','subject','uid','reason'] as $arg) { $this->addOptionalArgument($arg); }
    }
    protected function doExecute(): int
    {
        $input = $this->getInput(); $output = $this->getOutput(); $this->service = new Service();
        try {
            $action = $input->getArgument('action');
            if ($action === 'status') { $result = $this->service->flow()->status(); }
            elseif ($action === 'check') { $result = $this->service->flow()->checkDocuments(); }
            elseif ($action === 'invalidate') { $this->service->store()->purgeTickets(); $result = ['transactions_invalidated' => true]; }
            elseif (in_array($action, ['link','unlink'], true)) {
                if ($input->getArgument('issuer') !== $this->service->config()['issuer'] || !$input->getArgument('reason')) { throw new \RuntimeException('Exact configured issuer and an approval reason are required.'); }
                $hash = Identity::hash($input->getArgument('issuer'), (string)$input->getArgument('subject'));
                if ($action === 'link') { $user = $this->service->eligible((string)$input->getArgument('uid')); $this->service->store()->link($hash, $user['login']); }
                else { $this->service->store()->unlink($hash); }
                $this->service->store()->audit('administrator_approval', hash('sha256', $input->getArgument('reason')));
                $result = ['action' => $action, 'identity_reference' => $hash];
            } else { throw new \RuntimeException('Unknown action.'); }
            $output->writeln(json_encode($result, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));
            return Command::SUCCESS;
        } catch (\Throwable $e) { $output->writeln('<error>' . htmlspecialchars($e->getMessage(), ENT_QUOTES) . '</error>'); return Command::FAILURE; }
    }
}
