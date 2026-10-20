<?php
declare(strict_types=1);
$root = dirname(__DIR__); $count = 0;
$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
foreach ($iterator as $file) {
    $relative = substr($file->getPathname(),strlen($root)+1);
    if ($file->getExtension() !== 'php' || preg_match('~^(vendor|build|demo/data|demo/secrets|demo/project/vendor|demo/project/public|demo/project/config|demo/project/var)/~',$relative)) { continue; }
    $process = proc_open([PHP_BINARY,'-l',$file->getPathname()],[1=>['pipe','w'],2=>['pipe','w']],$pipes);
    $out=stream_get_contents($pipes[1]);$error=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);
    if (proc_close($process)!==0) { fwrite(STDERR,$out.$error);exit(1); } ++$count;
}
echo "Syntax: $count PHP files passed.\n";
