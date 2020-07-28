<?php

use Composer\Console\Application;
use Composer\Package\CompletePackage;
use Composer\Repository\InstalledArrayRepository;
use Momo\Sec\Inspect;
use PHPUnit\Framework\TestCase;

class CheckCommandTest extends TestCase {

    private $inspect;

    // fake
    private $app;
    private $repo;

    protected function setup() {
        $this->inspect = new Inspect();

        $this->app = new Application();
        $this->repo = new InstalledArrayRepository();
        $package = new CompletePackage('phpunit/phpunit', '6.3.0.0', '6.3.0');
        $package->setDescription("fake description");
        $this->repo->addPackage($package);

        // set composer config to test 'valid-project' dir
        putenv('COMPOSER='.__DIR__.'/valid-project/composer.json');

        $this->app->getComposer()->getRepositoryManager()->setLocalRepository($this->repo);
    }

    public function testGetDeps() {
        $method = new ReflectionMethod(\Momo\Sec\Command\CheckCommand::class, 'getDeps');
        $method->setAccessible(true);

        $command = $this->inspect->getCommands()[0];
        $command->setApplication($this->app);

        $method->invoke($command);

        $installedDeps = null;
        $reflect = new ReflectionClass($command);
        $props = $reflect->getProperties(ReflectionProperty::IS_PRIVATE | ReflectionProperty::IS_PROTECTED);

        foreach ($props as $prop) {
            $prop->setAccessible(true);
            if ($prop->getName() === 'installedDeps') {
                $installedDeps = $prop->getValue($command);
                break;
            }
        }

        $this->assertEquals($installedDeps, ['phpunit/phpunit' => '6.3.0']);
    }

    public function testBuildDepTree() {
        $method = new ReflectionMethod(\Momo\Sec\Command\CheckCommand::class, 'buildDepTree');
        $method->setAccessible(true);

        $command = $this->inspect->getCommands()[0];
        $command->setApplication($this->app);

        $depsTree = $method->invoke($command);
        $expect = [
            'name'          => 'mosec-test-proj',
            'version'       => '1.0.3',
            'from'          => ['mosec-test-proj@1.0.3'],
            'dependencies'  => [
                'phpunit/phpunit' => [
                    'name'          => 'phpunit/phpunit',
                    'version'       => '6.3.0',
                    'from'          => ['mosec-test-proj@1.0.3', 'phpunit/phpunit@6.3.0'],
                    'dependencies'  =>[]
                ]
            ]
        ];
        $this->assertEquals($expect, $depsTree);
    }

    public function testRendererOKResponse() {
        $method = new ReflectionMethod(\Momo\Sec\Command\CheckCommand::class, 'rendererResponse');
        $method->setAccessible(true);

        $response = [
            'ok' => true,
            'dependencyCount' => 0
        ];
        $method->invoke($this->inspect->getCommands()[0], json_encode($response));
        $this->assertTrue(true);
    }

    public function testRendererNotOKResponse() {
        $method = new ReflectionMethod(\Momo\Sec\Command\CheckCommand::class, 'rendererResponse');
        $method->setAccessible(true);

        $response = [
            'ok' => false,
            'dependencyCount' => 3,
            'vulnerabilities' => []
        ];
        $this->expectException(\Momo\Sec\Exception\FoundVulnException::class);
        $this->expectExceptionMessage(\Momo\Sec\Constants::ERROR_ON_VULNERABLE);
        $this->expectExceptionCode(1);
        $method->invoke($this->inspect->getCommands()[0], json_encode($response));
    }

    public function testPrintSingleVuln() {
        $vuln = [
            'severity'          => 'High',
            'title'             => 'title',
            'cve'               => 'CVE-0000-0001',
            'packageName'       => 'studyPackage',
            'version'           => '1.0.0',
            'from'              => ['parent@1.0.0', 'studyPackage@1.0.0'],
            'target_version'     => '1.0.1'
        ];

        $command = $this->inspect->getCommands()[0];
        $bufferIO = new \Composer\IO\BufferIO();
        $command->setIO($bufferIO);

        $method = new ReflectionMethod(\Momo\Sec\Command\CheckCommand::class, 'printSingleVuln');
        $method->setAccessible(true);
        $method->invoke($command, $vuln);

        $expect = <<<EOF
✗ High severity vulnerability (title - CVE-0000-0001) found on studyPackage@1.0.0
- From: parent@1.0.0 > studyPackage@1.0.0
! Fix version "1.0.1"


EOF;
        $this->assertEquals($expect, $bufferIO->getOutput());

    }
}