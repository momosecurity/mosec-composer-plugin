<?php

/*
 * Copyright 2020 momosecurity.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use Composer\Console\Application;
use Composer\Package\CompletePackage;
use Composer\Repository\LockArrayRepository;
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
        $this->repo = new LockArrayRepository();
        $package = new CompletePackage('phpunit/phpunit', '6.3.0.0', '6.3.0');
        $package->setDescription("fake description");
        $this->repo->addPackage($package);

        // set composer config to test 'valid-project' dir
        putenv('COMPOSER='.__DIR__.'/valid-project/composer.json');
    }

    public function testInstallDeps() {
        $method = new ReflectionMethod(\Momo\Sec\Command\CheckCommand::class, 'installDeps');
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

        $this->assertTrue(isset($installedDeps['phpunit/phpunit']));
        $this->assertEquals($installedDeps['phpunit/phpunit']->getPrettyVersion(), '6.3.0');
    }

    public function testBuildDepTree() {
        $method = new ReflectionMethod(\Momo\Sec\Command\CheckCommand::class, 'buildDepTree');
        $method->setAccessible(true);

        $command = $this->inspect->getCommands()[0];
        $command->setApplication($this->app);

        $depsTree = $method->invoke($command);
        $depsTree['dependencies']['phpunit/phpunit']['dependencies'] = [];
        $expect = [
            'name'          => 'momo/mosec-test-proj',
            'version'       => '1.0.3',
            'from'          => ['momo/mosec-test-proj@1.0.3'],
            'dependencies'  => [
                'phpunit/phpunit' => [
                    'name'          => 'phpunit/phpunit',
                    'version'       => '6.3.0',
                    'from'          => ['momo/mosec-test-proj@1.0.3', 'phpunit/phpunit@6.3.0'],
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

    /**
     * @throws ReflectionException
     */
    public function testRendererNotOKResponse() {
        $command = $this->inspect->getCommands()[0];
        $refClass = new ReflectionClass($command);
        $fFailOnVuln = $refClass->getProperty('failOnVuln');
        $mRendererResponse = $refClass->getMethod('rendererResponse');

        $fFailOnVuln->setAccessible(true);
        $mRendererResponse->setAccessible(true);

        $fFailOnVuln->setValue($command, true);
        $response = [
            'ok' => false,
            'dependencyCount' => 3,
            'vulnerabilities' => []
        ];
        $this->expectException(\Momo\Sec\Exception\FoundVulnException::class);
        $this->expectExceptionMessage(\Momo\Sec\Constants::ERROR_ON_VULNERABLE);
        $this->expectExceptionCode(1);
        $mRendererResponse->invoke($command, json_encode($response));
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