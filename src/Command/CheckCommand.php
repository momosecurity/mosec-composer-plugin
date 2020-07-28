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

namespace Momo\Sec\Command;


use Composer\Command\ShowCommand;
use Composer\IO\IOInterface;
use Composer\Package\Version\VersionParser;
use Composer\Repository\PlatformRepository;
use Composer\Repository\RepositoryInterface;
use Momo\Sec\Constants;
use Momo\Sec\Exception\APIException;
use Momo\Sec\Exception\DependenciesNotFoundException;
use Momo\Sec\Exception\FoundVulnException;
use Momo\Sec\Exception\NetworkException;
use Momo\Sec\Inspect;
use Momo\Sec\CurlClient;
use RuntimeException;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class CheckCommand extends ShowCommand {

    /**
     * @var Inspect
     */
    protected $inspect;

    /**
     * @var VersionParser
     */
    protected $versionParser;

    /**
     * @var array name:version pair
     */
    protected $systemDeps;

    /**
     * @var array name:version pair
     */
    protected $installedDeps;

    /**
     * 上报API
     * @var string
     */
    protected $endpoint;

    /**
     * 仅检查直接依赖
     * @var bool
     */
    protected $onlyProvenance = false;

    /**
     * 发现漏洞即编译失败
     * @var bool
     */
    protected $failOnVuln = true;

    public function __construct(Inspect $inspect, $name = null) {
        $this->inspect = $inspect;
        $this->versionParser = new VersionParser;
        parent::__construct($name);
    }

    protected function configure() {
        $this->setName('mosec:test')
            ->addOption('endpoint', '', InputOption::VALUE_REQUIRED, '上报API', '')
            ->addOption('severityLevel', '', InputOption::VALUE_OPTIONAL, '设置威胁等级 [High|Medium|Low]', 'High')
            ->addOption('onlyProvenance', '', InputOption::VALUE_NONE, '仅检查直接依赖', null)
            ->addOption('noExcept', '', InputOption::VALUE_NONE, '发现漏洞不抛出异常', null)
            ->setDescription('check vulnerabilities on package.lock')
            ->setHelp(<<<EOF
cmd> composer mosec:test --onlyProvenance --endpoint=https://your/api
EOF
);
    }

    protected function execute(InputInterface $input, OutputInterface $output) {
        $this->endpoint = $input->getOption('endpoint');
        if (empty($this->endpoint)) {
            throw new RuntimeException(Constants::ERROR_ON_NULL_ENDPOINT);
        }

        $this->onlyProvenance = $input->getOption('onlyProvenance');
        $this->failOnVuln = !$input->getOption('noExcept');

        $this->getDeps();
        $depTree = $this->buildDepTree();
        $depTree['type'] = Constants::BUILD_TOOL_TYPE;
        $depTree['language'] = Constants::PROJECT_LANGUAGE;
        $depTree['severityLevel'] = $input->getOption('severityLevel');

        $this->log(json_encode($depTree, JSON_PRETTY_PRINT), true, IOInterface::VERBOSE);

        $curl = new CurlClient();
        $response = $curl->post_json($this->endpoint, $depTree);
        if ($curl->http_code >= 400) {
            throw new NetworkException("NetworkError: {$curl->http_code}");
        }
        if (empty($response)) {
            throw new APIException(Constants::ERROR_ON_API);
        }

        $this->rendererResponse($response);
    }

    private function getDeps() {
        $composer = $this->getComposer(false);
        $platformOverrides = array();
        if ($composer) {
            $platformOverrides = $composer->getConfig()->get('platform') ?: array();
        }

        $platformRepo = new PlatformRepository(array(), $platformOverrides);
        $installedRepo = $this->getComposer()->getRepositoryManager()->getLocalRepository();
        $rootPkg = $this->getComposer()->getPackage();
        if (!$installedRepo->getPackages() && ($rootPkg->getRequires() || $rootPkg->getDevRequires())) {
            throw new DependenciesNotFoundException('No dependencies installed. Try running composer install or update.');
        }

        $this->systemDeps = $this->enumDeps($platformRepo);
        $this->installedDeps = $this->enumDeps($installedRepo);
    }

    /**
     * @param $repo RepositoryInterface
     * @return array
     */
    private function enumDeps($repo) {
        $packages = array();
        foreach ($repo->getPackages() as $package) {
            if (!isset($packages[$package->getName()])
                || !is_object($packages[$package->getName()])
                || version_compare($packages[$package->getName()]->getVersion(), $package->getVersion(), '<')
            ) {
                $packages[$package->getPrettyName()] = $package->getPrettyVersion();
            }
        }
        return $packages;
    }

    private function buildDepTree() {
        $repos = $installedRepo = $this->getComposer()->getRepositoryManager()->getLocalRepository();

        $rootRequires = $this->getRootRequires();
        $packages = $installedRepo->getPackages();
        usort($packages, 'strcmp');
        $arrayTree = array();
        foreach ($packages as $package) {
            if (in_array($package->getName(), $rootRequires, true)) {
                $arrayTree[] = $this->generatePackageTree($package, $installedRepo, $repos);
            }
        }

        $depsTree = [];
        $depsTree['name'] = $this->getComposer()->getPackage()->getPrettyName();
        $depsTree['version'] = $this->getComposer()->getPackage()->getPrettyVersion();
        if (strpos($depsTree['version'], 'No version set') !== false) {
            $depsTree['version'] = '1.0.0';
        }
        $depsTree['from'] = [$depsTree['name'].'@'.$depsTree['version']];
        $this->depsTreeToDict($depsTree, $arrayTree);

        return $depsTree;
    }

    private function depsTreeToDict(&$root, $arrayTree) {
        $root['dependencies'] = [];
        foreach ($arrayTree as $block) {
            if (isset($this->systemDeps[$block['name']])) {
                // jump system Dependencies
                continue;
            }

            $newBlock = [];
            $newBlock['name'] = $block['name'];
            if (isset($this->systemDeps[$block['name']])) {
                $newBlock['version'] = $this->systemDeps[$block['name']];
            } else if (isset($this->installedDeps[$block['name']])) {
                $newBlock['version'] = $this->installedDeps[$block['name']];
            } else {
                $newBlock['version'] = $block['version'];
            }

            $blockFrom = $root['from'] ?? [];
            $key = sprintf("%s@%s", $newBlock['name'], $newBlock['version']);
            $blockFrom[] = $key;
            $newBlock['from'] = $blockFrom;
            $newBlock['dependencies'] = [];
            if (isset($block['requires'])) {
                if (!$this->onlyProvenance){
                    $this->depsTreeToDict($newBlock, $block['requires']);
                }
            }

            $root['dependencies'][$newBlock['name']] = $newBlock;
        }
    }

    private function rendererResponse(string $response) {
        $responseJson = json_decode($response, true);
        if (isset($responseJson['ok']) && $responseJson['ok'] == true) {
            $this->log("<info>✓ Tested {$responseJson['dependencyCount']} dependencies for known vulnerabilities, no vulnerable paths found.</info>");
        } elseif (isset($responseJson['vulnerabilities'])) {
            $vulns = $responseJson['vulnerabilities'];
            foreach ($vulns as $vuln) {
                $this->printSingleVuln($vuln);
            }
            $this->log("<warning>Tested {$responseJson['dependencyCount']} dependencies for known vulnerabilities, found ".count($vulns)." vulnerable paths.</warning>");

            if ($this->failOnVuln) {
                throw new FoundVulnException(Constants::ERROR_ON_VULNERABLE);
            }
        }
    }

    private function printSingleVuln(Array $vuln) {
        $this->log("<error>✗ {$vuln['severity']} severity vulnerability ({$vuln['title']} - {$vuln['cve']}) found on {$vuln['packageName']}@{$vuln['version']}</error>");

        if (isset($vuln['from'])) {
            $fromArr = $vuln['from'];
            $fromStr = "";
            for($i=0, $len=count($fromArr); $i<$len; $i++) {
                $fromStr .= "{$fromArr[$i]} > ";
            }
            $fromStr = substr($fromStr, 0, strlen($fromStr)-3);
            $this->log("- From: {$fromStr}");
        }

        if (isset($vuln['target_version']) && !empty($vuln['target_version'])) {
            $this->log("<info>! Fix version ".json_encode($vuln['target_version'])."</info>");
        }
        $this->log("");
    }

    private function log($msg, $newline = true, $verbose = IOInterface::NORMAL) {
        $this->getIO()->write($msg, $newline, $verbose);
    }
}