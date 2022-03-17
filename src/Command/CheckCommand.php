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


use Composer\Command\BaseCommand;
use Composer\Filter\PlatformRequirementFilter\PlatformRequirementFilterFactory;
use Composer\Installer;
use Composer\IO\IOInterface;
use Composer\Package\CompletePackageInterface;
use Composer\Package\PackageInterface;
use Composer\Package\Version\VersionParser;
use Composer\Repository\PlatformRepository;
use Composer\Repository\RepositoryInterface;
use Momo\Sec\Constants;
use Momo\Sec\Exception\APIException;
use Momo\Sec\Exception\FoundVulnException;
use Momo\Sec\Exception\NetworkException;
use Momo\Sec\Inspect;
use Momo\Sec\CurlClient;
use RuntimeException;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class CheckCommand extends BaseCommand {

    /**
     * @var Inspect
     */
    protected $inspect;

    /**
     * @var VersionParser
     */
    protected $versionParser;

    /**
     * @var array<string, CompletePackageInterface>
     */
    protected $systemDeps;

    /**
     * @var array<string, CompletePackageInterface>
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

    protected $devMode = false;

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

        $this->installDeps();
        $depTree = $this->buildDepTree();
        $depTree['type'] = Constants::BUILD_TOOL_TYPE;
        $depTree['language'] = Constants::PROJECT_LANGUAGE;
        $depTree['severityLevel'] = $input->getOption('severityLevel');

        $this->log(json_encode($depTree, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), true, IOInterface::VERBOSE);

        $curl = new CurlClient();
        $response = $curl->post_json($this->endpoint, $depTree);
        if ($curl->http_code >= 400) {
            throw new NetworkException("NetworkError: {$curl->http_code}");
        }
        if (empty($response)) {
            throw new APIException(Constants::ERROR_ON_API);
        }

        $this->rendererResponse($response);

        return 0;
    }

    private function installDeps() {
        $composer = $this->getComposer(false);
        $io = $this->getIO();
        // 手动运行dry-run
        $install = Installer::create($io, $composer);
        $install->setDryRun(true);

        if (version_compare($composer::VERSION, "2.2.0", "<")) {
            $install->setIgnorePlatformRequirements(true);
        } else {
            $install->setPlatformRequirementFilter(PlatformRequirementFilterFactory::fromBoolOrList(true));
        }
        $install->run();

        $lockedRepo = $composer->getLocker()->getLockedRepository($this->devMode);

        $platformOverrides = $composer->getConfig()->get('platform') ?: array();
        $platformRepo = new PlatformRepository(array(), $platformOverrides);

        $this->systemDeps = $this->enumDeps($platformRepo);
        $this->installedDeps = $this->enumDeps($lockedRepo);
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
                || version_compare($packages[$package->getPrettyName()]->getVersion(), $package->getVersion(), '<')
            ) {
                $packages[$package->getPrettyName()] = $package;
            }
        }
        return $packages;
    }

    /**
     * @return string[]
     */
    private function getRootRequires() {
        $rootPackage = $this->getComposer()->getPackage();

        return array_map(
            'strtolower',
            array_keys(array_merge($rootPackage->getRequires(), $rootPackage->getDevRequires()))
        );
    }

    private function buildDepTree() {
        try {
            $lockedRepo = $this->getComposer()->getLocker()->getLockedRepository($this->devMode);
        } catch (\LogicException $ex) {
            $this->installDeps();
            $lockedRepo = $this->getComposer()->getLocker()->getLockedRepository($this->devMode);
        }

        $rootRequires = $this->getRootRequires();
        $packages = $lockedRepo->getPackages();
        usort($packages, 'strcmp');
        $arrayTree = array();
        $packageInTree = array();
        foreach ($packages as $package) {
            if (in_array($package->getName(), $rootRequires, true)) {
                $arrayTree[] = $this->generatePackageTree($package, $packageInTree);
            }
        }
        unset($packageInTree);

        $depsTree = [];
        $depsTree['name'] = $this->getComposer()->getPackage()->getPrettyName();
        $depsTree['version'] = $this->getComposer()->getPackage()->getPrettyVersion();
        if (strpos($depsTree['version'], 'No version set') !== false) {
            $depsTree['version'] = '1.0.0';
        }
        $depsTree['from'] = [$depsTree['name'] . '@' . $depsTree['version']];
        $this->depsTreeToDict($depsTree, $arrayTree);

        return $depsTree;
    }

    /**
     * Generate the package tree
     *
     */
    protected function generatePackageTree(
        PackageInterface $package,
                         &$packageInTree
    ) {
        $requires = $package->getRequires();
        ksort($requires);
        $children = array();
        foreach ($requires as $requireName => $require) {
            if (empty($packageInTree)) {
                $packageInTree[] = $package->getName();
            }

            $requirePackage = $this->getPackage($requireName);

            if ($requirePackage == null) {
                return [];
            }

            if (!in_array($requireName, $packageInTree, true)) {
                $packageInTree[] = $requireName;
                $deepChildren = $this->generatePackageTree($requirePackage, $packageInTree);
                if ($deepChildren) {
                    $children[] = $deepChildren;
                }
            }
        }
        $tree = array(
            'name' => $package->getPrettyName(),
            'version' => $package->getPrettyVersion(),
            'description' => $package instanceof CompletePackageInterface ? $package->getDescription() : '',
        );

        if ($children) {
            $tree['requires'] = $children;
        }

        return $tree;
    }

    /**
     * Get Package from Installed or System
     *
     * @param string $requireName
     * @return CompletePackageInterface|null
     */
    private function getPackage(string $requireName) {
        if (isset($this->installedDeps[$requireName])) {
            return $this->installedDeps[$requireName];
        }
        if (isset($this->systemDeps[$requireName])) {
            return $this->systemDeps[$requireName];
        }
        return null;
    }

    private function depsTreeToDict(&$root, $arrayTree) {
        $root['dependencies'] = [];
        foreach ($arrayTree as $block) {
            if ($block == [] || isset($this->systemDeps[$block['name']])) {
                // jump system Dependencies
                continue;
            }

            $newBlock = [];
            $newBlock['name'] = $block['name'];
            if (isset($this->systemDeps[$block['name']])) {
                $newBlock['version'] = $this->systemDeps[$block['name']]->getPrettyVersion();
            } else if (isset($this->installedDeps[$block['name']])) {
                $newBlock['version'] = $this->installedDeps[$block['name']]->getPrettyVersion();
            } else {
                $newBlock['version'] = $block['version'];
            }

            $blockFrom = $root['from'] ?? [];
            $key = sprintf("%s@%s", $newBlock['name'], $newBlock['version']);
            $blockFrom[] = $key;
            $newBlock['from'] = $blockFrom;
            $newBlock['dependencies'] = [];
            if (isset($block['requires'])) {
                if (!$this->onlyProvenance) {
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
            $this->log("<warning>Tested {$responseJson['dependencyCount']} dependencies for known vulnerabilities, found " . count($vulns) . " vulnerable paths.</warning>");

            if ($this->failOnVuln) {
                throw new FoundVulnException(Constants::ERROR_ON_VULNERABLE);
            }
        }
    }

    private function printSingleVuln(array $vuln) {
        $this->log("<error>✗ {$vuln['severity']} severity vulnerability ({$vuln['title']} - {$vuln['cve']}) found on {$vuln['packageName']}@{$vuln['version']}</error>");

        if (isset($vuln['from'])) {
            $fromArr = $vuln['from'];
            $fromStr = "";
            for ($i = 0, $len = count($fromArr); $i < $len; $i++) {
                $fromStr .= "{$fromArr[$i]} > ";
            }
            $fromStr = substr($fromStr, 0, strlen($fromStr) - 3);
            $this->log("- From: {$fromStr}");
        }

        if (isset($vuln['target_version']) && !empty($vuln['target_version'])) {
            $this->log("<info>! Fix version " . json_encode($vuln['target_version']) . "</info>");
        }
        $this->log("");
    }

    private function log($msg, $newline = true, $verbose = IOInterface::NORMAL) {
        $this->getIO()->write($msg, $newline, $verbose);
    }
}