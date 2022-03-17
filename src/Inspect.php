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

namespace Momo\Sec;


use Composer\Composer;
use Composer\IO\IOInterface;
use Composer\Plugin\Capability\CommandProvider;
use Composer\Plugin\Capable;
use Composer\Plugin\PluginInterface;

class Inspect implements PluginInterface, Capable, CommandProvider {

    /**
     * @var Composer
     */
    protected static $composer;

    /**
     * @inheritDoc
     */
    public function getCapabilities() {
        return [
            CommandProvider::class => __CLASS__,
        ];
    }

    /**
     * @inheritDoc
     */
    public function getCommands() {
        return [
            new Command\CheckCommand($this)
        ];
    }

    /**
     * @inheritDoc
     */
    public function activate(Composer $composer, IOInterface $io) {
        static::$composer = $composer;
    }

    public function deactivate(Composer $composer, IOInterface $io) {
        // TODO: Implement deactivate() method.
    }

    public function uninstall(Composer $composer, IOInterface $io) {
        // TODO: Implement uninstall() method.
    }
}