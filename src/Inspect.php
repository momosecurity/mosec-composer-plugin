<?php


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
}