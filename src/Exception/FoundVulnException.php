<?php

namespace Momo\Sec\Exception;


class FoundVulnException extends \RuntimeException {

    public function __construct(string $message)
    {
        parent::__construct($message, 1);
    }
}