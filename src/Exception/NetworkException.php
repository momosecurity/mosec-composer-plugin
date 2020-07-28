<?php

namespace Momo\Sec\Exception;


class NetworkException extends \RuntimeException {

    public function __construct(string $message)
    {
        parent::__construct($message, 1);
    }
}