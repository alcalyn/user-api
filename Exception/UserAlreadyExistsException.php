<?php

namespace Alcalyn\UserApi\Exception;

class UserAlreadyExistsException extends \RuntimeException
{
    /**
     * @param string $username
     * @param int $code
     * @param \Exception $previous
     */
    public function __construct($username = null, $code = 0, $previous = null)
    {
        parent::__construct('User '.$username.' already exists.', $code, $previous);
    }
}
