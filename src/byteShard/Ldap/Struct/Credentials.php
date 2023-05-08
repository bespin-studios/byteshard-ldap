<?php
/**
 * @copyright  Copyright (c) 2009 Bespin Studios GmbH
 * @license    See LICENSE file that is distributed with this source code
 */

namespace byteShard\Ldap\Struct;

use byteShard\Enum\LogLevel;
use byteShard\Internal\CredentialsInterface;
use JsonSerializable;

/**
 * Class Credentials
 * @package byteShard\Ldap\Struct
 */
class Credentials implements CredentialsInterface, JsonSerializable
{

    private string $username;
    private string $password;
    private string $domain;
    private string $new_password;
    private string $new_password_repeat;

    /**
     * @param ?string $username
     * @return self
     */
    public function setUsername(?string $username): self
    {
        if ($username !== null) {
            $this->username = $username;
        }
        return $this;
    }

    /**
     * @param ?string $password
     * @return self
     */
    public function setPassword(?string $password): self
    {
        if ($password !== null) {
            $this->password = $password;
        }
        return $this;
    }

    /**
     * @param ?string $domain
     * @return self
     */
    public function setDomain(?string $domain): self
    {
        if ($domain !== null) {
            $this->domain = $domain;
        }
        return $this;
    }

    /**
     * @param ?string $new_password
     * @return self
     */
    public function setNewPassword(?string $new_password): self
    {
        if ($new_password !== null) {
            $this->new_password = $new_password;
        }
        return $this;
    }

    /**
     * @param ?string $new_password_repeat
     * @return self
     */
    public function setNewPasswordRepeat(?string $new_password_repeat): self
    {
        if ($new_password_repeat !== null) {
            $this->new_password_repeat = $new_password_repeat;
        }
        return $this;
    }


    /**
     * @return string
     */
    public function getUsername(): string
    {
        return $this->username ?? '';
    }

    /**
     * @return string
     */
    public function getPassword(): string
    {
        return $this->password ?? '';
    }

    /**
     * @return string
     */
    public function getDomain(): string
    {
        return $this->domain ?? '';
    }

    /**
     * @return string
     */
    public function getNewPassword(): string
    {
        return $this->new_password ?? '';
    }

    /**
     * @return string
     */
    public function getNewPasswordRepetition(): string
    {
        return $this->new_password_repeat ?? '';
    }

    public function __debugInfo(): array
    {
        if (defined('DISCLOSE_CREDENTIALS') && DISCLOSE_CREDENTIALS === true && defined('LOGLEVEL') && LOGLEVEL === LogLevel::DEBUG) {
            return get_object_vars($this);
        }
        $debug_info                        = get_object_vars($this);
        $debug_info['password']            = !isset($this->password) ? '' : 'CONFIDENTIAL';
        $debug_info['new_password']        = !isset($this->new_password) ? '' : 'CONFIDENTIAL';
        $debug_info['new_password_repeat'] = !isset($this->new_password_repeat) ? '' : 'CONFIDENTIAL';
        return $debug_info;
    }

    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}
