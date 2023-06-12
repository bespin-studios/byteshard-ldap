<?php
/**
 * @copyright  Copyright (c) 2009 Bespin Studios GmbH
 * @license    See LICENSE file that is distributed with this source code
 */

namespace byteShard\Authentication;

use byteShard\Internal\Authentication\AuthenticationInterface;
use byteShard\Internal\Authentication\Struct;
use byteShard\Authentication\Enum;
use byteShard\Internal\Debug;
use byteShard\Ldap\Enum\Protocol;
use byteShard\Ldap\Struct\Credentials;

/**
 * Class Ldap
 * @package byteShard\Authentication
 */
class Ldap implements AuthenticationInterface
{
    private string    $host;
    private ?Protocol $protocolVersion = null;
    private int       $timeLimit;
    private int       $size_limit;
    private int       $referrals;
    private int       $networkTimeout;

    public function __construct(string $host = null, private int $port = 389, private readonly string $protocol = '')
    {
        if ($host !== null) {
            $this->host = $host;
        }
    }

    public function setHost(string $host): self
    {
        $this->host = $host;
        return $this;
    }

    public function setPort(int $port): self
    {
        $this->port = $port;
        return $this;
    }

    public function setProtocolVersion(Protocol $protocolVersion): static
    {
        $this->protocolVersion = $protocolVersion;
        return $this;
    }

    public function setTimelimit(int $timeLimit): self
    {
        if ($timeLimit >= 0) {
            $this->timeLimit = $timeLimit;
        } else {
            //TODO: log error
        }
        return $this;
    }

    public function setNetworkTimeout(int $timeout): self
    {
        if ($timeout >= 0) {
            $this->networkTimeout = $timeout;
        } else {
            //TODO: log error
        }
        return $this;
    }

    public function setSizelimit(int $sizeLimit): self
    {
        if ($sizeLimit >= 0) {
            $this->size_limit = $sizeLimit;
        } else {
            //TODO: log error
        }
        return $this;
    }

    public function setReferrals(bool $referrals): self
    {
        $this->referrals = $referrals ? 1 : 0;
        return $this;
    }

    public function authenticate(Struct\Result $auth): void
    {
        $ldap = new \byteShard\Ldap($this->host ?? '', $this->port, $this->protocol);
        if ($this->protocolVersion !== null) {
            $ldap->setProtocolVersion($this->protocolVersion);
        }
        if (isset($this->referrals)) {
            $ldap->setReferrals($this->referrals);
        }
        if (isset($this->size_limit)) {
            $ldap->setSizelimit($this->size_limit);
        }
        if (isset($this->timeLimit)) {
            $ldap->setTimelimit($this->timeLimit);
        }
        if (isset($this->networkTimeout)) {
            $ldap->setNetworkTimeout($this->networkTimeout);
        }
        $credentials = new Credentials();
        $credentials->setUsername($auth->getUsername());
        $credentials->setPassword($auth->getPassword());
        $credentials->setDomain($auth->getDomain());
        $result = $ldap->authenticate($credentials, true);
        if (isset($result->authenticated) && $result->authenticated === true) {
            $auth->setSuccess();
        } else {
            if (isset($result->errorCode)) {
                switch ($result->errorCode) {
                    case -1:
                        $auth->setAction(Enum\Action::AUTHENTICATION_TARGET_UNREACHABLE);
                        break;
                    case 52:
                        $auth->setAction(Enum\Action::INVALID_CREDENTIALS);
                        break;
                    case 532:
                        $auth->setAction(Enum\Action::PASSWORD_EXPIRED);
                        break;
                    default:
                        Debug::error('Undefined Ldap Error Code: '.$result->errorCode);
                        $auth->setError((string)$result->errorCode);
                        break;
                }
            }
            $auth->setSuccess(false);
        }
    }

    public function changePassword(Struct\Result $auth): Struct\Result
    {
        return $auth;
    }

    public function getUserID(string $username): ?int
    {
        return null;
    }

    /**
     * @param string $username
     * @return bool
     */
    public function checkUsernamePattern(string $username): bool
    {
        return true;
    }
}
