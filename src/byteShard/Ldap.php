<?php
/**
 * @copyright  Copyright (c) 2009 Bespin Studios GmbH
 * @license    See LICENSE file that is distributed with this source code
 */

namespace byteShard;

use byteShard\Enum\LogLevel;
use byteShard\Internal\CredentialsInterface;
use byteShard\Internal\Debug;
use byteShard\Ldap\Attributes;
use byteShard\Ldap\Filter;
use byteShard\Ldap\Enum\Protocol;
use byteShard\Validation\Email;
use LDAP\Connection;
use stdClass;
use function ldap_connect;

/**
 * Class Ldap
 * @exceptionId 00006
 * @package byteShard
 */
class Ldap
{
    private string     $host;
    private int        $port;
    private string     $protocol;
    private Connection $connection;
    private bool       $bind;
    private Protocol   $usedProtocolVersion = Protocol::V3;
    private Protocol   $optProtocolVersion  = Protocol::V3;
    private int        $usedSizeLimit       = 0;
    private string     $boundUser           = '';
    private bool       $bound               = false;
    private int        $optTimeLimit        = 30;
    private int        $optNetworkTimeout   = 15;
    private ?int       $optSizeLimit        = null;
    private int        $optReferrals        = 0;
    private bool       $usePaging           = false;
    private int        $pageSize            = 1000;
    private bool       $convertBinary       = true;
    private bool       $useStartTLS         = false;
    private bool       $ignoreTLSCert       = false;

    public function __construct(string $host, int $port = 389, string $protocol = '')
    {
        $this->host     = $host;
        $this->port     = $port;
        $this->protocol = $protocol;
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

    public function setProtocolVersion(Protocol $protocol): self
    {
        $this->optProtocolVersion = $protocol;
        return $this;
    }

    /**
     * @throws Exception
     */
    public function setPaging(int $size): static
    {
        if ($size >= 0) {
            $this->pageSize  = $size;
            $this->usePaging = true;
        } else {
            throw new Exception('Ldap::setPaging parameter $size must be equal or greater than 0. '.$size.' given', 100006008);
        }
        return $this;
    }

    /**
     * @throws Exception
     */
    public function setTimeLimit(int $timeLimit): self
    {
        if ($timeLimit >= 0) {
            $this->optTimeLimit = $timeLimit;
        } else {
            throw new Exception('Ldap::setTimeLimit parameter $timeLimit must be equal or greater than 0. '.$timeLimit.' given', 100006009);
        }
        return $this;
    }

    /**
     * @throws Exception
     */
    public function setNetworkTimeout(int $timeout): self
    {
        if ($timeout >= 0) {
            $this->optNetworkTimeout = $timeout;
        } else {
            throw new Exception('Ldap::setNetworkTimeout parameter $timeout must be equal or greater than 0. '.$timeout.' given', 100006010);
        }
        return $this;
    }

    /**
     * @throws Exception
     */
    public function setSizeLimit(int $sizeLimit): self
    {
        if ($sizeLimit >= 0) {
            $this->optSizeLimit = $sizeLimit;
        } else {
            throw new Exception('Ldap::setSizeLimit parameter $sizeLimit must be equal or greater than 0. '.$sizeLimit.' given', 100006011);
        }
        return $this;
    }

    /**
     * @param int $referrals
     * @return $this
     */
    public function setReferrals(int $referrals): self
    {
        $this->optReferrals = $referrals;
        return $this;
    }

    public function useStartTLS(bool $use = true): self
    {
        $this->useStartTLS = $use;
        return $this;
    }

    public function ignoreTLSCert(bool $ignore = true): self
    {
        $this->ignoreTLSCert = $ignore;
        return $this;
    }


    /**
     * @param CredentialsInterface $credentials
     * @param bool $returnVerbose
     * @return bool|stdClass
     * @throws Exception
     */
    public function authenticate(CredentialsInterface $credentials, bool $returnVerbose = false): bool|stdClass
    {
        if (!isset($this->connection)) {
            $result = $this->connect($credentials);
            $this->close();
            if ($returnVerbose === true) {
                return $result;
            }
            return $result->authenticated;
        }
        if ($credentials->getUsername() !== $this->boundUser) {
            $e = new Exception('This ldap instance is already bound to a different user', 100006001);
            $e->setLogChannel('byteShard');
            throw $e;
        }
        return $this->bound;
    }

    public function test(): ?Connection
    {
        $conn = ldap_connect('');
        if ($conn === false) {
            return null;
        }
        return $conn;
    }

    /**
     * @throws Exception
     */
    public function connect(CredentialsInterface $credentials): stdClass
    {
        $result                = new stdClass();
        $result->error         = false;
        $result->authenticated = false;

        $protocol = $this->protocol;
        $host     = $this->host;
        if (str_contains($this->host, '://')) {
            $host = substr($this->host, strpos($this->host, '://') + 3);
        }

        /** @noinspection PhpUndefinedConstantInspection */
        if (defined('DEBUG') && DEBUG === true && defined('DEBUG_LEVEL') && is_int(DEBUG_LEVEL) && DEBUG_LEVEL > 1) {
            /** @noinspection PhpUndefinedConstantInspection */
            ldap_set_option(null, LDAP_OPT_DEBUG_LEVEL, DEBUG_LEVEL);
            //Try to open a socket to validate if server:port is reachable
            $this->validate_host($host);
        }

        $connection = isset($this->port) ? ldap_connect($protocol.$host, $this->port) : ldap_connect($protocol.$host);
        if ($connection === false) {
            throw new Exception('Could not connect to Ldap Host', 100006012);
        }
        $this->connection = $connection;

        //Try to use defined protocol version. If no protocol version specified or the defined protocol version fails, try v3 then v2
        if (ldap_set_option($this->connection, LDAP_OPT_PROTOCOL_VERSION, $this->optProtocolVersion->value)) {
            $this->usedProtocolVersion = $this->optProtocolVersion;
        } else {
            if (ldap_set_option($this->connection, LDAP_OPT_PROTOCOL_VERSION, Protocol::V3->value)) {
                $this->usedProtocolVersion = Protocol::V3;
            } elseif (ldap_set_option($this->connection, LDAP_OPT_PROTOCOL_VERSION, Protocol::V2->value)) {
                $this->usedProtocolVersion = Protocol::V2;
            } else {
                $e = new Exception('Ldap: no valid protocol version found for host "'.$host.'"', 100006002);
                $e->setLogChannel('byteShard');
                throw $e;
            }
        }

        if ($this->useStartTLS === true) {
            ldap_start_tls($this->connection);
        }

        ldap_set_option($this->connection, LDAP_OPT_TIMELIMIT, $this->optTimeLimit);
        ldap_set_option($this->connection, LDAP_OPT_REFERRALS, $this->optReferrals);

        if (isset($this->optSizeLimit)) {
            ldap_set_option($this->connection, LDAP_OPT_SIZELIMIT, $this->optSizeLimit);
            $this->usedSizeLimit = $this->optSizeLimit;
        }
        ldap_set_option($this->connection, LDAP_OPT_NETWORK_TIMEOUT, $this->optNetworkTimeout);

        if (strlen($credentials->getUsername()) > 0 && strlen($credentials->getPassword()) > 0) {
            set_error_handler(function ($severity, $message, $file, $line, array $errorContext = []) {
                throw new Exception($message, 100006003);
            });
            $errorHandlerActive = true;
            try {
                $username = $credentials->getUsername();
                if (!Email::verify($username)) {
                    $domain   = $credentials->getDomain();
                    $username .= ($domain !== '') ? '@'.$domain : '';
                }
                $this->bind = ldap_bind($this->connection, $username, $credentials->getPassword());
            } catch (Exception $e) {
                restore_error_handler();
                $errorHandlerActive = false;
                $e->setMessage($e->getMessage().' for User ('.$credentials->getUsername().')');
                $e->setTraceLogFunctionArgumentsConfidential('ldap_bind');
                $e->setLogChannel('byteShard');
                $e->setCode(100006004);
                if (defined('LOGLEVEL') && LOGLEVEL === LogLevel::DEBUG) {
                    throw $e;
                }
            } finally {
                if ($errorHandlerActive === true) {
                    restore_error_handler();
                }
            }
            if (isset($this->bind) && $this->bind === true) {
                $result->authenticated = true;
                $this->bound           = true;
                $this->boundUser       = $credentials->getUsername();
            } else {
                $result->error      = true;
                $result->errorCode = $this->eval_ldap_error($credentials->getUsername(), $result);
            }
        }
        return $result;
    }

    public function close(): self
    {
        if (isset($this->connection)) {
            ldap_close($this->connection);
            unset($this->connection);
            unset($this->bind);
            $this->bound = false;
        }
        return $this;
    }

    public function changePassword(): void
    {
        //TODO: implement possibility to change ldap pass
    }

    public function open(): void
    {
        //TODO:
    }

    public function moveNext(): void
    {
        //TODO:
    }

    public function movePrevious(): void
    {
        //TODO:
    }

    public function moveFirst(): void
    {
        //TODO:
    }

    public function moveLast(): void
    {
        //TODO:
    }

    /**
     * @param Filter $filter
     * @param Attributes|null $attributes
     * @return array
     */
    public function getArray(Filter $filter, Attributes $attributes = null): array
    {
        $filters = $filter->getFilters();
        if ($attributes !== null) {
            $filter->setAttributeMap($attributes->getHashForParser());
        }
        foreach ($filters as $baseDn => $searchFilter) {
            $this->query($baseDn, $searchFilter, $filter, $attributes);
        }
        return $filter->getResult();
    }

    private function query(string $baseDn, string $searchFilter, Filter $filter, Attributes $attributes = null): void
    {
        $searchAttributes = [];
        $attributeMapping = [];
        if ($attributes !== null) {
            $searchAttributes = $attributes->getSearchAttributes();
            $attributeMapping = $attributes->getHashForParser();
        }
        if ($this->bound === true) {
            if (isset ($this->optSizeLimit) && $this->usedSizeLimit !== $this->optSizeLimit) {
                ldap_set_option($this->connection, LDAP_OPT_SIZELIMIT, $this->optSizeLimit);
                $this->usedSizeLimit = $this->optSizeLimit;
            }
            if ($this->usedProtocolVersion === Protocol::V3) {
                if ($this->usePaging === true) {
                    $cookie = '';
                    do {
                        $searchResult = ldap_search(
                            $this->connection,
                            $baseDn,
                            $searchFilter,
                            $searchAttributes,
                            0,
                            -1,
                            -1,
                            LDAP_DEREF_NEVER,
                            [['oid' => LDAP_CONTROL_PAGEDRESULTS, 'value' => ['size' => $this->pageSize, 'cookie' => $cookie]]]
                        );
                        ldap_parse_result($this->connection, $searchResult, $errorCode, $matchedDN, $errorMessage, $referrals, $controls);
                        $this->parse(ldap_get_entries($this->connection, $searchResult), $attributeMapping, $filter, $baseDn);
                        $cookie = $controls[LDAP_CONTROL_PAGEDRESULTS]['value']['cookie'] ?? '';
                    } while (!empty($cookie));
                } else {
                    // no paging
                    $searchResult = ldap_search($this->connection, $baseDn, $searchFilter, $searchAttributes);
                    $this->parse(ldap_get_entries($this->connection, $searchResult), $attributeMapping, $filter, $baseDn);
                }
            } else {
                // ldap protocol v2
                $searchResult = ldap_search($this->connection, $baseDn, $searchFilter, $searchAttributes);
                $this->parse(ldap_get_entries($this->connection, $searchResult), $attributeMapping, $filter, $baseDn);
            }
        }
    }

    /**
     * @param array $records
     * @param array $attributeMapping lowercase hash map
     * @param Filter $filter
     * @param string $baseDn
     * @return void
     */
    private function parse(array $records, array $attributeMapping, Filter $filter, string $baseDn): void
    {
        if (isset($records['count']) && is_int($records['count']) && $records['count'] > 0) {
            if (!empty($attributeMapping)) {
                // create this object so every result will have all the queried attributes
                $obj = new stdClass();
                foreach ($attributeMapping as $attribute) {
                    $obj->{$attribute} = null;
                }
                for ($i = 0; $i < $records['count']; $i++) {
                    $tmp              = clone $obj;
                    $lowerCaseRecords = array_change_key_case($records[$i]);
                    foreach ($attributeMapping as $recordAttribute => $resultProperty) {
                        if (array_key_exists($recordAttribute, $lowerCaseRecords) && array_key_exists('count', $lowerCaseRecords[$recordAttribute])) {
                            if ($lowerCaseRecords[$recordAttribute]['count'] === 1) {
                                if ($this->convertBinary === true && ($recordAttribute === 'objectguid' || $recordAttribute === 'objectsid')) {
                                    $tmp->{$resultProperty} = $this->guid_to_string($lowerCaseRecords[$recordAttribute][0]);
                                } else {
                                    $tmp->{$resultProperty} = $lowerCaseRecords[$recordAttribute][0];
                                }
                            } elseif (is_int($lowerCaseRecords[$recordAttribute]['count']) && $lowerCaseRecords[$recordAttribute]['count'] > 1) {
                                for ($j = 0; $j < $lowerCaseRecords[$recordAttribute]['count']; $j++) {
                                    $tmp->{$resultProperty}[$j] = $lowerCaseRecords[$recordAttribute][$j];
                                }
                            }
                        }
                    }
                    $filter->addResult($tmp, $baseDn);
                }
            } else {
                for ($i = 0; $i < $records['count']; $i++) {
                    $tmp = new stdClass();
                    foreach ($records[$i] as $attribute => $record) {
                        if (!is_int($attribute) && isset($record['count'])) {
                            if ($record['count'] === 1) {
                                if ($this->convertBinary === true && ($attribute === 'objectguid' || $attribute === 'objectsid')) {
                                    $tmp->{$attribute} = $this->guid_to_string($record[0]);
                                } else {
                                    $tmp->{$attribute} = $record[0];
                                }
                            } elseif (is_array($record) && is_int($record['count']) && $record['count'] > 1) {
                                for ($j = 0; $j < $record['count']; $j++) {
                                    $tmp->{$attribute}[$j] = $record[$j];
                                }
                            }
                        }
                    }
                    $filter->addResult($tmp, $baseDn);
                    unset($tmp);
                }
            }
        }
    }

    /**
     * evaluate ldap errors
     * @param string $username
     * @param stdClass $result
     * @return int
     */
    private function eval_ldap_error(string $username, stdClass $result): int
    {
        $ldapErrorNumber = null;
        ldap_get_option($this->connection, 0x0032, $ldapError);
        if (substr_count($ldapError, ',') >= 2) {
            $ldapErrorNumber = explode(',', $ldapError)[2];
            if (substr_count($ldapErrorNumber, ' ') >= 2) {
                $ldapErrorNumber = explode(' ', $ldapErrorNumber)[2];
                $ldapErrorNumber = (int)$ldapErrorNumber;
            }
        }
        switch (ldap_errno($this->connection)) {
            case -1:
                Debug::critical('Ldap Backtrace', debug_backtrace());
                Debug::critical(__METHOD__.'Ldap: server '.$this->host.' unreachable', array('Host' => $this->host, 'Port' => $this->port));
                break;
            case 49:
                if (is_int($ldapErrorNumber)) {
                    switch ($ldapErrorNumber) {
                        case 52:
                        case 53:
                            Debug::info('Ldap: Invalid credentials for user "'.$username.'"');
                            $result->error_msg = 'Ldap: Invalid credentials for user "'.$username.'"';
                            break;
                        case 530:
                            Debug::info('Ldap: not permitted to logon at this time');
                            $result->error_msg = 'Ldap: not permitted to logon at this time';
                            break;
                        case 531:
                            Debug::info('Ldap: not permitted to logon at this workstation');
                            $result->error_msg = 'Ldap: not permitted to logon at this workstation';
                            break;
                        case 532:
                            Debug::info('Ldap: Password expired for user "'.$username.'"');
                            $result->error_msg = 'Ldap: Password expired for user "'.$username.'"';
                            break;
                        case 533:
                            Debug::info('Ldap: Account disabled for user "'.$username.'"');
                            $result->error_msg = 'Ldap: Account disabled for user "'.$username.'"';
                            break;
                        case 701:
                            Debug::info('Ldap: Account expired for user "'.$username.'"');
                            $result->error_msg = 'Ldap: Account expired for user "'.$username.'"';
                            break;
                        case 773:
                            Debug::info('Ldap: User "'.$username.'" must reset password');
                            $result->error_msg = 'Ldap: User "'.$username.'" must reset password';
                            break;
                        case 775:
                            Debug::info('Ldap: Account locked for user "'.$username.'"');
                            $result->error_msg = 'Ldap: Account locked for user "'.$username.'"';
                            break;
                        default:
                            Debug::warning('Ldap: Unknown error occurred. ErrorCode: '.$ldapErrorNumber.'. ErrorMsg: '.ldap_error($this->connection));
                            $result->error_msg = 'Ldap: Unknown error occurred. ErrorCode: '.$ldapErrorNumber.'. ErrorMsg: '.ldap_error($this->connection);
                            break;
                    }
                } else {
                    Debug::warning('Ldap: Unknown error occurred.'."\n".' ErrorMsg: '.ldap_error($this->connection));
                }
                break;
            default:
                Debug::warning('Ldap: Unknown error occurred.', [
                    'ldapError'          => ldap_error($this->connection),
                    'ldapErrno'          => ldap_errno($this->connection),
                    'byteShardLdapError' => $ldapError,
                    'byteShardLdapErrno' => $ldapErrorNumber
                ]);
                break;
        }
        if ($ldapErrorNumber !== null) {
            return $ldapErrorNumber;
        }
        return ldap_errno($this->connection);
    }

    /**
     * Try to open a socket to validate if host:port is reachable
     * ldap connect does not provide good error messages in case the connection fails
     *
     * @param string $host
     * @throws Exception
     */
    private function validate_host(string $host): void
    {
        $sock = fsockopen($host, $this->port, $errorNumber, $errorMessage, 1);
        if (!$sock) {
            switch ($errorNumber) {
                case 0:
                    if (stripos($errorMessage, 'getaddrinfo failed') !== false) {
                        $e = new Exception('Ldap: Hostname could not be resolved: '.$this->host.(isset($this->port) ? ':'.$this->port : ''), 100006005);
                    } else {
                        $e = new Exception('Ldap: Host unreachable: '.$this->host.(isset($this->port) ? ':'.$this->port : ''), 100006006);
                    }
                    $e->setLogChannel('byteShard');
                    $e->setLdapErrors($this->host, $this->port, $errorMessage);
                    break;
                default:
                    $e = new Exception('Ldap: Host unreachable: '.$this->host.(isset($this->port) ? ':'.$this->port : ''), 100006007);
                    $e->setLogChannel('byteShard');
                    $e->setLdapErrors($this->host, $this->port, $errorMessage);
                    break;
            }
            throw $e;
        }
        fclose($sock);
    }

    /**
     * @param string $binary
     * @return string
     */
    private function guid_to_string(string $binary): string
    {
        $hex = unpack('H*hex', $binary)['hex'];
        return substr($hex, -26, 2).substr($hex, -28, 2).substr($hex, -30, 2).substr($hex, -32, 2).'-'.substr($hex, -22, 2).substr($hex, -24, 2).'-'.substr($hex, -18, 2).substr($hex, -20, 2).'-'.substr($hex, -16, 4).'-'.substr($hex, -12, 12);
    }
}
