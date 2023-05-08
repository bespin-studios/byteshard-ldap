<?php
/**
 * @copyright  Copyright (c) 2009 Bespin Studios GmbH
 * @license    See LICENSE file that is distributed with this source code
 */

namespace byteShard\Ldap;

use byteShard\Ldap\Enum\ResultIndex;

/**
 * Class Element
 * @package byteShard\Ldap
 */
class Element
{
    private string       $field;
    private string       $value;
    private ?string      $dn;
    private ?string      $resultIndexField;
    private ?ResultIndex $resultIndexCase;

    /**
     * @param string $field
     * @param string $value
     * @param ?string $dn
     * @param ?string $resultIndexField
     * @param ?ResultIndex $resultIndexCase
     */
    public function __construct(string $field, string $value, ?string $dn = null, ?string $resultIndexField = null, ?ResultIndex $resultIndexCase = null)
    {
        $this->field            = $field;
        $this->value            = $value;
        $this->dn               = $dn;
        $this->resultIndexField = $resultIndexField;
        $this->resultIndexCase  = $resultIndexCase;
    }

    public function getResultIndexField(): ?string
    {
        return $this->resultIndexField;
    }

    public function getResultIndexCase(): ?ResultIndex
    {
        return $this->resultIndexCase;
    }

    public function getDN(): ?string
    {
        return $this->dn;
    }

    public function getField(): string
    {
        return $this->field;
    }

    public function getValue(): string
    {
        return $this->value;
    }

    public function getFilter(): string
    {
        return '('.$this->field.'='.$this->value.')';
    }
}
