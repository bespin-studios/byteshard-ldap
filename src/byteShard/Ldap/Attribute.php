<?php
/**
 * @copyright  Copyright (c) 2009 Bespin Studios GmbH
 * @license    See LICENSE file that is distributed with this source code
 */

namespace byteShard\Ldap;

use byteShard\Ldap\Enum\ResultObject;

/**
 * Class Attribute
 * @package byteShard\Ldap
 */
class Attribute
{
    private string              $search;
    private string|ResultObject $result;

    /**
     * Attribute constructor.
     * @param string $searchAttribute the ldap attribute to include in the result
     * @param string|ResultObject|null $resultObjectProperty
     */
    public function __construct(string $searchAttribute, null|string|ResultObject $resultObjectProperty = null)
    {
        $this->search = $searchAttribute;
        $this->result = $resultObjectProperty !== null ? $resultObjectProperty : $searchAttribute;
    }

    /**
     * @return string
     * @internal
     */
    public function getSearchAttribute(): string
    {
        return $this->search;
    }

    /**
     * @return string
     * @internal
     */
    public function getResultAttribute(): string
    {
        if ($this->result instanceof ResultObject) {
            return $this->result->value;
        }
        return $this->result;
    }
}
