<?php
/**
 * @copyright  Copyright (c) 2009 Bespin Studios GmbH
 * @license    See LICENSE file that is distributed with this source code
 */

namespace byteShard\Ldap;

/**
 * Class Attribute
 * @package byteShard\Ldap
 */
class Attribute
{
    private string $search;
    private string $result;

    /**
     * Attribute constructor.
     * @param string $searchAttribute the ldap attribute to include in the result
     * @param ?string $resultObjectProperty
     */
    public function __construct(string $searchAttribute, ?string $resultObjectProperty = null)
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
        return $this->result;
    }
}
