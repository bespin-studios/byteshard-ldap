<?php
/**
 * @copyright  Copyright (c) 2009 Bespin Studios GmbH
 * @license    See LICENSE file that is distributed with this source code
 */

namespace byteShard\Ldap;

/**
 * Class Attributes
 * @package byteShard\Ldap
 */
class Attributes
{
    /**
     * @var Attribute[]
     */
    public array $attributes = [];

    /**
     * Attributes constructor.
     * @param Attribute ...$attributes
     */
    public function __construct(Attribute ...$attributes)
    {
        foreach ($attributes as $attribute) {
            $this->attributes[$attribute->getSearchAttribute()] = $attribute;
        }
    }

    /**
     * @param Attribute ...$attributes
     */
    public function addAttribute(Attribute ...$attributes): void
    {
        foreach ($attributes as $attribute) {
            $this->attributes[$attribute->getSearchAttribute()] = $attribute;
        }
    }

    /**
     * @return array<string>
     */
    public function getSearchAttributes(): array
    {
        $result = [];
        foreach ($this->attributes as $attribute) {
            $result[] = $attribute->getSearchAttribute();
        }
        return $result;
    }

    /**
     * byteShard\Ldap::parser will try to match all attributes against a lower case hash map
     * @return array<string,string>
     */
    public function getHashForParser(): array
    {
        $result = [];
        foreach ($this->attributes as $attribute) {
            $result[strtolower($attribute->getSearchAttribute())] = $attribute->getResultAttribute();
        }
        return $result;
    }
}
