<?php
/**
 * @copyright  Copyright (c) 2009 Bespin Studios GmbH
 * @license    See LICENSE file that is distributed with this source code
 */

namespace byteShard\Ldap;

use byteShard\Ldap\Enum\ResultIndex;
use stdClass;

/**
 * Class Filter
 * @package byteShard\Ldap
 */
class Filter
{
    /**
     * @var Element[]
     */
    private array       $elements        = [];
    private string      $prefix;
    private array       $result          = [];
    private array       $reverseElement  = [];
    private array       $attributeMap    = [];
    private array       $dnElements      = [];
    private string      $filter;
    private string      $baseDn;
    private ResultIndex $resultIndexCase = ResultIndex::UNCHANGED_DIRECTORY;

    /**
     * Filter constructor.
     * @param string $baseDn
     */
    public function __construct(string $baseDn)
    {
        $this->baseDn = $baseDn;
    }

    /**
     * @param string $filter
     * @return $this
     */
    public function setFilter(string $filter): self
    {
        $this->filter = $filter;
        return $this;
    }

    /**
     * @param ResultIndex $resultIndex
     * @return $this
     */
    public function setDefaultResultIndexCase(ResultIndex $resultIndex): self
    {
        $this->resultIndexCase = $resultIndex;
        return $this;
    }

    /**
     * @param Element ...$elements
     * @return void
     */
    public function addElements(Element ...$elements): void
    {
        foreach ($elements as $element) {
            $dn = $element->getDN();
            if ($dn === null) {
                $this->elements[] = $element;
            } else {
                $this->dnElements[$dn][] = $element;
            }
        }
    }

    /**
     * @param string $prefix
     * @return $this
     */
    public function setPrefix(string $prefix): self
    {
        $this->prefix = $prefix;
        return $this;
    }

    /**
     * @return array
     */
    public function getResult(): array
    {
        if (isset($this->filter)) {
            return $this->result;
        }
        foreach ($this->reverseElement as $attributes) {
            if (!empty($attributes)) {
                foreach ($attributes as $elements) {
                    if (!empty($elements)) {
                        foreach ($elements as $element => $elementData) {
                            if ($element !== '*') {
                                $element = match (ResultIndex::tryFrom($elementData['case'])) {
                                    ResultIndex::LOWER   => strtolower($element),
                                    ResultIndex::UPPER   => strtoupper($element),
                                    ResultIndex::LCFIRST => lcfirst($element),
                                    ResultIndex::UCFIRST => ucfirst($element),
                                    default              => $element,
                                };

                                $this->result[$element]            = new stdClass();
                                $this->result[$element]->LdapError = true;
                            }
                        }
                    }
                }
            }
        }
        return $this->result;
    }

    /**
     * @return array
     * @internal
     */
    public function getFilters(): array
    {
        if (isset($this->filter)) {
            return [$this->baseDn => $this->filter];
        }
        $filters = [];
        if (!empty($this->elements)) {
            $elements = [];
            foreach ($this->elements as $element) {
                $elements[] = $element->getFilter();
            }
            if (!isset($this->prefix)) {
                $filters[$this->baseDn] = '(|'.implode('', $elements).')';
            } else {
                $filters[$this->baseDn] = '('.$this->prefix.'(|'.implode('', $elements).'))';
            }
        }
        if (!empty($this->dnElements)) {
            foreach ($this->dnElements as $filterDn => $elements) {
                $implodeElements = [];
                /**@var Element $element */
                foreach ($elements as $element) {
                    $implodeElements[] = $element->getFilter();
                    if (!isset($this->prefix)) {
                        $filters[$filterDn] = '(|'.implode('', $implodeElements).')';
                    } else {
                        $filters[$filterDn] = '('.$this->prefix.'(|'.implode('', $implodeElements).'))';
                    }
                }
            }
        }
        return $filters;
    }

    /**
     * @param stdClass $result
     * @param string $dn
     * @internal
     */
    public function addResult(stdClass $result, string $dn = ''): void
    {
        if (isset($this->filter)) {
            $this->result[] = $result;
        } else {
            $dn = strtolower($dn);
            if (array_key_exists($dn, $this->reverseElement)) {
                foreach ($this->reverseElement[$dn] as $searchProperty => $item) {
                    $resultProperty = $searchProperty;
                    if (array_key_exists($searchProperty, $this->attributeMap)) {
                        $resultProperty = $this->attributeMap[$searchProperty];
                    }
                    if (isset($result->{$resultProperty})) {
                        $reverseKey  = strtolower($result->{$resultProperty});
                        $add         = false;
                        $case        = ResultIndex::UNCHANGED_QUERY;
                        $returnIndex = $resultProperty;
                        if (array_key_exists($reverseKey, $item)) {
                            $case = ResultIndex::tryFrom($item[$reverseKey]['case']);
                            if (array_key_exists('return_index', $item[$reverseKey])) {
                                if (array_key_exists($item[$reverseKey]['return_index'], $this->attributeMap) && isset($result->{$this->attributeMap[$item[$reverseKey]['return_index']]})) {
                                    $returnIndex = $this->attributeMap[$item[$reverseKey]['return_index']];
                                } elseif (isset($result->{$item[$reverseKey]['return_index']})) {
                                    $returnIndex = $item[$reverseKey]['return_index'];
                                }
                            }
                            $add = true;
                        } elseif (array_key_exists('*', $item)) {
                            $case = ResultIndex::tryFrom($item['*']['case']);
                            if (array_key_exists('return_index', $item['*'])) {
                                if (array_key_exists($item['*']['return_index'], $this->attributeMap) && isset($result->{$this->attributeMap[$item['*']['return_index']]})) {
                                    $returnIndex = $this->attributeMap[$item['*']['return_index']];
                                } elseif (isset($result->{$item['*']['return_index']})) {
                                    $returnIndex = $item['*']['return_index'];
                                }
                            }
                            $add = true;
                        }
                        if ($add === true) {
                            $key                           = match ($case) {
                                ResultIndex::UNCHANGED_QUERY     => $item[$reverseKey],
                                ResultIndex::UNCHANGED_DIRECTORY => $result->{$returnIndex},
                                ResultIndex::LOWER               => strtolower($result->{$returnIndex}),
                                ResultIndex::UPPER               => strtoupper($result->{$returnIndex}),
                                ResultIndex::LCFIRST             => lcfirst($result->{$returnIndex}),
                                ResultIndex::UCFIRST             => ucfirst($result->{$returnIndex}),
                                default                          => $result->{$returnIndex},
                            };
                            $this->result[$key]            = $result;
                            $this->result[$key]->LdapError = false;
                        }
                        if (array_key_exists($reverseKey, $item)) {
                            unset($this->reverseElement[$dn][$searchProperty][$reverseKey]);
                            if (count($this->reverseElement[$dn][$searchProperty]) === 0) {
                                unset($this->reverseElement[$dn][$searchProperty]);
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * @param array $attributeMap
     * @internal
     */
    public function setAttributeMap(array $attributeMap): void
    {
        if (!empty($attributeMap)) {
            $this->attributeMap = $attributeMap;

            foreach ($this->elements as $element) {
                $elementCase = $element->getResultIndexCase();
                if ($elementCase === null) {
                    $elementCase = $this->resultIndexCase;
                }
                $resultIndex = $element->getResultIndexField();
                if ($resultIndex === null) {
                    $this->reverseElement[$this->baseDn][$element->getField()][strtolower($element->getValue())] = array('case' => $elementCase, 'query_value' => $element->getValue());
                } else {
                    $this->reverseElement[$this->baseDn][$element->getField()][strtolower($element->getValue())] = array('case' => $elementCase, 'query_value' => $element->getValue(), 'return_index' => strtolower($resultIndex));
                }
            }

            foreach ($this->dnElements as $dn => $elements) {
                foreach ($elements as $element) {
                    $elementCase = $this->resultIndexCase;
                    if ($this->resultIndexCase === ResultIndex::UNCHANGED_QUERY) {
                        $elementCase = ResultIndex::UNCHANGED_DIRECTORY;
                    }
                    /**@var Element $element */
                    $resultIndex = $element->getResultIndexField();
                    if ($resultIndex === null) {
                        $this->reverseElement[$dn][$element->getField()][strtolower($element->getValue())] = array('case' => $elementCase, 'query_value' => $element->getValue());
                    } else {
                        $this->reverseElement[$dn][$element->getField()][strtolower($element->getValue())] = array('case' => $elementCase, 'query_value' => $element->getValue(), 'return_index' => strtolower($resultIndex));
                    }
                }
            }

            $this->reverseElement = array_change_key_case($this->reverseElement);
            foreach ($this->reverseElement as $dn => $elements) {
                $this->reverseElement[$dn] = array_change_key_case($elements);
            }
        }
    }
}
