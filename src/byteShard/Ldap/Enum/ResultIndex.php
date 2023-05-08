<?php
/**
 * @copyright  Copyright (c) 2009 Bespin Studios GmbH
 * @license    See LICENSE file that is distributed with this source code
 */

namespace byteShard\Ldap\Enum;

/**
 * Class ResultIndex
 * @package byteShard\Ldap\Enum
 */
enum ResultIndex: int
{
    case UNCHANGED_QUERY = 0;
    case UNCHANGED_DIRECTORY = 1;
    case LOWER = 2;
    case UPPER = 3;
    case LCFIRST = 4;
    case UCFIRST = 5;
}
