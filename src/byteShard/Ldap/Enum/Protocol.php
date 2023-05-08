<?php
/**
 * @copyright  Copyright (c) 2009 Bespin Studios GmbH
 * @license    See LICENSE file that is distributed with this source code
 */

namespace byteShard\Ldap\Enum;

/**
 * Class Protocol
 * @package byteShard\Ldap\Enum
 */
enum Protocol: int
{
    case V2 = 2;
    case V3 = 3;
}
