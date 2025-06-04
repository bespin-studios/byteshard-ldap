<?php

namespace byteShard\Ldap\Enum;

enum ResultObject: string
{
    case dn        = 'dn';
    case Username  = 'Username';
    case Mail      = 'Mail';
    case Firstname = 'Firstname';
    case Lastname  = 'Lastname';
    case Groups    = 'Groups';
}
