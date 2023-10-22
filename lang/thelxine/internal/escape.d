/++
    Escape-sequence utils for the Thelxine Scripting Language implementation

    Copyright: © 2023  Elias Batek
    License: Boost Software License, Version 1.0
    Authors: Elias Batek
 +/
module thelxine.internal.escape;

@safe pure nothrow @nogc:

bool isValidCharEscapeSequence(const char c)
{
    switch (c)
    {
    case '\\':
    case '0':
    case 'e':
    case 'n':
    case 'r':
    case 't':
        return true;

    default:
        return false;
    }
}
