/++
    ASCII utils for the Thelxine Scripting Language implementation

    Copyright: © 2023  Elias Batek
    License: Boost Software License, Version 1.0
    Authors: Elias Batek
 +/
module thelxine.internal.ascii;

@safe pure nothrow @nogc:

///
bool isAlphaNumericOrUnderscore(const char c)
{
    return (
        (c <= 'z')
            && (c >= '0')
            && (
                (c >= 'a')
                || ((c >= 'A') && (c <= 'Z'))
                || (c <= '9')
                || (c == '_')
            )
    );
}

///
bool isDigitBase10(const char c)
{
    return ((c <= '9') && (c >= '0'));
}

///
bool isDigitBase2orUnderscore(const char c)
{
    return ((c == '0') || (c == '1') || (c == '_'));
}

///
bool isDigitBase8orUnderscore(const char c)
{
    return (((c <= '7') && (c >= '0')) || (c == '_'));
}

///
bool isDigitBase10orUnderscore(const char c)
{
    return (((c <= '9') && (c >= '0')) || (c == '_'));
}

bool isDigitBase16orUnderscore(const char c)
{
    immutable char c2 = (c & 0b1101_1111); // convert to upper-case
    return (
        ((c >= '0') && (c <= '9'))
            || ((c2 >= 'A') && (c2 <= 'F'))
            || (c == '_')
    );
}

///
bool isWhitespace(const char c)
{
    return (
        (c == ' ')
            || ((c >= '\t') && (c <= '\r'))
    );
}
