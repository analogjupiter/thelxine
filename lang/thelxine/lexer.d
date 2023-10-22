/++
    Lexer for the Thelxine Scripting Language

    Copyright: © 2023  Elias Batek
    License: Boost Software License, Version 1.0
    Authors: Elias Batek
 +/
module thelxine.lexer;

import thelxine.core;
import thelxine.internal.ascii;
import thelxine.internal.escape;

///
struct Location
{
    /++
        File name/path
     +/
    hstring file = null;

    /++
        Offset from the beginning of the file in bytes
        (counting from 0)
     +/
    size_t offset = 0;
}

///
struct LocationHumanReadable
{
    /++
        File name/path
     +/
    hstring file = null;

    /++
        Line number of the current line
        (counting from 1)
     +/
    long line = 1;

    /++
        Column: code point offset within the current line
        (counting from 1)
     +/
    long col = 1;

    static LocationHumanReadable fromMachineReadable(Location location, hstring source)
    {
        long line = 1; // @suppress(dscanner.suspicious.label_var_same_name)
        size_t offsetCurrentLine = 0;

        foreach (idx, char c; source[0 .. location.offset])
        {
            if (c == '\n')
            {
                ++line;
                offsetCurrentLine = idx;
            }
        }

        immutable long col = 1 + location.offset - offsetCurrentLine; // @suppress(dscanner.suspicious.label_var_same_name)
        return LocationHumanReadable(location.file, line, col);
    }
}

///
enum TokenType : int
{
    error = 0,

    hashBang,
    whitespace,

    // significant whitespace
    indentation,
    lineFeed,

    // comments
    commentLine,
    commentBlock,
    commentDocLine,
    commentDocBlock,

    // punctuation
    comma,
    semicolon,
    colon,

    // dot operator & friends
    opDot,
    opDotSafe,
    opNullCoalescing,
    opTernary,

    // dollar operator
    opDollar,

    // brackets
    bracketParenOpen,
    bracketParenClose,
    bracketSquareOpen,
    bracketSquareClose,
    bracketCurlyOpen,
    bracketCurlyClose,

    // unary operators
    opUnaryIncrement,
    opUnaryDecrement,

    // logical negation operator
    opLogicalNegation,
    opLogicalAnd,
    opLogicalOr,

    // comparison operators
    opCmpEquals,
    opCmpNotEquals,
    opCmpLessThan,
    opCmpGreaterThan,
    opCmpLessThanOrEqual,
    opCmpGreaterThanOrEqual,

    // binary operators
    opBinaryAdd,
    opBinarySub,
    opBinaryMul,
    opBinaryDiv,
    opBinaryMod,
    opBinaryAnd,
    opBinaryOr,
    opBinaryXor,
    opBinaryShiftL,
    opBinaryShiftR,
    opBinaryConcat,

    // assignment operator
    opAssign,

    // operation assignment operators
    opBinaryAddAssign,
    opBinarySubAssign,
    opBinaryMulAssign,
    opBinaryDivAssign,
    opBinaryModAssign,
    opBinaryAndAssign,
    opBinaryOrAssign,
    opBinaryXorAssign,
    opBinaryShiftLAssign,
    opBinaryShiftRAssign,
    opBinaryConcatAssign,
    opAppend = opBinaryConcatAssign,

    // literals
    literalBool,
    literalIntegerBase2,
    literalIntegerBase8,
    literalIntegerBase10,
    literalIntegerBase16,
    literalChar,
    literalFloat,
    literalString,

    // thelxine keywords
    kwModule,
    kwEntrypoint,

    // keywords
    kwAssert,
    kwBreak,
    kwByte,
    kwChar,
    kwConst,
    kwContinue,
    kwDo,
    kwDouble,
    kwFloat,
    kwFor,
    kwForeach,
    kwIf,
    kwImport,
    kwInt,
    kwShort,
    kwUbyte,
    kwUint,
    kwUlong,
    kwUshort,
    kwStruct,
    kwWhile,
    kwVoid,

    // identifier
    identifier,
    attribute,
    identifierReserved,
}

///
enum TokenErrorType
{
    none = 0,

    badLiteralChar,
    badLiteralInteger,
    badLiteralNumeric,

    unexpectedChar,
    unexpectedControlChar,
    unexpectedEOF,
    unexpectedEOL,
    unexpectedMultiByte,

    ice = (int.max - 1),
}

///
struct Token
{
    TokenType type;
    hstring data;
    Location location;

    TokenErrorType error = TokenErrorType.none;

@safe pure nothrow @nogc:

    bool isError() const
    {
        return (this.type == TokenType.error);
    }
}

private Token withType(const Token token, const TokenType type) @safe pure nothrow @nogc
{
    pragma(inline, true);
    return Token(type, token.data, token.location, TokenErrorType.none);
}

/++
    Validates a literal

    This function has certain assumptions about its input data.
 +/
bool validateLiteral(TokenType type, bool hasPrefix, bool checkPrefix)(const hstring literal) @safe pure nothrow @nogc
{
    static bool validateIntegerLiteral(string prefix, alias validate)(const hstring literal)
    {
        if (literal.length == 0)
            return false;

        static if (hasPrefix)
        {
            enum prefixLength = prefix.length;

            static if (checkPrefix)
                if (literal[0 .. prefixLength] != "0b")
                    return false;

            foreach (const char c; literal[prefixLength .. $])
                if (!validate(c))
                    return false;

            return true;
        }
        else
        {
            foreach (const char c; literal)
                if (!validate(c))
                    return false;

            return true;
        }
    }

    static if (type == TokenType.literalIntegerBase2)
        return validateIntegerLiteral!("0b", isDigitBase2orUnderscore)(literal);

    else static if (type == TokenType.literalIntegerBase8)
        return validateIntegerLiteral!("0o", isDigitBase8orUnderscore)(literal);

    else static if (type == TokenType.literalIntegerBase10)
        return validateIntegerLiteral!("", isDigitBase10orUnderscore)(literal);

    else static if (type == TokenType.literalIntegerBase16)
        return validateIntegerLiteral!("0o", isDigitBase16orUnderscore)(literal);

    else static if (type == TokenType.literalChar)
    {
        static assert(!hasPrefix, "Unsupported format");
        static assert(!checkPrefix, "Unsupported check");

        switch (literal.length)
        {
        case 1:
            return true;

        case 2:
            return (
                (literal[0] == '\\')
                && (literal[1].isValidCharEscapeSequence)
            );

        default:
            return false;

        }
    }

    else
        static assert(false, "Unsupported literal type");
}

///
bool isInsignificantWhitespace(const char c) @safe pure nothrow @nogc
{
    return ((c <= '\r') && (c >= '\x0B'));
}

/++
    Lexical tokenizer implementation
    for the Thelxine Scripting Language
 +/
struct ThelxineLexer
{
    public this(hstring source, Location location) @safe pure nothrow @nogc
    {
        _source = source;
        _location = location;

        _empty = false;
        this.popFront();
    }

    public this(hstring source, hstring fileName) @safe pure nothrow @nogc
    {
        this(source, Location(fileName, 0));
    }

    private
    {
        hstring _source;
        Location _location;

        bool _empty = true;
        Token _front;
    }

@safe pure nothrow @nogc:
public:

    ///
    hstring file() const
    {
        return _location.file;
    }

    ///
    bool empty() const
    {
        return _empty;
    }

    ///
    Token front() const
    {
        return _front;
    }

    ///
    void popFront()
    {
        // EOF?
        if (_source.length == 0)
        {
            _empty = true;
            return;
        }

        _front = this.lex();
    }

private:

    void wind(size_t n)
    {
        pragma(inline, true);
        _source = _source[n .. $];
        _location.offset += n;
    }

    hstring windSlice(size_t n)
    {
        pragma(inline, true);
        const output = _source[0 .. n];
        this.wind(n);
        return output;
    }

    bool isOnFinalChar() const
    {
        pragma(inline, true);
        return (_source.length == 1);
    }

    bool isNext(const char c) const
    {
        pragma(inline, true);
        return (!this.isOnFinalChar) && (c == _source[1]);
    }

    bool hasLeftAtLeast(size_t n)
    {
        pragma(inline, true);
        return (_source.length >= n);
    }

    bool hasWhitespaceAt(size_t idx)
    {
        pragma(inline, true);

        immutable c = _source[idx];
        return (
            (c == ' ')
                || ((c >= '\t') && (c <= '\r'))
        );
    }

    bool beginsWith(string needle, size_t offset = 0)
    {
        pragma(inline, true);

        if (_source.length < (needle.length + offset))
            return false;

        return (_source[offset .. needle.length] == needle);
    }

    Token makeToken(TokenType type, hstring data) const
    {
        pragma(inline, true);
        return Token(type, data, _location);
    }

    Token makeTokenWindSlice(TokenType type, size_t nWindSlice)
    {
        pragma(inline, true);

        const location = _location;
        return Token(type, this.windSlice(nWindSlice), location);
    }

    Token makeTokenWindSlice(TokenType type, size_t nWindSlice, size_t nPreWind, size_t nPostWind)
    {
        pragma(inline, true);

        const location = _location;

        this.wind(nPreWind);
        const output = Token(type, this.windSlice(nWindSlice), location);
        this.wind(nPostWind);

        return output;
    }

    Token makeErrorToken(TokenErrorType type, hstring data) const
    {
        pragma(inline, true);
        return Token(TokenType.error, data, _location, type);
    }

    Token makeErrorTokenWindSlice(TokenErrorType type, size_t nWindSlice)
    {
        pragma(inline, true);
        const location = _location;
        return Token(TokenType.error, this.windSlice(nWindSlice), location, type);
    }

    Token lex()
    {
        do
        {
            final switch (_source[0])
            {
            case '\x00':
            case '\x01':
            case '\x02':
            case '\x03':
            case '\x04':
            case '\x05':
            case '\x06':
            case '\x07':
            case '\x08':
                return this.makeErrorTokenWindSlice(TokenErrorType.unexpectedControlChar, 1);

            case '\t': // \0x09
                return this.makeTokenWindSlice(TokenType.indentation, 1);
            case '\n': // \0x0A
                return this.makeTokenWindSlice(TokenType.lineFeed, 1);

            case '\x0B':
            case '\x0C':
            case '\r': // \0x0D
                return this.lexInsignificantWhitespace();

            case '\x0E':
            case '\x0F':
            case '\x10':
            case '\x11':
            case '\x12':
            case '\x13':
            case '\x14':
            case '\x15':
            case '\x16':
            case '\x17':
            case '\x18':
            case '\x19':
            case '\x1A':
            case '\x1B':
            case '\x1C':
            case '\x1D':
            case '\x1E':
            case '\x1F':
                return this.makeErrorTokenWindSlice(TokenErrorType.unexpectedControlChar, 1);

            case ' ': // \x20
                return this.lexInsignificantWhitespace();

            case '!': // \x21
                return this.lexIfNextIsElse('=', TokenType.opCmpNotEquals, TokenType.opLogicalNegation);

            case '"': // \x22
                return this.lexStringLiteral();

            case '#': // \x23
                return this.lexHashbang();

            case '$': // \x24
                return this.makeTokenWindSlice(TokenType.opDollar, 1);

            case '%': // \x25
                return this.lexIfNextIsElse('=', TokenType.opBinaryModAssign, TokenType.opBinaryMod);

            case '&': // \x26
                return this.lexIfNextIsElse(
                    '&', TokenType.opLogicalAnd,
                    '=', TokenType.opBinaryAndAssign,
                    TokenType.opBinaryAnd
                );

            case '\'': //\x27
                return this.lexCharLiteral();

            case '(': // \x28
                return this.makeTokenWindSlice(TokenType.bracketParenOpen, 1);

            case ')': // \x29
                return this.makeTokenWindSlice(TokenType.bracketParenClose, 1);

            case '*': // \x2A
                return this.lexIfNextIsElse('=', TokenType.opBinaryMulAssign, TokenType.opBinaryMul);

            case '+': // \x2B
                return this.lexIfNextIsElse(
                    '=', TokenType.opBinaryAddAssign,
                    '+', TokenType.opUnaryIncrement,
                    TokenType.opBinaryAdd
                );

            case ',': // \x2C
                return this.makeTokenWindSlice(TokenType.comma, 1);

            case '-': // \x2D
                return this.lexIfNextIsElse(
                    '=', TokenType.opBinarySubAssign,
                    '-', TokenType.opUnaryDecrement,
                    TokenType.opBinarySub
                );

            case '.': // \x2E
                return this.makeTokenWindSlice(TokenType.opDot, 1);

            case '/': // \x2F
                return this.lexSlashFwd();

            case '0': // \x30
                return this.lexNumericLiteralOfUnknownBase();
            case '1': // \x31
            case '2': // \x32
            case '3': // \x33
            case '4': // \x34
            case '5': // \x35
            case '6': // \x36
            case '7': // \x37
            case '8': // \x38
            case '9': // \x39
                return this.lexNumericLiteralBase10();

            case ':': // \x3A'
                return this.makeTokenWindSlice(TokenType.colon, 1);

            case ';': // \x3B'
                return this.makeTokenWindSlice(TokenType.semicolon, 1);

            case '<': // \x3C'
                // TODO: shift + shift-assign
                return this.lexIfNextIsElse('=', TokenType.opCmpLessThanOrEqual, TokenType.opCmpLessThan);

            case '=': // \x3D'
                return this.lexIfNextIsElse('=', TokenType.opCmpEquals, TokenType.opAssign);

            case '>': // \x3E'
                // TODO: shift + shift-assign
                return this.lexIfNextIsElse('=', TokenType.opCmpGreaterThanOrEqual, TokenType.opCmpGreaterThan);

            case '?': // \x3F'
                return this.lexIfNextIsElse(
                    '.', TokenType.opDotSafe, // .?
                    '?', TokenType.opNullCoalescing, // ??
                    TokenType.opTernary,
                );

            case '@': // \x40'
                return this.lexAttribute();

            case 'A': // \x41'
            case 'B': // \x42'
            case 'C': // \x43'
            case 'D': // \x44'
            case 'E': // \x45'
            case 'F': // \x46'
            case 'G': // \x47'
            case 'H': // \x48'
            case 'I': // \x49'
            case 'J': // \x4A'
            case 'K': // \x4B'
            case 'L': // \x4C'
            case 'M': // \x4D'
            case 'N': // \x4E'
            case 'O': // \x4F'
            case 'P': // \x50'
            case 'Q': // \x51'
            case 'R': // \x52'
            case 'S': // \x53'
            case 'T': // \x54'
            case 'U': // \x55'
            case 'V': // \x56'
            case 'W': // \x57'
            case 'X': // \x58'
            case 'Y': // \x59'
            case 'Z': // \x5A'
                return this.lexWord!(TokenType.identifier)();

            case '[': // \x5B'
                return this.makeTokenWindSlice(TokenType.bracketSquareOpen, 1);

            case '\\': //\x5C'
                break;

            case ']': // \x5D'
                return this.makeTokenWindSlice(TokenType.bracketSquareClose, 1);

            case '^': // \x5E'
                return this.lexIfNextIsElse('=', TokenType.opBinaryXorAssign, TokenType.opBinaryXor);

            case '_': // \x5F'
                return this.lexIdentifierOrKeyword!'_'();

            case '`': // \x60'
                break;

            case 'a': // \x61'
                return this.lexIdentifierOrKeyword!'a'();
            case 'b': // \x62'
                return this.lexIdentifierOrKeyword!'b'();
            case 'c': // \x63'
                return this.lexIdentifierOrKeyword!'c'();
            case 'd': // \x64'
                return this.lexIdentifierOrKeyword!'d'();
            case 'e': // \x65'
                return this.lexIdentifierOrKeyword!'e'();
            case 'f': // \x66'
                return this.lexIdentifierOrKeyword!'f'();
            case 'g': // \x67'
                return this.lexIdentifierOrKeyword!'g'();
            case 'h': // \x68'
                return this.lexIdentifierOrKeyword!'h'();
            case 'i': // \x69'
                return this.lexIdentifierOrKeyword!'i'();
            case 'j': // \x6A'
                return this.lexIdentifierOrKeyword!'j'();
            case 'k': // \x6B'
                return this.lexIdentifierOrKeyword!'k'();
            case 'l': // \x6C'
                return this.lexIdentifierOrKeyword!'l'();
            case 'm': // \x6D'
                return this.lexIdentifierOrKeyword!'m'();
            case 'n': // \x6E'
                return this.lexIdentifierOrKeyword!'n'();
            case 'o': // \x6F'
                return this.lexIdentifierOrKeyword!'o'();
            case 'p': // \x70'
                return this.lexIdentifierOrKeyword!'p'();
            case 'q': // \x71'
                return this.lexIdentifierOrKeyword!'q'();
            case 'r': // \x72'
                return this.lexIdentifierOrKeyword!'r'();
            case 's': // \x73'
                return this.lexIdentifierOrKeyword!'s'();
            case 't': // \x74'
                return this.lexIdentifierOrKeyword!'t'();
            case 'u': // \x75'
                return this.lexIdentifierOrKeyword!'u'();
            case 'v': // \x76'
                return this.lexIdentifierOrKeyword!'v'();
            case 'w': // \x77'
                return this.lexIdentifierOrKeyword!'w'();
            case 'x': // \x78'
                return this.lexIdentifierOrKeyword!'x'();
            case 'y': // \x79'
                return this.lexIdentifierOrKeyword!'y'();
            case 'z': // \x7A'
                return this.lexIdentifierOrKeyword!'z'();

            case '{': // \x7B'
                return this.makeTokenWindSlice(TokenType.bracketCurlyOpen, 1);

            case '|': // \x7C'
                return this.lexIfNextIsElse(
                    '|', TokenType.opLogicalOr,
                    '=', TokenType.opBinaryOrAssign,
                    TokenType.opBinaryOrAssign
                );

            case '}': // \x7D'
                return this.makeTokenWindSlice(TokenType.bracketCurlyClose, 1);

            case '~': // \x7E'
                return this.lexIfNextIsElse('=', TokenType.opBinaryConcatAssign, TokenType.opBinaryConcat);

            case '\x7F':
                return this.makeErrorTokenWindSlice(TokenErrorType.unexpectedControlChar, 1);

                // unicode
            case '\x80':
            case '\x81':
            case '\x82':
            case '\x83':
            case '\x84':
            case '\x85':
            case '\x86':
            case '\x87':
            case '\x88':
            case '\x89':
            case '\x8A':
            case '\x8B':
            case '\x8C':
            case '\x8D':
            case '\x8E':
            case '\x8F':
            case '\x90':
            case '\x91':
            case '\x92':
            case '\x93':
            case '\x94':
            case '\x95':
            case '\x96':
            case '\x97':
            case '\x98':
            case '\x99':
            case '\x9A':
            case '\x9B':
            case '\x9C':
            case '\x9D':
            case '\x9E':
            case '\x9F':
            case '\xA0':
            case '\xA1':
            case '\xA2':
            case '\xA3':
            case '\xA4':
            case '\xA5':
            case '\xA6':
            case '\xA7':
            case '\xA8':
            case '\xA9':
            case '\xAA':
            case '\xAB':
            case '\xAC':
            case '\xAD':
            case '\xAE':
            case '\xAF':
            case '\xB0':
            case '\xB1':
            case '\xB2':
            case '\xB3':
            case '\xB4':
            case '\xB5':
            case '\xB6':
            case '\xB7':
            case '\xB8':
            case '\xB9':
            case '\xBA':
            case '\xBB':
            case '\xBC':
            case '\xBD':
            case '\xBE':
            case '\xBF':
            case '\xC0':
            case '\xC1':
            case '\xC2':
            case '\xC3':
            case '\xC4':
            case '\xC5':
            case '\xC6':
            case '\xC7':
            case '\xC8':
            case '\xC9':
            case '\xCA':
            case '\xCB':
            case '\xCC':
            case '\xCD':
            case '\xCE':
            case '\xCF':
            case '\xD0':
            case '\xD1':
            case '\xD2':
            case '\xD3':
            case '\xD4':
            case '\xD5':
            case '\xD6':
            case '\xD7':
            case '\xD8':
            case '\xD9':
            case '\xDA':
            case '\xDB':
            case '\xDC':
            case '\xDD':
            case '\xDE':
            case '\xDF':
            case '\xE0':
            case '\xE1':
            case '\xE2':
            case '\xE3':
            case '\xE4':
            case '\xE5':
            case '\xE6':
            case '\xE7':
            case '\xE8':
            case '\xE9':
            case '\xEA':
            case '\xEB':
            case '\xEC':
            case '\xED':
            case '\xEE':
            case '\xEF':
            case '\xF0':
            case '\xF1':
            case '\xF2':
            case '\xF3':
            case '\xF4':
            case '\xF5':
            case '\xF6':
            case '\xF7':
            case '\xF8':
            case '\xF9':
            case '\xFA':
            case '\xFB':
            case '\xFC':
            case '\xFD':
            case '\xFE':
            case '\xFF':
                return this.lexUnexpectedMultiByte();
            }
        }
        while (_source.length > 0);

        _empty = true;
        return this.makeErrorToken(TokenErrorType.ice, null);
    }

    Token lexHashbang()
    {
        if ((this.isOnFinalChar) || (_source[1] != '!'))
            return this.makeErrorTokenWindSlice(TokenErrorType.unexpectedChar, 1);

        foreach (idx, const char c; _source)
            if (c == '\n')
                return this.makeTokenWindSlice(TokenType.hashBang, idx);

        return this.makeTokenWindSlice(TokenType.hashBang, _source.length);
    }

    Token lexInsignificantWhitespace()
    {
        foreach (idx, const char c; _source[1 .. $])
            if (!c.isInsignificantWhitespace)
                return this.makeTokenWindSlice(TokenType.whitespace, (idx + 1));

        return this.makeTokenWindSlice(TokenType.whitespace, _source.length);
    }

    Token lexStringLiteral()
    {
        bool wasEscapeChar = false;
        foreach (idx, char c; _source[1 .. $])
        {
            if (c == '\n')
                return this.makeErrorTokenWindSlice(TokenErrorType.unexpectedEOL, (idx + 1));

            if (!wasEscapeChar)
            {
                if (c == '\\')
                {
                    wasEscapeChar = true;
                    continue;
                }

                if (c == '"')
                    return this.makeTokenWindSlice(TokenType.literalString, idx, 1, 1);

                wasEscapeChar = false;
            }
        }

        return this.makeErrorTokenWindSlice(TokenErrorType.unexpectedEOF, _source.length);
    }

    Token lexCharLiteral()
    {
        bool escapeActive = false;

        foreach (idx, const char c; _source[1 .. $])
        {
            if (c == '\n')
                return this.makeErrorTokenWindSlice(TokenErrorType.unexpectedEOL, (idx + 1));

            if (escapeActive)
            {
                escapeActive = false;
                continue;
            }

            if (c == '\'')
            {
                if (!validateLiteral!(TokenType.literalChar, false, false)(_source[1 .. (idx + 1)]))
                    return this.makeErrorTokenWindSlice(TokenErrorType.badLiteralChar, (idx + 2));

                return this.makeTokenWindSlice(TokenType.literalChar, idx, 1, 1);
            }

            if (c == '\\')
            {
                escapeActive = true;
                continue;
            }
        }

        return this.makeErrorTokenWindSlice(TokenErrorType.unexpectedEOF, _source.length);
    }

    Token lexWord(TokenType type = TokenType.identifier)()
    {
        foreach (size_t idx, const char c; _source)
        {
            // end of identifier?
            if (!c.isAlphaNumericOrUnderscore)
                return this.makeTokenWindSlice(type, idx);
        }

        return this.makeTokenWindSlice(type, _source.length);
    }

    /+
        Lexes an integer literal
        of a specified base
        but doesn't check whether the prefix matches that base.
     +/
    Token lexIntegerLiteralWithKnownBase(TokenType type)()
    {
        const Token token = lexWord!(type);

        // invalid data?
        if (!validateLiteral!(type, true, false)(token.data))
            return Token(TokenType.error, token.data, token.location, TokenErrorType.badLiteralInteger);

        return token;
    }

    /+
        Lexes an integer literal
        after checking whether data follows after the base prefix.
     +/
    Token lexIntegerLiteralWithBasePrefix(TokenType type)()
    {
        if (_source.length == 2)
            return this.makeErrorTokenWindSlice(TokenErrorType.unexpectedEOF, 1);

        return this.lexIntegerLiteralWithKnownBase!type();
    }

    /+
        Lexes a numeric literal
        after determining in which base it is notated.

        Hint: Call this for words starting with '0'.
     +/
    Token lexNumericLiteralOfUnknownBase()
    {
        if (this.isOnFinalChar)
            return this.makeTokenWindSlice(TokenType.literalIntegerBase10, 1);

        switch (_source[1])
        {
        default:
            return this.lexNumericLiteralBase10;

        case 'b': // base 2
            return this.lexIntegerLiteralWithBasePrefix!(TokenType.literalIntegerBase2);

        case 'o': // base 8
            return this.lexIntegerLiteralWithBasePrefix!(TokenType.literalIntegerBase8);

        case 'x': // base 16
            return this.lexIntegerLiteralWithKnownBase!(TokenType.literalIntegerBase16);
        }
    }

    /+
        Lexes a numeric literal in decimal notation (base 10)
     +/
    Token lexNumericLiteralBase10()
    {
        bool hasComma = false;

        size_t idxEnd = _source.length;
        foreach (idx, const char c; _source)
        {
            if (c.isDigitBase10orUnderscore)
                continue;

            if (c == '.')
            {
                // 2nd comma -> opDot
                if (hasComma)
                {
                    idxEnd = idx;
                    break;
                }

                hasComma = true;
                continue;
            }

            idxEnd = idx;
            break;
        }

        immutable type = (hasComma) ? TokenType.literalFloat : TokenType.literalIntegerBase10;
        return this.makeTokenWindSlice(type, idxEnd);
    }

    Token lexIdentifierOrKeyword(char firstLetter)()
    {
        const token = this.lexWord!(TokenType.identifier)();

        static if (firstLetter == '_')
        {
            if ((token.data.length >= 2) && (token.data[1] == '_'))
                return token.withType(TokenType.identifierReserved);

            return token;
        }

        else static if (firstLetter == 'a')
        {
            switch (token.data[1 .. $])
            {
            case "ssert":
                return token.withType(TokenType.kwBreak);
            default:
                return token;
            }
        }

        else static if (firstLetter == 'b')
        {
            switch (token.data[1 .. $])
            {
            case "reak":
                return token.withType(TokenType.kwBreak);
            case "yte":
                return token.withType(TokenType.kwByte);
            default:
                return token;
            }
        }

        else static if (firstLetter == 'c')
        {
            switch (token.data[1 .. $])
            {
            case "har":
                return token.withType(TokenType.kwChar);
            case "onst":
                return token.withType(TokenType.kwConst);
            case "ontinue":
                return token.withType(TokenType.kwContinue);
            default:
                return token;
            }
        }

        else static if (firstLetter == 'd')
        {
            switch (token.data[1 .. $])
            {
            case "o":
                return token.withType(TokenType.kwDo);
            case "ouble":
                return token.withType(TokenType.kwDouble);
            default:
                return token;
            }
        }

        else static if (firstLetter == 'f')
        {
            switch (token.data[1 .. $])
            {
            case "loat":
                return token.withType(TokenType.kwFloat);
            case "or":
                return token.withType(TokenType.kwFor);
            case "oreach":
                return token.withType(TokenType.kwForeach);
            default:
                return token;
            }
        }

        else static if (firstLetter == 'i')
        {
            switch (token.data[1 .. $])
            {
            case "f":
                return token.withType(TokenType.kwIf);
            case "mport":
                return token.withType(TokenType.kwImport);
            case "nt":
                return token.withType(TokenType.kwInt);
            default:
                return token;
            }
        }

        else static if (firstLetter == 's')
        {
            switch (token.data[1 .. $])
            {
            case "hort":
                return token.withType(TokenType.kwShort);
            case "truct":
                return token.withType(TokenType.kwStruct);
            default:
                return token;
            }
        }

        else static if (firstLetter == 't')
        {
            switch (token.data[1 .. $])
            {
            case "helxine_module":
                return token.withType(TokenType.kwModule);
            case "helxine_script":
                return token.withType(TokenType.kwEntrypoint);
            default:
                return token;
            }
        }

        else static if (firstLetter == 'u')
        {
            switch (token.data[1 .. $])
            {
            case "byte":
                return token.withType(TokenType.kwUbyte);
            case "int":
                return token.withType(TokenType.kwUint);
            case "long":
                return token.withType(TokenType.kwUlong);
            case "short":
                return token.withType(TokenType.kwUshort);
            default:
                return token;
            }
        }

        else static if (firstLetter == 'w')
        {
            switch (token.data[1 .. $])
            {
            case "hile":
                return token.withType(TokenType.kwWhile);
            default:
                return token;
            }
        }

        else static if (firstLetter == 'v')
        {
            switch (token.data[1 .. $])
            {
            case "oid":
                return token.withType(TokenType.kwVoid);
            default:
                return token;
            }
        }

        else
            return token;
    }

    Token lexAttribute()
    {
        if (this.isOnFinalChar)
            return this.makeErrorTokenWindSlice(TokenErrorType.unexpectedEOF, 1);

        foreach (size_t idx, const char c; _source[1 .. $])
        {
            // end of identifier?
            if (!c.isAlphaNumericOrUnderscore)
                return this.makeTokenWindSlice(TokenType.attribute, idx, 1, 0);
        }

        return this.makeTokenWindSlice(TokenType.attribute, _source.length, 1, 0);
    }

    /// lex '/' ("forward slash")
    Token lexSlashFwd()
    {
        static Token lexCommentBlock(const char block)(ref ThelxineLexer that)
        {
            pragma(inline, true);

            bool couldClose = false;
            foreach (idx, const char c; that._source[2 .. $])
            {
                if (c == block)
                {
                    couldClose = true;
                    continue;
                }

                if (couldClose && (c == '/'))
                {
                    if (that._source[2] == block)
                        return that.makeTokenWindSlice(TokenType.commentDocBlock, (idx - 2), 3, 2);

                    return that.makeTokenWindSlice(TokenType.commentBlock, (idx - 1), 2, 2);
                }
            }

            return that.makeErrorTokenWindSlice(TokenErrorType.unexpectedEOF, that._source.length);
        }

        static Token lexCommentLine(ref ThelxineLexer that)
        {
            pragma(inline, true);

            foreach (idx, const char c; that._source[2 .. $])
            {
                if (c == '\n')
                {
                    if (that._source[2] == '/')
                        return that.makeTokenWindSlice(TokenType.commentDocLine, (idx - 1), 3, 0);

                    return that.makeTokenWindSlice(TokenType.commentLine, idx, 2, 0);
                }
            }

            return that.makeTokenWindSlice(TokenType.commentLine, that._source.length, 2, 0);
        }

        if (!this.isOnFinalChar)
        {
            switch (_source[1])
            {
            case '=':
                return this.makeTokenWindSlice(TokenType.opBinaryDivAssign, 2);
            case '/':
                return lexCommentLine(this);
            case '*':
                return lexCommentBlock!'*'(this);
            case '+':
                return lexCommentBlock!'+'(this);
            default:
                break;
            }
        }

        return this.makeTokenWindSlice(TokenType.opBinaryDiv, 1);
    }

    /*Token lexIfNextIsElse(const char pred, const TokenType match, const TokenType else_)
    {
        pragma(inline, true);

        if (!this.isOnFinalChar && (_source[1] == pred))
            return this.makeTokenWindSlice(match, 2);

        return this.makeTokenWindSlice(else_, 1);
    }*/

    /*Token lexIfNextIsElseIfElse(
        const char pred, const TokenType match,
        const char predElseIf, const TokenType matchElseIf,
        const TokenType else_
    )
    {
        pragma(inline, true);

        if (!this.isOnFinalChar)
        {
            if (_source[1] == pred)
                return this.makeTokenWindSlice(match, 2);

            if (_source[1] == predElseIf)
                return this.makeTokenWindSlice(matchElseIf, 2);
        }

        return this.makeTokenWindSlice(else_, 1);
    }*/

    /+
        if (_source[1] == args[0])
            return args[1];
        if (args > 2) {
            else if (_source[1] == args[2])
                return args[3];
            […repeat…]
        }
        else
            return args[$ - 1];
     +/
    Token lexIfNextIsElse(Args...)(
        Args args,
    )
    {
        pragma(inline, true);

        static assert((args.length % 2) == 1, "Invalid argument count");

        if (!this.isOnFinalChar)
        {
            static Token impl(Args...)(
                ref ThelxineLexer that,
                Args args,
            )
            {
                pragma(inline, true);

                static if (args.length == 1)
                    return that.makeTokenWindSlice(args[$ - 1], 1);
                else
                {
                    static assert(
                        __traits(compiles, { const char pred = args[0]; }), "Bad char predicate"
                    );
                    static assert(
                        __traits(compiles, { const TokenType tokenType = args[1]; }), "Bad TokenType"
                    );

                    if (that._source[1] == args[0])
                        return that.makeTokenWindSlice(args[1], 2);

                    return impl(that, args[2 .. $]);
                }
            }

            return impl(this, args);
        }

        static assert(
            __traits(compiles, { const TokenType tokenType = args[$ - 1]; }), "Bad TokenType @else"
        );
        return this.makeTokenWindSlice(args[$ - 1], 1);
    }

    Token lexUnexpectedMultiByte()
    {
        foreach (idx, char c; _source[1 .. $])
            if (c <= '\x7F')
                return this.makeErrorTokenWindSlice(TokenErrorType.unexpectedMultiByte, idx + 1);

        return this.makeErrorTokenWindSlice(TokenErrorType.unexpectedMultiByte, _source.length);
    }
}
