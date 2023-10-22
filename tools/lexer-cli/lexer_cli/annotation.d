/++
    Lexer CLI (Thelxine Scripting Language)

    Copyright: © 2023  Elias Batek
    License: Boost Software License, Version 1.0
    Authors: Elias Batek
 +/
module lexer_cli.annotation;

import std.stdio;
import std.typecons : tuple;
import thelxine.lexer;

long lexAnnotated(const string source, const string file) @safe
{
    long errors = 0;
    auto lexer = ThelxineLexer(source, file);

    if (lexer.empty)
        return 0;

    long line = 1;

    do
    {
        errors += annotateLine(source, lexer, line);
        if (lexer.empty)
            return errors;

        ++line;
    }
    while (true);
}

private:

enum columnLength = 19;

long annotateLine(const string source, ref ThelxineLexer lexer, const long lineNumber) @safe
{
    ThelxineLexer copy = lexer;
    auto meta = analyizeLine(lexer);
    if (meta.offsetEnd < 0)
        meta.offsetEnd = source.length;

    writePadMB(source[meta.offsetStart .. meta.offsetEnd]);
    if ((source.length > 0) && (source[meta.offsetEnd - 1] != '\n'))
        writeln();

    annotateLineArrows(copy, meta.tokens, meta.offsetStart);

    for (long n = meta.tokens; n > 0; --n)
        annotateToken(copy, n, meta.offsetStart);

    writeln("^ line ", lineNumber, "\n");

    return meta.errors;
}

void writePadMB(string unicode) @safe
{
    static int utf8FurtherCodeUnits(char c)
    {
        immutable m = (c & 0b_1111_0000);

        // 1-byte char
        if (m == 0)
            return 0;

        // 2-byte char
        if (m == 0b_1100_0000)
            return 1;

        // 3-byte char
        if (m == 0b_1110_0000)
            return 2;

        // 4-byte char
        if (m == 0b_1111_0000)
            return 3;

        return -1;
    }

    while (unicode.length > 0)
    {
        write(unicode[0]);
        immutable further = utf8FurtherCodeUnits(unicode[0]);

        unicode = unicode[1 .. $];

        if (further > 0)
        {
            // invalid UTF-8 sequence (length)?
            if (unicode.length < further)
            {
                write(dchar(0xFFFD));
                return;
            }

            write(unicode[0 .. further]);
            unicode = unicode[further .. $];

            final switch (further)
            {
            case 1:
                write("…");
                break;
            case 2:
                write("……");
                break;
            case 3:
                write("………");
                break;
            }
        }
    }
}

struct LineMeta
{
    long errors;
    long tokens;
    ptrdiff_t offsetStart;
    ptrdiff_t offsetEnd;
}

void annotateLineArrows(ThelxineLexer lexer, long tokens, const size_t offsetStart) @safe
{
    size_t offset = offsetStart;

    foreach (Token token; lexer)
    {
        if (tokens == 0)
            break;

        if (token.type == TokenType.whitespace)
        {
            --tokens;
            continue;
        }

        immutable apply = token.location.offset - offset;
        offset = token.location.offset + 1;

        for (size_t i = 0; i < apply; ++i)
            write(' ');

        write('#');

        if (token.type == TokenType.indentation)
            write('\t');

        --tokens;
    }

    writeln();
}

void annotateToken(ThelxineLexer lexer, long tokens, const size_t offsetStart) @safe
{
    if (tokens == 0)
        return;

    size_t offset = offsetStart;

    foreach (Token token; lexer)
    {
        --tokens;

        if (token.type == TokenType.whitespace)
        {
            if (tokens == 0)
                break;

            continue;
        }

        immutable apply = token.location.offset - offset;
        offset = token.location.offset + 1;
        for (size_t i = 0; i < apply; ++i)
            write(' ');

        if (tokens > 0)
        {
            write('|');

            if (token.type == TokenType.indentation)
                write('\t');

            continue;
        }

        write('\'');
        for (size_t i = (columnLength - ((token.location.offset - offsetStart) % columnLength)); i > 0; --i)
            write('-');

        if (token.isError)
            write("- [ERROR: ", token.error, ']');
        else
            write("- [", token.type, ']');

        break;
    }

    writeln();
}

LineMeta analyizeLine(ref ThelxineLexer lexer) @safe
{
    auto result = LineMeta(0, 0, 0, -1);

    if (lexer.empty)
    {
        result.offsetEnd = 0;
        return result;
    }

    result.offsetStart = lexer.front.location.offset;

    while (!lexer.empty)
    {
        ++result.tokens;

        switch (lexer.front.type)
        {
        case TokenType.lineFeed:
            result.offsetEnd = lexer.front.location.offset + 1;
            lexer.popFront();
            return result;

        case TokenType.error:
            ++result.errors;
            break;

        default:
            break;
        }

        lexer.popFront();
    }

    return result;
}
