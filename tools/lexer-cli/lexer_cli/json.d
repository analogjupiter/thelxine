/++
    Lexer CLI (Thelxine Scripting Language)

    Copyright: © 2023  Elias Batek
    License: Boost Software License, Version 1.0
    Authors: Elias Batek
 +/
module lexer_cli.json;

import std.json : JSONOptions, JSONValue;
import std.stdio;
import thelxine.lexer;

long lexJSON(const string source, const string file) @safe
{
    long errors = 0;

    auto lexer = ThelxineLexer(source, file);

    //writefln!"{%s: ["(jsonEncode(lexer.file));
    writeln('[');
    bool firstToken = true;

    foreach (Token token; lexer)
    {
        if (firstToken)
            firstToken = false;
        else
            writeln(",");

        if (token.type == TokenType.error)
            ++errors;

        writeToken(token);
    }
    //writeln("\n]}");
    writeln("\n]");

    return errors;
}

private:

enum jsonOptions = JSONOptions.doNotEscapeSlashes;

string jsonEncode(T)(T value)
{
    return JSONValue(value).toString(jsonOptions);
}

void writeToken(const Token token) @safe
{
    if (token.type == TokenType.error)
    {
        enum format = `{"%s": {"offset": %d, "data": %s, "error": "%s"}}`;
        writef!format(
            token.type,
            token.location.offset,
            jsonEncode(token.data),
            token.error,
        );
        return;
    }

    enum format = `{"%s": {"offset": %d, "data": %s}}`;
    writef!format(
        token.type,
        token.location.offset,
        jsonEncode(token.data),
    );
}
