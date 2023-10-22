/++
    Lexer CLI (Thelxine Scripting Language)

    Copyright: © 2023  Elias Batek
    License: Boost Software License, Version 1.0
    Authors: Elias Batek
 +/
module app;

import std.stdio;

int main(string[] args)
{
    import std.getopt;

    string format = "annotate";

    GetoptResult opts = getopt(
        args,
        "f|format",
        "Output format"
            ~ "\n\t=annotate\tGenerate code annotated with lexical information"
            ~ "\n\t=json    \tGenerate a JSON array of lexical tokens",
        &format,
    );

    if ((args.length < 2) || (opts.helpWanted))
    {
        defaultGetoptPrinter(
            "Thelxine Lexer CLI\n\nUsage:\n\t" ~ args[0] ~ " [<options>] <source-file>\n",
            opts.options
        );
        return 0;
    }

    if (args.length > 2)
    {
        stderr.writeln("Error: Too many source files");
        return 1;
    }

    string file = args[1];
    long errors = lexFileAs(file, format);

    if (errors < 0)
        return 1;

    if (errors > 0)
    {
        stderr.writefln!"Warning: %d lexical error(s)"(errors);
        return 2;
    }

    return 0;
}

private:

long lexFileAs(string file, string format)
{
    switch (format)
    {
    case "annotate":
    case "a":
        {
            import lexer_cli.annotation;

            return lexFile!lexAnnotated(file);
        }

    case "json":
    case "j":
        {
            import lexer_cli.json;

            return lexFile!lexJSON(file);
        }

    default:
        stderr.writeln("Unsupported output format: ", format);
        return -1;
    }
}

long lexFile(alias processor)(string file) @safe
{
    import std.file;

    string source = readText(file);
    return processor(source, file);
}
