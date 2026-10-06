"""Closed PostgreSQL 17 DDL grammar for the database admission boundary.

This is deliberately not a general SQL parser. Every token must be consumed by
a supported production; procedural SQL, data writes and type aliases are not
classified by guessing what an identifier or a string contains.
"""

from dataclasses import dataclass
import re


class SqlRefused(ValueError):
    """A content-free refusal safe to return across the process boundary."""


@dataclass(frozen=True)
class Token:
    kind: str
    value: str


@dataclass(frozen=True)
class Shape:
    columns: tuple[tuple[str, str], ...]
    extensions: tuple[str, ...]


IDENTIFIER = re.compile(r"[a-z_][a-z_0-9]{0,62}\Z")
WORD = re.compile(r"[A-Za-z_][A-Za-z_0-9$]*")
NUMBER = re.compile(r"[0-9]+(?:\.[0-9]+)?")
TYPES = {
    "smallint", "integer", "bigint", "numeric", "decimal", "real", "boolean",
    "text", "bytea", "json", "jsonb", "uuid", "date", "timestamp", "timestamptz",
    "char", "varchar", "double",
}
TYPE_ALIASES = {
    "int2": "smallint", "int4": "integer", "int8": "bigint", "bool": "boolean",
    "float4": "real", "float8": "double precision", "decimal": "numeric", "bpchar": "char",
}
CATALOG_TYPES = {
    "int2", "int4", "int8", "bool", "float4", "float8", "numeric", "text",
    "bytea", "json", "jsonb", "uuid", "date", "timestamp", "timestamptz", "bpchar", "varchar",
}


def tokens(sql: str) -> list[Token]:
    result: list[Token] = []
    position = 0
    while position < len(sql):
        char = sql[position]
        if char in " \t\r\n":
            position += 1
        elif sql.startswith("--", position):
            position += 2
            while position < len(sql) and sql[position] not in "\r\n":
                position += 1
        elif sql.startswith("/*", position):
            depth = 1
            position += 2
            while position < len(sql) and depth:
                if sql.startswith("/*", position):
                    depth += 1
                    if depth > 32:
                        raise SqlRefused("SQL_LIMIT")
                    position += 2
                elif sql.startswith("*/", position):
                    depth -= 1
                    position += 2
                else:
                    position += 1
            if depth:
                raise SqlRefused("SQL_UNTERMINATED_COMMENT")
        elif char in "'\"":
            quote = char
            position += 1
            value = ""
            while position < len(sql):
                char = sql[position]
                position += 1
                if char == quote:
                    if position < len(sql) and sql[position] == quote:
                        value += quote
                        position += 1
                    else:
                        break
                else:
                    if char == "\\" or ord(char) < 32 or ord(char) > 126:
                        raise SqlRefused("SQL_UNSUPPORTED_LITERAL")
                    value += char
            else:
                raise SqlRefused("SQL_UNTERMINATED_QUOTE")
            result.append(Token("identifier" if quote == '"' else "literal", value))
        elif match := WORD.match(sql, position):
            result.append(Token("word", match.group().lower()))
            position = match.end()
        elif match := NUMBER.match(sql, position):
            result.append(Token("number", match.group()))
            position = match.end()
        elif sql[position:position + 2] in {"<=", ">=", "<>", "!="}:
            result.append(Token("symbol", sql[position:position + 2]))
            position += 2
        elif char in "(),.;[]=<>+-*/%~":
            result.append(Token("symbol", char))
            position += 1
        else:
            raise SqlRefused("SQL_UNSUPPORTED_TOKEN")
        if len(result) > 32768:
            raise SqlRefused("SQL_LIMIT")
    result.append(Token("end", ""))
    return result


class Parser:
    def __init__(self, sql: str):
        self.items = tokens(sql)
        self.position = 0
        self.columns: dict[str, str] = {}
        self.extensions: list[str] = []
        self.expression_depth = 0

    @property
    def current(self) -> Token:
        return self.items[self.position]

    def take(self, value: str) -> bool:
        if self.current.kind in {"word", "symbol"} and self.current.value == value:
            self.position += 1
            return True
        return False

    def require(self, value: str) -> None:
        if not self.take(value):
            raise SqlRefused("SQL_UNSUPPORTED_GRAMMAR")

    def identifier(self) -> str:
        item = self.current
        if item.kind not in {"word", "identifier"} or not IDENTIFIER.fullmatch(item.value):
            raise SqlRefused("SQL_UNSUPPORTED_IDENTIFIER")
        self.position += 1
        return item.value

    def qualified(self) -> str:
        schema = self.identifier()
        if schema in {"pg_catalog", "information_schema", "migration_runner", "pg_temp"} or schema.startswith("pg_"):
            raise SqlRefused("SQL_RESERVED_SCHEMA")
        self.require(".")
        return schema + "." + self.identifier()

    def extension(self) -> str:
        item = self.current
        if item.kind not in {"word", "identifier"} or not re.fullmatch(r"[a-z_][a-z_0-9-]{0,62}", item.value):
            raise SqlRefused("SQL_UNSUPPORTED_IDENTIFIER")
        self.position += 1
        return item.value

    def column_type(self) -> str:
        type_token = self.current
        name = self.identifier()
        if name == "pg_catalog":
            self.require(".")
            name = self.identifier()
            if name not in CATALOG_TYPES:
                raise SqlRefused("SQL_UNSUPPORTED_TYPE")
        elif type_token.kind == "identifier":
            # Quoted keyword aliases can resolve to same-plan composite row types.
            raise SqlRefused("SQL_UNSUPPORTED_TYPE")
        name = TYPE_ALIASES.get(name, name)
        if name not in TYPES and name != "double precision":
            raise SqlRefused("SQL_UNSUPPORTED_TYPE")
        if name == "double":
            self.require("precision")
            name = "double precision"
        if self.take("("):
            if name not in {"char", "varchar", "numeric", "timestamp", "timestamptz"}:
                raise SqlRefused("SQL_UNSUPPORTED_TYPE")
            first = self.current
            if first.kind != "number" or not first.value.isdigit() or len(first.value) > 8:
                raise SqlRefused("SQL_UNSUPPORTED_TYPE")
            self.position += 1
            args = [int(first.value)]
            if self.take(","):
                second = self.current
                if name != "numeric" or second.kind != "number" or not second.value.isdigit() or len(second.value) > 4:
                    raise SqlRefused("SQL_UNSUPPORTED_TYPE")
                self.position += 1
                args.append(int(second.value))
            self.require(")")
            if ((name in {"char", "varchar"} and not 1 <= args[0] <= 10485760)
                    or (name in {"timestamp", "timestamptz"} and not 0 <= args[0] <= 6)
                    or (name == "numeric" and (not 1 <= args[0] <= 1000
                                             or (len(args) == 2 and not 0 <= args[1] <= args[0])))):
                raise SqlRefused("SQL_UNSUPPORTED_TYPE")
            name += "(" + ",".join(str(arg) for arg in args) + ")"
        dimensions = 0
        while self.take("["):
            self.require("]")
            dimensions += 1
            if dimensions > 6:
                raise SqlRefused("SQL_UNSUPPORTED_TYPE")
            name += "[]"
        return name

    def literal(self) -> None:
        signed = self.take("-") or self.take("+")
        if self.current.kind == "number":
            self.position += 1
        elif not signed and (self.current.kind == "literal"
                             or (self.current.kind == "word" and self.current.value in {"null", "true", "false"})):
            self.position += 1
        else:
            raise SqlRefused("SQL_UNSUPPORTED_LITERAL")

    def expression(self, allowed: set[str]) -> None:
        self.expression_depth += 1
        if self.expression_depth > 32:
            raise SqlRefused("SQL_LIMIT")
        self.disjunction(allowed)
        self.expression_depth -= 1

    def disjunction(self, allowed: set[str]) -> None:
        self.conjunction(allowed)
        while self.take("or"):
            self.conjunction(allowed)

    def conjunction(self, allowed: set[str]) -> None:
        self.comparison(allowed)
        while self.take("and"):
            self.comparison(allowed)

    def comparison(self, allowed: set[str]) -> None:
        if self.take("not"):
            self.require("(")
            self.expression(allowed)
            self.require(")")
            return
        self.arithmetic(allowed)
        if self.take("is"):
            self.take("not")
            if not (self.take("null") or self.take("true") or self.take("false")):
                raise SqlRefused("SQL_UNSUPPORTED_EXPRESSION")
        elif self.take("between"):
            self.arithmetic(allowed)
            self.require("and")
            self.arithmetic(allowed)
        elif self.take("in"):
            self.require("(")
            self.literal()
            while self.take(","):
                self.literal()
            self.require(")")
        elif self.current.kind == "symbol" and self.current.value in {"=", "<>", "!=", "<", ">", "<=", ">=", "~"}:
            self.position += 1
            self.arithmetic(allowed)

    def arithmetic(self, allowed: set[str]) -> None:
        self.product(allowed)
        while self.take("+") or self.take("-"):
            self.product(allowed)

    def product(self, allowed: set[str]) -> None:
        self.atom(allowed)
        while self.take("*") or self.take("/") or self.take("%"):
            self.atom(allowed)

    def atom(self, allowed: set[str]) -> None:
        if self.take("("):
            self.expression(allowed)
            self.require(")")
        elif self.current.kind in {"number", "literal"} or self.current.value in {"null", "true", "false", "-", "+"}:
            self.literal()
        else:
            name = self.identifier()
            if self.take("("):
                if name not in {"isfinite", "char_length"}:
                    raise SqlRefused("SQL_UNSUPPORTED_FUNCTION")
                argument = self.identifier()
                if argument not in allowed:
                    raise SqlRefused("SQL_UNKNOWN_COLUMN")
                self.require(")")
            elif name not in allowed:
                raise SqlRefused("SQL_UNKNOWN_COLUMN")

    def names(self) -> list[str]:
        self.require("(")
        result = [self.identifier()]
        while self.take(","):
            result.append(self.identifier())
        self.require(")")
        if len(result) != len(set(result)):
            raise SqlRefused("SQL_DUPLICATE_COLUMN")
        return result

    def reference(self) -> None:
        self.require("references")
        self.qualified()
        self.names()

    def table_constraint(self, allowed: set[str]) -> None:
        if self.take("constraint"):
            self.identifier()
        if self.take("check"):
            self.require("(")
            self.expression(allowed)
            self.require(")")
        elif self.take("unique"):
            if not set(self.names()) <= allowed:
                raise SqlRefused("SQL_UNKNOWN_COLUMN")
        elif self.take("primary"):
            self.require("key")
            if not set(self.names()) <= allowed:
                raise SqlRefused("SQL_UNKNOWN_COLUMN")
        elif self.take("foreign"):
            self.require("key")
            if not set(self.names()) <= allowed:
                raise SqlRefused("SQL_UNKNOWN_COLUMN")
            self.reference()
        else:
            raise SqlRefused("SQL_UNSUPPORTED_CONSTRAINT")

    def column(self, table: str) -> str:
        name = self.identifier()
        qualified = table + "." + name
        if qualified in self.columns:
            raise SqlRefused("SQL_DUPLICATE_COLUMN")
        self.columns[qualified] = self.column_type()
        while self.current.kind == "word":
            if self.take("not"):
                self.require("null")
            elif self.take("null") or self.take("unique"):
                pass
            elif self.take("primary"):
                self.require("key")
            elif self.take("default"):
                self.literal()
            elif self.take("check"):
                self.require("(")
                self.expression({name})
                self.require(")")
            elif self.current.value == "references":
                self.reference()
            else:
                raise SqlRefused("SQL_UNSUPPORTED_COLUMN_CLAUSE")
        return name

    def parse(self) -> Shape:
        count = 0
        while self.current.kind != "end":
            count += 1
            if count > 1024:
                raise SqlRefused("SQL_LIMIT")
            if self.take("create"):
                if self.take("schema"):
                    schema = self.identifier()
                    if schema.startswith("pg_") or schema in {"information_schema", "migration_runner"}:
                        raise SqlRefused("SQL_RESERVED_SCHEMA")
                elif self.take("extension"):
                    self.extensions.append(self.extension())
                elif self.take("table"):
                    table = self.qualified()
                    self.require("(")
                    allowed: set[str] = set()
                    while True:
                        if self.current.kind == "word" and self.current.value in {"constraint", "check", "unique", "primary", "foreign"}:
                            self.table_constraint(allowed)
                        else:
                            allowed.add(self.column(table))
                        if not self.take(","):
                            break
                    self.require(")")
                else:
                    raise SqlRefused("SQL_UNSUPPORTED_STATEMENT")
            elif self.take("alter"):
                self.require("table")
                table = self.qualified()
                self.require("add")
                self.take("column")
                self.column(table)
            elif self.take("drop"):
                if self.take("table"):
                    self.qualified()
                elif self.take("schema"):
                    schema = self.identifier()
                    if schema.startswith("pg_") or schema in {"information_schema", "migration_runner"}:
                        raise SqlRefused("SQL_RESERVED_SCHEMA")
                else:
                    raise SqlRefused("SQL_UNSUPPORTED_STATEMENT")
                self.require("restrict")
            else:
                raise SqlRefused("SQL_UNSUPPORTED_STATEMENT")
            self.require(";")
        if not count:
            raise SqlRefused("SQL_EMPTY")
        return Shape(tuple(sorted(self.columns.items())), tuple(self.extensions))


def inspect_sql(sql: str) -> Shape:
    return Parser(sql).parse()
