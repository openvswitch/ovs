import re

class Error(Exception):
    def __init__(self, msg):
        Exception.__init__(self)
        self.msg = msg

def getMember(json, name, validTypes, description, default=None):
    if name in json:
        member = json[name]
        if len(validTypes) and type(member) not in validTypes:
            raise Error("%s: type mismatch for '%s' member"
                        % (description, name))
        return member
    return default

def mustGetMember(json, name, expectedType, description):
    member = getMember(json, name, expectedType, description)
    if member == None:
        raise Error("%s: missing '%s' member" % (description, name))
    return member

class DbSchema:
    def __init__(self, name, tables):
        self.name = name
        self.tables = tables

    @staticmethod
    def fromJson(json):
        name = mustGetMember(json, 'name', [unicode], 'database')
        tablesJson = mustGetMember(json, 'tables', [dict], 'database')
        tables = {}
        for tableName, tableJson in tablesJson.iteritems():
            tables[tableName] = TableSchema.fromJson(tableJson,
                                                     "%s table" % tableName)
        return DbSchema(name, tables)

class IdlSchema(DbSchema):
    def __init__(self, name, tables, idlPrefix, idlHeader):
        DbSchema.__init__(self, name, tables)
        self.idlPrefix = idlPrefix
        self.idlHeader = idlHeader

    @staticmethod
    def fromJson(json):
        schema = DbSchema.fromJson(json)
        idlPrefix = mustGetMember(json, 'idlPrefix', [unicode], 'database')
        idlHeader = mustGetMember(json, 'idlHeader', [unicode], 'database')
        return IdlSchema(schema.name, schema.tables, idlPrefix, idlHeader)

class TableSchema:
    def __init__(self, columns):
        self.columns = columns

    @staticmethod
    def fromJson(json, description):
        columnsJson = mustGetMember(json, 'columns', [dict], description)
        columns = {}
        for name, json in columnsJson.iteritems():
            columns[name] = ColumnSchema.fromJson(
                json, "column %s in %s" % (name, description))
        return TableSchema(columns)

class ColumnSchema:
    def __init__(self, type, persistent):
        self.type = type
        self.persistent = persistent

    @staticmethod
    def fromJson(json, description):
        type = Type.fromJson(mustGetMember(json, 'type', [dict, unicode],
                                           description),
                             'type of %s' % description)
        ephemeral = getMember(json, 'ephemeral', [bool], description)
        persistent = ephemeral != True
        return ColumnSchema(type, persistent)

def escapeCString(src):
    dst = ""
    for c in src:
        if c in "\\\"":
            dst += "\\" + c
        elif ord(c) < 32:
            if c == '\n':
                dst += '\\n'
            elif c == '\r':
                dst += '\\r'
            elif c == '\a':
                dst += '\\a'
            elif c == '\b':
                dst += '\\b'
            elif c == '\f':
                dst += '\\f'
            elif c == '\t':
                dst += '\\t'
            elif c == '\v':
                dst += '\\v'
            else:
                dst += '\\%03o' % ord(c)
        else:
            dst += c
    return dst

def returnUnchanged(x):
    return x

class UUID:
    x = "[0-9a-fA-f]"
    uuidRE = re.compile("^(%s{8})-(%s{4})-(%s{4})-(%s{4})-(%s{4})(%s{8})$"
                        % (x, x, x, x, x, x))

    def __init__(self, value):
        self.value = value

    @staticmethod
    def fromString(s):
        if not uuidRE.match(s):
            raise Error("%s is not a valid UUID" % s)
        return UUID(s)

    @staticmethod
    def fromJson(json):
        if UUID.isValidJson(json):
            return UUID(json[1])
        else:
            raise Error("%s is not valid JSON for a UUID" % json)

    @staticmethod
    def isValidJson(json):
        return len(json) == 2 and json[0] == "uuid" and uuidRE.match(json[1])
            
    def toJson(self):
        return ["uuid", self.value]

    def cInitUUID(self, var):
        m = re.match(self.value)
        return ["%s.parts[0] = 0x%s;" % (var, m.group(1)),
                "%s.parts[1] = 0x%s%s;" % (var, m.group(2), m.group(3)),
                "%s.parts[2] = 0x%s%s;" % (var, m.group(4), m.group(5)),
                "%s.parts[3] = 0x%s;" % (var, m.group(6))]

class Atom:
    def __init__(self, type, value):
        self.type = type
        self.value = value

    @staticmethod
    def fromJson(type_, json):
        if ((type_ == 'integer' and type(json) in [int, long])
            or (type_ == 'real' and type(json) in [int, long, float])
            or (type_ == 'boolean' and json in [True, False])
            or (type_ == 'string' and type(json) in [str, unicode])):
            return Atom(type_, json)
        elif type_ == 'uuid':
            return UUID.fromJson(json)
        else:
            raise Error("%s is not valid JSON for type %s" % (json, type_))

    def toJson(self):
        if self.type == 'uuid':
            return self.value.toString()
        else:
            return self.value

    def cInitAtom(self, var):
        if self.type == 'integer':
            return ['%s.integer = %d;' % (var, self.value)]
        elif self.type == 'real':
            return ['%s.real = %.15g;' % (var, self.value)]
        elif self.type == 'boolean':
            if self.value:
                return ['%s.boolean = true;']
            else:
                return ['%s.boolean = false;']
        elif self.type == 'string':
            return ['%s.string = xstrdup("%s");'
                    % (var, escapeCString(self.value))]
        elif self.type == 'uuid':
            return self.value.cInitUUID(var)

    def toEnglish(self, escapeLiteral=returnUnchanged):
        if self.type == 'integer':
            return '%d' % self.value
        elif self.type == 'real':
            return '%.15g' % self.value
        elif self.type == 'boolean':
            if self.value:
                return 'true'
            else:
                return 'false'
        elif self.type == 'string':
            return escapeLiteral(self.value)
        elif self.type == 'uuid':
            return self.value.value

# Returns integer x formatted in decimal with thousands set off by commas.
def commafy(x):
    return _commafy("%d" % x)
def _commafy(s):
    if s.startswith('-'):
        return '-' + _commafy(s[1:])
    elif len(s) <= 3:
        return s
    else:
        return _commafy(s[:-3]) + ',' + _commafy(s[-3:])

class BaseType:
    def __init__(self, type,
                 enum=None,
                 refTable=None, refType="strong",
                 minInteger=None, maxInteger=None,
                 minReal=None, maxReal=None,
                 minLength=None, maxLength=None):
        self.type = type
        self.enum = enum
        self.refTable = refTable
        self.refType = refType
        self.minInteger = minInteger
        self.maxInteger = maxInteger
        self.minReal = minReal
        self.maxReal = maxReal
        self.minLength = minLength
        self.maxLength = maxLength

    @staticmethod
    def fromJson(json, description):
        if type(json) == unicode:
            return BaseType(json)
        else:
            atomicType = mustGetMember(json, 'type', [unicode], description)
            enum = getMember(json, 'enum', [], description)
            if enum:
                enumType = Type(atomicType, None, 0, 'unlimited')
                enum = Datum.fromJson(enumType, enum)
            refTable = getMember(json, 'refTable', [unicode], description)
            refType = getMember(json, 'refType', [unicode], description)
            if refType == None:
                refType = "strong"
            minInteger = getMember(json, 'minInteger', [int, long], description)
            maxInteger = getMember(json, 'maxInteger', [int, long], description)
            minReal = getMember(json, 'minReal', [int, long, float], description)
            maxReal = getMember(json, 'maxReal', [int, long, float], description)
            minLength = getMember(json, 'minLength', [int], description)
            maxLength = getMember(json, 'minLength', [int], description)
            return BaseType(atomicType, enum, refTable, refType, minInteger, maxInteger, minReal, maxReal, minLength, maxLength)

    def toEnglish(self, escapeLiteral=returnUnchanged):
        if self.type == 'uuid' and self.refTable:
            s = escapeLiteral(self.refTable)
            if self.refType == 'weak':
                s = "weak reference to " + s
            return s
        else:
            return self.type

    def constraintsToEnglish(self, escapeLiteral=returnUnchanged):
        if self.enum:
            literals = [value.toEnglish(escapeLiteral)
                        for value in self.enum.values]
            if len(literals) == 2:
                return 'either %s or %s' % (literals[0], literals[1])
            else:
                return 'one of %s, %s, or %s' % (literals[0],
                                                 ', '.join(literals[1:-1]),
                                                 literals[-1])
        elif self.minInteger != None and self.maxInteger != None:
            return 'in range %s to %s' % (commafy(self.minInteger),
                                         commafy(self.maxInteger))
        elif self.minInteger != None:
            return 'at least %s' % commafy(self.minInteger)
        elif self.maxInteger != None:
            return 'at most %s' % commafy(self.maxInteger)
        elif self.minReal != None and self.maxReal != None:
            return 'in range %g to %g' % (self.minReal, self.maxReal)
        elif self.minReal != None:
            return 'at least %g' % self.minReal
        elif self.maxReal != None:
            return 'at most %g' % self.maxReal
        elif self.minLength != None and self.maxLength != None:
            if self.minLength == self.maxLength:
                return 'exactly %d characters long' % (self.minLength)
            else:
                return 'between %d and %d characters long' % (self.minLength, self.maxLength)
        elif self.minLength != None:
            return 'at least %d characters long' % self.minLength
        elif self.maxLength != None:
            return 'at most %d characters long' % self.maxLength
        else:
            return ''

    def toCType(self, prefix):
        if self.refTable:
            return "struct %s%s *" % (prefix, self.refTable.lower())
        else:
            return {'integer': 'int64_t ',
                    'real': 'double ',
                    'uuid': 'struct uuid ',
                    'boolean': 'bool ',
                    'string': 'char *'}[self.type]

    def copyCValue(self, dst, src):
        args = {'dst': dst, 'src': src}
        if self.refTable:
            return ("%(dst)s = %(src)s->header_.uuid;") % args
        elif self.type == 'string':
            return "%(dst)s = xstrdup(%(src)s);" % args
        else:
            return "%(dst)s = %(src)s;" % args

    def initCDefault(self, var, isOptional):
        if self.refTable:
            return "%s = NULL;" % var
        elif self.type == 'string' and not isOptional:
            return "%s = \"\";" % var
        else:
            return {'integer': '%s = 0;',
                    'real': '%s = 0.0;',
                    'uuid': 'uuid_zero(&%s);',
                    'boolean': '%s = false;',
                    'string': '%s = NULL;'}[self.type] % var

    def cInitBaseType(self, indent, var):
        stmts = []
        stmts.append('ovsdb_base_type_init(&%s, OVSDB_TYPE_%s);' % (
                var, self.type.upper()),)
        if self.enum:
            stmts.append("%s.enum_ = xmalloc(sizeof *%s.enum_);"
                         % (var, var))
            stmts += self.enum.cInitDatum("%s.enum_" % var)
        if self.type == 'integer':
            if self.minInteger != None:
                stmts.append('%s.u.integer.min = INT64_C(%d);' % (var, self.minInteger))
            if self.maxInteger != None:
                stmts.append('%s.u.integer.max = INT64_C(%d);' % (var, self.maxInteger))
        elif self.type == 'real':
            if self.minReal != None:
                stmts.append('%s.u.real.min = %d;' % (var, self.minReal))
            if self.maxReal != None:
                stmts.append('%s.u.real.max = %d;' % (var, self.maxReal))
        elif self.type == 'string':
            if self.minLength != None:
                stmts.append('%s.u.string.minLen = %d;' % (var, self.minLength))            
            if self.maxLength != None:
                stmts.append('%s.u.string.maxLen = %d;' % (var, self.maxLength))
        elif self.type == 'uuid':
            if self.refTable != None:
                stmts.append('%s.u.uuid.refTableName = "%s";' % (var, escapeCString(self.refTable)))
        return '\n'.join([indent + stmt for stmt in stmts])

class Type:
    def __init__(self, key, value=None, min=1, max=1):
        self.key = key
        self.value = value
        self.min = min
        self.max = max
    
    @staticmethod
    def fromJson(json, description):
        if type(json) == unicode:
            return Type(BaseType(json))
        else:
            keyJson = mustGetMember(json, 'key', [dict, unicode], description)
            key = BaseType.fromJson(keyJson, 'key in %s' % description)

            valueJson = getMember(json, 'value', [dict, unicode], description)
            if valueJson:
                value = BaseType.fromJson(valueJson,
                                          'value in %s' % description)
            else:
                value = None

            min = getMember(json, 'min', [int], description, 1)
            max = getMember(json, 'max', [int, unicode], description, 1)
            return Type(key, value, min, max)

    def isScalar(self):
        return self.min == 1 and self.max == 1 and not self.value

    def isOptional(self):
        return self.min == 0 and self.max == 1

    def isOptionalPointer(self):
        return (self.min == 0 and self.max == 1 and not self.value
                and (self.key.type == 'string' or self.key.refTable))

    def toEnglish(self, escapeLiteral=returnUnchanged):
        keyName = self.key.toEnglish(escapeLiteral)
        if self.value:
            valueName = self.value.toEnglish(escapeLiteral)

        if self.isScalar():
            return keyName
        elif self.isOptional():
            if self.value:
                return "optional %s-%s pair" % (keyName, valueName)
            else:
                return "optional %s" % keyName
        else:
            if self.max == "unlimited":
                if self.min:
                    quantity = "%d or more " % self.min
                else:
                    quantity = ""
            elif self.min:
                quantity = "%d to %d " % (self.min, self.max)
            else:
                quantity = "up to %d " % self.max

            if self.value:
                return "map of %s%s-%s pairs" % (quantity, keyName, valueName)
            else:
                if keyName.endswith('s'):
                    plural = keyName + "es"
                else:
                    plural = keyName + "s"
                return "set of %s%s" % (quantity, plural)

    def constraintsToEnglish(self, escapeLiteral=returnUnchanged):
        s = ""

        constraints = []
        keyConstraints = self.key.constraintsToEnglish(escapeLiteral)
        if keyConstraints:
            if self.value:
                constraints += ['key ' + keyConstraints]
            else:
                constraints += [keyConstraints]

        if self.value:
            valueConstraints = self.value.constraintsToEnglish(escapeLiteral)
            if valueConstraints:
                constraints += ['value ' + valueConstraints]

        return ', '.join(constraints)
                
    def cDeclComment(self):
        if self.min == 1 and self.max == 1 and self.key.type == "string":
            return "\t/* Always nonnull. */"
        else:
            return ""

    def cInitType(self, indent, var):
        initKey = self.key.cInitBaseType(indent, "%s.key" % var)
        if self.value:
            initValue = self.value.cInitBaseType(indent, "%s.value" % var)
        else:
            initValue = ('%sovsdb_base_type_init(&%s.value, '
                         'OVSDB_TYPE_VOID);' % (indent, var))
        initMin = "%s%s.n_min = %s;" % (indent, var, self.min)
        if self.max == "unlimited":
            max = "UINT_MAX"
        else:
            max = self.max
        initMax = "%s%s.n_max = %s;" % (indent, var, max)
        return "\n".join((initKey, initValue, initMin, initMax))

class Datum:
    def __init__(self, type, values):
        self.type = type
        self.values = values

    @staticmethod
    def fromJson(type_, json):
        if not type_.value:
            if len(json) == 2 and json[0] == "set":
                values = []
                for atomJson in json[1]:
                    values += [Atom.fromJson(type_.key, atomJson)]
            else:
                values = [Atom.fromJson(type_.key, json)]
        else:
            if len(json) != 2 or json[0] != "map":
                raise Error("%s is not valid JSON for a map" % json)
            values = []
            for pairJson in json[1]:
                values += [(Atom.fromJson(type_.key, pairJson[0]),
                            Atom.fromJson(type_.value, pairJson[1]))]
        return Datum(type_, values)

    def cInitDatum(self, var):
        if len(self.values) == 0:
            return ["ovsdb_datum_init_empty(%s);" % var]

        s = ["%s->n = %d;" % (var, len(self.values))]
        s += ["%s->keys = xmalloc(%d * sizeof *%s->keys);"
              % (var, len(self.values), var)]

        for i in range(len(self.values)):
            key = self.values[i]
            if self.type.value:
                key = key[0]
            s += key.cInitAtom("%s->keys[%d]" % (var, i))
        
        if self.type.value:
            s += ["%s->values = xmalloc(%d * sizeof *%s->values);"
                  % (var, len(self.values), var)]
            for i in range(len(self.values)):
                value = self.values[i][1]
                s += key.cInitAtom("%s->values[%d]" % (var, i))
        else:
            s += ["%s->values = NULL;" % var]

        if len(self.values) > 1:
            s += ["ovsdb_datum_sort_assert(%s, OVSDB_TYPE_%s);"
                  % (var, self.type.key.upper())]

        return s
