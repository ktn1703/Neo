#!/usr/bin/python3

import sys, os, io, ast, re, random, marshal, base64, zlib, bz2, lzma
import hashlib, time, argparse, traceback

sys.setrecursionlimit(1 << 20)

if sys.version_info < (3, 10):
    print("NEO-MATRIX requires Python 3.10+")
    sys.exit(1)

try:
    from pystyle import *
except Exception:
    class Col:
        white = black = green = dark_gray = light_gray = red = purple = blue = yellow = cyan = orange = light_green = light_red = ""
        reset = "\033[0m"
        def Symbol(s, *a, **k): return f"[{s}]"
    class Colors:
        red_to_white = white_to_red = cyan_to_green = blue_to_purple = purple_to_red = red_to_purple = yellow_to_red = ""
        def DynamicMIX(*a, **k): return ""
        def StaticMIX(*a, **k): return ""
    class Colorate:
        def Diagonal(*a, **k): return a[-1]
        def Horizontal(*a, **k): return a[-1]
    class Add:
        def Add(a, b, **k): return a + b
    class System:
        def Clear(): print("\033[2J\033[H", end="")
    class Animate: pass

VER = f"{sys.version_info.major}.{sys.version_info.minor}"

OFF = 0xFF78FF
K   = random.randint(1, 0xFFFFFFFF)

NAME = {}
def rn(k=9):
    return "_" + "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", k=k))

def QN(key):
    if key not in NAME:
        NAME[key] = rn()
    return NAME[key]

QN("dec"); QN("int"); QN("float"); QN("bytes"); QN("str"); QN("chr")
QN("join"); QN("map"); QN("list"); QN("eval"); QN("exec"); QN("import")
QN("vars"); QN("globals"); QN("getattr"); QN("bd")
QN("sysm"); QN("osm"); QN("mz"); QN("lm"); QN("bz"); QN("b64"); QN("ms")
QN("die"); QN("len"); QN("hl")

DIE_CODE = 0xC0DE

INNER_NAME = '<NeoMatrix>'

KILL_MODULES = (
    "frida", "pydevd", "debugpy", "pyrasite", "lief", "ptvsd", "pycharm",
    "gdb", "pytineye", "yara", "sysmon", "trace", "coverage", "line_profiler",
)

MITM_TOKENS = (
    "httptoolkit", "fiddler", "burp", "charles", "zaproxy", "mitmproxy",
    "optimizely", "proxify", "vanguard",
)

def mkmarker():
    return "_NEO_" + format(random.getrandbits(160), "040x") + "_"

def make_ks(data, need):
    out = b''
    n = 0
    while len(out) < need:
        out += hashlib.sha256(data + n.to_bytes(8, 'big')).digest()
        n += 1
    return out[:need]

def splitnc(data, n):
    n = max(1, n)
    q, r = divmod(len(data), n)
    parts = []
    off = 0
    for i in range(n):
        s = q + (1 if i < r else 0)
        parts.append(data[off:off + s])
        off += s
    return parts

def enc_seq(s):
    return [(ord(c) ^ K) + OFF for c in s]

def S(s):
    return f"{QN('dec')}({enc_seq(s)})"

def I(v):
    return f"{QN('int')}({S(str(v))})"

def F(v):
    return f"{QN('float')}({S(repr(v))})"

def B(v):
    if isinstance(v, bytes) and all(32 <= b < 127 for b in v):
        return f"{QN('bytes')}({S(v.decode('ascii'))})"
    return None

HANZI = "天地玄黄宇宙洪荒日月盈昃辰宿列张金木水火土龙虎风云雷电山河星海"
def hz():
    return "".join(random.choices(HANZI, k=random.randint(7, 9)))

def anti_pycdc_block():
    e = {
        'Z': '1/0,',
        'T': 'len+1,',
        'N': 'xyz,',
        'T2': '"a"+1,',
        'I': '[][99],',
        'K': '{}[""],',
        'M': "__import__('xyz'),",
        'V': 'int("a",99),',
        'A': '[].__x,',
        'F': 'open("ww"),',
        'G': '0 if False else 1//0,',
        'H': 'f"{[0]}" and (1//0),',
        'Q': '{}.get(0) and 1//0,',
        'W': 'not 0 or [][99],',
    }
    ct = max(60, min(250, 1200 // len(e)))
    for k in e:
        e[k] = e[k] * ct
    block = '\n'.join(f'try:({v})\nexcept:0' for v in e.values())
    return '\ntry:pass\nexcept:pass\nelse:pass\nfinally:pass\n' + block + '\n'

def clean_try_except(source):
    try:
        t = ast.parse(source)
        body = t.body
        try_except = ast.Try(
            body=body,
            handlers=[
                ast.ExceptHandler(
                    type=ast.Name(id='KeyboardInterrupt', ctx=ast.Load()),
                    name=None,
                    body=[
                        ast.Expr(ast.Call(func=ast.Name(id='print', ctx=ast.Load()),
                                          args=[ast.Constant(value='\n\nExiting...')], keywords=[])),
                        ast.Expr(ast.Call(func=ast.Name(id='exit', ctx=ast.Load()), args=[], keywords=[])),
                    ],
                ),
                ast.ExceptHandler(
                    type=ast.Name(id='Exception', ctx=ast.Load()),
                    name='e',
                    body=[ast.Expr(ast.Call(func=ast.Name(id='print', ctx=ast.Load()),
                                            args=[ast.Name(id='e', ctx=ast.Load())], keywords=[]))],
                ),
            ],
            orelse=[], finalbody=[]
        )
        m = ast.Module(body=[try_except], type_ignores=[])
        ast.fix_missing_locations(m)
        return ast.unparse(m)
    except SyntaxError:
        return source

def joinstr(f):
    if not isinstance(f, ast.JoinedStr):
        return f
    vl = []
    for i in f.values:
        if isinstance(i, ast.Constant):
            if isinstance(i.value, str):
                vl.append(i)
            else:
                vl.append(str(i.value))
        elif isinstance(i, ast.FormattedValue):
            value_expr = i.value
            if i.conversion == 115:
                value_expr = ast.Call(func=ast.Name(id='str', ctx=ast.Load()), args=[value_expr], keywords=[])
            elif i.conversion == 114:
                value_expr = ast.Call(func=ast.Name(id='repr', ctx=ast.Load()), args=[value_expr], keywords=[])
            elif i.conversion == 97:
                value_expr = ast.Call(func=ast.Name(id='ascii', ctx=ast.Load()), args=[value_expr], keywords=[])
            if i.format_spec:
                spec = i.format_spec if isinstance(i.format_spec, ast.Constant) else i.format_spec
                value_expr = ast.Call(func=ast.Name(id='format', ctx=ast.Load()), args=[value_expr, spec], keywords=[])
            vl.append(value_expr)
        else:
            vl.append(i)
    if not vl:
        return ast.Constant(value='')
    if len(vl) == 1 and isinstance(vl[0], ast.Constant):
        return vl[0]
    return ast.Call(
        func=ast.Attribute(value=ast.Constant(value=''), attr='join', ctx=ast.Load()),
        args=[ast.Tuple(elts=vl, ctx=ast.Load())],
        keywords=[],
    )

class Cv(ast.NodeTransformer):
    def visit_JoinedStr(self, node):
        return joinstr(node)

BUILTINS = set(['__import__', 'abs', 'all', 'any', 'ascii', 'bin', 'breakpoint', 'callable', 'chr',
    'compile', 'delattr', 'dir', 'divmod', 'eval', 'exec', 'format', 'getattr', 'globals', 'hasattr',
    'hash', 'hex', 'id', 'input', 'isinstance', 'issubclass', 'iter', 'aiter', 'len', 'locals', 'max',
    'min', 'next', 'anext', 'oct', 'ord', 'pow', 'print', 'repr', 'round', 'setattr', 'sorted', 'sum',
    'vars', 'None', 'Ellipsis', 'NotImplemented', 'False', 'True', 'bool', 'memoryview', 'bytearray',
    'bytes', 'classmethod', 'complex', 'dict', 'enumerate', 'filter', 'float', 'frozenset', 'property',
    'int', 'list', 'map', 'object', 'range', 'reversed', 'set', 'slice', 'staticmethod', 'str', 'super',
    'tuple', 'type', 'zip', 'open', 'Exception', 'KeyboardInterrupt', 'MemoryError', 'ValueError',
    'TypeError', 'KeyError', 'IndexError', 'ArithmeticError', 'ZeroDivisionError', 'NameError',
    'OverflowError', 'NotImplementedError', 'StopIteration', 'assert', 'delattr'])

def obf_vars(source):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and any(n.name == '*' for n in node.names):
            return source

    module_names = set()
    declared = set()
    method_names = set()
    attr_names = set()
    kwarg_names = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            module_names.add(node.names[0].name.split('.')[0])
            if node.names[0].asname:
                declared.add(node.names[0].asname)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                module_names.add(node.module.split('.')[0])
            for a in node.names:
                if a.asname:
                    declared.add(a.asname)
                else:
                    module_names.add(a.name)
        elif isinstance(node, ast.Attribute):
            attr_names.add(node.attr)
        elif isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg:
                    kwarg_names.add(kw.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            declared.add(node.name)
        elif isinstance(node, ast.ClassDef):
            declared.add(node.name)
        elif isinstance(node, ast.arg):
            declared.add(node.arg)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            declared.add(node.id)
        elif isinstance(node, ast.Global):
            declared.update(node.names)
        elif isinstance(node, ast.Nonlocal):
            declared.update(node.names)
        elif isinstance(node, ast.ExceptHandler):
            if node.name:
                declared.add(node.name)

    for parent in ast.walk(tree):
        if isinstance(parent, ast.ClassDef):
            for sub in parent.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    method_names.add(sub.name)

    not_rename = attr_names | kwarg_names | method_names
    aliases = {}
    for name in declared:
        if name in aliases or name in module_names or name in BUILTINS:
            continue
        if name.startswith('__') or name in ('self', 'cls', '_'):
            continue
        if name in not_rename:
            continue
        aliases[name] = hz()

    class Ren(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id in aliases:
                node.id = aliases[node.id]
            return node
        def visit_FunctionDef(self, node):
            if node.name in aliases:
                node.name = aliases[node.name]
            self.generic_visit(node)
            return node
        def visit_AsyncFunctionDef(self, node):
            if node.name in aliases:
                node.name = aliases[node.name]
            self.generic_visit(node)
            return node
        def visit_ClassDef(self, node):
            if node.name in aliases:
                node.name = aliases[node.name]
            self.generic_visit(node)
            return node
        def visit_arg(self, node):
            if node.arg in aliases:
                node.arg = aliases[node.arg]
            return node
        def visit_Global(self, node):
            node.names = [aliases.get(x, x) for x in node.names]
            return node
        def visit_Nonlocal(self, node):
            node.names = [aliases.get(x, x) for x in node.names]
            return node
    tree = Ren().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)

HIDE_LIST = ['chr', 'ord', 'hex', 'bin', 'oct', 'bytes', 'bytearray', 'str', 'int', 'float',
             'globals', 'locals', 'vars', 'exec', 'eval', 'getattr', 'setattr', 'delattr', 'dir',
             '__import__', 'compile', 'map', 'filter', 'zip', 'hash', 'repr', 'format', 'len',
             'range', 'type', 'print', 'input', 'open', 'sorted', 'sum', 'abs', 'min', 'max',
             'next', 'iter', 'enumerate', 'reversed', 'isinstance', 'issubclass', 'hasattr',
             'callable', 'super', 'object', 'staticmethod', 'classmethod', 'property', 'bool',
             'list', 'dict', 'set', 'tuple', 'round', 'pow', 'divmod', 'id', 'slice']

def hide_builtins(source):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in HIDE_LIST:
            try:
                node = ast.parse(f"{QN('bd')}[{S(node.id)}]").body[0].value
            except Exception:
                pass
    return ast.unparse(tree)

def obf_consts(source):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source
    for i in ast.walk(tree):
        if isinstance(i, (ast.Global, ast.Nonlocal)):
            continue
        for f, v in ast.iter_fields(i):
            if isinstance(v, list):
                ar = []
                for j in v:
                    if isinstance(j, ast.Constant) and isinstance(j.value, str):
                        try:
                            ar.append(ast.parse(S(j.value)).body[0].value)
                            continue
                        except Exception:
                            pass
                    elif isinstance(j, ast.Constant) and isinstance(j.value, int) and not isinstance(j.value, bool):
                        try:
                            ar.append(ast.parse(I(j.value)).body[0].value)
                            continue
                        except Exception:
                            pass
                    elif isinstance(j, ast.Constant) and isinstance(j.value, float):
                        try:
                            ar.append(ast.parse(F(j.value)).body[0].value)
                            continue
                        except Exception:
                            pass
                    elif isinstance(j, ast.Constant) and isinstance(j.value, bytes):
                        bb = B(j.value)
                        if bb:
                            ar.append(ast.parse(bb).body[0].value)
                            continue
                    elif isinstance(j, ast.JoinedStr):
                        ar.append(joinstr(j))
                        continue
                    elif isinstance(j, ast.AST):
                        pass
                    ar.append(j)
                setattr(i, f, ar)
            else:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    try:
                        setattr(i, f, ast.parse(S(v.value)).body[0].value)
                    except Exception:
                        pass
                elif isinstance(v, ast.Constant) and isinstance(v.value, int) and not isinstance(v.value, bool):
                    try:
                        setattr(i, f, ast.parse(I(v.value)).body[0].value)
                    except Exception:
                        pass
                elif isinstance(v, ast.Constant) and isinstance(v.value, float):
                    try:
                        setattr(i, f, ast.parse(F(v.value)).body[0].value)
                    except Exception:
                        pass
                elif isinstance(v, ast.Constant) and isinstance(v.value, bytes):
                    bb = B(v.value)
                    if bb:
                        try:
                            setattr(i, f, ast.parse(bb).body[0].value)
                        except Exception:
                            pass
                elif isinstance(v, ast.JoinedStr):
                    setattr(i, f, joinstr(v))
    return ast.unparse(tree)

def I_(v):
    return I(v)

def gen_jcode(code):
    men = hz()
    bao = hz()
    qua = hz()
    return [
        ast.Assign(targets=[ast.Name(id=bao, ctx=ast.Store())], value=ast.Constant(value=men)),
        ast.Assign(targets=[ast.Name(id=qua, ctx=ast.Store())], value=ast.Constant(value=True)),
        ast.If(
            test=ast.BoolOp(op=ast.And(), values=[
                ast.Compare(left=ast.Name(id=bao, ctx=ast.Load()), ops=[ast.Eq()],
                            comparators=[ast.Constant(value=men)]),
                ast.Compare(left=ast.Name(id=qua, ctx=ast.Load()), ops=[ast.NotEq()],
                            comparators=[ast.Constant(value=True)]),
            ]),
            body=[ast.Expr(value=ast.Lambda(
                args=ast.arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]),
                body=ast.parse(S('灵魂暗影')).body[0].value)
            )],
            orelse=[ast.If(
                test=ast.BoolOp(op=ast.And(), values=[
                    ast.Compare(left=ast.Name(id=bao, ctx=ast.Load()), ops=[ast.Eq()],
                                comparators=[ast.Constant(value=men)]),
                    ast.Compare(left=ast.Name(id=qua, ctx=ast.Load()), ops=[ast.NotEq()],
                                comparators=[ast.Constant(value=False)]),
                ]),
                body=[ast.Try(
                    body=[ast.Expr(value=ast.Tuple(elts=[
                        ast.BinOp(left=ast.Constant(value=1), op=ast.Div(), right=ast.Constant(value=0)),
                        ast.BinOp(left=ast.Constant(value=123), op=ast.Div(), right=ast.Constant(value=0)),
                        ast.BinOp(left=ast.Constant(value=12312321312), op=ast.Div(), right=ast.Constant(value=0)),
                    ], ctx=ast.Load()))],
                    handlers=[ast.ExceptHandler(body=[code])],
                    orelse=[], finalbody=[]
                )],
                orelse=[ast.If(
                    test=ast.BoolOp(op=ast.Or(), values=[
                        ast.Compare(left=ast.Name(id=bao, ctx=ast.Load()), ops=[ast.Eq()],
                                    comparators=[ast.parse(S('废墟')).body[0].value]),
                        ast.Compare(left=ast.Name(id=qua, ctx=ast.Load()), ops=[ast.Eq()],
                                    comparators=[ast.Constant(value=False)]),
                    ]),
                    body=[ast.Expr(value=ast.Call(
                        func=ast.Lambda(args=ast.arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]),
                                        body=ast.Call(func=ast.Name(id='print', ctx=ast.Load()),
                                                      args=[ast.parse(S('虚空回响')).body[0].value], keywords=[])),
                        args=[], keywords=[]))],
                    orelse=[ast.While(test=ast.Constant(value=True), body=[ast.Pass()], orelse=[]),
                            ast.Expr(value=ast.Call(func=ast.Name(id='print', ctx=ast.Load()),
                                                    args=[ast.parse(S('数字洪流')).body[0].value], keywords=[]))]
                )]
            )]
        ),
    ]

def junk_cases(en, max_value):
    cases = []
    line = max_value + 1
    for _ in range(random.randint(1, 4)):
        case_name = hz()
        cases.append(ast.If(
            test=ast.Compare(
                left=ast.Subscript(value=ast.Attribute(value=ast.Name(id=en), attr='args'),
                                   slice=ast.Constant(value=0)),
                ops=[ast.Eq()], comparators=[ast.parse(I_(line)).body[0].value]),
            body=[ast.Assign(targets=[ast.Name(id=case_name, ctx=ast.Store())],
                             value=ast.parse(I_(random.randint(0xFFFFF, 0xFFFFFFFFFFFF))).body[0].value)],
            orelse=[]))
        line += 1
    return cases

def bl(body):
    var = hz(); en = hz()
    tb = [
        ast.AugAssign(target=ast.Name(id=var, ctx=ast.Store()), op=ast.Add(),
                      value=ast.parse(I_(1)).body[0].value),
        ast.Try(
            body=[ast.Raise(exc=ast.Call(func=ast.Name(id='MemoryError', ctx=ast.Load()),
                                         args=[ast.Name(id=var, ctx=ast.Load())], keywords=[]))],
            handlers=[ast.ExceptHandler(type=ast.Name(id='MemoryError', ctx=ast.Load()), name=en, body=[])],
            orelse=[], finalbody=[]
        )
    ]
    for i in body:
        tb[1].handlers[0].body.append(ast.If(
            test=ast.Compare(
                left=ast.Subscript(value=ast.Attribute(value=ast.Name(id=en, ctx=ast.Load()), attr='args'),
                                   slice=ast.Constant(value=0)),
                ops=[ast.Eq()], comparators=[ast.parse(I_(1)).body[0].value]),
            body=[i], orelse=[]))
    tb[1].handlers[0].body.extend(junk_cases(en, len(body) + 1))
    node = ast.Assign(targets=[ast.Name(id=var, ctx=ast.Store())],
                      value=ast.parse(I_(0)).body[0].value)
    return [node] + tb

def _bl(node):
    olb = node.body
    var = hz(); en = hz()
    tb = [
        ast.AugAssign(target=ast.Name(id=var, ctx=ast.Store()), op=ast.Add(),
                      value=ast.parse(I_(1)).body[0].value),
        ast.Try(
            body=[ast.Raise(exc=ast.Call(func=ast.Name(id='MemoryError', ctx=ast.Load()),
                                         args=[ast.Name(id=var, ctx=ast.Load())], keywords=[]))],
            handlers=[ast.ExceptHandler(type=ast.Name(id='MemoryError', ctx=ast.Load()), name=en, body=[])],
            orelse=[], finalbody=[]
        )
    ]
    for i in olb:
        tb[1].handlers[0].body.append(ast.If(
            test=ast.Compare(
                left=ast.Subscript(value=ast.Attribute(value=ast.Name(id=en, ctx=ast.Load()), attr='args'),
                                   slice=ast.Constant(value=0)),
                ops=[ast.Eq()], comparators=[ast.parse(I_(1)).body[0].value]),
            body=[i], orelse=[]))
    tb[1].handlers[0].body.extend(junk_cases(en, len(olb) + 1))
    node.body = [ast.Assign(targets=[ast.Name(id=var, ctx=ast.Store())],
                            value=ast.parse(I_(0)).body[0].value)] + tb
    return node

def process_block(block):
    nb = []
    for node in block:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            nb.append(_bl(node))
        elif isinstance(node, ast.ClassDef):
            inner = []
            for m in node.body:
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    inner.append(_bl(m))
                elif isinstance(m, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Expr)):
                    inner.extend(bl([m]))
                else:
                    inner.append(m)
            node.body = inner
            nb.append(node)
        elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Expr)):
            nb.extend(bl([node]))
        elif isinstance(node, ast.Try):
            node.body = process_block(node.body)
            for handler in node.handlers:
                handler.body = process_block(handler.body)
            if node.orelse:
                node.orelse = process_block(node.orelse)
            if node.finalbody:
                node.finalbody = process_block(node.finalbody)
            nb.append(node)
        else:
            nb.append(node)
    return nb

def spam(source):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source
    nb = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            nb.append(_bl(node))
        elif isinstance(node, ast.ClassDef):
            inner = []
            for m in node.body:
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    inner.append(_bl(m))
                elif isinstance(m, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Expr)):
                    inner.extend(bl([m]))
                else:
                    inner.append(m)
            node.body = inner
            nb.append(node)
        elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Expr)):
            nb.extend(bl([node]))
        elif isinstance(node, ast.Try):
            node.body = process_block(node.body)
            for handler in node.handlers:
                handler.body = process_block(handler.body)
            if node.orelse:
                node.orelse = process_block(node.orelse)
            if node.finalbody:
                node.finalbody = process_block(node.finalbody)
            nb.append(node)
        else:
            nb.append(node)
    tree.body = nb
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)

def q(s):
    return enc_seq(s)

def build_antidump():
    ga = QN('getattr')
    sm = QN('sysm')
    bd = QN('bd')
    ms = QN('ms')
    osm = QN('osm')
    die = QN('die')
    T = lambda v: f"{bd}[{S(v)}]"
    bs = S('\\')
    sl = S('/')
    ln = rn()
    L = []
    a = L.append

    a(f"for _n_ in ({', '.join(S(x) for x in KILL_MODULES)}):")
    a(f"    if _n_ in {ga}({sm}, {S('modules')}): {die}()")
    a(f"for _en_ in ({', '.join(S(x) for x in (S('PYTHONBREAKPOINT'), S('PYTHONPYCACHEPREFIX')))}):")
    a(f"    if {S('breakpoint')} in {osm}.environ.get(_en_, {S('')}).lower(): {die}()")
    a(f"try:")
    a(f"    _m_ = {ga}({sm}, {S('monitoring')})")
    a(f"    _ev_ = {ga}(_m_, {S('get_events')})()")
    a(f"    for _tid_ in _ev_:")
    a(f"        if _ev_[_tid_]: {die}()")
    a(f"except Exception:")
    a(f"    pass")
    a(f"try:")
    a(f"    if {T('type')}({ga}({ms}, {S('loads')})) != {T('type')}({T('len')}): {die}()")
    a(f"    if {T('type')}({ga}({ms}, {S('loads')})) != {T('type')}({ga}({ms}, {S('dumps')})): {die}()")
    a(f"    if {T('type')}({ga}({ms}, {S('load')})) != {T('type')}({ga}({ms}, {S('dumps')})): {die}()")
    a(f"    if {T('type')}({ga}({ms}, {S('dump')})) != {T('type')}({T('len')}): {die}()")
    a(f"except Exception: {die}()")
    a(f"if {T('type')}({T('compile')}) != {T('type')}({T('len')}): {die}()")
    a(f"if {T('type')}({T('__import__')}) != {T('type')}({T('len')}): {die}()")
    a(f"if {T('type')}({ga}({sm}, {S('gettrace')})) != {T('type')}({T('len')}): {die}()")
    a(f"if {T('type')}({ga}({sm}, {S('setprofile')})) != {T('type')}({T('len')}): {die}()")
    a(f"try:")
    a(f"    _fk_ = {T('getattr')}({T('__import__')}({S('types')}), {S('ModuleType')})({S('marshal')})")
    a(f"    for _at_ in ({S('loads')}, {S('dumps')}, {S('load')}, {S('dump')}):")
    a(f"        {T('setattr')}(_fk_, _at_, (lambda *_v_: {die}()))")
    a(f"    {ga}({sm}, {S('modules')})[{S('marshal')}] = _fk_")
    a(f"except Exception: {die}()")
    a(f"def {ln}():")
    a(f"    _me_ = {ga}(({QN('globals')})(), {S('get')})({S('__file__')}, {S('')})")
    a(f"    _me_ = {ga}({ga}(_me_, {S('replace')})({bs}, {sl}), {S('rsplit')})({sl}, 1)[-1]")
    a(f"    _af_ = {ga}({sm}, {S('argv')})[0] if {ga}({sm}, {S('argv')}) else {S('')}")
    a(f"    _af_ = {ga}({ga}(_af_, {S('replace')})({bs}, {sl}), {S('rsplit')})({sl}, 1)[-1]")
    a(f"    if _me_ != _af_: {die}()")
    a(f"    _f_ = {ga}({sm}, {S('_getframe')})()")
    a(f"    while _f_ is not None:")
    a(f"        _c_ = {ga}({ga}(_f_, {S('f_code')}), {S('co_filename')}) or {S('')}")
    a(f"        _c_ = {ga}({ga}(_c_, {S('replace')})({bs}, {sl}), {S('rsplit')})({sl}, 1)[-1]")
    a(f"        if _c_ != _me_ and _c_ != {S(INNER_NAME)}: {die}()")
    a(f"        _f_ = {ga}(_f_, {S('f_back')})")
    a(f"{ln}()")
    return "\n".join(L)

def build_guard():
    return build_antidump() + "\n" + (
        f"if {QN('getattr')}({QN('sysm')},{S('gettrace')})() is not None:\n"
        f"    {QN('die')}()\n"
        f"{QN('getattr')}({QN('sysm')},{S('settrace')})(None)\n"
        f"try:\n"
        f"    {QN('getattr')}({QN('sysm')},{S('setprofile')})(None)\n"
        f"    if {QN('getattr')}({QN('getattr')}({QN('sysm')},{S('monitoring')}),{S('get_events')})():\n"
        f"        {QN('die')}()\n"
        f"except Exception:\n"
        f"    pass\n"
    )

def build_antihook():
    return (
        f"if {QN('getattr')}({QN('sysm')}, {S('gettrace')})() is not None: {QN('die')}()\n"
        f"{QN('getattr')}({QN('sysm')}, {S('settrace')})(None)\n"
        f"{QN('getattr')}({QN('sysm')}, {S('setprofile')})(None)\n"
        f"try:\n"
        f"    if {QN('getattr')}({QN('getattr')}({QN('sysm')},{S('monitoring')}),{S('get_events')})():\n"
        f"        {QN('die')}()\n"
        f"except Exception:\n"
        f"    pass\n"
        f"for _n_ in ({', '.join(S(x) for x in KILL_MODULES)}):\n"
        f"    if _n_ in {QN('sysm')}.modules: {QN('die')}()\n"
    )

def build_runtime_legacy(compiled, protect=True):
    m1 = mkmarker()
    m2 = mkmarker()
    m1h = m1.encode().hex()
    m2h = m2.encode().hex()

    la = []
    a = la.append

    a("# -*- coding: utf-8 -*-")
    a(f"import sys as {QN('sysm')}")
    a(f"{QN('bd')} = (lambda _bx_: _bx_ if isinstance(_bx_, dict) else vars(_bx_))(globals()['__builtins__'])")
    a(f"{QN('getattr')} = {QN('bd')}['getattr']")
    a(f"{QN('str')} = {QN('bd')}['str']")
    a(f"{QN('chr')} = {QN('bd')}['chr']")
    a(f"{QN('join')} = {QN('getattr')}({QN('str')}(), 'join')")
    a(f"{QN('int')} = {QN('bd')}['int']")
    a(f"{QN('len')} = {QN('bd')}['len']")
    a(f"{QN('float')} = {QN('bd')}['float']")
    a(f"{QN('bytes')} = {QN('bd')}['bytes']")
    a(f"{QN('list')} = {QN('bd')}['list']")
    a(f"{QN('map')} = {QN('bd')}['map']")
    a(f"{QN('eval')} = {QN('bd')}['eval']")
    a(f"{QN('exec')} = {QN('bd')}['exec']")
    a(f"{QN('import')} = {QN('bd')}['__import__']")
    a(f"{QN('vars')} = {QN('bd')}['vars']")
    a(f"{QN('globals')} = {QN('bd')}['globals']")
    a(f"{QN('dec')} = (lambda {QN('join')},{QN('chr')},_k_,_o_: (lambda _s_: {QN('join')}({QN('chr')}(((_x_ - _o_) ^ _k_)) for _x_ in _s_)))({QN('join')},{QN('chr')},{K},{OFF})")

    a(f"def {QN('die')}():")
    a(f"    raise ({QN('bd')}[{S('SystemExit')}])({I(0xC0DE)}) from None")

    a(f"_vv_ = {QN('getattr')}({QN('getattr')}({QN('sysm')}, {S('version_info')}), {S('major')})")
    a(f"_w_ = {QN('getattr')}({QN('getattr')}({QN('sysm')}, {S('version_info')}), {S('minor')})")
    a(f"if _vv_ != {I(sys.version_info.major)} or _w_ != {I(sys.version_info.minor)}:")
    a(f"    {QN('die')}()")

    a(f"{QN('osm')} = {QN('import')}({S('os')})")
    a(f"{QN('mz')} = {QN('import')}({S('zlib')})")
    a(f"{QN('lm')} = {QN('import')}({S('lzma')})")
    a(f"{QN('bz')} = {QN('import')}({S('bz2')})")
    a(f"{QN('b64')} = {QN('import')}({S('base64')})")
    a(f"{QN('ms')} = {QN('import')}({S('marshal')})")
    a(f"{QN('hl')} = {QN('import')}({S('hashlib')})")

    if protect:
        a(f"if {QN('getattr')}({QN('sysm')}, {S('gettrace')})() is not None: {QN('die')}()")
        a(f"{QN('getattr')}({QN('sysm')}, {S('settrace')})(None)")
        a(f"{QN('getattr')}({QN('sysm')}, {S('setprofile')})(None)")
        a(f"for _n_ in ({S('frida')}, {S('pydevd')}, {S('debugpy')}, {S('pyrasite')}, {S('lief')}, {S('ptvsd')}, {S('pycharm')}, {S('gdb')}):")
        a(f"    if _n_ in {QN('sysm')}.modules: {QN('die')}()")
        a(f"for _e_ in ({S('HTTP_PROXY')}, {S('HTTPS_PROXY')}, {S('http_proxy')}, {S('https_proxy')}):")
        a(f"    if {S('127.0.0.1')} in {QN('osm')}.environ.get(_e_, {S('')}): {QN('die')}()")
        a(f"for _t_ in ({S('HTTP_TOOLKIT_ACTIVE')}, {S('SSL_CERT_FILE')}, {S('NODE_EXTRA_CA_CERTS')}):")
        a(f"    if {S('httptoolkit')} in {QN('osm')}.environ.get(_t_, {S('')}): {QN('die')}()")
        a(f"if {QN('bd')}[{S('type')}]({QN('getattr')}({QN('ms')}, {S('loads')})) != {QN('bd')}[{S('type')}]({QN('bd')}[{S('len')}]): {QN('die')}()")
        a(build_antidump())

    A = "\n".join(la)

    lc = []
    ca = lc.append
    ca("try:")
    ca(f"    _ow_ = {QN('getattr')}({QN('bd')}[{S('open')}]({QN('globals')}()[{S('__file__')}], {S('rb')}), {S('read')})()")
    ca(f"    _i1_ = {QN('getattr')}(_ow_, {S('index')})({QN('getattr')}({QN('bytes')}, {S('fromhex')})({S(m1h)}))")
    ca(f"    _i2_ = {QN('getattr')}(_ow_, {S('index')})({QN('getattr')}({QN('bytes')}, {S('fromhex')})({S(m2h)}), _i1_ + {I(len(m1))})")
    ca(f"    _mt_ = _ow_[:_i1_] + _ow_[_i2_ + {I(len(m2))}:]")
    ca(f"    _A_ = {QN('getattr')}({QN('bz')}, {S('decompress')})(_pp_)")
    ca(f"    _B_ = {QN('getattr')}({QN('lm')}, {S('decompress')})(_A_)")
    ca(f"    _C_ = {QN('getattr')}({QN('mz')}, {S('decompress')})(_B_)")
    ca(f"    _D_ = {QN('getattr')}({QN('b64')}, {S('b85decode')})(_C_)")
    ca(f"    _Kq_ = {QN('bytes')}()")
    ca(f"    _nn_ = {I(0)}")
    ca(f"    while {QN('len')}(_Kq_) < {QN('len')}(_D_):")
    ca(f"        _Kq_ += {QN('getattr')}({QN('hl')}, {S('sha256')})(_mt_ + {QN('getattr')}({QN('int')}(_nn_), {S('to_bytes')})(8, {S('big')})).digest()")
    ca(f"        _nn_ = _nn_ + {I(1)}")
    ca(f"    _E_ = {QN('bytes')}([(_b_ ^ _Kq_[_iX_]) for _iX_, _b_ in enumerate(_D_)])")
    ca(f"    _F_ = {QN('getattr')}({QN('ms')}, {S('loads')})(_E_)")
    ca("except Exception:")
    ca(f"    {QN('die')}()")
    ca("")
    ca(f"del _ow_, _mt_, _Kq_, _nn_, _pp_, _A_, _B_, _C_, _D_, _E_")
    ca(f"{QN('exec')}(_F_, {QN('globals')}())")
    C = "\n".join(lc)

    material = "#!/usr/bin/python" + VER + "\n" + A + "\n# \n" + C + "\n"
    ks = make_ks(material.encode('utf-8'), len(compiled))
    xored = bytes(a ^ b for a, b in zip(compiled, ks))
    s85 = base64.b85encode(xored)
    z1 = zlib.compress(s85)
    z2 = lzma.compress(z1)
    z3 = bz2.compress(z2)

    chunk = 1500
    parts = [z3[i:i + chunk] for i in range(0, len(z3), chunk)]

    pnames = []
    for part in parts:
        pname = rn()
        pnames.append(pname)

    refs = []
    for pname in pnames:
        refs.append(f"{QN('getattr')}({pname} , {S('to_bytes')})(({QN('getattr')}({pname} , {S('bit_length')})() + 7) // 8, {S('big')})[1:]")

    pc = "\n".join(f"{pname} = {int.from_bytes(b'\x01' + part, 'big')}" for pname, part in zip(pnames, parts))
    pp = f"_pp_ = {QN('getattr')}({QN('bytes')}(), {S('join')})([{', '.join(refs)}])"
    return "\n".join(la + ["# " + m1, pc, pp, "# " + m2] + lc)

def pipeline(source, mode=2, protect=True, hide=True, more=True, style="mine"):
    global K
    K = random.randint(1, 0xFFFFFFFF)

    code = source
    code = clean_try_except(code)
    try:
        tree = ast.parse(code)
        code = ast.unparse(Cv().visit(tree))
    except SyntaxError:
        pass

    if mode >= 2 and more:
        code = obf_vars(code)
        if hide:
            code = hide_builtins(code)
        code = obf_consts(code)
        if more:
            code = spam(code)
    else:
        code = obf_consts(code)
        code = spam(code)

    if mode >= 3 and more:
        code = spam(code)

    final = build_guard() + anti_pycdc_block() + "\n" + code

    compiled = marshal.dumps(compile(final, INNER_NAME, 'exec'))
    if style == "legacy":
        header = build_runtime_legacy(compiled, protect)
    else:
        header = build_runtime(compiled, protect)

    out = f"#!/usr/bin/python{VER}\n" + header + "\n"

    return out

MINERALS = [
    "bauxite", "apatite", "ilmenite", "monazite", "zircon", "cassiterite",
    "scheelite", "wolframite", "hematite", "magnetite", "galena", "sphalerite",
    "chalcopyrite", "cinnabar", "stibnite", "pyrolusite", "cryptomelane",
    "siderite", "smithsonite", "azurite", "malachite", "bornite", "realgar",
    "orpiment", "millerite", "pentlandite", "skutterudite", "vanadinite",
    "wulfenite", "anglesite", "cerussite", "brucite", "diaspore", "boehmite",
    "chromite", "columbite", "euclase", "magnesite", "kaolinite", "bentonite",
    "dolomite", "barite", "fluorite", "calcite", "gahnite", "annabergite",
    "manganite", "rhodochrosite", "stilbite", "lazurite", "aurichalcite",
]

class MINE:
    def __init__(self):
        self.pool = list(MINERALS)
        random.shuffle(self.pool)
        self.i = 0
        self.used = set()

    def n(self):
        while self.i < len(self.pool):
            c = self.pool[self.i]
            self.i += 1
            if c not in self.used:
                self.used.add(c)
                return c
        k = 0
        while True:
            c = f"lode_{k}"
            k += 1
            if c not in self.used:
                self.used.add(c)
                return c

    def nl(self):
        return "_" + self.n()

def _big():
    return random.randint(10 ** 15, 9 * 10 ** 16)

def alias_expr(T):
    kw = {"T": T}
    for k in "abcdefg":
        kw[k] = _big()
    return random.choice([
        "({T}) if bool(type(int({a})>int({b})<int({c})>int({d}))) == bool(bool(str({e}) is not str({f}))) and bool(int({g})) < bool(type(None)) else {T}",
        "({T}) if bool(bool(bool(None))) < bool(type(str({a}))) or bool(int({b})) > bool(bool(str({c}))) else {T}",
        "({T}) if (bool(type(int({d}))) ^ bool(type(str({e})))) == bool(type(None)) and bool(int({f})) == bool(bool(None)) else {T}",
        "({T}) if bool(type(int({c}))) <= bool(type(int({d}))) and bool(str({e}) is not str({f})) < bool(type(None)) else {T}",
    ]).format(**kw)

def build_runtime(compiled, protect=True):
    m1 = mkmarker()
    m2 = mkmarker()
    m1h = m1.encode().hex()
    m2h = m2.encode().hex()

    la = []
    a = la.append
    mine = MINE()

    lock = (
        f"_vv_=__import__('sys').version_info\n"
        f"if _vv_.major!={sys.version_info.major} or _vv_.minor!={sys.version_info.minor}:\n"
        f"    raise SystemExit({0xC0DE})\n"
        f"del _vv_\n"
    )
    dec_expr = ('"".join(map(lambda _m_: chr((_m_ - ' + str(OFF) + ') ^ ' + str(K) + '), '
               + repr(enc_seq(lock)) + '))')
    a("# -*- coding: utf-8 -*-")
    banner = (("(((([" + '["TRUONG_NHAT_BAO_NAM","https://github.com/ktn1703/Neo","PYTHON",' + VER + '],')
              + '__import__("builtins").exec' + "(" + dec_expr + ")]" + ")))")
    nb = banner.count("(") - banner.count(")")
    if nb > 0:
        banner += ")" * nb
    elif banner.count("[") != banner.count("]"):
        banner += "]" * (banner.count("[") - banner.count("]"))
    a(banner)

    sysa = mine.n()
    a(f"import sys as {sysa}")

    bm = {}
    for k in ("str", "int", "float", "bytes", "list", "map", "chr", "eval",
              "exec", "getattr", "vars", "globals", "type", "len", "__import__", "dict"):
        nm = mine.n()
        bm[k] = nm
        a(f"globals()['{nm}'] = {alias_expr(k)}")

    deca = mine.n()
    a(f"({deca}) = (lambda _j_,_c_,_k_,_o_:(lambda _s_:_j_(_c_(((_x_-_o_)^_k_)) for _x_ in _s_)))(({bm['str']})().join,({bm['chr']}),{K},{OFF})")
    d = deca
    g = bm['getattr']

    for mk in ("os", "zlib", "lzma", "bz2", "base64", "marshal", "hashlib"):
        nm = mine.n()
        bm[mk] = nm
        a(f"({nm}) = ({bm['__import__']})(({d})({q(mk)}))")

    dnm = mine.n()
    a(f"def {dnm}():")
    a(f"    raise (SystemExit)(({bm['int']})(({d})({q(str(0xC0DE))}))) from None")

    bdname = mine.n()
    a(f"({bdname}) = (lambda _bx_: _bx_ if isinstance(_bx_, dict) else vars(_bx_))(globals()['__builtins__'])")
    jnm = mine.n()
    a(f"({jnm}) = ({bm['str']})().join")
    bridge = {
        'bd': bdname, 'sysm': sysa, 'osm': bm['os'], 'mz': bm['zlib'],
        'lm': bm['lzma'], 'bz': bm['bz2'], 'b64': bm['base64'], 'ms': bm['marshal'],
        'hl': bm['hashlib'],
        'dec': deca, 'die': dnm, 'getattr': bm['getattr'], 'str': bm['str'],
        'chr': bm['chr'], 'join': jnm, 'int': bm['int'], 'float': bm['float'],
        'bytes': bm['bytes'], 'list': bm['list'], 'map': bm['map'], 'len': bm['len'],
        'eval': bm['eval'], 'exec': bm['exec'], 'import': bm['__import__'],
        'vars': bm['vars'], 'globals': bm['globals'],
    }
    for _k, _v in bridge.items():
        a(f"globals()['{QN(_k)}'] = ({_v})")

    if protect:
        a(f"if ({g})(({sysa}),({d})({q('gettrace')}))() is not None: ({dnm})()")
        a(f"({g})(({sysa}),({d})({q('settrace')}))(None)")
        a(f"({g})(({sysa}),({d})({q('setprofile')}))(None)")
        bads = ",".join(f"({d})({q(x)})" for x in ("frida", "pydevd", "debugpy", "pyrasite", "lief", "ptvsd", "pycharm", "gdb"))
        a(f"for _n_ in {bads}:")
        a(f"    if _n_ in ({g})(({sysa}),({d})({q('modules')})): ({dnm})()")
        evs = ",".join(f"({d})({q(x)})" for x in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"))
        a(f"for _e_ in {evs}:")
        a(f"    if ({d})({q('127.0.0.1')}) in ({g})(({bm['os']}),({d})({q('environ')})).get(_e_,({d})([])): ({dnm})()")
        evs2 = ",".join(f"({d})({q(x)})" for x in ("HTTP_TOOLKIT_ACTIVE", "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS"))
        a(f"for _t_ in {evs2}:")
        a(f"    if ({d})({q('httptoolkit')}) in ({g})(({bm['os']}),({d})({q('environ')})).get(_t_,({d})([])): ({dnm})()")
        a(f"if ({bm['type']})(({g})(({bm['marshal']}),({d})({q('loads')}))) != ({bm['type']})(({bm['len']})): ({dnm})()")
        a(build_antidump())

    A = "\n".join(la)
    ll = mine.nl()
    lc = []
    ca = lc.append
    ca("try:")
    ca(f"    _ow_ = {QN('getattr')}({QN('bd')}[{S('open')}]({QN('globals')}()[{S('__file__')}], {S('rb')}), {S('read')})()")
    ca(f"    _i1_ = {QN('getattr')}(_ow_, {S('index')})({QN('getattr')}({QN('bytes')}, {S('fromhex')})({S(m1h)}))")
    ca(f"    _i2_ = {QN('getattr')}(_ow_, {S('index')})({QN('getattr')}({QN('bytes')}, {S('fromhex')})({S(m2h)}), _i1_ + {I(len(m1))})")
    ca(f"    _mt_ = _ow_[:_i1_] + _ow_[_i2_ + {I(len(m2))}:]")
    ca(f"    _k1 = {QN('getattr')}({QN('bz')}, {S('decompress')})({ll})")
    ca(f"    _k2 = {QN('getattr')}({QN('lm')}, {S('decompress')})(_k1)")
    ca(f"    _k3 = {QN('getattr')}({QN('mz')}, {S('decompress')})(_k2)")
    ca(f"    _k4 = {QN('getattr')}({QN('b64')}, {S('b85decode')})(_k3)")
    ca(f"    _Kq_ = {QN('bytes')}()")
    ca(f"    _nn_ = {I(0)}")
    ca(f"    while {QN('len')}(_Kq_) < {QN('len')}(_k4):")
    ca(f"        _Kq_ += {QN('getattr')}({QN('hl')}, {S('sha256')})(_mt_ + {QN('getattr')}({QN('int')}(_nn_), {S('to_bytes')})(8, {S('big')})).digest()")
    ca(f"        _nn_ = _nn_ + {I(1)}")
    ca(f"    _k5 = {QN('bytes')}([(_b_ ^ _Kq_[_iX_]) for _iX_, _b_ in enumerate(_k4)])")
    ca(f"    _k6 = {QN('getattr')}({QN('ms')}, {S('loads')})(_k5)")
    ca("except Exception:")
    ca(f"    {QN('die')}()")
    ca(f"del {ll},_ow_,_mt_,_Kq_,_nn_,_k1,_k2,_k3,_k4,_k5")
    ca("try:")
    ca(f"    {QN('exec')}(_k6, {QN('globals')}())")
    ca("except Exception:")
    ca(f"    {QN('die')}()")
    C = "\n".join(lc)

    material = "#!/usr/bin/python" + VER + "\n" + A + "\n# \n" + C + "\n"
    ks = make_ks(material.encode('utf-8'), len(compiled))
    xored = bytes(b ^ k for b, k in zip(compiled, ks))
    s85 = base64.b85encode(xored)
    z1 = zlib.compress(s85)
    z2 = lzma.compress(z1)
    z3 = bz2.compress(z2)

    chunk = 1500
    parts = [z3[i:i + chunk] for i in range(0, len(z3), chunk)]

    pnames = []
    for part in parts:
        nm = mine.nl()
        pnames.append(nm)
    pc = "\n".join(f"{nm} = {int.from_bytes(b'\x01' + part, 'big')}" for nm, part in zip(pnames, parts))

    refs = []
    for nm in pnames:
        bl = f"({g})({nm},({d})({q('bit_length')}))()"
        refs.append(f"({g})({nm},({d})({q('to_bytes')}))(({bl}+7)>>3,({d})({q('big')}))[1:]")
    pp_line = f"{ll} = ({bm['bytes']})().join([{', '.join(refs)}])"

    return "\n".join(la + ["# " + m1, pc, pp_line, "# " + m2] + lc)

dark = Col.dark_gray if hasattr(Col, 'dark_gray') else ''
light = Col.light_gray if hasattr(Col, 'light_gray') else ''
green = getattr(Col, 'green', '')
cyan = getattr(Col, 'cyan', '')
matrix = Colors.StaticMIX((Col.green, Col.cyan)) if hasattr(Colors, 'StaticMIX') else ''

LOGO = r"""

    ___           ___           ___
   /\__\         /\  \         /\  \
  /::|  |       /::\  \       /::\  \
 /:|:|  |      /:/\:\  \     /:/\:\  \
/:/|:|  |__   /::\~\:\  \   /:/  \:\  \
/:/ |:| /\__\ /:/\:\ \:\__\ /:/__/ \:\__\
\/__|:|/:/  / \:\~\:\ \/__/ \:\  \ /:/  /
    |:/:/  /   \:\ \:\__\    \:\  /:/  /
    |::/  /     \:\ \/__/     \:\/:/  /
    /:/  /       \:\__\        \::/  /
    \/__/         \/__/         \/__/

    INFO AUTHOR: https://6cxl.lol
    TOOL OBF:    github.com/ktn1703/Neo

"""

def stage(text, symbol='NEO', col1=None, col2=None):
    return f" [{symbol}] {text}"

def log_info(t):
    print(stage(t, 'INFO'))
def log_event(t):
    print(stage(t, 'EVENT'))
def log_ok(t):
    print(stage(t, 'OK'))
def log_warn(t):
    print(stage(t, 'WARN'))

def print_logo():
    print(LOGO)
    print(stage(f" Neo-Matrix {VER} · keep the Red Pill ", symbol='?'))

def parse_args():
    p = argparse.ArgumentParser(description='NEO-MATRIX ULTIMATE OBFUSCATOR')
    p.add_argument('-f', '--file', help='path to the file to obfuscate')
    p.add_argument('-o', '--output', help='output file (default: neo-<name>)')
    p.add_argument('-m', '--mode', type=int, default=2, help='mode (1=light, 2=full, 3=mega)')
    p.add_argument('--no-protect', action='store_true', help='disable anti-hook/anti-debug header')
    p.add_argument('--no-hide', action='store_true', help='disable hide-builtins')
    p.add_argument('--no-more', action='store_true', help='disable variable renaming and advanced spam')
    p.add_argument('--banner', action='store_true', help='show banner even with -f')
    p.add_argument('--style', choices=['mine', 'legacy'], default='mine',
                   help='output style: mine (mineral) | legacy (classic)')
    return p.parse_args()

def run_headless(file, output, mode, protect, hide, more, style='mine'):
    with open(file, 'r', encoding='utf-8-sig') as f:
        source = f.read()
    log_event(f'Loaded {file} ({len(source)} bytes)')
    out = pipeline(source, mode=mode, protect=protect, hide=hide, more=more, style=style)
    with open(output, 'w', encoding='utf-8', newline='\n') as f:
        f.write(out)
    log_ok(f'Saved {output} | engine done.')

def main():
    args = parse_args()

    if args.file:
        if args.banner:
            print_logo()
        output = args.output or ('neo-' + args.file)
        protect = not args.no_protect
        hide = not args.no_hide
        more = not args.no_more
        mode = args.mode
        style = args.style
        st = time.time()
        try:
            run_headless(args.file, output, mode, protect, hide, more, style)
            log_info(f'Done in {time.time() - st:.3f}s')
            return
        except Exception as e:
            log_warn(f'Engine error: {e}')
            traceback.print_exc()
            sys.exit(1)

    print_logo()
    print()
    file = input(stage('Drag file into console then Enter: ', symbol='?', col2=cyan)).replace('"', '').replace("'", '').strip()
    while True:
        try:
            with open(file, 'r', encoding='utf-8-sig') as f:
                source = f.read()
            break
        except FileNotFoundError:
            file = input(stage('File not found, try again: ', symbol='?', col2=Col.yellow)).replace('"', '').replace("'", '').strip()

    while True:
        try:
            mode = int(input(stage('MODE (1=Light, 2=Full, 3=Mega): ', symbol='?', col2=cyan)))
            if 1 <= mode <= 3:
                break
        except ValueError:
            pass

    more = input(stage('More obfuscation? (y/N): ', symbol='?', col2=cyan)).strip().upper() != 'N'
    hide = input(stage('Hide builtins? (Y/n): ', symbol='?', col2=cyan)).strip().upper() != 'N'
    protect = input(stage('Anti-hook / Anti-debug? (Y/n): ', symbol='?', col2=cyan)).strip().upper() != 'N'

    output = input(stage('Output file name (leave blank for default): ', symbol='?', col2=cyan)).strip()
    if not output:
        output = 'neo-' + file

    print()
    log_event('Starting Neo-Matrix engine...')
    stt = time.time()
    try:
        out = pipeline(source, mode=mode, protect=protect, hide=hide, more=more)
        with open(output, 'w', encoding='utf-8', newline='\n') as f:
            f.write(out)
        log_ok(f'Saved {output}')
        log_info(f'>>> Done in {time.time() - stt:.3f}s')
    except Exception as e:
        log_warn(f'Engine error: {e}')
        traceback.print_exc()

if __name__ == '__main__':
    main()