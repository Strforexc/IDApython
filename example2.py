import ida_hexrays as hx
import ida_hexrays
import ida_bytes
import idautils
import ida_kernwin
import ida_lines
import ida_funcs
import idc
import idaapi
from ida_idaapi import __EA64__, BADADDR


# ----------------------------------------------------------------------------


def findexpr(cfunc, ctree, expr):
    """
    cfunc :     cfunc_t
    ctree:      citem_i
    expr:       lambda/function:f(cfunc_t,citem_t)
    return addr
    """

    # use to vist every item
    class Visitor(ida_hexrays.ctree_visitor_t):
        def __init__(self, cfunc, expr):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
            self.cfunc = cfunc
            self.query = expr
            self.found = list()
            return

        def process(self, i):
            try:
                cnt = 1
                for _query in self.query:
                    if _query(self.cfunc, i):
                        print(ParseResult(self.cfunc, i))
                        self.found.append({cnt:str(ParseResult(self.cfunc, i))})
                    cnt = cnt + 1
            except:
                pass
            return 0

        def visit_insn(self, i):
            return self.process(i)

        def visit_expr(self, e):
            return self.process(e)

    if cfunc:
        itfinder = Visitor(cfunc, expr)
        itfinder.apply_to(cfunc.body, None)
        return itfinder.found

    return list()


class ParseResult():
    def __init__(self, cfunc=None, i=None):
        if isinstance(cfunc, hx.cfuncptr_t):
            self.entry = cfunc.entry_ea
        elif isinstance(cfunc, int):
            self.entry = cfunc
        else:
            self.entry = idaapi.BADADDR
        if isinstance(i, (hx.cexpr_t, hx.cinsn_t)):
            self.ea = i.ea if not isinstance(cfunc, hx.cfuncptr_t) else self.find_closest_address(cfunc, i)
            self.v = ida_lines.tag_remove(i.print1(None))
        elif isinstance(i, tuple):
            self.ea, self.v = i
        else:
            self.ea = idaapi.BADADDR
            self.v = "<undefined>"

    def find_closest_address(self, cfunc, i):
        parent = i
        while parent:
            if parent and parent.ea != idaapi.BADADDR:
                return parent.ea
            parent = cfunc.body.find_parent_of(parent)
        return idaapi.BADADDR

    def __str__(self):
        return "[%x] %x: \"%s\"" % (self.entry, self.ea, self.v)


def exec_findrc4(expr):
    flags = 0
    eas = idautils.Functions()
    result = list()
    for ea in eas:
        f = ida_funcs.get_func(ea)
        if f:
            cfunc = None
            hf = ida_hexrays.hexrays_failure_t()
            try:
                cfunc = ida_hexrays.decompile(f, hf, flags)
            except Exception as e:
                pass
            if cfunc:
                result += findexpr(cfunc, cfunc.body, expr)
    return result


def findrc4(expr):
    try:
        r = exec_findrc4(expr)
        print("<query> done! %d unique hits." % len(r))
        for e in r:
            print(e)

    except Exception as exc:
        print("some errors happened")
        return
    return r


expr1 = lambda cf, i: ((i.op is idaapi.cot_asg and
i.x.op is idaapi.cot_var and
i.y.op is idaapi.cot_smod and
i.y.x.op is idaapi.cot_add and
i.y.x.x.op is idaapi.cot_var and
i.y.x.y.op is idaapi.cot_num and
i.y.y.op is idaapi.cot_num and
i.y.y.numval() == 256) or
(i.op is idaapi.cot_asg and
i.x.op is idaapi.cot_var and
i.y.op is idaapi.cot_cast and
i.y.x.op is idaapi.cot_add and
i.y.x.x.op is idaapi.cot_var and
i.y.x.y.op is idaapi.cot_num and
("8" in str(i.y.type))))

expr2 = lambda cf, i: ((i.op is idaapi.cot_asg and
i.x.op is idaapi.cot_var and
i.y.op is idaapi.cot_smod and
i.y.y.op is idaapi.cot_num and
i.y.y.numval() == 256 ) or (i.op is idaapi.cot_asg and
i.x.op is idaapi.cot_var and
i.y.op is idaapi.cot_cast and
i.y.x.op is idaapi.cot_add and
 ("8" in str(i.y.type) ) ))


expr3 = lambda cf, i:(i.op is idaapi.cot_asgxor and
i.x.op is idaapi.cot_ptr and
i.x.x.op is idaapi.cot_cast and
i.x.x.x.op is idaapi.cot_add )

expr = []
expr.append(expr1)
expr.append(expr2)
expr.append(expr3)

tmp = findrc4(expr)
print(tmp)
res = {1: [], 2: [], 3: []}
match = [0,0,0]
for i in tmp:
    # i:str
    index = str(i.keys()).split('[')[1][0]
    value = str(i.values())[14:-4]
    res[int(index)].append(value)

if len(res[1]) != 0:
    for k in res[1]:
        pattern = k[k.find('['):k.find(']')+1]
        cnt = 0
        for i in range(2, 4):
            for j in res[i]:
                if pattern in j:
                    match[i-1] = match[i-1] + 1
    if(match[1] >= 2 and match[2] >= 1):
        print(f"RC4_function at addr:0x{pattern[1:-1]}")