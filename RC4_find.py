import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_hexrays
import ida_netnode
import ida_idp
import idaapi
import idautils
import ida_lines
import ida_hexrays as hx
# Icon
icon = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x000\x00\x00\x00%\x08\x06\x00\x00\x00\x04\x19j\xaf\x00\x00\x00\x01sRGB\x00\xae\xce\x1c\xe9\x00\x00\x00\x04gAMA\x00\x00\xb1\x8f\x0b\xfca\x05\x00\x00\x00\tpHYs\x00\x00\x0e\xc3\x00\x00\x0e\xc3\x01\xc7o\xa8d\x00\x00\x06\x0cIDATXG\xed\x97{PTu\x14\xc7\xcf\xdd]vY\x9e\xbb\x08\x08\xb8\x12h>\x92t@\x13\x07\xb2\x04\x93\xac\x1c\tL\x19\x9f\x199\x16\x16\x1a\x98\xa3i9\x84J\xa33\x068\xcd\xa0\xd9\x03m0Lj4\x07\xa3\xc9\x07\xa4#\xf8\xd8\x89-5\x1b\x9f\xa4;$\x12\xb2\xbca\x1f\xf7\xf6\xfb\xdd=\xbb\xee\xb2w/\xeb\x8c\x7f\xf4\xc7~\x98\xe3\xfd}\xcf]\x99s\xf8\x9d\xf3\xfb\x9d\x05/^\xbcx\xd1\x10+&v\x97\x18\xe7`\xf5\xc4\x0e\x11[@\xec\x7f\t\r\x9c\x06\xe8\x18\xb4;\xa3\x9f\xa3\x9f\x7f\xec0\xf8\xf4\x98\xbb\xebr\x17W^\xb9\x9a\xb8\xbe\xe6\xe4{\xe8\xf2\x98\xc9k2v\x8dz%\xa9\x89\x05\x0b\xaf\x1f\xf4wv\x87\xfa\xaa\x03\xa8\xee6\xf7\x0f<\x19\x1ce({.\xa7\x92\x7f\xe9!\x8f\x94\x80~c^^C]]\xc9\x82\x06\x1dz\xac\xbc<<\x04\xb2\xa3#!\xd2W\x0e\xe1\xea\x90\xf6\xf0\xf9\x0b\xa7\xa8__\xf9\x0cyE\xcb\xc7\xa9\x84\x026\xcd\x02\xe9\xe8PT\xce0\xe4gz\xd8\x84\xcc\xea\xf4\xcdG\xd05$\x1e\'\xa0/)\x8a\xef\xff\xa5\xa6v\xfa\xa9\x0b\xaa{\x03F\xde\x17\xa1\x90CUb\x1c\xff\xa4H\xfc\x03\xa0S\xa1\xccL8T\xed\x18@\x121{\tI\xd4~\x10\xb83\x9d.\x05\x912\x12CV\xec\xd4\x84=\xa9\xf9M\xe8\x12E\x82OQn\x97\x14\xa8\x06\xce5|\xf5\x93\xbe\xc5\x1e<\xc51x\x8a1X\xb5sP\xf0\x94\x06b4\t\x1e\xb6\xbd\x17LZ\xda\xef\xc2X8Vu\xb6\xe5F-\xca!\xf1(\x01\xd0\xea\n\xd9\xb6\xd6\xc95\xf7\xdb\xd0\x01\xb0i\xec\x13N\xc1K\xa2c\xb4\x11\xd9\xb9E(\x07\xa3\'\x96e]\x02\x98\xab\xafv\xe1R\x90;=m1s\x8fm9\x80R\x94!\x13\xd8\xf1\xf5\xad\\CG\xcf\x1a\x96\x9c%5-\x0f\xd0\x0b\xa4\xe6#p\x05`\xf2\x0b0\x04\xcdxa\x89:5\xd5\x80.!\xe8N\xf0\x18\xf5\xed]a\x8a\xc0n\x94\x82\x9ci\xb9\xba\xf8\xc5\xa3\x1fe\xa0t\x8bh\x02{k\xbb\xe3O\xb5\x86o\xdd3~\x13\x18X\x16\xbd\xce0r\x85\xd1\x1c\xa4\xca\x0e[\xfe\xd65t\xb9\x83\xee\x82\x15\x8e\x8b\xf2\xed\xe3\xe6\x92\':\\\xe1\xc8;\xed\xbf\xb7\xcasjw\xc7\xa0K\x10\xb7\t\x94\x1cnW\x9d\xbc\xc4\xec5\x99Au]\x9d\x08gF\xa6C\xb8C\xc9\xd8z\xc1<,\xb4lR\xc5\x0f\x1e\x9f\x1a6.\xaf\xfc\xb2n\x822r\x17JAh?\x9ch\xd6\x1dE)\x88\xdb\x04\xb4\xff\xf8\x14\xb4vqSQ\xc2\xcf\xe3\xf3!\xc8?\x18\x15@\xa3\xa1\x1b\x98(M\xfd\xf0\xb5\x9b\x0b\xd15\x14\xf9\xf8\xa4T\xd1\x7f\x1a\x96\x94\xe6\x8dT\x868\x9f\xc9\x83h\xed\xef\x98\xb8\xecD\xf1\xf7(]\x10L\xa0\xa0\xaa7\xaf\xad\x13\xf2P\xf2\xd0\x1eP\xa7mC\x05\xb0\xe6\xd2u\xa8\x92\x07mV\'$\x88\xd5\xbd\r\xdb\xb8a\x83O\x802\x11F\xbc\x14\xa5T\xa3\x12\xa6\xfa\xef\x8b\xaf\xa5W\x17\xceA\xe9\x84\xcb=\xb0\xa1\xb2/Fw\xc7\xd2HK\x07]N\\\xd8\x1e\x0b\xdd]\xad\xa8\xec\xa7\x8b\xbdA\x05\xa0\xc1\xd3\xf7\xb6Q\x82\xfe\x9f\x91\xd6\xa5\x95\x98\xcf\x96\xa6\xb4+\xcd\xb5b\xb7\x92\x8c\xdc\x0f\xeb\x9e\x9a\x9b\xb01i\x91\xd3\xfd\xe0\xba\x03\x0c\xf7\xaa\xbb\xe0)\xe3\x16\x1f\xc4\x15\x0f\rJhh\xa3~\xdb\x05F\x0f}[\xf0\x14\xfbqj\xa3iuE\xdd\xbc@\xf68JA\xcc\xa4\x1f\xaa\xee\x9eOAi\xc7%\x81\xf3\xe7Z\xf6+e\xd6YE\x88\xe0\xe8i\x90\xb8\xea$*;4x\xc7\xc1\x8e\x06M\x13\x1b<\x89\xd2\xec]v\x8b\xfb##\xe3\x8b\xf0\xba\xb4\x99\xb2\x16\xf4\xb8\xa2`d\x86\x85c\xa6\x9fEi\xc7%\x81\xba\xd2X\x83Zn\xcaD)H\x80f\x1a\xcc\xfc\xf0\xafN\x7f\xff\xa0c\xe8\xf2\x94\x85\xc4\x1c\x9b\x19\xb8\x9b\x1b\xa2\xb9\xae\xc6r\xce\xd8\x01\x9f\x87\\\x84\x11L\x1f\xbey\x88\\"\x03\xa9\x91]\xb1>a\xfeut\xd9\x11l\xe2\x8a\xfc\xd0#\xc3\x14\xfdn;\x9f\xc7O\x134{[s Y\xd1\x92\xa0M9\xf8/Kk\xbd\x84\x18\xadw{\xd3\x12h3\xf3Ip\\\xbb\n\xee\xed+c\xcc\xf7TRrB\xab\xa4&\xd8\xedw\xc1\xba\x87\x0e\xc8\x8c\\i\xf3\xdb\x07\xaaQ:\xe1\xb6m\xc8E"M+\xea\xd4\xb2\x8c4\x1e]\x82L\xd20\x85\xa5\xcb\xfd?F)\x06-)\xfbLDH\xe6\xb4S\xd2\xa1\xe7\xf2\x07\xa8y\x8c\xe4~.\xbe?\x16\xb6\xb3q\xbcVI\x94:\x06\xb8\xd4\xa6\xec}\x82\xa7\x9d\xe0\x0eP\x18\x86\xb1<;\x9a\xcdTH\xdd\xf7\x03\xe5J3W\x90[\xde\xe5\xd2\\\x02$\x13s\xdc\xa5\xfa\x06\xed\xcd\xf5\xb8\xb6#\x0f\x00x?\xe2\x1a<\xcf\xdc\x07_\xc6\xc70V\x15\x99\xed.x\x8a\xdb\x04(\x85\x8b\xd4M*\x85x?X\xc8\x84q\xbb\x959\xdcx\xbbO\xf4\xcaGh\xb9\xd9G\x8a\xe4\x1c\x83D\xdf\xea:N\xf8\xf8\x01\xec\xd7\xfc\x06\xe3\xc0\x94s<\xf3\x13\xd1\x8bN4\x01J%\xe9\x870\xdf~\xd1Q\xa1\xcf\x04\xaa-G,\xe5(\xc5\xd0ge\xcd\x99\x1d\xa6\x96\x0e\xa0\x86\xa4U&\x10JB\xed\'+=\xfd\xe6\xc1\xefP\xbae\xc8\x04(\x07\xd7\x0e[*\x03\x8b\xe8_\xa2\xa3\x17R\x96\xef\xeeu:a\x84\xa8\xcc\xbf1\xef\xc7"\xa9\x02%\x1f<M\xc2\tY\xb0\x0e\xfc5\x1e\x8d(\x1e%@\xfa\xa1\'i\x14\x9b\xe9\xc3\x88\xf7C\xb3\x81-&7\xb9\xdb~\xe0\xfe\\\x91!a\r[\x93\xe2\x18\xa8/\xf3A\xaf5\x89\xe4w0\tR\xf7\x10<+\x9bI\xd0y2\xa2x\x96\x00\x85\xf6C\x80\xb4\x7f\xc8~\xb8\xa2\xb7\x1c\xfe]\xcf9\xde\xbc<\x9c6%\x14:N\x97\x83\xd9\x1aWR\x9c\x04\x0e\x15>L\xe2\xd3w\xa5$xr\x96\xcaG\xacf\x9e\xfeVt\xb7\x1dy\xa4/\xf5\x94\x8c-\xfa7dJ\x19?j\xd8\xb2\xb7}S\xb0\xe9\xd8\x08\x85n\xc72u\x1dJ\x1e\xee\xec\x98x\x90\xca\x1cv\x87~\x9a\x85\xa5\x05\xcd3*\n5\xbf\xf2\xbf\xc5\'\xd8\x00\x93\x1b\xbe!;.\xfc\xe5\xc3\x8b\x17/^\xbc<^\x00\xfe\x03t\xd3\x12d\xcd*\xb7\xe1\x00\x00\x00\x00IEND\xaeB`\x82'
icon_id = idaapi.load_custom_icon(data=icon, format="png")

class RC4_Finder(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        print("[RC4] Search started")
        rc4run()
        print("[RC4] search done")
        pass

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

def rc4run():
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
                            i.y.y.numval() == 256) or (i.op is idaapi.cot_asg and
                                                       i.x.op is idaapi.cot_var and
                                                       i.y.op is idaapi.cot_cast and
                                                       i.y.x.op is idaapi.cot_add and
                                                       ("8" in str(i.y.type))))

    expr3 = lambda cf, i: (i.op is idaapi.cot_asgxor and
                           i.x.op is idaapi.cot_ptr and
                           i.x.x.op is idaapi.cot_cast and
                           i.x.x.x.op is idaapi.cot_add)

    expr = []
    expr.append(expr1)
    expr.append(expr2)
    expr.append(expr3)

    tmp = findrc4(expr)
    print(tmp)
    res = {1: [], 2: [], 3: []}
    match = [0, 0, 0]
    for i in tmp:
        # i:str
        index = str(i.keys()).split('[')[1][0]
        value = str(i.values())[14:-4]
        res[int(index)].append(value)

    if len(res[1]) != 0:
        for k in res[1]:
            pattern = k[k.find('['):k.find(']') + 1]
            cnt = 0
            for i in range(2, 4):
                for j in res[i]:
                    if pattern in j:
                        match[i - 1] = match[i - 1] + 1
        if (match[1] >= 2 and match[2] >= 1):
            print(f"RC4_function at addr:0x{pattern[1:-1]}")
    pass

def findrc4(expr):
    try:
        r = exec_findrc4(expr)
        print("RC4finder done! %d unique hits." % len(r))
        for e in r:
            print(e)

    except Exception as exc:
        print("some errors happened")
        return
    return r

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

def findexpr(cfunc, ctree, expr):
    """
    cfunc :     cfunc_t
    ctree:      citem_i
    expr:       lambda/function:f(cfunc_t,citem_t)
    return addr
    """
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
                        self.found.append({cnt: str(ParseResult(self.cfunc, i))})
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


class MyPlugin(ida_idaapi.plugin_t):
    wanted_name = "RC4_finder"
    wanted_hotkey = ""
    comment = "A plugin for find RC4 cryptor"
    help = ""
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        self.banner()
        if ida_hexrays.init_hexrays_plugin():

            idaapi.register_action(
                idaapi.action_desc_t(
                    "RC4:find", # The action name. This acts like an ID and must be unique
                    "RC4 finder",  # The action text.
                    RC4_Finder(),
                    "",
                    "",
                    icon_id
                )
            )

            if not idaapi.attach_action_to_menu("Search", "RC4:find", idaapi.SETMENU_APP):
                print("[RC4 Finder] Failed attaching to menu.")
        return idaapi.PLUGIN_KEEP

    def run(self):
        pass

    def term(self):
        pass

    def banner(self):
        print("---------------------------------------------------------------------------------------------")
        print("RC4 finder loaded.")
        print("Run via Search -> RC4 Finder")
        print("---------------------------------------------------------------------------------------------")
        # print("RC4finder start...")

def PLUGIN_ENTRY():
    return  MyPlugin()