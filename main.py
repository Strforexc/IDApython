# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

import ida_hexrays as hx
import ida_bytes
import idautils
import ida_kernwin
import ida_lines
import ida_funcs
import idc
from ida_idaapi import __EA64__, BADADDR

__author__ = "Dennis Elser @ https://github.com/patois"
SCRIPT_NAME = "hxtb"



class query_result_t():
    def __init__(self, cfunc=None, i=None):
        if isinstance(cfunc, hx.cfuncptr_t):
            self.entry = cfunc.entry_ea
        elif isinstance(cfunc, int):
            self.entry = cfunc
        else:
            self.entry = BADADDR
        if isinstance(i, (hx.cexpr_t, hx.cinsn_t)):
            self.ea = i.ea if not isinstance(cfunc, hx.cfuncptr_t) else self.find_closest_address(cfunc, i)
            self.v = ida_lines.tag_remove(i.print1(None))
        elif isinstance(i, tuple):
            self.ea, self.v = i
        else:
            self.ea = BADADDR
            self.v = "<undefined>"

    def find_closest_address(self, cfunc, i):
        parent = i
        while parent:
            if parent and parent.ea != BADADDR:
                return parent.ea
            parent = cfunc.body.find_parent_of(parent)
        return BADADDR

    def __str__(self):
        return "[%x] %x: \"%s\"" % (self.entry, self.ea, self.v)


# ----------------------------------------------------------------------------
def find_item(ea, q, parents=False, flags=0):
    """find item within AST of decompiled function
    arguments:
    ea:         address belonging to a function
    q:          lambda/function: f(cfunc_t, citem_t) returning a bool
    parents:    False -> discard cexpr_t parent nodes
                True  -> maintain citem_t parent nodes
    returns list of query_result_t objects
    """

    f = ida_funcs.get_func(ea)
    if f:
        cfunc = None
        hf = hx.hexrays_failure_t()
        try:
            cfunc = hx.decompile(f, hf, flags)
        except Exception as e:
            print("[%s] %x: unable to decompile: '%s'" % (SCRIPT_NAME, ea, hf))
            print("\t (%s)" % e)
            return list()

        if cfunc:
            return find_child_item(cfunc, cfunc.body, q, parents)
    return list()


def find_child_item(cfunc, i, q, parents=False):
    class citem_finder_t(hx.ctree_visitor_t):
        def __init__(self, cfunc, q, parents):
            hx.ctree_visitor_t.__init__(self,
                                        hx.CV_PARENTS if parents else hx.CV_FAST)

            self.cfunc = cfunc
            self.query = q
            self.found = list()
            return

        def process(self, i):
            """process cinsn_t and cexpr_t elements alike"""

            try:
                if self.query(self.cfunc, i):
                    self.found.append(query_result_t(self.cfunc, i))
            except:
                pass
            return 0

        def visit_insn(self, i):

            return self.process(i)

        def visit_expr(self, e):
            print(i)
            return self.process(e)

    if cfunc:
        itfinder = citem_finder_t(cfunc, q, parents)
        itfinder.apply_to(i, None)
        return itfinder.found
    return list()


def exec_query(q, ea_list, query_full, parents=False, flags=0):
    find_elem = find_item
    result = list()
    for ea in ea_list:
        result += find_elem(ea, q, parents=parents, flags=flags)
    return result


def query(q, ea_list=None, query_full=True, do_print=False):
    if not ea_list:
        ea_list = [ida_kernwin.get_screen_ea()]
    r = list()
    try:
        r = exec_query(q, ea_list, query_full)
        if do_print:
            print("<query> done! %d unique hits." % len(r))
            for e in r:
                print(e)
    except Exception as exc:
        print("<query> error:", exc)
    return r

func_list = [func for func in idautils.Functions()]
print(func_list)
expr = lambda cf, e: (e.op is idaapi.cit_if )
query(expr,func_list,do_print=False)








