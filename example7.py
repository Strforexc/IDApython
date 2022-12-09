"""
summary: iterate a cblock_t object

description:
  Using a `ida_hexrays.ctree_visitor_t`, search for
  `ida_hexrays.cit_block` instances and dump them.

author: EiNSTeiN_ (einstein@g3nius.org)
"""

from __future__ import print_function
import ida_kernwin
import ida_hexrays
import ida_bytes
import ida_funcs
import ida_hexrays

class cblock_visitor_t(ida_hexrays.ctree_visitor_t):

    def __init__(self):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)

    def visit_insn(self, ins):
        if ins.op == ida_hexrays.cit_block:
            self.dump_block(ins.ea, ins.cblock)
        return 0

    def dump_block(self, ea, b):
        # iterate over all block instructions
        print("dumping block %x" % (ea, ))
        for ins in b:
            print("  %x: insn %s" % (ins.ea, ins.opname))

f = ida_funcs.get_func(ida_kernwin.get_screen_ea())
hf = ida_hexrays.hexrays_failure_t()
cfunc = ida_hexrays.decompile(f, hf, 0)
cbv = cblock_visitor_t()
cbv.apply_to(cfunc.body, None)





