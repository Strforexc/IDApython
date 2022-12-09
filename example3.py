# invert if/else blocks
"""
 For example, a statement like

      if ( cond )
      {
        statements1;
      }
      else
      {
        statements2;
      }

  will be displayed as

      if ( !cond )
      {
        statements2;
      }
      else
      {
        statements1;
      }
"""
import ida_kernwin
import ida_hexrays
import ida_netnode
import ida_idaapi
import ida_idp

import traceback

NETNODE_NAME = '$ tzz-inverted-if'
inverter_actname = "vds3:invert"

class invert_action_hander_t(ida_kernwin.action_handler_t):
    def __init__(self, inverter):
        ida_kernwin.action_handler_t.__init__(self)
        inverter: hexrays_callback_info
        self.inverter = inverter

    def activate(self, ctx):
        vdui = ida_hexrays.get_widget_vdui(ctx.widget)
        self.inverter.invert_if_event(vdui)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if \
            ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else \
            ida_kernwin.AST_ENABLE_FOR_WIDGET

class hexrays_callback_info(object):

    def __init__(self):
        self.vu = None
        self.node = ida_netnode.netnode()
        if not self.node.create(NETNODE_NAME):
            self.load()
        else:
            self.stored = []

    def load(self):
        self.stored = []
        try:
            data = self.node.getblob(0,"I")
            if data:
                self.stored = eval(data.decode("UTF-8"))
                print('Invert-if Loaded %s' % (repr(self.stored), ))
        except:
            print("Failed to load invert-if loacations")
            traceback.print_exc()
            return

    def save(self):
        try:
            self.node.setblob(repr(self.stored).encode("UTF-8"),0,'I')
        except:
            print("Failed to save invert-if locations")
            traceback.print_exc()
            return
        return

    def invert_if(self,insn):
        # insn:ida_hexrays.cinsn_t(ida_hexrays.citem_t)

        if insn.opname != 'if':
            return False

        cif = insn.details
        #
        if not cif.ithen or not cif.ielse:
            return False
        ida_hexrays.qswap(cif.ithen, cif.ielse) # 这一步是将if 里的语句和else 里的语句进行了交换。
        # switch
        cond = ida_hexrays.cexpr_t(cif.expr) # 这是生成一个新的条件判断语句
        notcond = ida_hexrays.lnot(cond) # 对其进行取反
        cif.expr.swap(notcond) # 交换
        return True

    def add_location(self,ea):
        if ea in self.stored:
            self.stored.remove(ea)
        else:
            self.stored.append(ea)
        return

    def find_if_statement(self,vu):
# Check if the item under the cursor is 'if' or 'else' keyword
# If yes, return pointer to the corresponding ctree item
        vu:ida_hexrays.vdui_t
        vu.get_current_item(ida_hexrays.USE_KEYBOARD)
        item =vu.item
        item:ida_hexrays.ctree_item_t
        # 用户选光标指的是if item，就返回给他
        if item.is_citem() and item.it.op == ida_hexrays.cit_if and item.it.to_specific_type.cif.ielse is not None:
            return item.it.to_specific_type
        # 如果用户选择的是else item，这个时候 因为else在ctree 中没有对应的项，只能通过 vdui_t 中提供的信息来判断，判断代码如下
        # vu.tail它表示当前汇编代码的位置信息,vu.tail 包含两个成员变量：citype 和 loc，分别表示当前汇编代码的类型和位置
        if vu.tail.citype == ida_hexrays.VDI_TAIL and vu.tail.loc.itp == ida_hexrays.ITP_ELSE:

            class if_finder_t(ida_hexrays.ctree_visitor_t):
                def __init__(self,ea):
                    ## CV_FAST 表示快速遍历选项,它可以让 ctree_visitor_t 在遍历 ctree 时跳过一些节点，以提高遍历速度
                    ## CV_INSNS 表示遍历语句选项，它可以让 ctree_visitor_t 在遍历 ctree 时只访问 citem（汇编语句）
                    ##而跳过其他类型的节点。这个选项可以用来快速遍历汇编代码中的所有语句，但是不能访问汇编代码的其他部分
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST | ida_hexrays.CV_INSNS)
                    self.ea = ea
                    self.found = None
                    return
                def visit_insn(self, i):
                    if i.op == ida_hexrays.cit_if and i.ea == self.ea:
                        self.found = i
                        return 1
                    return  0

            iff = if_finder_t(vu.tail.loc.ea)
            if iff.apply_to(vu.cfunc.body,None):
                return iff.found
        return
    def invert_if_event(self,vu):
        i = self.find_if_statement(vu)
        if not i:
            return False
        if self.invert_if(i):
            self.add_location(i.ea)

        return True

    def restore(self,cfunc):

        class visitor(ida_hexrays.ctree_visitor_t):

            def __init__(self,inverter,cfunc):
                ida_hexrays.ctree_visitor_t.__init__(self,ida_hexrays.CV_FAST|ida_hexrays.CV_INSNS)
                self.inverter = inverter
                self.cfunc = cfunc
                return

            def visit_insn(self, i) -> "int":
                try:
                    if i.op == ida_hexrays.cit_if and i.ea  in self.inverter.stored:
                        self.inverter.invert_if(i)
                except:
                    traceback.print_exc()
                return  0

        visitor(self,cfunc).apply_to(cfunc.body,None)

        return

class vds3_hooks_t(ida_hexrays.Hexrays_Hooks):
    def __init__(self,i):
        ida_hexrays.Hexrays_Hooks.__init__(self)
        self.i = i

    def populating_popup(self, widget,phandle,vu):
        ida_kernwin.attach_action_to_popup(vu.ct,None,inverter_actname)
        return 0
    def maturity(self, cfunc,maturity):
        if maturity == ida_hexrays.CMAT_FINAL:
            self.i.restored(cfunc)
        return 0

class idp_hooks_t(ida_idp.IDP_Hooks):
    def __init__(self,i):
        ida_idp.IDP_Hooks.__init__(self)
        self.i = i

    def ev_privrange_changed(self, old_privrange, delta):
        self.node.create(NETNODE_NAME)


class my_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE
    wanted_name = "Hex-Rays Strforexc-if-inventer (IDAPython)"
    wanted_hotkey = ""
    comment = "Strforexc Sample plugin3 for Hex-Rays decompiler"
    help = ""
    def init(self):
        if ida_hexrays.init_hexrays_plugin():
            i = hexrays_callback_info()
            ida_kernwin.register_action(
                ida_kernwin.action_desc_t(
                    inverter_actname,
                    "Invert then/else",
                    invert_action_hander_t(i),
                    "I"
                )
            )
            self.vds3_hooks = vds3_hooks_t(i)
            self.vds3_hooks.hook()
            self.idp_hooks = idp_hooks_t(i)
            self.idp_hooks.hook()

            return  ida_idaapi.PLUGIN_KEEP
    def term(self):
        self.vds3_hooks.unhook()

    def run(self,arg):
        pass
def PUGIN_ENTRY():
    return my_plugin_t()



























