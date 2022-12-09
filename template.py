# -*- coding:utf-8 -*-

# ======= import =======
import idc
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_hexrays
import ida_netnode
import ida_idp
import idaapi
import idautils
import ida_lines

from datetime import datetime


class Funname(idaapi.plugin_t):  # 继承 idaapi.plugin_t
    """
    插件类
    """
    flags = idaapi.PLUGIN_UNL # 还有各种参数。
    comment = "IDA Plugin comment"
    wanted_name = "listfunc"  # 插件的名称，在IDA界面导航栏中显示 Edit->Plugins->myplugin
    wanted_hotkey = "Alt-F6"  # 插件的快捷键
    help = "Coming soon..."

    def init(self):
        """
        初始化方法
        """
        idaapi.msg(">>> My plugin starts. {0}\n".format(datetime.now()))

        # # 导入python目录下的功能模块
        # idaapi.require("funcname")
        # idaapi.require("funcname.listFuncImpl")
        # 如果插件简单，可以直接在一个文件中运行



        return idaapi.PLUGIN_OK  # return PLUGIN_KEEP

    def run(self, arg):
        pass
#        funcname.listFuncImpl.main()  # 注意这里的调用方式是从python中模块的文件夹开始

    def term(self):
        idaapi.msg(">>> My plugin ends. {0}\n".format(datetime.now()))


def PLUGIN_ENTRY():
    """
    实例化插件对象
    """
    return Funname()

