import ida_hexrays
import ida_funcs
import ida_kernwin
import ida_lines


def myprint():
    if not ida_hexrays.init_hexrays_plugin():
        return False  # 判断插件初始化
    print(f"Hex-rays version {ida_hexrays.get_hexrays_version()} has been detected")

    f = ida_funcs.get_func(ida_kernwin.get_screen_ea())
    if f is None:
        print("Please make the cursor within a function")
        return True
    cfunc = ida_hexrays.decompile(f)
    cfunc.print_func()
    if cfunc is None:
        print("Fail to decompile")
        return True

    sv = cfunc.get_pseudocode()
    #一个伪代码对象

    for sline in sv:
        # print(ida_lines.tag_remove(sline.line))
        print(ida_lines.tag_remove(sline.linejk))


if __name__ == "__main__":
    myprint()
