# -*- coding:utf-8 -*-
import os

from matplotlib import pyplot as plt

import ida_ida
from idaapi import plugin_t
from idaapi import PLUGIN_PROC
from idaapi import PLUGIN_OK
import ida_nalt
import idaapi
import idautils
import idc
import time


# 获取SO文件名和路径
def getSoPathAndName():
    fullpath = ida_nalt.get_input_file_path()
    filepath, filename = os.path.split(fullpath)
    return filepath, filename


# 获取代码段的范围
def getSegAddr():
    textStart = []
    textEnd = []

    for seg in idautils.Segments():
        if (idc.get_segm_name(seg)).lower() == '.text' or (
                idc.get_segm_name(seg)).lower() == 'text':
            tempStart = idc.get_segm_start(seg)
            tempEnd = idc.get_segm_end(seg)

            textStart.append(tempStart)
            textEnd.append(tempEnd)

    return min(textStart), max(textEnd)


class traceNatives(plugin_t):
    flags = PLUGIN_PROC
    comment = "asm_ins_stat"
    help = ""
    wanted_name = "asm_ins_stat"
    wanted_hotkey = ""

    def init(self):
        print("asm_ins_stat(v0.1) plugin has been loaded.")
        return PLUGIN_OK

    def run(self, arg):
        so_path, so_name = getSoPathAndName()
        script_name = so_name.split(".")[0] + "_" + str(int(time.time())) + ".txt"
        save_path = os.path.join(so_path, script_name)
        print(f"正在导出...路径：{save_path}")
        F = open(save_path, "w+", encoding="utf-8")
        total_ins = {}
        for ea in range(ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea()):
            ins = idautils.DecodeInstruction(ea)
            if ins:
                canon_mnem = ins.get_canon_mnem()
                if canon_mnem:
                    if total_ins.get(canon_mnem):
                        total_ins[canon_mnem] = total_ins[canon_mnem] + 1
                    else:
                        total_ins[canon_mnem] = 1
        total_ins = sorted(total_ins.items(), key=lambda x: x[1], reverse=True)
        ins_num = 0
        ins_use_times=0
        for kv in total_ins:
            ins_use_times = kv[1] + ins_use_times
            ins_num=ins_num+1
            F.write("%-15s   ->   %-10d\n" % (kv[0], kv[1]))
            F.flush()
        F.write("\nTotal.\nNumber of instructions: %d\nInstruction use times：%d\n" % (ins_num,ins_use_times))
        F.flush()
        F.close()
        print(f"导出完成：{save_path}")
        draw_from_dict(total_ins[0:50])  # 不显示柱状图可以注释掉

    def term(self):
        pass


def draw_from_dict(data):
    x = []
    y = []
    for d in reversed(data):
        x.append(d[0])
        y.append(d[1])
    plt.barh(x[0:len(data)], y[0:len(data)])
    plt.show()
    manager = plt.get_current_fig_manager()
    # matplotlib3.3.4 work
    manager.window.showMaximized()


def PLUGIN_ENTRY():
    return traceNatives()
