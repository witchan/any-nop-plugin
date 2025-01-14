import ida_idaapi
import ida_kernwin
import idautils
import idc
import ida_bytes

NOP_INSTRUCTION = 0xD503201F

def get_instructions_ending_at(addr, count):
    instructions = []
    cur = addr
    for _ in range(count):
        if cur == idc.BADADDR:
            break
        mnem = idc.print_insn_mnem(cur)
        op1  = idc.print_operand(cur, 0)
        op2  = idc.print_operand(cur, 1)
        instructions.append((cur, mnem, op1, op2))
        cur = idc.prev_head(cur)
    instructions.reverse()
    return instructions

def match_instructions(instructions, expected):
    if len(instructions) != len(expected):
        return False

    for (ea, mnem, op1, op2), (exp_mnem, exp_op1, exp_op2) in zip(instructions, expected):
        if mnem != exp_mnem:
            return False
        if op1 != exp_op1:
            return False
        if op2 != exp_op2:
            return False
    return True

def parse_user_pattern(user_input):
    if not user_input:
        return []

    lines = user_input.splitlines()
    pattern = []

    for line in lines:
        line_no_comment = line.split(';', 1)[0].strip()
        if not line_no_comment:
            continue

        line_clean = line_no_comment.replace(',', '')

        tokens = line_clean.split()
        if not tokens:
            continue

        if len(tokens) == 1:
            mnem = tokens[0]
            op1  = ""
            op2  = ""
        elif len(tokens) == 2:
            mnem = tokens[0]
            op1  = tokens[1]
            op2  = ""
        else:
            mnem = tokens[0]
            op1  = tokens[1]
            op2  = tokens[2]

        pattern.append((mnem, op1, op2))

    return pattern

class AnyNopPlugmod(ida_idaapi.plugmod_t):
    def run(self, arg):
        print(">>> [Any Nop] run() is invoked.")

        default_text = (
            "MOV X0, #0x1A\n"
            "MOV X1, #0x1F\n"
            "MOV X2, #0\n"
            "MOV X3, #0\n"
            "MOV X16, #0\n"
            "SVC 0x80"
        )
        user_input = ida_kernwin.ask_text(
            0,
            default_text,
            "请输入要匹配并替换为 NOP 的指令序列："
        )

        if not user_input:
            print("[Any Nop] 用户未输入或取消，操作中止。")
            return

        # 2) 解析用户粘贴的文本 -> 构造期望的指令列表
        expected_pattern = parse_user_pattern(user_input)
        if not expected_pattern:
            print("[Any Nop] 未能解析出任何指令模式，操作中止。")
            return

        print(f"[Any Nop] 解析指令模式: {expected_pattern}")

        # 3) 遍历数据库所有指令，匹配并 patch
        start_addr = idc.get_inf_attr(idc.INF_MIN_EA)
        end_addr   = idc.get_inf_attr(idc.INF_MAX_EA)
        print(f"[Any Nop] Scanning from 0x{start_addr:X} to 0x{end_addr:X}...")

        instr_count = len(expected_pattern)
        matched_count = 0

        for addr in idautils.Heads(start_addr, end_addr):
            instructions = get_instructions_ending_at(addr, instr_count)
            # 与用户输入的指令模式比对
            if match_instructions(instructions, expected_pattern):
                matched_count += 1
                print(f"[*] Found match at 0x{addr:X}!")
                # 打印匹配到的指令
                for i, (ea, mnem, op1, op2) in enumerate(instructions, start=1):
                    print(f"  {i}. 0x{ea:X}: {idc.GetDisasm(ea)}")

                # 将这些指令全部 patch NOP
                for (ea, _, _, _) in instructions:
                    ida_bytes.patch_dword(ea, NOP_INSTRUCTION)

        print(f"[Any Nop] Done. Patched {matched_count} match.")


class AnyNopPlugin(ida_idaapi.plugin_t):
    """
    插件入口类
    """
    flags = ida_idaapi.PLUGIN_UNL | ida_idaapi.PLUGIN_MULTI
    comment = "Replace the input assembly instructions with nop."
    help = "User can paste lines with `; comments`, which will be stripped."
    wanted_name = "Any Nop - WitChan"
    wanted_hotkey = "Ctrl-Alt-N"

    def init(self):
        print(">>> [Any Nop] init() called.")
        return AnyNopPlugmod()

    def term(self):
        pass

    def run(self, arg):
        pass

def PLUGIN_ENTRY():
    return AnyNopPlugin()
