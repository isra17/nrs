from idaapi import *
import ntpath
import idaapi
import struct
import string
import nrs.strings
import nrs.fileform
import nrs

allowed_name_char = string.ascii_letters + string.digits + '$'
def canonize_name(name):
    """ Limit names to a subset of ascii character. """
    return str(''.join([c if c in allowed_name_char else '_' for c in name]))

def str_to_number(sym):
    if not sym.is_string():
        return None

    try:
        if sym[:2] == '0x':
            return int(sym, 16)
        elif sym[0] == '0':
            return int(sym, 8)
        else:
            return int(sym)
    except:
        return None

STR_LANG_FLAG = 1 << 31
OP_SIZE = 4
INST_SIZE = 7 * OP_SIZE

class NsisProcessor(processor_t):
    """ NSIS Processor class used by IDA to disassemble and analyze NSIS code. """
    # IDP id (Chosen arbitrarily > 0x8000).
    id = 0x8513

    # Processor features.
    flag = PR_USE32 | PR_DEFSEG32 | PR_RNAMESOK | PRN_HEX | PR_NO_SEGMOVE

    # Bits in byte for code segments.
    cnbits = 8

    #  Bits in byte for non-code segments.
    dnbits = 8

    # Short processor names.
    psnames = ['nsis']

    # Long processor names.
    plnames = ['NSIS Script Byte code']

    # Size of a segment registrer in bytes.
    segreg_size = 0

    # Array or 'return' instruction opcodes.
    retcodes = [struct.pack('<I',1) + struct.pack('<I', 0) * 6]

    # First's instruction icode.
    instruc_start = 0

    # Size of long double.
    tbyte_size = 0

    # Assembler features.
    assembler = {
        # Assembler flags.
        'flag': ASB_BINF3 | ASH_HEXF3 | ASO_OCTF1,

        # User defined flags.
        'uflag': 0,

        # Assembler name.
        'name': 'NSIS Script Byte code assembler',

        # org directive.
        'origin': 'org',

        # end directive.
        'end': 'end',

        # Comment string.
        'cmnt': ';',

        # ASCII string delimiter.
        'ascsep': '"',

        # ASCII char constant delimiter.
        'accsep': "'",

        # ASCII special chars.
        'esccodes': '"\'',

        # Data representation.
        'a_ascii': 'db',
        'a_byte': 'db',
        'a_word': 'dw',
        'a_dword': 'dd',

        'a_dups': '#d dup(#v)',
        'a_bss': '%s dup ?',
        'a_seg': 'seg',
        'a_curip': '$',
        'a_public': 'public',
        'a_weak': 'weak',
        'a_extrn': 'extrn',
        'a_comdef': '',
        'a_align': 'align',
        'lbrace': '(',
        'rbrace': ')',
        'a_mod': '%',
        'a_band': '&',
        'a_bor': '|',
        'a_xor': '^',
        'a_bnot': '~',
        'a_shl': '<<',
        'a_shr': '>>',
        'a_sizeof_fmt': 'size %s',
    } # Assembler.

    INTOP_SYM = ['+','-','*','/','|','&','^','!','||','&&','%','<<','>>']

    # NSIS specific flags.
    FLo_IntOp =       0x01
    FLo_PluginCall =  0x02

    FLa_CheckNoFlow = 0x04
    FLa_NoFlow =      0x08
    FLa_StackArgs =   0x10

    def rebase_string_addr(self, addr):
        if addr & STR_LANG_FLAG:
            return addr
        seg = get_segm_by_name('STRINGS')
        return addr + seg.startEA

    def rebase_var_addr(self, addr):
        seg = get_segm_by_name('VARS')
        return addr + seg.startEA

    def rebase_code_entry(self, entry):
        seg = get_segm_by_name('ENTRIES')
        return nrs.entry_to_offset(entry) + seg.startEA

    def get_string_symbols(self, addr):
        seg = get_segm_by_name('STRINGS')
        if not seg.contains(addr):
            return None

        seg = get_segm_by_name('STRINGS')
        maxlen = min(seg.endEA - addr, nrs.fileform.NSIS_MAX_STRLEN)
        data = GetManyBytes(addr, maxlen)
        symbols, _ = nrs.strings.symbolize(data, 0, self.nsis_version)
        return symbols

    def get_string(self, addr):
        seg = get_segm_by_name('STRINGS')
        if not seg.contains(addr):
            return None, 0

        maxlen = min(seg.endEA - addr, nrs.fileform.NSIS_MAX_STRLEN)
        data = GetManyBytes(addr, maxlen)
        string, l = nrs.strings.decode(data, 0, self.nsis_version)
        return str(string), l

    def read_params(self):
        return [ua_next_long() for _ in range(6)]

    def decode_plugin_call(self, opcode, params):
        if opcode != self.itype_CALL: return
        if ua_next_long() != self.itype_EXTRACTFILE: return
        self.read_params()
        if ua_next_long() != self.itype_SETFLAG: return
        self.read_params()
        argn = 0
        while True:
            opcode = ua_next_long()
            if opcode == self.itype_PUSHPOP and \
                    self.read_params()[1:3] == [0,0]:
                argn += 1
            elif opcode == self.itype_REGISTERDLL:
                # Plugin call!
                params = self.read_params()
                self.cmd.itype = self.itype_PLUGINCALL
                self.op_str(self.cmd.Op1, params[0])
                self.op_str(self.cmd.Op2, params[1])
                self.op_imm(self.cmd.Op3, argn)
                self.cmd.Op3.specval |= self.FLa_StackArgs
                self.cmd.auxpref |= self.FLo_PluginCall
                return True
            else:
                return

    def get_plugin_call_args(self, cmd, op):
        first = cmd.ea + INST_SIZE * 3
        return [self.rebase_string_addr(Dword(first + OP_SIZE + i*INST_SIZE))
                    for i in range(op.value)]

    def get_frame_retsize(self):
        return 4

    def header(self):
        return 'NSIS Script V' + str(self.nsis_version)

    def ana(self):
        """ Decode NSIS instruction. """
        opcode = ua_next_long()
        params = self.read_params()

        if self.decode_plugin_call(opcode, params):
            return self.cmd.size
        self.cmd.size = INST_SIZE

        if opcode < len(self.itable):
            ins = self.itable[opcode]
        else:
            ins = self.itable[0]

        # Decode "virtual instruction" (eg. PUSHPOP -> PUSH/POP/EXCH)
        if ins.v:
            opcode = ins.v(opcode, params)
            ins = self.itable[opcode]

        self.cmd.itype = opcode
        self.cmd.auxpref |= ins.ap
        return self.cmd.size if self.decode(ins.d, params) else 0

    def handle_string(self, offb, op, addr):
        sym_addr = addr
        symbols = self.get_string_symbols(addr)
        if symbols:
            for i, symbol in enumerate(symbols):
                if symbol.is_var():
                    var_addr = self.rebase_var_addr(symbol.nvar)
                    ua_add_dref(offb, var_addr, dr_R)
                    sym_addr += 4
                elif symbol.is_string():
                    n = str_to_number(symbol)
                    if n is None:
                        ua_add_dref(offb, sym_addr, dr_R)
                        string_name = canonize_name(symbol)
                        idaapi.make_ascii_string(sym_addr, len(symbol), ASCSTR_C)
                        idaapi.do_name_anyway(sym_addr, string_name[:15])
                    sym_addr += len(symbol)
                else:
                    sym_addr += 4

    def handle_operand(self, op, isRead):
        dref_flag = dr_R if isRead else dr_W
        offb = (op.n+1)*OP_SIZE

        if op.type == o_mem:
            if op.dtyp == dt_string:
                self.handle_string(offb, op, op.addr)
            else:
                ua_add_dref(offb, op.addr, dref_flag)
        elif op.type == o_near:
            if self.cmd.itype == self.itype_CALL:
                fl = fl_CN
            else:
                fl = fl_JN
            ua_add_cref(offb, op.addr, fl)
        elif op.type == o_imm and op.specval & self.FLa_StackArgs:
            for arg in self.get_plugin_call_args(self.cmd, op):
                self.handle_string(0, op, arg)

    def emu(self):
        """ Emulate instruction behavior. """
        feature = self.cmd.get_canon_feature()

        if feature & CF_USE1:
            self.handle_operand(self.cmd.Op1, 1)
        if feature & CF_USE2:
            self.handle_operand(self.cmd.Op2, 1)
        if feature & CF_USE3:
            self.handle_operand(self.cmd.Op3, 1)
        if feature & CF_USE4:
            self.handle_operand(self.cmd.Op4, 1)
        if feature & CF_USE5:
            self.handle_operand(self.cmd.Op5, 1)
        if feature & CF_USE6:
            self.handle_operand(self.cmd.Op6, 1)

        if feature & CF_CHG1:
            self.handle_operand(self.cmd.Op1, 0)
        if feature & CF_CHG2:
            self.handle_operand(self.cmd.Op2, 0)
        if feature & CF_CHG3:
            self.handle_operand(self.cmd.Op3, 0)
        if feature & CF_CHG4:
            self.handle_operand(self.cmd.Op4, 0)
        if feature & CF_CHG5:
            self.handle_operand(self.cmd.Op5, 0)
        if feature & CF_CHG6:
            self.handle_operand(self.cmd.Op6, 0)

        if feature & CF_JUMP:
            QueueSet(Q_jumps, self.cmd.ea)

        # Add flow cref.
        noFlow = self.get_auxpref() & self.FLa_NoFlow
        if not (feature & CF_STOP or noFlow):
            ua_add_cref(0, self.cmd.ea + self.cmd.size, fl_F)

        return 1

    def out(self):
        """ Output instruction in textform. """
        buf = idaapi.init_output_buffer(1024)

        if self.cmd.auxpref & self.FLo_PluginCall:
            lib,_ = self.get_string(self.cmd[0].addr)
            fn,_ = self.get_string(self.cmd[1].addr)
            lib = ntpath.splitext(ntpath.basename(lib))[0]
            out_line('{}::{}'.format(lib, fn), COLOR_INSN)
            OutChar(' ')
            out_one_operand(2)
        else:
            OutMnem(12)
            for i, op in ((i, self.cmd[i]) for i in range(6)):
                if op.type == o_void:
                    break
                if i > 0:
                    out_symbol(',')
                    OutChar(' ')
                out_one_operand(i)

        term_output_buffer()
        cvar.gl_comm = 1
        MakeLine(buf)

    def out_str(self, op, addr):
        symbols = self.get_string_symbols(addr)
        # Translated string.
        if symbols is None:
            self.out_name_addr(op, addr)
        elif not symbols:
            out_line('""', COLOR_STRING)
        else:
            for i, symbol in enumerate(symbols):
                if symbol.is_reg():
                    out_register(self.regNames[symbol.nvar])
                elif symbol.is_var():
                    var_addr = self.rebase_var_addr(symbol.nvar)
                    out_name_expr(op, var_addr, var_addr)
                else:
                    n = str_to_number(symbol)
                    if n is None:
                        out_line('"' + str(symbol) + '"', COLOR_STRING)
                    else:
                        out_long(n, 16)

    def out_name_addr(self, op, addr):
        r = out_name_expr(op, addr, BADADDR)
        if not r:
            out_tagon(COLOR_ERROR)
            OutLong(op.addr, 16)
            out_tagoff(COLOR_ERROR)
            QueueSet(Q_noName, self.cmd.ea)

    def outop(self, op):
        """ Output instruction's operand in textform. """

        if op.type == o_reg:
            out_register(self.regNames[op.reg])
        elif op.type == o_imm:
            if op.specval & self.FLo_IntOp:
                out_line(self.INTOP_SYM[op.value], COLOR_SYMBOL)
            elif op.specval & self.FLa_StackArgs:
                args = self.get_plugin_call_args(self.cmd, op)
                for i, arg in enumerate(args):
                    if i > 0:
                        out_symbol(',')
                        OutChar(' ')
                    self.out_str(op, arg)
            else:
                OutValue(op, OOFW_IMM | OOF_SIGNED)
        elif op.type == o_near:
            self.out_name_addr(op, op.addr)
        elif op.type == o_mem:
            if op.dtyp == dt_string:
                self.out_str(op, op.addr)
            else:
                self.out_name_addr(op, op.addr)
        else:
            return False
        return True

    # Instruction decoding functions.
    def op_str(self, op, addr):
        # Some string are used as numbers, register or nvar.
        addr = self.rebase_string_addr(addr)
        symbols = self.get_string_symbols(addr)
        if symbols and len(symbols) == 1:
            symbol = symbols[0]
            if symbol.is_nvar():
                return self.op_var(op, symbol.nvar)
            if symbol.is_string():
                n = str_to_number(symbol)
                if n is not None:
                    return self.op_imm(op, n)

        op.type = o_mem
        op.dtyp = dt_string
        op.addr = addr


    def op_imm(self, op, imm):
        op.type = o_imm
        op.dtyp = dt_dword
        op.value = imm

    def op_var(self, op, x):
        if x < 20:
            op.type = o_reg
            op.reg = x
        elif x == 0xffffffff:
            op.type = o_imm
            op.dtyp = dt_dword
            op.value = -1
        else:
            op.type = o_mem
            op.dtyp = dt_byte
            op.addr = self.rebase_var_addr(x)

    def op_jmp(self, op, addr):
        op.type = o_near
        op.addr = self.rebase_code_entry(addr-1)

    def op_void(self, op):
        op.type = o_void

    def decode(self, fmt, params):
        if fmt == '':
            self.op_void(self.cmd.Op1)
            return True

        noFlow = False
        # Most instruction with jumps can lead to no flow reference if no
        # jumps address are set to 0.
        if 'J' in fmt and self.cmd.auxpref & self.FLa_CheckNoFlow:
            noFlow = True

        for i, (c,p) in enumerate(zip(fmt, params)):
            op = self.cmd[i]
            if c == 'I':
                self.op_imm(op, p)
            elif c == 'S':
                self.op_str(op, p)
            elif c == 'V':
                self.op_var(op, p)
            elif c == 'J':
                if p > 0:
                    self.op_jmp(op, p)
                else:
                    self.op_imm(op, p)
                    noFlow = False
            elif c == 'O': # Math operand.
                self.op_imm(op, p)
                op.specval |= self.FLo_IntOp
            elif c == '2': # SendMessage bitshift one of its operant.
                self.op_imm(op, p >> 2)
            else:
                raise Exception('Unknown format flag: ' + c)

        if noFlow:
            self.cmd.auxpref |= self.FLa_NoFlow
        return True

    def virt_pushpop(self, opcode, params):
        if params[1]:
            return self.itype_POP
        elif params[2]:
            return self.itype_EXCH
        else:
            return self.itype_PUSH

    def virt_setflag(self, opcode, params):
        if params[0] == 2 and params[1] == 0xac:
            return self.itype_CLEARERRORS
        return opcode

    def virt_ifflag(self, opcode, params):
        if params[1] == 0 and params[2] == 2 and params[3] == 0:
            return self.itype_IFERRORS
        return opcode

    def virt_strcpy(self, opcode, params):
        if params[2] == 0 and params[3] == 0:
            return self.itype_ASSIGNVAR
        return opcode

    def virt_showwindow(self, opcode, params):
        if params[2]:
            return self.itype_HIDEWINDOW
        elif params[3]:
            return self.itype_ENABLEWINDOW
        return opcode

    def virt_delreg(self, opcode, params):
        if params[4]:
            return self.itype_DELETEREGKEY
        return self.itype_DELETEREGVALUE

    def virt_regenum(self, opcode, params):
        if params[4]:
            return self.itype_REGENUMKEY
        return self.itype_REGENUMVALUE

    def virt_fwrite(self, opcode, params):
        if params[2]:
            return self.itype_FILEWRITEBYTE
        return self.itype_FILEWRITE

    def virt_fread(self, opcode, params):
        if params[3]:
            return self.itype_FILEREADBYTE
        return self.itype_FILEREAD

    def virt_log(self, opcode, params):
        if params[0]:
            return self.itype_LOGSET
        return self.itype_LOGTEXT

    def init_instructions(self):
        class idef:
            def __init__(self, name, cf=0, d='', v=None, ap=0):
                self.name = name
                self.cf = cf
                self.d = d
                self.v = v
                self.ap = ap

        i_invalid = idef(name='INVALID')
        def notimplemented(n):
            return idef(name='NotImplemented_' + hex(n))

        self.itable = [
            i_invalid, # 0x00
            idef(name='Return', d='', cf=CF_STOP), # 0x01
            idef(name='Jmp', d='J', cf=CF_USE1, ap=self.FLa_CheckNoFlow), # 0x02
            idef(name='Abort', d='I', cf=CF_USE1|CF_STOP), # 0x03
            idef(name='Quit', cf=CF_STOP), #0x04
            idef(name='Call', d='J', cf=CF_USE1|CF_CALL), # 0x05
            idef(name='UpdateText', d='S', cf=CF_USE1), # 0x06
            idef(name='Sleep', d='I', cf=CF_USE1), # 0x07
            idef(name='BringToFront'), # 0x08
            idef(name='ChDetailsView', d='SS', cf=CF_USE1|CF_USE2), # 0x09
            idef(name='SetFileAttributes', d='SI', cf=CF_USE1|CF_USE2), # 0x0a
            idef(name='CreateDir', d='SI', cf=CF_USE1|CF_USE2), # 0x0b
            idef(name='IfFileExists', d='SJJ', cf=CF_USE1|CF_USE2|CF_USE3, ap=self.FLa_CheckNoFlow), # 0x0c
            idef(name='SetFlag', d='IS', v=self.virt_setflag, cf=CF_USE1|CF_USE2), # 0x0d
            idef(name='IfFlag', d='JJII',v=self.virt_ifflag, cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4, ap=self.FLa_CheckNoFlow), # 0x0e
            idef(name='GetFlag', d='VI', cf=CF_CHG1|CF_USE2), # 0x0f
            idef(name='Rename', d='SSIS', cf=CF_CHG1|CF_USE2|CF_USE3|CF_USE4), # 0x10
            idef(name='GetFullPathName', d='SVI', cf=CF_USE1|CF_CHG2|CF_USE3), # 0x11
            idef(name='SearchPath', d='VS', cf=CF_CHG1|CF_USE2), # 0x12
            idef(name='GetTempFilename', d='VS', cf=CF_CHG1|CF_USE2), # 0x13
            idef(name='ExtractFile', d='ISIIII', cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4|CF_USE5|CF_USE6), # 0x14
            idef(name='DeleteFile', d='SI', cf=CF_USE1|CF_USE2), # 0x15
            idef(name='MessageBox', d='ISIJIJ', cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4|CF_USE5), # 0x16
            idef(name='RmDir', d='SI', cf=CF_USE1|CF_USE2), # 0x17
            idef(name='StrLe', d='VS', v=self.virt_setflag, cf=CF_CHG1|CF_USE2), # 0x18
            idef(name='StrCpy', d='VSSS', v=self.virt_strcpy, cf=CF_CHG1|CF_USE2|CF_USE3|CF_USE4), # 0x19
            idef(name='StrCmp', d='SSJJI', cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4|CF_USE5, ap=self.FLa_CheckNoFlow), # 0x1a
            idef(name='ReadEnv', d='VSI', cf=CF_CHG1|CF_USE2|CF_USE3), # 0x1b
            idef(name='IntCmp', d='SSJJJI', cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4|CF_USE5|CF_USE6, ap=self.FLa_CheckNoFlow), # 0x1c
            idef(name='IntOp', d='VSSO', cf=CF_CHG1|CF_USE2|CF_USE3|CF_USE4), # 0x1d
            idef(name='IntFmt', d='VSS', cf=CF_CHG1|CF_USE2|CF_USE3), # 0x1d
            idef(name='PushPop', v=self.virt_pushpop), # 0x1f
            idef(name='FindWindow', d='VSSSS', cf=CF_CHG1|CF_USE2|CF_USE3|CF_USE4|CF_USE5), # 0x20
            idef(name='SendMessage', d='VSSSS2', cf=CF_CHG1|CF_USE2|CF_USE3|CF_USE4|CF_USE5|CF_USE6), # 0x21
            idef(name='IsWindow', d='SJJ', cf=CF_USE1|CF_USE2|CF_USE3, ap=self.FLa_CheckNoFlow), # 0x22
            idef(name='GetDlgItem', d='VSS', cf=CF_CHG1|CF_USE2|CF_USE3), # 0x23
            idef(name='SetCtlColors', d='SI', cf=CF_USE1|CF_USE2), # 0x24
            idef(name='SetBrandingImage', d='SII', cf=CF_USE1|CF_USE2), # 0x25
            idef(name='CreateFont', d='VSSSI', cf=CF_CHG1|CF_USE2|CF_USE3|CF_USE4|CF_USE5), # 0x26
            idef(name='ShowWindow', d='SS', v=self.virt_showwindow, cf=CF_USE1|CF_USE2), # 0x27
            idef(name='ShellExec', d='SSSS', cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4), # 0x28
            idef(name='Execute', d='SII', cf=CF_USE1|CF_USE2|CF_USE3), # 0x29
            idef(name='GetFileTime', d='VVS', cf=CF_CHG1|CF_CHG2|CF_USE3), # 0x2a
            idef(name='GetDLLVersion', d='VVS', cf=CF_CHG1|CF_CHG2|CF_USE3), # 0x2b
            idef(name='RegisterDLL', d='SSSI', cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4), # 0x2c
            idef(name='CreateShortcut', d='SSSSS', cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4|CF_USE5), # 0x2d
            idef(name='CopyFiles', d='SSS', cf=CF_USE1|CF_USE2|CF_USE3), # 0x2e
            idef(name='Reboot'), # 0x2f
            idef(name='WriteIni', d='SSSS', cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4), # 0x30
            idef(name='ReadIni', d='VSSS', cf=CF_CHG1|CF_USE2|CF_USE3|CF_USE4), # 0x31
            idef(name='DeleteRegKey', d='ISSS', v=self.virt_delreg, cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4), # 0x32
            idef(name='WriteRegValue', d='ISSII', cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4|CF_USE5), # 0x33
            idef(name='ReadRegValue', d='VISSI', cf=CF_CHG1|CF_USE2|CF_USE3|CF_USE4|CF_USE5), # 0x34
            idef(name='RegEnumKey', d='VISS', v=self.virt_regenum, cf=CF_CHG1|CF_USE2|CF_USE3|CF_USE4), # 0x35
            idef(name='FileClose', d='V', cf=CF_USE1), # 0x36
            idef(name='FileOpen', d='VIIS', cf=CF_CHG1|CF_USE2|CF_USE3|CF_USE4), # 0x37
            idef(name='FileWrite', d='VS', v=self.virt_fwrite, cf=CF_USE1|CF_USE2), # 0x38
            idef(name='FileRead', d='VVS', v=self.virt_fread, cf=CF_USE1|CF_CHG2|CF_USE3), # 0x39
            idef(name='FileSeek', d='VVSI', cf=CF_USE1|CF_CHG2|CF_USE3|CF_USE4), # 0x3a
            idef(name='FindClose', d='V', cf=CF_USE1), # 0x3b
            idef(name='FindNext', d='VV', cf=CF_CHG1|CF_USE2), # 0x3c
            idef(name='FindFirst', d='VVS', cf=CF_CHG1|CF_CHG2|CF_USE3), # 0x3d
            idef(name='WriteUninstaller', d='SIIS', cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4), # 0x3e
            idef(name='LogText', d='S', v=self.virt_log, cf=CF_USE1), # 0x3f
            idef(name='SectionSet', d='SII', cf=CF_USE1|CF_USE2|CF_USE3), # 0x40
            idef(name='InstTypeSet', d='SIII', cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4), # 0x41
            idef(name='GetLabelAddr'), # 0x42
            idef(name='GetFunctionAddr'), # 0x43
            idef(name='LockWindow', d='I', cf=CF_USE1), # 0x44
        ]

        self.itable += [
            idef(name='Push', d='S', cf=CF_USE1),
            idef(name='Pop', d='V', cf=CF_CHG1),
            idef(name='Exch', d='I', cf=CF_USE1|CF_CHG1),
            idef(name='ClearErrors'),
            idef(name='IfErrors', d='J', cf=CF_USE1),
            idef(name='AssignVar', d='VS', cf=CF_CHG1|CF_USE2),
            idef(name='EnableWindow', d='SS', cf=CF_USE1|CF_USE2),
            idef(name='HideWindow', d='SS', cf=CF_USE1|CF_USE2),
            idef(name='DeleteRegValue', d='ISSS', cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4),
            idef(name='RegEnumValue', d='VISS', cf=CF_CHG1|CF_USE2|CF_USE3|CF_USE4),
            idef(name='FileWriteByte', d='VS', cf=CF_USE1|CF_USE2),
            idef(name='FileReadByte', d='VV', cf=CF_USE1|CF_CHG2),
            idef(name='LogSet', d='I', cf=CF_USE1),
            idef(name='PluginCall', cf=CF_USE1|CF_USE2|CF_USE3),
        ]

        # Now create an instruction table compatible with IDA processor module requirements
        instructions = []
        for i, x in enumerate(self.itable):
            d = dict(name=x.name, feature=x.cf)
            instructions.append(d)
            setattr(self, 'itype_' + x.name.upper(), i)

        # icode of the last instruction + 1
        self.instruc_end = len(instructions) + 1

        # Array of instructions
        self.instruc = instructions

        # Icode of return instruction. It is ok to give any of possible return
        # instructions
        self.icode_return = self.itype_RETURN

    def init_registers(self):
        """
        This function parses the register table and creates corresponding
        ireg_XXX constants
        """
        self.regNames = sorted([x for n in range(10) for x in ('$'+str(n), '$R'+str(n))])
        self.regNames += ['CS','DS'] # Fake segment registers.

        # Create the ireg_XXXX constants
        for i, name in enumerate(self.regNames):
            setattr(self, 'ireg_' + name, i)

        # Segment register information (use virtual CS and DS registers if your
        # processor doesn't have segment registers):
        self.regFirstSreg = self.ireg_CS
        self.regLastSreg  = self.ireg_DS

        # number of CS register
        self.regCodeSreg = self.ireg_CS

        # number of DS register
        self.regDataSreg = self.ireg_DS

    def __init__(self):
        idaapi.processor_t.__init__(self)
        self.PTRSZ = 4
        self.init_instructions()
        self.init_registers()
        self.nsis_netnode = netnode('$ NSIS')
        self.nsis_version = self.nsis_netnode.hashstr('VERSION_MAJOR')

def PROCESSOR_ENTRY():
    return NsisProcessor()

