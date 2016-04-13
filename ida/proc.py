from idaapi import *
import idaapi
import struct
import nrs

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

    def rebase_string_addr(self, addr):
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
        maxlen = min(seg.endEA - addr, nrs.fileform.NSIS_MAX_STRLEN)
        data = GetManyBytes(addr, maxlen)
        symbols, _ = nrs.strings.symbolize(data, 0, self.nsis_version)
        return symbols

    def get_frame_retsize(self):
        return 4

    def header(self):
        return

    def handle_operand(self, op, isRead):
        dref_flag = dr_R if isRead else dr_W
        offb = (op.n+1)*4

        if op.type == o_mem:
            ua_add_dref(offb, op.addr, dref_flag)
        elif op.type == o_near:
            if self.cmd.itype == self.itype_CALL:
                fl = fl_CN
            else:
                fl = fl_JN
            ua_add_cref(offb, op.addr, fl)

    def ana(self):
        """ Decode NSIS instruction. """
        opcode = ua_next_long()
        params = [ua_next_long() for _ in range(6)]

        if opcode < len(self.itable):
            ins = self.itable[opcode]
        else:
            ins = self.itable[0]

        # Decode "virtual instruction" (eg. PUSHPOP -> PUSH/POP/EXCH)
        if ins.v:
            opcode = ins.v(opcode, params)
            ins = self.itable[opcode]

        self.cmd.itype = opcode
        return self.cmd.size if self.decode(ins.d, params) else 0

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
        if not (feature & CF_STOP):
            ua_add_cref(0, self.cmd.ea + self.cmd.size, fl_F)

        return 1

    def out(self):
        """ Output instruction in textform. """
        buf = idaapi.init_output_buffer(1024)
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

    def outop(self, op):
        """ Output instruction's operand in textform. """
        def out_name_addr(addr):
            r = out_name_expr(op, addr, addr)
            if not r:
                out_tagon(COLOR_ERROR)
                OutLong(addr, 16)
                out_tagoff(COLOR_ERROR)
                QueueSet(Q_noName, self.cmd.ea)

        if op.type == o_reg:
            out_register(self.regNames[op.reg])
        elif op.type == o_imm:
            OutValue(op, OOFW_IMM)
        elif op.type == o_near:
            out_name_addr(op.addr)
        elif op.type == o_mem:
            if op.dtyp == dt_string:
                symbols = self.get_string_symbols(op.addr)
                if not symbols:
                    out_line('""', COLOR_STRING)
                elif len(symbols) == 1:
                    symbol =  symbols[0]
                    if symbol.is_reg():
                        out_register(self.regNames[symbols[0].nvar])
                    elif symbol.is_var():
                        var_addr = self.rebase_var_addr(symbol.nvar)
                        out_name_addr(var_addr)
                    elif symbol.is_string() and \
                            all(c in string.digits for c in symbol):
                        OutLong(int(symbol), 10)
                    else:
                        out_name_addr(op.addr)
                else:
                    out_name_addr(op.addr)
            else:
                out_name_addr(op.addr)
        else:
            return False
        return True

    # Instruction decoding functions.
    def op_str(self, op, addr):
        op.type = o_mem
        op.dtyp = dt_string
        op.addr = self.rebase_string_addr(addr)

    def op_imm(self, op, imm):
        op.type = o_imm
        op.dtyp = dt_dword
        op.value = imm

    def op_var(self, op, x):
        if x < 20:
            op.type = o_reg
            op.reg = x
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
            else:
                return False
        return True

    def virt_pushpop(self, opcode, params):
        if params[1]:
            return self.itype_POP
        elif params[1]:
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

    def init_instructions(self):
        class idef:
            def __init__(self, name, cf=0, d='', v=None):
                self.name = name
                self.cf = cf
                self.d = d
                self.v = v

        i_invalid = idef(name='INVALID')
        def notimplemented(n):
            return idef(name='NotImplemented_' + hex(n))

        self.itable = [
            i_invalid, # 0x00
            idef(name='RETURN', d='', cf=CF_STOP), # 0x01
            notimplemented(2), # 0x02
            idef(name='ABORT', d='I', cf=CF_USE1|CF_STOP), # 0x03
            notimplemented(4), # 0x04
            idef(name='CALL', d='J', cf=CF_USE1|CF_CALL), # 0x05
            notimplemented(6), # 0x06
            notimplemented(7), # 0x07
            notimplemented(8), # 0x08
            notimplemented(9), # 0x09
            notimplemented(10), # 0x0a
            idef(name='CREATEDIR', d='SI', cf=CF_USE1|CF_USE2), # 0x0b
            notimplemented(12), # 0x0c
            idef(name='SETFLAG', d='II', v=self.virt_setflag,
                 cf=CF_USE1|CF_USE2), # 0x0d
            idef(name='IFFLAG', d='JJII',v=self.virt_ifflag,
                 cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4), # 0x0e
            notimplemented(15),
            notimplemented(16),
            notimplemented(17),
            notimplemented(18),
            notimplemented(19),
            idef(name='EXTRACTFILE', d='ISIIII',
                 cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4|CF_USE5|CF_USE6), # 0x14
            notimplemented(21),
            notimplemented(22),
            notimplemented(23),
            idef(name='STRLEN', d='VS', v=self.virt_setflag,
                 cf=CF_CHG1|CF_USE2), # 0x18
            idef(name='STRCPY', d='VSSS', v=self.virt_strcpy,
                 cf=CF_CHG1|CF_USE2|CF_USE3|CF_USE4), # 0x19
            idef(name='STRCMP', d='SSJJI',
                 cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4|CF_USE5), # 0x1a
            notimplemented(27),
            notimplemented(28),
            notimplemented(29),
            notimplemented(30),
            idef(name='PUSHPOP', v=self.virt_pushpop), # 0x1f
        ]

        self.itable += [idef(name='Invalid'+hex(i))
                            for i in range(len(self.itable),100)]

        self.itable += [
            idef(name='PUSH', d='S', cf=CF_USE1),
            idef(name='POP', d='V', cf=CF_CHG1),
            idef(name='EXCH', d='I', cf=CF_USE1|CF_CHG1),
            idef(name='CLEARERRORS'),
            idef(name='IFERRORS', d='J', cf=CF_USE1),
            idef(name='ASSIGNVAR', d='VS', cf=CF_CHG1|CF_USE2),
        ]

        # Now create an instruction table compatible with IDA processor module requirements
        instructions = []
        for i, x in enumerate(self.itable):
            d = dict(name=x.name, feature=x.cf)
            instructions.append(d)
            setattr(self, 'itype_' + x.name, i)

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

