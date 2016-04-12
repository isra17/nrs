from idaapi import *
import idaapi
import struct

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

    def get_frame_retsize(self):
        return 4

    def header(self):
        return

    def handle_operand(self, op, isRead):
        dref_flag = dr_R if isRead else dr_W

        if op.type == o_mem:
            ua_add_dref((op.n+1)*4, op.addr, dref_flag)

    def ana(self):
        """ Decode NSIS instruction. """
        opcode = ua_next_long()
        params = [ua_next_long() for _ in range(6)]

        if opcode < len(self.itable):
            ins = self.itable[opcode]
        else:
            ins = self.itable[0]

        self.cmd.itype = opcode
        return self.cmd.size if ins.d(params) else 0

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
        if op.type == o_imm:
            OutValue(op, OOFW_IMM)
        elif op.type == o_mem:
            r = out_name_expr(op, op.addr, BADADDR)
            if not r:
                out_tagon(COLOR_ERROR)
                OutLong(op.addr, 16)
                out_tagoff(COLOR_ERROR)
                QueueSet(Q_noName, self.cmd.ea)
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
            op.dtyp = dt_string
            op.addr = self.rebase_var_addr(x)

    def op_void(self, op):
        op.type = o_void

    def decode_VOID(self, params):
        """ Decode instruction without operands. """
        self.cmd.Op1.type = o_void
        return True

    def decode_SI(self, params):
        self.op_str(self.cmd.Op1, params[0])
        self.op_imm(self.cmd.Op2, params[1])
        self.op_void(self.cmd.Op3)
        return True

    def decode_ISIIII(self, params):
        self.op_imm(self.cmd.Op1, params[0])
        self.op_str(self.cmd.Op2, params[1])
        self.op_imm(self.cmd.Op3, params[2])
        self.op_imm(self.cmd.Op4, params[3])
        self.op_imm(self.cmd.Op5, params[4])
        self.op_imm(self.cmd.Op6, params[5])
        return True

    def decode_VSII(self, params):
        self.op_var(self.cmd.Op1, params[0])
        self.op_str(self.cmd.Op2, params[1])
        self.op_imm(self.cmd.Op3, params[2])
        self.op_imm(self.cmd.Op4, params[3])
        self.op_void(self.cmd.Op5)
        return True

    def init_instructions(self):
        class idef:
            def __init__(self, name, cf, d):
                self.name = name
                self.cf = cf
                self.d = d

        i_invalid = idef(name='INVALID', d=self.decode_VOID, cf = 0)
        def notimplemented(n):
            return idef(name='NotImplemented_' + str(n), d=self.decode_VOID, cf=0)

        self.itable = [
            i_invalid, # 0x00
            idef(name='RETURN', d=self.decode_VOID, cf=CF_STOP), # 0x01
            notimplemented(2),
            notimplemented(3),
            notimplemented(4),
            notimplemented(5),
            notimplemented(6),
            notimplemented(7),
            notimplemented(8),
            notimplemented(9),
            notimplemented(10),
            idef(name='CREATEDIR', d=self.decode_SI, cf=CF_USE1 | CF_USE2), # 0x0b
            notimplemented(12),
            notimplemented(13),
            notimplemented(14),
            notimplemented(15),
            notimplemented(16),
            notimplemented(17),
            notimplemented(18),
            notimplemented(19),
            idef(name='EXTRACTFILE', d=self.decode_ISIIII, \
                 cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4|CF_USE5|CF_USE6), # 0x14
            notimplemented(21),
            notimplemented(22),
            notimplemented(23),
            notimplemented(24),
            idef(name='ASSIGNVAR', d=self.decode_VSII, \
                 cf=CF_USE1|CF_USE2|CF_USE3|CF_USE4), # 0x19
            notimplemented(26),
        ]

        self.itable += [idef(name='Invalid'+str(i), d=self.decode_VOID,cf=0)
                            for i in range(len(self.itable),100)]

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

def PROCESSOR_ENTRY():
    return NsisProcessor()

