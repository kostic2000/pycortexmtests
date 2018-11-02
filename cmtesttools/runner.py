import struct
import unicorn as uc
import unicorn.arm_const as arm
import gdbbackend

SEMIHOSTING_EnterSVC = 0x17
SEMIHOSTING_ReportException = 0x18
SEMIHOSTING_SYS_CLOSE = 0x02
SEMIHOSTING_SYS_CLOCK = 0x10
SEMIHOSTING_SYS_ELAPSED = 0x30
SEMIHOSTING_SYS_ERRNO = 0x13
SEMIHOSTING_SYS_FLEN = 0x0C
SEMIHOSTING_SYS_GET_CMDLINE = 0x15
SEMIHOSTING_SYS_HEAPINFO = 0x16
SEMIHOSTING_SYS_ISERROR = 0x08
SEMIHOSTING_SYS_ISTTY = 0x09
SEMIHOSTING_SYS_OPEN = 0x01
SEMIHOSTING_SYS_READ = 0x06
SEMIHOSTING_SYS_READC = 0x07
SEMIHOSTING_SYS_REMOVE = 0x0E
SEMIHOSTING_SYS_RENAME = 0x0F
SEMIHOSTING_SYS_SEEK = 0x0A
SEMIHOSTING_SYS_SYSTEM = 0x12
SEMIHOSTING_SYS_TICKFREQ = 0x31
SEMIHOSTING_SYS_TIME = 0x11
SEMIHOSTING_SYS_TMPNAM = 0x0D
SEMIHOSTING_SYS_WRITE = 0x05
SEMIHOSTING_SYS_WRITEC = 0x03
SEMIHOSTING_SYS_WRITE0 = 0x04

class RunnerException(Exception): pass

class Runner(object):

    def __hook_code(self, _uc, address, size, user_data):
        self.pc = address    # workaround for unicorn bug
        if self.count is not None:
            self.count -= 1
            if self.count < 0:
                self.running = False
                _uc.emu_stop()
        
    def __hook_intr(self, _uc, intno, user_data):
        # check for a break point
        if intno == 7: # bkpt
            pc = _uc.reg_read(arm.UC_ARM_REG_PC)
            inst = _uc.mem_read(pc, 2)
            
            if inst[1] == 0xbe: # bkpt
                if inst[0] == 0xab: # semihosting
                    reason = _uc.reg_read(arm.UC_ARM_REG_R0)
                    arg = _uc.reg_read(arm.UC_ARM_REG_R1)
                    ret = self.handle_semihosting(reason, arg)
                    _uc.reg_write(arm.UC_ARM_REG_R0, ret)
                    _uc.reg_write(arm.UC_ARM_REG_PC, (self.pc + 2)| 1)
                elif inst[0] == 0x10: # terminate
                    self.running = False
                    self.exit_code = _uc.reg_read(arm.UC_ARM_REG_R0)
                    _uc.emu_stop()
                elif inst[0] == 0x11: # unhandled exception
                    self.err = RunnerException("Unhandled exception")
                    self.running = False;
                    _uc.emu_stop()
        else:
            self.err = RunnerException("Unknown interrupt %x" % intno)
            _uc.emu_stop()        
    
    def __init__(self, mem_map, firmware, semihosting_handler = None, gdb_server = None):
        self.firmware = firmware
        self.semihosting_handler = semihosting_handler
        self.gdb_backend = None
        self.running = False
        self.err = None
        self.exit_code = None
        self.mu = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_THUMB | uc.UC_MODE_MCLASS)

        for m in mem_map:
            self.mu.mem_map(m[0], m[1], m[2])

        for seg in firmware.get_segments():
            self.mu.mem_write(seg[0], seg[1])

        self.mu.hook_add(uc.UC_HOOK_CODE, self.__hook_code)
        self.mu.hook_add(uc.UC_HOOK_INTR, self.__hook_intr)

        if gdb_server is not None:
            self.gdb_backend = gdbbackend.GdbBackend(self.mu, gdb_server)

        sp = struct.unpack("<I", self.mu.mem_read(0, 4))[0]
        self.mu.reg_write(arm.UC_ARM_REG_SP, sp)
        pc = struct.unpack("<I", self.mu.mem_read(4, 4))[0]
        self.mu.reg_write(arm.UC_ARM_REG_PC, pc)

    def handle_semihosting(self, reason, arg):

        def read_word(addr):
            return struct.unpack("<I", self.mu.mem_read(addr, 4))[0];
        
        def read_str(addr, l):
            return self.mu.mem_read(addr, l).decode()
               
        def read_str0(addr):
            s = ""
            i = addr
            while True:
                c = chr(self.mu.mem_read(i, 1)[0])
                if c == chr(0):
                    break
                s += c
                i += 1
            return s
        
        def write_str0(addr, s):
            self.mu_mem_write(addr, bytearray(s))
            self.mu_mem_write(addr + len(s), b'\0')
       
        if self.semihosting_handler is not None:
            if reason == SEMIHOSTING_SYS_CLOSE:
                return self.semihosting_handler.close(read_word(arg))
            elif reason == SEMIHOSTING_SYS_CLOCK:
                return -1
            elif reason == SEMIHOSTING_SYS_ELAPSED:
                return -1
            elif reason == SEMIHOSTING_SYS_ERRNO:
                return self.semihosting_handler.get_errno()
            elif reason == SEMIHOSTING_SYS_FLEN:
                return self.semihosting_handler.flen(read_word(arg))
            elif reason == SEMIHOSTING_SYS_GET_CMDLINE:
                cmdline = self.semihosting_handler.get_cmdline()
                if cmdline is not None:
                    write_str0(read_word(arg), cmdline)
                    self.mu.mem_write(read_word(arg + 4), struct.pack("<I", len(cmdline)))
                    return 0
                else:
                    return -1
            elif reason == SEMIHOSTING_SYS_HEAPINFO:
                return -1
            elif reason == SEMIHOSTING_SYS_ISERROR:
                return self.semihosting_handler.iserror(read_word(arg));
            elif reason == SEMIHOSTING_SYS_ISTTY:
                return self.semihosting_handler.istty(read_word(arg));
            elif reason == SEMIHOSTING_SYS_OPEN:
                return self.semihosting_handler.open(read_str(read_word(arg), read_word(arg + 8)), read_word(arg + 4))
            elif reason == SEMIHOSTING_SYS_READ:
                num = read_word(arg + 8)
                buf = self.semihosting_handler.read(read_word(arg), num)
                if buf is not None:
                    self.mu.mem_write(read_word(arg + 4), buf)
                    return 0 if len(buf) == num else len(buf)
                else:
                    return -1
            elif reason == SEMIHOSTING_SYS_READC:
                return self.semihosting_handler.readc()
            elif reason == SEMIHOSTING_SYS_REMOVE:
                return self.semihosting_handler.remove(read_str(read_word(arg), read_word(arg + 4)))
            elif reason == SEMIHOSTING_SYS_RENAME:
                return self.semihosting_handler.rename(read_str(read_word(arg), read_word(arg + 4)),
                                                       read_str(read_word(arg + 8), read_word(arg + 12)))
            elif reason == SEMIHOSTING_SYS_SEEK:
                return self.semihosting_handler.seek(read_word(arg), read_word(arg + 4))
            elif reason == SEMIHOSTING_SYS_SYSTEM:
                return self.semihosting_handler.system(read_str(read_word(arg), read_word(arg + 4)))
            elif reason == SEMIHOSTING_SYS_TICKFREQ:
                return -1
            elif reason == SEMIHOSTING_SYS_TIME:
                return self.semihosting_handler.time()
            elif reason == SEMIHOSTING_SYS_TMPNAM:
                l = read_word(arg + 8)
                tmpname = self.semihosting_handler.tmpnam(read_word(arg + 4), l - 1)
                if tmpname is not None and l > len(tmpname):
                    write_str0(read_word(arg), tmpname)
                    return 0
                else:
                    return -1
            elif reason == SEMIHOSTING_SYS_WRITE:
                return self.semihosting_handler.write(read_word(arg), self.mu.mem_read(read_word(arg + 4), read_word(arg + 8)))
            elif reason == SEMIHOSTING_SYS_WRITEC:
                self.semihosting_handler.writec(self.mu.mem_read(arg, 1).decode())
                return 0
            elif reason == SEMIHOSTING_SYS_WRITE0:
                self.semihosting_handler.write(read_str0(arg))
                return 0
            else:   
                return -1
            
        else:
            return -1

    def run(self, count = None):

        self.count = count if count is not None and count != 0 else None
        self.err = None
        pc = self.mu.reg_read(arm.UC_ARM_REG_PC)
        self.running = True
       
        while self.running:
            if self.gdb_backend is not None:
                if not self.gdb_backend.handle_debugger(pc): break
                pc = self.mu.reg_read(arm.UC_ARM_REG_PC) # in case it's changed
            self.mu.emu_start(pc | 1, 0, 0, 0)
            pc = self.pc
            self.mu.reg_write(arm.UC_ARM_REG_PC, pc) # workaround for unicorn bug
            if self.err is not None:
                raise self.err
            
        return self.exit_code

