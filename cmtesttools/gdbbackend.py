import logging
import struct
import binascii
import unicorn as uc
import unicorn.arm_const as arm

STATE_QUIT = 0
STATE_STOPPED = 1
STATE_STEP = 2
STATE_RUN = 3

_WATCH_PNT_WRITE = 2
_WATCH_PNT_READ = 3
_WATCH_PNT_ACCESS = 4

logger = logging.getLogger(__name__)

class GdbBackend(object):
   
    _gen_regs = [
                arm.UC_ARM_REG_R0, arm.UC_ARM_REG_R1, arm.UC_ARM_REG_R2, arm.UC_ARM_REG_R3, arm.UC_ARM_REG_R4, arm.UC_ARM_REG_R5,
                arm.UC_ARM_REG_R6, arm.UC_ARM_REG_R7, arm.UC_ARM_REG_R8, arm.UC_ARM_REG_R9, arm.UC_ARM_REG_R10, arm.UC_ARM_REG_R11,
                arm.UC_ARM_REG_R12, arm.UC_ARM_REG_SP, arm.UC_ARM_REG_LR, arm.UC_ARM_REG_PC, # 15 main one
                None, None, None, None, None, None, None, None, None,   # pad to 25
                arm.UC_ARM_REG_CPSR
                ]
    
    _gen_regs_dense = [r for r in _gen_regs if r is not None]

    _imp_regs_i = [ _gen_regs.index(arm.UC_ARM_REG_SP), _gen_regs.index(arm.UC_ARM_REG_PC), _gen_regs.index(arm.UC_ARM_REG_CPSR) ]

    _brk_points = dict()
    _watch_points = dict()
    _watch_point_ranges = []

    def __hook_code(self, _uc, address, size, user_data):
        if self._state == STATE_STEP:
            self._step_count += 1
            if self._step_count > 1:
                # step has been done
                self._state = STATE_STOPPED
                self._gdb_server.send_reply(self._quick_status())

        elif self._state == STATE_RUN:
            if self._gdb_server.should_break():
                self._state = STATE_STOPPED
                self._gdb_server.send_reply(self._quick_status(0))
            elif address in self._brk_points:
                self._state = STATE_STOPPED;
                self._gdb_server.send_reply(self._quick_status(5, "hwbreak"))
                
        if self._state == STATE_STOPPED:
            self._uc.emu_stop()
        
        
    def __hook_intr(self, _uc, intno, user_data):
        # check for a break point
        if intno == 7: # bkpt
            pc = _uc.reg_read(arm.UC_ARM_REG_PC)
            logger.debug("Breakpoint exception triggered @%08x", pc)
            inst = _uc.mem_read(pc, 2)

            if inst[1] == 0xbe: # bkpt indeed
                # check for semihosting
                if inst[0] != 0xab and self._state == STATE_RUN:
                    self._state = STATE_STOPPED
                    self._gdb_server.send_reply(self._quick_status(5, "swbreak"))

                _uc.reg_write(arm.UC_ARM_REG_PC, (pc + 2) | 1)    # thumb mode

    def __init__(self, _uc, gdb_server):
        self._uc = _uc
        self._gdb_server = gdb_server
        self._state = STATE_STOPPED
        self._step_count = 0
        self._uc.hook_add(uc.UC_HOOK_CODE, self.__hook_code)
        self._uc.hook_add(uc.UC_HOOK_INTR, self.__hook_intr)          

    def _quick_status(self, signal = 5, reason = ""):
        s = f"T{signal:02x}"
        if len(reason) != 0:
            s += reason + ";"
        for ri in self._imp_regs_i:
            s += "%02x:%s;" % (ri, binascii.hexlify(struct.pack("<I", self._uc.reg_read(self._gen_regs[ri]))).decode())
        return s

    def _handle_qmark(self, subcmd):
        self._gdb_server.send_reply(self._quick_status())

    def _handle_c(self, subcmd):
        logger.debug("Received 'continue' command @%s", subcmd if len(subcmd) != 0 else "current")
        if len(subcmd) != 0:
            addr = int(subcmd, 16)
            self._uc.write_reg(arm.UC_ARM_REG_PC, addr)
        self._state = STATE_RUN
    
    def _handle_G(self, subcmd):
        vals = binascii.unhexlify(subcmd.encode())
        if len(vals) >= len(self._gen_regs_dense) * 4:
            for i in range(len(self._gen_regs_dense)):
                val = struct.unpack_from("<I", vals, i * 4)[0]
                self._uc.reg_write(self._gen_regs_dense[i], val)
            self._gdb_server.send_reply("OK")
        else:
            self._gdb_server.send_reply("E01")
        
        
    def _handle_g(self, subcmd):
        if len(subcmd) == 0:
            pb = b""
            for r in self._gen_regs_dense:
                pb += binascii.hexlify(struct.pack("<I", self._uc.reg_read(r)))
            self._gdb_server.send_reply(pb.decode())
        else:
            self._gdb_server.send_reply("")

    def _handle_k(self, subcmd):
        self.__state = STATE_QUIT

    def _handle_M(self, subcmd):
        addr, size_data = subcmd.split(",")
        size, data = size_data.split(":")
        addr = int(addr, 16)
        size = int(size, 16)
        logger.debug("Received a 'write memory' command (@%#.8x : %d bytes -> %s)", addr, size, data)
        blob = binascii.unhexlify(data.encode())
        try:
            self._uc.mem_write(addr, blob)
            self._gdb_server.send_reply("OK");
        except uc.UcError as e:
            logger.debug("%s", e)
            self._gdb_server.send_reply("E01");

    def _handle_m(self, subcmd):
        addr, size = subcmd.split(",")
        addr = int(addr, 16)
        size = int(size, 16)
        logger.debug("Received a 'read memory' command (@%#.8x : %d bytes)", addr, size)
        try:
            blob = self._uc.mem_read(addr, size)
            self._gdb_server.send_reply(binascii.hexlify(blob).decode())
        except uc.UcError as e:
            logger.debug("%s", e)
            self._gdb_server.send_reply("E01");
            
    def _handle_p(self, subcmd):
        logger.debug("Received 'register read' for %s", subcmd)
        regi = int(subcmd, 16)
        if regi < len(self._gen_regs and self._gen_regs[regi] is not None):
            self._gdb_server.send_reply(binascii.hexlify(struct.pack("<I", self._uc.reg_read(self._gen_regs[regi]))).decode())
        else:
            self._gdb_server.send_reply("E01")
            
    def _handle_P(self, subcmd):
        logger.debug("Received 'register write' for %s", subcmd)
        (regi, val) = subcmd.split("=")
        regi = int(regi, 16)
        val = struct.unpack("<I", binascii.unhexlify(val))[0]
        if regi < len(self._gen_regs) and self._gen_regs[regi] is not None:
            self._uc.reg_write(self._gen_regs[regi], val)
            self._gdb_server.send_reply("OK")
        else:
            self._gdb_server.send_reply("E01")            

    def _handle_q(self, subcmd):
        if subcmd.startswith("Supported"):
            logger.debug("Received qSupported command");
            self._gdb_server.send_reply("hwbreak+;swbreak+;qXfer:memory-map:read+")
        elif subcmd.startswith("Attached"):
            logger.debug("Received qAttached command")
            self._gdb_server.send_reply("1")
        elif subcmd.startswith("Xfer:memory-map:read"):
            logger.debug("Received memory-map read command")
            s = "l<memory-map>"
            for r in self._uc.mem_regions():
                s += "<memory type='ram' start='%#x' length='%d'/>" % (r[0], r[1] - r[0] + 1)
            s += "</memory-map>"
            self._gdb_server.send_reply(s)
        else:
            logger.debug("The subcommand %r is not implemented in q", subcmd)
            self._gdb_server.send_reply("")
           
    def _handle_s(self, subcmd):
        logger.debug("Received a 'single step' command @%s", subcmd if len(subcmd) != 0 else "current")
        if len(subcmd) != 0:
            addr = int(subcmd, 16)
            self._uc.write_reg(arm.UC_ARM_REG_PC, addr)
        self._state = STATE_STEP
        self._step_count = 0
    
    def _handle_v(self, subcmd):
        if subcmd == "CtrlC":
            logger.debug("Received 'vCtrlC'");
            if self._state == STATE_RUN:
                self._state = STATE_STOPPED;
                self._gdb_server.send_reply("OK")
            else:
                self._gdb_server.send_reply("E01")
        else:
            logger.debug("The subcommand %r is not implemented in v", subcmd)
            self._gdb_server.send_reply("")
            
    def _handle_Z(self, subcmd):
        (bk_type, addr, length) = subcmd.split(",")
        addr = int(addr, 16)
        length = int(length, 16)
        logger.debug("Recevied 'set breakpoint' @ %04x", addr)
        if bk_type == "0" or bk_type == "1":    # software or hardware
            self._brk_points[addr] = (length)
            self._gdb_server.send_reply("OK")
        else:
            self._gdb_server.send_reply("")
            
    def _handle_z(self, subcmd):               
        (bk_type, addr, length) = subcmd.split(",")
        addr = int(addr, 16)
        length = int(length, 16)
        if bk_type == "0" or bk_type == "1":    # software or hardware
            logger.debug("Recevied 'clear breakpoint' @ %04x", addr)
            if addr in self._brk_points:
                del self._brk_points[addr]
            self._gdb_server.send_reply("OK")
        else:
            self._gdb_server.send_reply("")
    
    __dispatchers = {
        '?' : _handle_qmark,
        'c' : _handle_c,
        'G' : _handle_G,
        'g' : _handle_g,
        'M' : _handle_M,
        'm' : _handle_m,
        'k' : _handle_k,
        'p' : _handle_p,
        'P' : _handle_P,
        'q' : _handle_q,
        's' : _handle_s,
        'v' : _handle_v,
        'Z' : _handle_Z,
        'z' : _handle_z
    }

    def handle_debugger(self, addr):
           
        while self._state == STATE_STOPPED:
            
            packet = self._gdb_server.wait_packet()
            
            if packet is None:
                self._state = STATE_QUIT
                #self._uc.emu_stop()
                break
            
            cmd, subcmd = packet[0], packet[1 :]
        
            if cmd in self.__dispatchers:
                self.__dispatchers[cmd](self, subcmd)
            else:
                logger.debug("%r command not handled", packet)
                self._gdb_server.send_reply("")
                
        return (self._state == STATE_RUN or self._state == STATE_STEP)
