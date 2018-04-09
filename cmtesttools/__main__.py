import argparse
import unicorn as uc
import firmware
import gdbserver
import semihosting
import runner

parser = argparse.ArgumentParser(description = "Cortex-M runner.")
parser.add_argument("-flash", type=int, required = True, help = "Flash size in KBs", metavar = "<flash-size>")
parser.add_argument("-ram", type=int, required = True, help = "RAM size in KBs", metavar = "<ram-size>")
parser.add_argument("-gdb", action = "store_true", help = "Act as GDB backend and wait for connection")
parser.add_argument("-gdb-port", type=int, default = 3334, help = "GDB port number to listen to", metavar = "<gdb-port>")
parser.add_argument("elf", help = "Input Elf file", metavar = "<elf-file>")

opts = parser.parse_args()

mem_map = [
(0, opts.flash * 1024, uc.UC_PROT_READ | uc.UC_PROT_EXEC),
(0x20000000, opts.ram * 1024, uc.UC_PROT_ALL)
];

frm = firmware.Firmware(opts.elf)

class __null_ctx :
    def __enter__(self): return self
    def __exit__(self, exc_type, exc_value, traceback): pass

gdb_srv = None
if opts.gdb:
    gdb_srv = gdbserver.GdbServer(("", opts.gdb_port))
    gdb_ctx = gdb_srv.wait_connection()
else:
    gdb_ctx = __null_ctx()

with gdb_ctx:
    r = runner.Runner(mem_map, frm, semihosting.Semihosting(), gdb_srv)
    exit(r.run())
