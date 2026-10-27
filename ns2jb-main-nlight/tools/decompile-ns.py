# Ghidra headless post-script: decompile the ns registration-send chain.
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

prog = currentProgram
fm = prog.getFunctionManager()
di = DecompInterface()
di.openProgram(prog)
af = prog.getAddressFactory()
space = af.getDefaultAddressSpace()
monitor = ConsoleTaskMonitor()

targets = [0x1b5060, 0x67950, 0x1815e0, 0x181690, 0x546a0,
           0x1b6de8, 0x1a726c, 0x1ad69c, 0x6c90, 0x6dc0, 0x6dd0, 0x9250]
for t in targets:
    addr = space.getAddress(t)
    func = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
    if func is None:
        createFunction(addr, "sub_%x" % t)
        func = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
    if func is None:
        print("### %s: no function" % hex(t))
        continue
    res = di.decompileFunction(func, 240, monitor)
    if res.decompileCompleted():
        print("===DECOMP 0x%x (%s)===" % (t, func.getName()))
        print(res.getDecompiledFunction().getC())
    else:
        print("### 0x%x failed: %s" % (t, res.getErrorMessage()))

print("===XREFS to vtable region 0x4038a8..===")
rm = prog.getReferenceManager()
for v in range(0x403890, 0x4038f8, 8):
    a = space.getAddress(v)
    for ref in rm.getReferencesTo(a):
        print("XREF to %#x from %s" % (v, ref.getFromAddress()))