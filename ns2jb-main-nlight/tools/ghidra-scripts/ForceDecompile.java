// ForceDecompile: disassemble + create a function at each address, then decompile.
// For vtable functions Ghidra's auto-analysis never reached (headless -noanalysis
// projects leave gaps). Writes out/<program>.force-<ts>.c
//@category fw23
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.io.*;
import java.util.*;

public class ForceDecompile extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) { println("usage: ForceDecompile <hexaddr> [...]"); return; }
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        StringBuilder sb = new StringBuilder();
        for (String a : args) {
            Address addr = currentProgram.getAddressFactory().getAddress(a);
            if (addr == null) { sb.append("// bad address ").append(a).append("\n"); continue; }
            // Make sure memory is disassembled here.
            disassemble(addr);
            Function f = getFunctionAt(addr);
            if (f == null) {
                Function created = createFunction(addr, null);
                if (created != null) f = created;
            }
            if (f == null) {
                // fall back: containing function
                f = getFunctionContaining(addr);
            }
            if (f == null) { sb.append("// no function at ").append(a).append("\n"); println("no function at " + a); continue; }
            println("decompiling " + f.getName() + " @ " + f.getEntryPoint());
            DecompileResults res = di.decompileFunction(f, 240, monitor);
            sb.append("// ===== ").append(f.getName()).append(" @ ").append(f.getEntryPoint()).append("\n");
            sb.append(res.getDecompiledFunction() != null ? res.getDecompiledFunction().getC() : "// decompile failed\n");
            sb.append("\n");
        }
        File out = new File(System.getProperty("user.home") + "/dev/ns2jb/fw-re/out/" + currentProgram.getName()
            + ".force-" + System.currentTimeMillis() + ".c");
        out.getParentFile().mkdirs();
        try (Writer w = new FileWriter(out)) { w.write(sb.toString()); }
        println("wrote " + out);
    }
}