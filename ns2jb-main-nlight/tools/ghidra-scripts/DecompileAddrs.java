// DecompileAddrs: decompile functions containing given addresses.
//@category fw23
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.io.*;
import java.util.*;

public class DecompileAddrs extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("usage: DecompileAddrs <hexaddr> [<hexaddr>...]");
            return;
        }
        String out = System.getProperty("user.home") + "/dev/ns2jb/fw-re/out/" + currentProgram.getName()
            + ".addrs-" + System.currentTimeMillis() + ".c";
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        Set<Function> done = new LinkedHashSet<>();
        try (PrintWriter f = new PrintWriter(out)) {
            for (String a : args) {
                Address addr = currentProgram.getAddressFactory().getAddress(a);
                Function fn = getFunctionContaining(addr);
                if (fn == null) {
                    f.println("// no function at " + a);
                    println("no function at " + a);
                    continue;
                }
                if (!done.add(fn)) continue;
                f.println("// ===== " + fn.getName() + " @ " + fn.getEntryPoint() + " =====");
                DecompileResults res = dec.decompileFunction(fn, 120, monitor);
                if (res.getDecompiledFunction() != null)
                    f.println(res.getDecompiledFunction().getC());
                else
                    f.println("// decompile failed: " + res.getErrorMessage());
            }
        }
        dec.dispose();
        println("DecompileAddrs done -> " + out);
    }
}
