// RefsInRange: list+decompile all functions containing references INTO an
// address range (e.g. an error-constant table page).
//@category fw23
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class RefsInRange extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Address lo = toAddr(Long.decode(args[0]));
        Address hi = toAddr(Long.decode(args[1]));
        ReferenceIterator it = currentProgram.getReferenceManager().getReferenceIterator(lo);
        Set<Function> fns = new LinkedHashSet<>();
        long n = 0;
        while (it.hasNext()) {
            Reference r = it.next();
            if (r.getToAddress().compareTo(lo) >= 0 && r.getToAddress().compareTo(hi) <= 0) {
                n++;
                Function f = getFunctionContaining(r.getFromAddress());
                if (f != null) fns.add(f);
                if (n < 20) println("ref " + r.getFromAddress() + " -> " + r.getToAddress());
            }
        }
        println("total refs in range: " + n + ", functions: " + fns.size());
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        StringBuilder sb = new StringBuilder();
        for (Function f : fns) {
            sb.append("// ==== ").append(f.getName()).append(" @ ").append(f.getEntryPoint()).append("\n");
            DecompileResults res = di.decompileFunction(f, 120, monitor);
            if (res.getDecompiledFunction() != null)
                sb.append(res.getDecompiledFunction().getC()).append("\n");
        }
        File out = new File(System.getProperty("user.dir") + "/out/" + currentProgram.getName()
            + ".range-" + System.currentTimeMillis() + ".c");
        out.getParentFile().mkdirs();
        try (Writer w = new FileWriter(out)) { w.write(sb.toString()); }
        println("wrote " + out);
    }
}
