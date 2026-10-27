// FindErrSites: scan every instruction for the packed-Result construction
// movk wN, #imm, lsl #16 whose 32-bit value matches the given error, and
// decompile enclosing functions.
//@category fw23
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import java.io.*;
import java.util.*;

public class FindErrSites extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        long want = Long.decode(args[0]);
        Set<Function> fns = new LinkedHashSet<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            for (int opi = 0; opi < ins.getNumOperands(); opi++) {
                for (Object o : ins.getOpObjects(opi)) {
                    if (o instanceof ghidra.program.model.scalar.Scalar) {
                        long v = ((ghidra.program.model.scalar.Scalar) o).getValue();
                        if (v == want) {
                            println("scalar " + Long.toHexString(want) + " at " + ins.getAddress());
                            Function f = getFunctionContaining(ins.getAddress());
                            if (f != null) fns.add(f);
                        }
                    }
                }
            }
        }
        println("functions: " + fns.size());
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
            + ".errs-" + System.currentTimeMillis() + ".c");
        out.getParentFile().mkdirs();
        try (Writer w = new FileWriter(out)) { w.write(sb.toString()); }
        println("wrote " + out);
    }
}
