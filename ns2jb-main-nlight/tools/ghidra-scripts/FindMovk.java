// FindMovk: find movk-with-immediate instructions (lsl 16 assumed for u32
// error construction) and decompile enclosing functions.
//@category fw23
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import java.io.*;
import java.util.*;

public class FindMovk extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        long want = Long.decode(args[0]);
        Set<Function> fns = new LinkedHashSet<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        int n = 0;
        while (it.hasNext()) {
            Instruction ins = it.next();
            if (!ins.getMnemonicString().equals("movk")) continue;
            for (int opi = 0; opi < ins.getNumOperands(); opi++) {
                for (Object o : ins.getOpObjects(opi)) {
                    if (o instanceof Scalar && ((Scalar) o).getValue() == want) {
                        n++;
                        println("movk 0x" + Long.toHexString(want) + " at " + ins.getAddress());
                        Function f = getFunctionContaining(ins.getAddress());
                        if (f != null) fns.add(f);
                    }
                }
            }
        }
        println("sites: " + n + ", functions: " + fns.size());
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
            + ".movk-" + System.currentTimeMillis() + ".c");
        out.getParentFile().mkdirs();
        try (Writer w = new FileWriter(out)) { w.write(sb.toString()); }
        println("wrote " + out);
    }
}
