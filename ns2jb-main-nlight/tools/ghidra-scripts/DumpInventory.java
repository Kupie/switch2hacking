// DumpInventory: function list + defined strings w/ xrefs (fw23 reversing)
//@category fw23
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class DumpInventory extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outDir = System.getProperty("user.home") + "/dev/ns2jb/fw-re/out/";
        new File(outDir).mkdirs();
        String base = outDir + currentProgram.getName();

        // functions
        try (PrintWriter f = new PrintWriter(base + ".funcs.txt")) {
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext()) {
                Function fn = it.next();
                long size = fn.getBody().getNumAddresses();
                f.printf("%s %s %d%n", fn.getEntryPoint(), fn.getName(), size);
            }
        }

        // strings + xrefs
        try (PrintWriter f = new PrintWriter(base + ".strings.txt")) {
            DataIterator di = currentProgram.getListing().getDefinedData(true);
            while (di.hasNext()) {
                Data d = di.next();
                Object val = d.getValue();
                if (val instanceof String) {
                    String s = (String) val;
                    if (s.length() < 3) continue;
                    StringBuilder refs = new StringBuilder();
                    for (Reference r : currentProgram.getReferenceManager().getReferencesTo(d.getAddress())) {
                        refs.append(String.format(" <-%s(%s)", r.getFromAddress(),
                                r.getReferenceType()));
                    }
                    f.printf("%s | %s | %s%n", d.getAddress(), s.replace("\n", "\\n"), refs);
                }
            }
        }
        println("DumpInventory done -> " + base + ".*");
    }
}
