import ghidra.app.util.headless.HeadlessScript;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

import java.io.PrintStream;
import java.io.FileOutputStream;

import java.util.Iterator;
import java.util.HashSet;

public class ExportAccurateCallgraph extends HeadlessScript {

	public void run() throws Exception {

		// Get the output file from the command line argument
		String[] args = getScriptArgs();
		String path = "/dev/shm/pcode_callgraph.json";
		if (args.length == 0) {
			System.err.println("Using /dev/shm/pcode_callgraph.json as default path");
		} else {
			path = args[0];
		}

		println(String.format("[DEBUG] Output file: %s", path)); // DEBUG
		FileOutputStream fout;
		try {
			fout = new FileOutputStream(path);
		} catch (Exception e) {
			printf("Failed opening output file: Exception %s\n", e.toString());
			return;
		}
		PrintStream pout = new PrintStream(fout);

		// The actual thing
		DecompInterface ifc = new DecompInterface();
		DecompileOptions opt = new DecompileOptions();
		ifc.setOptions(opt);
		ifc.openProgram(currentProgram);

		pout.format("[\n");

		HashSet<Long> external_functions = new HashSet<>();
		Listing listing = currentProgram.getListing();
		FunctionIterator iter_functions = listing.getExternalFunctions();
		while (iter_functions.hasNext() && !monitor.isCancelled()) {
			Function f = iter_functions.next();
			for (Address a : f.getFunctionThunkAddresses())
				external_functions.add(a.getOffset());
		}

		boolean f_need_comma = false;
		iter_functions = listing.getFunctions(true);
		while (iter_functions.hasNext() && !monitor.isCancelled()) {
			Function f = iter_functions.next();
			if (external_functions.contains(f.getEntryPoint().getOffset()))
				continue;

			if (f_need_comma)
				pout.format(",\n");
			else
				f_need_comma = true;


			pout.format("  {\n" + "    \"name\": \"%s\",\n" + "    \"addr\": \"%#x\",\n" + "    \"calls\": [\n",
					f.getName(), f.getEntryPoint().getOffset());

			DecompileResults dr = ifc.decompileFunction(f, 300, monitor);
			HighFunction h = dr.getHighFunction();
			if (h != null) {
				boolean need_comma = false;
				Iterator<PcodeOpAST> opcodes_iter = h.getPcodeOps();
				while (opcodes_iter.hasNext()) {
					PcodeOpAST op = opcodes_iter.next();
					if (op.getOpcode() != PcodeOp.CALL)
						continue;

					Address target = op.getInput(0).getAddress();
					if (external_functions.contains(target.getOffset()))
						continue;

					if (need_comma)
						pout.format(",\n");
					else
						need_comma = true;


					pout.format("      { \"offset\": \"%#x\", \"callsite\" : \"%#x\" }",
						target.getOffset(), op.getSeqnum().getTarget().getOffset());
				}
			}

			pout.format("\n    ]\n  }\n");
		}
		pout.format("]\n");

		fout.close();
		pout.close();
	}
}
