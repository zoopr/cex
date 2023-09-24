import ghidra.app.util.headless.HeadlessScript;

import ghidra.program.model.listing.Function;

import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

import java.io.PrintWriter;
import java.io.PrintStream;
import java.io.FileOutputStream;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.Stack;

import generic.stl.Pair;

import java.util.HashSet;
import java.util.Set;
import java.util.List;
import java.util.ArrayList; 

public class ExportCFG extends HeadlessScript {
    boolean is_arm;

    private boolean isThumb(Function f) {
        if (!is_arm)
            return false;

		Register tmode_r = currentProgram.getRegister("TMode");
		if (currentProgram.getProgramContext().getRegisterValue(tmode_r, f.getEntryPoint()).getUnsignedValueIgnoreMask().compareTo(BigInteger.ONE) == 0)
			return true;
        return false;
    }

    private static class BlockRes {
        Set<Address> ret_sites = new HashSet<Address>();
        Stack<CodeBlock> stack = new Stack<CodeBlock>();
        String json = "";
    }

    private String parseFunc(Function f, HashSet<Long> external_functions, SimpleBlockModel model) throws ghidra.util.exception.CancelledException {
        // if (f.isExternal() || f.isThunk()) {
        //     continue;
        // }

        StringBuilder pout = new StringBuilder();

        pout.append(String.format(" {\n"));
        pout.append(String.format("  \"name\": \"%s\",\n", f.getName().replace('"', '_')));
        pout.append(String.format("  \"addr\": \"%#x\",\n", f.getEntryPoint().getOffset()));
        pout.append(String.format("  \"is_returning\" : \"%s\",\n", f.hasNoReturn() ? "false" : "true"));
        pout.append(String.format("  \"is_thumb\" : \"%s\",\n", isThumb(f) ? "true" : "false"));
        pout.append(String.format("  \"blocks\": [\n"));
        CodeBlock entry_block  = model.getCodeBlockAt(f.getEntryPoint(), monitor);
        if (entry_block == null) {
            pout.append(String.format("  ],\n"));
            pout.append(String.format("  \"return_sites\" : [\n"));
            pout.append(String.format("  ]\n"));
            pout.append(String.format("    }\n"));
            return pout.toString();
        }

        Set<Address> ret_sites = new HashSet<Address>();
        Stack<CodeBlock> stack = new Stack<CodeBlock>();
        Set<CodeBlock> visited = new HashSet<CodeBlock>();
        stack.push(entry_block);

        while (!stack.empty()) {
            CodeBlock block = stack.pop();
            visited.add(block);

            BlockRes res = parseBlock(block, external_functions);
            ret_sites.addAll(res.ret_sites);
            pout.append(String.format(res.json));
            for (CodeBlock x:res.stack){
                if (!visited.contains(x))
                    stack.push(x);
            }

            if (!stack.empty()) {
                pout.append(String.format(",\n"));
            }
        }
        pout.append(String.format("  ],\n"));

        boolean need_comma = false;
        pout.append(String.format("  \"return_sites\" : [\n"));
        for (Address r : ret_sites) {
            if (need_comma)
                pout.append(String.format(",\n"));
            else
                need_comma = true;
            pout.append(String.format("    \"%#x\"", r.getOffset()));
        }
        pout.append(String.format("\n  ]\n"));
        pout.append(String.format(" }\n"));
        // printf("Finished Function string: %s\n", pout.toString());
        return pout.toString();
    }

    private BlockRes parseBlock(CodeBlock block, HashSet<Long> external_functions) throws ghidra.util.exception.CancelledException {
        // We will do it with a string instead of a printstream
        StringBuilder pout = new StringBuilder();

        BlockRes res = new BlockRes();
        Set<Pair<Address, Address>> call_successors = new HashSet<Pair<Address, Address>>();

        pout.append(String.format("    {\n"));
        pout.append(String.format("      \"addr\" : \"%#x\",\n", block.getFirstStartAddress().getOffset()));
        pout.append(String.format("      \"instructions\" : [\n"));

        InstructionIterator iter = currentProgram.getListing().getInstructions(block, true);

        while (iter.hasNext()) {
            Instruction inst = iter.next();
            for (PcodeOp op : inst.getPcode())
                if (op.getOpcode() == PcodeOp.RETURN)
                    res.ret_sites.add(inst.getAddress());

            pout.append(String.format("        { \"addr\": \"%#x\", \"size\": %d, \"mnemonic\" : \"%s\" }", inst.getAddress().getOffset(), inst.getLength(), inst.toString()));
            if (iter.hasNext())
                pout.append(String.format(",\n"));
            else
                pout.append(String.format("\n"));

            FlowType ft = inst.getFlowType();
            if (ft != null && ft.isCall()) {
                for (Address dst : inst.getFlows()) {
                    call_successors.add(new Pair<>(dst, inst.getAddress()));
                }
            }
            if (ft != null && ft.isComputed()) {
                for (Address dst : inst.getFlows()) {
                    if (getFunctionAt(dst) != null)
                        call_successors.add(new Pair<>(dst, inst.getAddress()));
                }
            }
        }
        pout.append(String.format("      ],\n"));

        pout.append(String.format("      \"successors\" : [\n"));
        boolean first_iter_insts = true;
        CodeBlockReferenceIterator succ_iter = block.getDestinations(monitor);
        while (succ_iter.hasNext()) {
            CodeBlockReference succ_ref = succ_iter.next();
            if (succ_ref.getFlowType().isCall())
                continue;

            CodeBlock succ = succ_ref.getDestinationBlock();
            Address dst = succ.getFirstStartAddress();
            if (succ_ref.getFlowType().isComputed() && getFunctionAt(dst) != null)
                // It is a call
                continue;

            if (!first_iter_insts)
                pout.append(String.format(",\n"));
            else
                first_iter_insts = false;
            
            if (succ != null)
                res.stack.push(succ);
            pout.append(String.format("        \"%#x\"", succ.getFirstStartAddress().getOffset()));
        }
        pout.append(String.format("\n"));
        pout.append(String.format("      ],\n"));

        pout.append(String.format("      \"calls\" : [\n"));
        Iterator<Pair<Address, Address>> calls = call_successors.iterator();
        while(calls.hasNext()) {
            Pair<Address, Address> call = calls.next();
            if (external_functions.contains(call.first.getOffset())) {
                Function ext_f = getFunctionAt(call.first);
                if (ext_f != null) {
                    pout.append(String.format("        { \"name\": \"%s\", \"callsite\" : \"%#x\", \"type\" : \"external\" }",
                            ext_f.getName(), call.second.getOffset()));
                }
            } else {
                pout.append(String.format("        { \"offset\": \"%#x\", \"callsite\" : \"%#x\", \"type\" : \"normal\" }",
                        call.first.getOffset(), call.second.getOffset()));
            }
            if (calls.hasNext())
                pout.append(String.format(",\n"));
            else
                pout.append(String.format("\n"));
        }
        pout.append(String.format("      ]\n"));

        pout.append(String.format("    }\n"));
        res.json = pout.toString();
        //printf("Finished block string: %s\n", pout.toString());
        return res;
    }

    public void run() throws Exception {

        // Get the output file from the command line argument
        String[] args = getScriptArgs();
        String path   = "/dev/shm/cfg.json";
        if (args.length == 0) {
            System.err.println("Using /dev/shm/cfg.json as default path");
        } else {
            path = args[0];
        }

        is_arm = currentProgram.getLanguage().getProcessor().toString().equals("ARM");

        printf("[DEBUG] Output file: %s\n", path); // DEBUG
        FileOutputStream fout;
        try {
            fout = new FileOutputStream(path);
        } catch (Exception e) {
            printf("Failed opening output file: Exception %s\n", e.toString());
            return;
        }
        PrintStream pout = new PrintStream(fout,true);

        // The actual thing
        SimpleBlockModel model = new SimpleBlockModel(currentProgram);

        Listing listing = currentProgram.getListing();

        HashSet<Long> external_functions = new HashSet<>();
        FunctionIterator iter_ext_functions = listing.getExternalFunctions();
        while (iter_ext_functions.hasNext() && !monitor.isCancelled()) {
            Function f = iter_ext_functions.next();
            for (Address a : f.getFunctionThunkAddresses())
                external_functions.add(a.getOffset());
        }

        FunctionIterator iter_functions = listing.getFunctions(true);

        pout.format("[\n");

        List<String> func_jsonObjects = new ArrayList();

        while (iter_functions.hasNext() && !monitor.isCancelled()) {
            Function f = iter_functions.next();
            pout.format(parseFunc(f,external_functions,model));
            if (iter_functions.hasNext()){
                pout.format(",\n");
            }
            if (pout.checkError()) {
                printf("Printstream reached error!");
                break;
            }    
        }
        pout.format("]\n");


        pout.close();
        fout.close();
    }
}
