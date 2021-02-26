import os
import sys
import json
import hashlib
import subprocess
import networkx as nx

from cfg_extractors import CFGNodeData, CGNodeData, ICfgExtractor
from cfg_extractors.elf_utils import check_pie


class GhidraBinaryData(object):
    def __init__(self, cfg_raw=None, cg_raw=None, cg=None):
        self.cfg_raw = cfg_raw
        self.cg_raw  = cg_raw
        self.cg      = cg


class GhidraCfgExtractor(ICfgExtractor):
    CMD_CALLGRAPH = [
        "$GHIDRA_HOME/support/analyzeHeadless",
        "/dev/shm",
        "Test.gpr",
        "-import",
        "$BINARY",
        "-postScript",
        "ExportCallgraph.java",
        "$OUTFILE",
        "-deleteProject",
        "-scriptPath",
        os.path.realpath(os.path.dirname(__file__))]

    CMD_CFG = [
        "$GHIDRA_HOME/support/analyzeHeadless",
        "$PROJ_FOLDER",
        "$PROJ_NAME",
        "-import",
        "$BINARY",
        "-postScript",
        "ExportCFG.java",
        "$OUTFILE",
        # "-deleteProject",
        "-scriptPath",
        os.path.realpath(os.path.dirname(__file__))]

    CMD_PIE_ELF = [
        "-loader",
        "ElfLoader",
        "-loader-imagebase",
        "400000" ]

    def __init__(self):
        super().__init__()
        self.data = dict()

    def loadable(self):
        return "GHIDRA_HOME" in os.environ

    @staticmethod
    def _get_cmd_callgraph(binary):
        ghidra_home = os.environ["GHIDRA_HOME"]
        cmd = GhidraCfgExtractor.CMD_CALLGRAPH[:]

        for i in range(len(cmd)):
            cmd[i] = cmd[i]                           \
                .replace("$GHIDRA_HOME", ghidra_home) \
                .replace("$BINARY", binary)           \
                .replace("$OUTFILE", "/dev/shm/cg.json")

        if check_pie(binary):
            cmd += GhidraCfgExtractor.CMD_PIE_ELF
        return cmd

    def _get_cmd_cfg(self, binary):
        ghidra_home = os.environ["GHIDRA_HOME"]
        cmd = GhidraCfgExtractor.CMD_CFG[:]

        with open(binary,'rb') as f_binary:
            binary_md5 = hashlib.md5(f_binary.read()).hexdigest()
        proj_name = "ghidra_proj_" + binary_md5  + ".gpr"
        for i in range(len(cmd)):
            cmd[i] = cmd[i]                                     \
                .replace("$GHIDRA_HOME", ghidra_home)           \
                .replace("$BINARY", binary)                     \
                .replace("$PROJ_FOLDER", self.get_tmp_folder()) \
                .replace("$PROJ_NAME", proj_name)               \
                .replace("$OUTFILE", "/dev/shm/cfg.json")

        if check_pie(binary):
            cmd += GhidraCfgExtractor.CMD_PIE_ELF
        return cmd

    def get_callgraph_with_script(self, binary, entry=None):
        # Old function
        if binary not in self.data:
            self.data[binary] = GhidraBinaryData()

        if self.data[binary].cg_raw is None:
            cmd = GhidraCfgExtractor._get_cmd_callgraph(binary)
            subprocess.check_call(cmd, stdout=subprocess.DEVNULL)

            with open("/dev/shm/cg.json", "r") as fin:
                callgraph_raw = json.load(fin)

            self.data[binary].cg_raw = callgraph_raw

        cg = nx.DiGraph()
        for node in self.data[binary].cg_raw:
            addr = int(node["addr"], 16)
            name = node["name"]
            cg.add_node(addr, data=CGNodeData(addr=addr, name=name))

        for node in self.data[binary].cg_raw:
            src = int(node["addr"], 16)
            for call in node["calls"]:
                dst = int(call, 16)
                cg.add_edge(src, dst)

        if entry is None:
            return cg
        if entry not in cg.nodes:
            return nx.null_graph()
        return nx.ego_graph(cg, entry, radius=sys.maxsize)

    def _load_cfg_raw(self, binary):
        if binary not in self.data:
            self.data[binary] = GhidraBinaryData()

        if self.data[binary].cfg_raw is None:
            cmd = self._get_cmd_cfg(binary)
            subprocess.check_call(cmd, stdout=subprocess.DEVNULL)

            with open("/dev/shm/cfg.json", "r") as fin:
                cfg_raw = json.load(fin)

            self.data[binary].cfg_raw = cfg_raw

    def get_callgraph(self, binary, entry=None):
        self._load_cfg_raw(binary)

        if self.data[binary].cg is None:
            cg = nx.DiGraph()
            for fun_raw in self.data[binary].cfg_raw:
                fun_addr = int(fun_raw["addr"], 16)
                fun_name = fun_raw["name"]
                cg.add_node(fun_addr, data=CGNodeData(addr=fun_addr, name=fun_name))

            for fun_raw in self.data[binary].cfg_raw:
                src = int(fun_raw["addr"], 16)
                for block_raw in fun_raw["blocks"]:
                    for call_raw in block_raw["calls"]:
                        dst = int(call_raw, 16)
                        cg.add_edge(src, dst)
            self.data[binary].cg = cg

        if entry is None:
            return self.data[binary].cg
        if entry not in cg.nodes:
            return nx.null_graph()
        return nx.ego_graph(self.data[binary].cg, entry, radius=sys.maxsize)

    def get_cfg(self, binary, addr):
        self._load_cfg_raw(binary)

        target_fun = None
        for fun_raw in self.data[binary].cfg_raw:
            if int(fun_raw["addr"], 16) == addr:
                target_fun = fun_raw
                break

        if target_fun is None:
            return None

        cfg = nx.DiGraph()
        for block_raw in target_fun["blocks"]:
            addr  = int(block_raw["addr"], 16)
            code  = block_raw["instructions"]
            calls = list(map(lambda x: int(x, 16), block_raw["calls"]))
            cfg.add_node(addr, data=CFGNodeData(addr=addr, code=code, calls=calls))

        for block_raw in target_fun["blocks"]:
            src = int(block_raw["addr"], 16)
            for dst_raw in block_raw["successors"]:
                dst = int(dst_raw, 16)
                cfg.add_edge(src, dst)

        return cfg
