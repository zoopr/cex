from yapsy.IPlugin import IPlugin

import os
import networkx as nx

class FunctionNotFoundException(Exception):
    def __init__(self, addr):
        super().__init__("Function @ %#x not found" % addr)


class CFGInstruction(object):
    def __init__(self, addr: int, call_refs: list, mnemonic: str):
        self.addr      = addr
        self.mnemonic  = mnemonic
        self.call_refs = call_refs

    def to_json(self):
        return '{{"addr": {addr}, "mnemonic": "{mnemonic}", "call_refs": {call_refs}}}'.format(
            addr=self.addr,
            mnemonic=self.mnemonic,
            call_refs='[%s]' % ", ".join(map(str, self.call_refs)))

    def __str__(self):
        return "%#x : %s" % (self.addr, self.mnemonic)


class CFGNodeData(object):
    def __init__(self, addr: int, insns: list, calls: list):
        self.addr  = addr
        self.insns = insns
        self.calls = calls

    def get_dot_label(self):
        return "\l".join(map(str, self.insns)) + "\l"

    def get_json(self, successors: list):
        res = '{{"addr": {addr}, "instructions": {insns}, "successors": {successors}}}'
        insns = map(lambda x: x.to_json(), self.insns)
        successors = map(str, successors)
        return res.format(
            addr=self.addr,
            insns="[%s]" % ", ".join(insns),
            successors="[%s]" % ", ".join(successors))

    def join(self, other):
        " Append other instructions to self "
        assert isinstance(other, CFGNodeData)
        return CFGNodeData(self.addr, self.insns + other.insns, self.calls + other.calls)

    def merge(self, other):
        """
        Return the block that has LESS instructions.
         rationale:
           If a graph has a block with less instructions, it is likely
           that the block has been splitted, so the graph is more precise
        """

        assert isinstance(other, CFGNodeData)
        assert self.addr == other.addr

        if len(self.insns) <= len(other.insns):
            return self
        return other

    def explode(self):
        " Split the node in len(insns) nodes "

        res = list()
        for insn in self.insns:
            res.append(CFGNodeData(insn.addr, [insn], insn.call_refs))
        return res

    def __str__(self):
        return "<CFGNode %#x>" % self.addr


class CGNodeData(object):
    def __init__(self, addr: int, name: str):
        self.name = name
        self.addr = addr

    def get_dot_label(self):
        return "%s @ %#x" % (self.name, self.addr)

    def get_json(self, successors: list):
        return '{{"addr": {addr}, "name": "{name}", "successors": {successors}}}'.format(
            addr=self.addr,
            name=self.name,
            successors="[%s]" % ", ".join(map(str, successors)))

    def __str__(self):
        return "<CGNode %s @ %#x>" % (self.name, self.addr)


class ICfgExtractor(IPlugin):
    def __init__(self):
        super().__init__()
        if not os.path.exists(self.get_tmp_folder()):
            os.mkdir(self.get_tmp_folder())

    def loadable(self):
        return True

    def get_callgraph(self, binary, entry=None):
        # FIXME: in all plugins the callgraph should be a MultiGraph
        #        where each edge has the callsite info
        raise NotImplementedError

    def get_cfg(self, binary, addr):
        raise NotImplementedError

    def get_tmp_folder(self):
        return "/dev/shm/cex_projects"

    @staticmethod
    def normalize_graph(graph, merge_calls=False):
        """ 
            Merge nodes n1 and n2 if:
              - n1 is the only (direct) predecessor of n2
              - n2 is the only (direct) successor of n1
              - the last instruction of n1 is not a call (only if merge_calls is False)
        """
        merged_nodes = dict()
        out_graph    = nx.DiGraph()
        for n_id in graph.nodes:
            if n_id in merged_nodes:
                continue

            orig_n_id = n_id
            merged_node_data = graph.nodes[n_id]["data"]
            while 1:
                node_data  = graph.nodes[n_id]["data"]
                successors = list(graph.successors(n_id))
                if len(successors) != 1:
                    break

                unique_successor_id = successors[0]
                predecessors = list(graph.predecessors(unique_successor_id))
                if len(predecessors) != 1:
                    break

                assert predecessors[0] == n_id
                if not merge_calls and isinstance(node_data, CFGNodeData) and \
                        len(node_data.insns[-1].call_refs) > 0:
                    break

                unique_successor_data = graph.nodes[unique_successor_id]["data"]
                merged_nodes[unique_successor_id] = orig_n_id
                merged_node_data = merged_node_data.join(unique_successor_data)
                n_id = unique_successor_id

            out_graph.add_node(orig_n_id, data=merged_node_data)

        for src_id, dst_id in graph.edges:
            if dst_id in merged_nodes:
                # this edge is surely unique, and is the edge (n1, n2) where n1 and n2 has been merged. Delete this edge!
                continue
            if src_id in merged_nodes:
                # this is an edge from the n2 to its successors, I want to preserve those edges. Keep them!
                src_id = merged_nodes[src_id]
            out_graph.add_edge(src_id, dst_id)

        return out_graph

    def clear_cache(self):
        return  # Look in subclasses
