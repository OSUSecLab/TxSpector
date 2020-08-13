# BSD 3-Clause License
#
# Copyright (c) 2020, The Ohio State Univerisity. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""evm_efg.py: parse the transaction trace and build a execution flow graph (efg)"""

import typing as t

import src.cfg as cfg
import src.opcodes as opcodes


class EVMBasicBlock(cfg.BasicBlock):
    """
    Represents a single basic block in the Execution Flow Graph (EFG), including
    its parent and child nodes in the graph structure.
    """

    def __init__(self, entry: int = None, exit: int = None,
                 evm_ops: t.List['EVMOp'] = None):
        """
        Creates a new basic block containing operations between the
        specified entry and exit instruction counters (inclusive).

        Args:
          entry: block entry point program counter
          exit: block exit point program counter
          evm_ops: a sequence of operations that constitute this BasicBlock's code. Default empty.
        """
        super().__init__(entry, exit)

        self.evm_ops = evm_ops if evm_ops is not None else []
        """List of EVMOps contained within this EVMBasicBlock"""


    def __str__(self):
        """Returns a string representation of this block and all ops in it."""
        super_str = super().__str__()
        op_seq = "\n".join(str(op) for op in self.evm_ops)
        return "\n".join([super_str, self._STR_SEP, op_seq])

    def split(self, entry: int) -> 'EVMBasicBlock':
        """
        Splits current block into a new block, starting at the specified
        entry op index. Returns a new EVMBasicBlock with no preds or succs.

        Args:
          entry: unique index of EVMOp from which the block should be split. The
            EVMOp at this index will become the first EVMOp of the new BasicBlock.
        """
        # Create the new block.
        new = type(self)(entry, self.exit, self.evm_ops[entry - self.entry:])

        # Update the current node.
        self.exit = entry - 1
        self.evm_ops = self.evm_ops[:entry - self.entry]

        # Update the block pointer in each line object
        self.__update_evmop_refs()
        new.__update_evmop_refs()

        return new

    def __update_evmop_refs(self):
        # Update references back to parent block for each opcode
        # This needs to be done when a block is split
        for op in self.evm_ops:
            op.block = self


class EVMOp:
    """
    Represents a single EVM operation.
    """
    def __init__(self, pc: int, opcode: opcodes.OpCode, value: int = None, value_extra: int = None,
                 call_depth: int = None, loc: int = None, call_number: int = None):
        """
        Create a new EVMOp object from the given params which should correspond to
        disasm output.
        """

        # Programming counter
        self.pc = pc

        # VM operation code
        self.opcode = opcode

        # Constant int value or None. Not only PUSH opcode has this value
        self.value = value
        
        # Four call opcodes has a special type: 0,1, they need extra type
        # value_extra is used to store more arguments for call, callcode, delegatecall, staticcall
        self.value_extra = value_extra
    
        # Call depth is the depth of the called smart contracts
        self.call_depth = call_depth

        # Loc is the programming opcode counter
        self.loc = loc

        # Call number, if you are interested in the details, please refer to our paper
        self.call_number = call_number


    # The default string of the opcodes
    def __str__(self):
        if self.value is None:
            return "{0} {1}".format(self.pc, self.opcode)
        else:
            if self.value_extra is None:
                return "{0} {1} {2}".format(self.pc, self.opcode, hex(self.value))
            else:
                return "{0} {1} {2} {3}".format(self.pc, self.opcode, hex(self.value), hex(self.value_extra))


    def __repr__(self):
        return "<{0} object {1}: {2}>".format(
            self.__class__.__name__,
            hex(id(self)),
            self.__str__()
        )


# Convert the trace (sequence of opcodes) into basic blocks
def blocks_from_ops(ops: t.Iterable[EVMOp]) -> t.Iterable[EVMBasicBlock]:
    """
    Process a sequence of EVMOps and create a sequence of EVMBasicBlocks.

    Args:
      ops: sequence of EVMOps to be put into blocks.

    Returns:
      List of BasicBlocks from the input opcodes.
    """
    blocks = []

    # details for block currently being processed
    entry, exit = (0, len(ops) - 1) if len(ops) > 0 \
        else (None, None)
    current = EVMBasicBlock(entry, exit)

    call_number = 0
    for i, op in enumerate(ops):
        if op.pc == 0 and i != 0:
            call_number += 1
        op.call_number = call_number

    # Linear scan of all EVMOps to create initial EVMBasicBlocks
    call_depth = 0
    for i, op in enumerate(ops):
        op.block = current
        current.evm_ops.append(op)

        # Remove all the intra blocks and only focus on the inter edges
        # add a condition to create a new block when encountering the new contract 0;
        if op.pc == 0 and i == 0:
            call_depth = 1
        elif op.pc == 0 and i != 0:
            call_depth += 1
            new = current.split(i)
            blocks.append(current)
            current = new

        # Add CREATE and CREATE2
        elif op.opcode.is_kind_four() or op.opcode.is_kind_five():
            # Make sure conditions such as 238;ADD 239;CALL will not be split
            if ops[i-1].call_number == op.call_number \
                and op.pc - ops[i - 1].pc == ops[i - 1].opcode.op_pc_gap() \
                and not ops[i-1].opcode.possibly_halts():
                pass
            else:
                call_depth -= 1
                new = current.split(i)
                blocks.append(current)
                current = new

        # Always add last block if its last instruction does not alter flow
        elif i == len(ops) - 1:
            blocks.append(current)

        op.loc = i
        op.call_depth = call_depth

    return blocks
