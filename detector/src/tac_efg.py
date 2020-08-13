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

"""tac_efg.py: generate a Intermediate Representation based execution flow graph."""
from collections import defaultdict

import copy
import logging
import typing as t
import src.cfg as cfg
import src.evm_efg as evm_efg
import src.memtypes as mem
import src.opcodes as opcodes
import src.patterns as patterns
import src.settings as settings
from src.lattice import SubsetLatticeElement as ssle

POSTDOM_END_NODE = "END"
"""The name of the synthetic end node added for post-dominator calculations."""
UNRES_DEST = "?"
"""The name of the unresolved jump destination auxiliary node."""

def remove_0x(temptstr):
    if temptstr.startswith("0x"):
        return temptstr[2:]
    return temptstr


class TACGraph(cfg.ControlFlowGraph):
    """
    A execution flow graph holding Three-Address Code blocks and the edges between them.
    """

    def __init__(self, evm_blocks: t.Iterable[evm_efg.EVMBasicBlock]):
        """
        Construct a TAC execution flow graph from a given sequence of EVM blocks.
        Immediately after conversion, constants will be propagated and folded
        through arithmetic operations, and EFG edges will be connected up, wherever
        they can be inferred.

        Args:
          evm_blocks: an iterable of EVMBasicBlocks to convert into TAC form.
        """
        super().__init__()

        # Convert the input EVM blocks to TAC blocks.
        destack = Destackifier()

        # Create a whole global stack to store all the tempt_stacks to deal with multiple smart contracts
        stacks = []

        for i, b in enumerate(evm_blocks):
            tac_block = destack.convert_block(b, stacks)
            self.blocks.append(tac_block)

        """The sequence of TACBasicBlocks contained in this graph."""
        for b in self.blocks:
            b.cfg = self

        self.root = next((b for b in self.blocks if b.entry == 0), None)
        """
        The root block of this EFG.
        The entry point will always be at index 0, if it exists.
        """

        self.split_node_succs = {}
        """
        A mapping from addresses to addresses storing all successors of a
        block at the time it was split. At merge time these edges can be restored.
        """

        self.function_extractor = None
        """
        A FunctionExtractor object, which encapsulates solidity functions and extracts logic.
        """

        # Add some fields to store stack and memory values
        # This function is not used in our work
        self.stack_values = defaultdict(dict)
        self.memory = bytearray()

        # Propagate constants and add EFG edges.
        # Assgin the opcode related value to memory and stack
        self.apply_operations()

        # Connect all the edges
        for i, b in enumerate(self.blocks):
            b.index = i

        self.connectEFGNode()


    # Accept extracted argument from the opcode
    @classmethod
    def from_opcode(cls, opcode: t.Iterable) -> 'TACGraph':
        """
        Construct and return a TACGraph from the given geth opcode.

        Args:
          opcode: a sequence of EVM opcode, either in a hexadecimal string format or a byte array.
        """
        original_opcodes = []
        for l in opcode:
            if len(l.strip()) > 0:
                # One example of the opcode line: 0; PUSH1; 0x64, which represents <PC; OPCODE NAME; ARGS>
                args = l.strip().split(";")
                if args[2] == "":
                    original_opcodes.append(evm_efg.EVMOp(int(args[0]), opcodes.opcode_by_name(args[1]), None, None))
                else:
                    if "," in args[2]:
                        args_extras = args[2].strip().split(",")
                        original_opcodes.append(evm_efg.EVMOp(int(args[0]), opcodes.opcode_by_name(args[1]),
                                                           int(args_extras[0]), int(args_extras[1])))
                    else:
                        if opcodes.opcode_by_name(args[1]).name == opcodes.SELFDESTRUCT.name:
                            addr = int(args[2], 0)
                            original_opcodes.append(evm_efg.EVMOp(int(args[0]), opcodes.opcode_by_name(args[1]), addr, None))
                        else:
                            original_opcodes.append(evm_efg.EVMOp(int(args[0]), opcodes.opcode_by_name(args[1]), int(args[2]), None))

        # Obtain evm opcode based EFG firstly 
        basic_blocks = evm_efg.blocks_from_ops(original_opcodes)
        return cls(basic_blocks)

    @property
    def tac_ops(self):
        for block in self.blocks:
            for op in block.tac_ops:
                yield op

    @property
    def last_op(self):
        return max((b.last_op for b in self.blocks),
                   key=lambda o: o.pc)

    def apply_operations(self, use_sets=False) -> None:
        """
        Propagate and fold constants through the arithmetic TAC instructions
        in this EFG.

        If use_sets is True, folding will also be done on Variables that
        possess multiple possible values, performing operations in all possible
        combinations of values.
        """
        for block in self.blocks:
            # Add stack and memory for the whole TAC-based EFG and store the related value from geth to memory, stack
            block.apply_operations(self.stack_values, self.memory, use_sets)

    def connectEFGNode(self):
        if len(list(self.blocks)) > 1:
            for i, block in enumerate(self.blocks):
                if i == 0:
                    block.preds = []
                    block.succs = [self.blocks[i + 1]]
                elif i == len(self.blocks)-1:
                    block.preds = [self.blocks[i - 1]]
                    block.succs = []
                else:
                    block.preds = [self.blocks[i - 1]]
                    block.succs = [self.blocks[i + 1]]

    def extract_functions(self):
        """
        Attempt to extract solidity functions from this contract.
        Call this after having already called prop_vars_between_blocks() on efg.
        """
        import src.function as function
        fe = function.FunctionExtractor(self)
        fe.extract()
        self.function_extractor = fe


class TACBasicBlock(evm_efg.EVMBasicBlock):
    """
    A basic block containing both three-address code, and its
    equivalent EVM code, along with information about the transformation
    applied to the stack as a consequence of its execution.
    """
    def __init__(self, entry_pc: int, exit_pc: int,
                 tac_ops: t.List['TACOp'],
                 evm_ops: t.List[evm_efg.EVMOp],
                 delta_stack: mem.VariableStack,
                 cfg=None, index=None):
        """
        Args:
          entry_pc: The pc of the first byte in the source EVM block
          exit_pc: The pc of the last byte in the source EVM block
          tac_ops: A sequence of TACOps whose execution is equivalent to the source
                   EVM code.
          evm_ops: the source EVM code.
          delta_stack: A stack describing the change in the stack state as a result
                       of running this block.
                       This stack contains the new items inhabiting the top of
                       stack after execution, along with the number of items
                       removed from the stack.
          cfg: The TACGraph to which this block belongs.

          Entry and exit variables should span the entire range of values enclosed
          in this block, taking care to note that the exit address may not be an
          instruction, but an argument of a PUSH.
          The range of pc values spanned by all blocks in a CFG should be a
          continuous range from 0 to the maximum value with no gaps between blocks.

          If the input stack state is known, obtain the exit stack state by
          popping off delta_stack.empty_pops items and add the delta_stack items
          to the top.
        """

        super().__init__(entry_pc, exit_pc, evm_ops)

        self.tac_ops = tac_ops
        """A sequence of TACOps whose execution is equivalent to the source EVM
           code"""

        self.delta_stack = delta_stack
        """
        A stack describing the stack state changes caused by running this block.
        MetaVariables named Sn symbolically denote the variable that was n places
        from the top of the stack at entry to this block.
        """

        self.entry_stack = mem.VariableStack()
        """Holds the complete stack state before execution of the block."""

        self.exit_stack = mem.VariableStack()
        """Holds the complete stack state after execution of the block."""

        self.symbolic_overflow = False
        """
        Indicates whether a symbolic stack overflow has occurred in dataflow
        analysis of this block.
        """

        self.cfg = cfg
        """The TACGraph to which this block belongs."""

        self.index = index

    def __str__(self):
        super_str = super().__str__()
        op_seq = "\n".join(str(op) for op in self.tac_ops)
        entry_stack = "Entry stack: {}".format(str(self.entry_stack))
        stack_pops = "Stack pops: {}".format(self.delta_stack.empty_pops)
        stack_adds = "Stack additions: {}".format(str(self.delta_stack))
        exit_stack = "Exit stack: {}".format(str(self.exit_stack))
        return "\n".join([super_str, self._STR_SEP, op_seq, self._STR_SEP,
                          entry_stack, stack_pops, stack_adds, exit_stack])

    def accept(self, visitor: patterns.Visitor) -> None:
        """
        Accepts a visitor and visits itself and all TACOps in the block.

        Args:
          visitor: an instance of :obj:`patterns.Visitor` to accept.
        """
        super().accept(visitor)

        if visitor.can_visit(TACOp) or visitor.can_visit(TACAssignOp):
            for tac_op in self.tac_ops:
                visitor.visit(tac_op)

    def __deepcopy__(self, memodict={}):
        """Return a copy of this block."""

        new_block = TACBasicBlock(self.entry, self.exit,
                                  copy.deepcopy(self.tac_ops, memodict),
                                  [copy.copy(op) for op in self.evm_ops],
                                  copy.deepcopy(self.delta_stack, memodict))

        new_block.fallthrough = self.fallthrough
        new_block.has_unresolved_jump = self.has_unresolved_jump
        new_block.symbolic_overflow = self.symbolic_overflow
        new_block.entry_stack = copy.deepcopy(self.entry_stack, memodict)
        new_block.exit_stack = copy.deepcopy(self.exit_stack, memodict)
        new_block.preds = copy.copy(self.preds)
        new_block.succs = copy.copy(self.succs)
        new_block.ident_suffix = self.ident_suffix
        new_block.cfg = self.cfg

        new_block.reset_block_refs()

        return new_block

    @property
    def last_op(self) -> 'TACOp':
        """Return the last TAC operation in this block if it exists."""
        if len(self.tac_ops):
            return self.tac_ops[-1]
        return None

    @last_op.setter
    def last_op(self, op):
        """
        Set the last TAC operation in this block, if there is one.
        Append if one doesn't exist.
        """
        if len(self.tac_ops):
            self.tac_ops[-1] = op
        else:
            self.tac_ops.append(op)

    def reset_block_refs(self) -> None:
        """Update all operations and new def sites to refer to this block."""

        for op in self.evm_ops:
            op.block = self
        for op in self.tac_ops:
            op.block = self
            if isinstance(op, TACAssignOp) and isinstance(op.lhs, mem.Variable):
                for site in op.lhs.def_sites:
                    site.block = self

    def apply_operations(self, stack_values: defaultdict, memory: bytearray, use_sets=False) -> None:
        """
        Propagate and fold constants through the arithmetic TAC instructions in this block.
        """
        for op in self.tac_ops:
            if op.opcode == opcodes.CONST:
                op.lhs.values = op.args[0].value.values

            # Special cases: they both belong to three_store_two.
            elif op.opcode == opcodes.CALLDATACOPY or op.opcode == opcodes.CODECOPY \
                or op.opcode == opcodes.RETURNDATACOPY:
                arg0 = remove_0x(str(op.args[0]))
                destoffset = int(arg0, 16)
                arg2 = remove_0x(str(op.args[2]))
                length = int(arg2, 16)
                value = op.value
                memory[destoffset: destoffset + length] = value.to_bytes(length, byteorder='big')
            elif op.opcode == opcodes.EXTCODECOPY:
                arg1 = remove_0x(str(op.args[1]))
                destoffset = int(arg1, 16)
                arg3 = remove_0x(str(op.args[3]))
                length = int(arg3, 16)
                value = op.value
                memory[destoffset: destoffset + length] = value.to_bytes(length, byteorder='big')

            # Special cases: cases for kind one and two, but those opcodes are not in three_store
            # Those opcodes have already had their value assigned to the lhs in the __handal_evm_op
            elif op.opcode.is_kind_one() or op.opcode.is_kind_two():
                continue

            # Special cases: SLOAD and MLOAD get their value from the geth, and these values have been assigned
            elif op.opcode == opcodes.MLOAD or op.opcode == opcodes.SLOAD:
                continue

            # Special cases: SSTORE and MSTORE. Store variable values to the related storage and memory
            elif op.opcode == opcodes.SSTORE:
                var_name = "S[{}]".format(op.args[0])
                var_value = op.args[1].value.values
                stack_values[var_name] = var_value
            elif op.opcode == opcodes.MSTORE:
                arg0 = remove_0x(str(op.args[0]))
                offset = int(arg0, 16)
                arg1 = remove_0x(str(op.args[1]))
                value = int(arg1, 16)
                memory[offset: offset + 32] = value.to_bytes(32, byteorder='big')
            elif op.opcode == opcodes.MSTORE8:
                arg0 = remove_0x(str(op.args[0]))
                offset = int(arg0, 16)
                arg1 = remove_0x(str(op.args[1]))
                value = int(arg1, 16)
                memory[offset: offset + 1] = value.to_bytes(8, byteorder='big')

            elif op.opcode.is_arithmetic():
                if op.constant_args() or (op.constrained_args() and use_sets):
                    rhs = [arg.value for arg in op.args] 
                    op.lhs.values = mem.Variable.arith_op(op.opcode.name, rhs).values
                elif not op.lhs.is_unconstrained:
                    op.lhs.widen_to_top()


class TACOp(patterns.Visitable):
    """
    A Three-Address Code operation.
    Each operation consists of an opcode object defining its function,
    a list of argument variables, and the unique program counter address
    of the EVM instruction it was derived from.
    """

    def __init__(self, opcode: opcodes.OpCode, args: t.List['TACArg'],
                 pc: int, block=None, value: int = None,
                 loc: int = None, call_depth: int = None, call_number: int = None):
        """
        Args:
          opcode: the operation being performed.
          args: Variables that are operated upon.
          pc: the program counter at the corresponding instruction in the original bytecode.
          block: the block this operation belongs to. Defaults to None.
          value: The value generated by Geth. Only kind three that stores two opcodes needs this field.
          loc: the position of the opcode
          call_depth: the depth of the called smart contracts
          call_number: the number of the called smart contracts so far
        """
        self.opcode = opcode
        self.args = args
        self.pc = pc
        self.block = block
        self.value = value
        self.loc = loc
        self.call_depth = call_depth
        self.call_number = call_number

    def __str__(self):
        if self.opcode in [opcodes.MSTORE, opcodes.MSTORE8, opcodes.SSTORE]:
            if self.opcode == opcodes.MSTORE:
                lhs = "M[{}]".format(self.args[0])
            elif self.opcode == opcodes.MSTORE8:
                lhs = "M8[{}]".format(self.args[0])
            else:
                lhs = "S[{}]".format(self.args[0])

            return "{}: {} = {}".format(hex(self.pc), lhs,
                                        " ".join([str(arg) for arg in self.args[1:]]))
        return "{}: {} {}".format(hex(self.pc), self.opcode,
                                  " ".join([str(arg) for arg in self.args]))

    def __repr__(self):
        return "<{0} object {1}, {2}>".format(
            self.__class__.__name__,
            hex(id(self)),
            self.__str__()
        )

    def constant_args(self) -> bool:
        """True iff each of this operations arguments is a constant value."""
        return all([arg.value.is_const for arg in self.args])

    def constrained_args(self) -> bool:
        """True iff none of this operations arguments is value-unconstrained."""
        return all([not arg.value.is_unconstrained for arg in self.args])

    @staticmethod
    def has_lhs() -> bool:
        return False

    @classmethod
    def convert_jump_to_throw(cls, op: 'TACOp') -> 'TACOp':
        """
        Given a jump, convert it to a throw, preserving the condition var if JUMPI.
        Otherwise, return the given operation unchanged.
        """
        if op.opcode not in [opcodes.JUMP, opcodes.JUMPI]:
            return op
        elif op.opcode == opcodes.JUMP:
            return cls(opcodes.THROW, [], op.pc, op.block)
        elif op.opcode == opcodes.JUMPI:
            return cls(opcodes.THROWI, [op.args[1]], op.pc, op.block)

    def __deepcopy__(self, memodict={}):
        new_op = type(self)(self.opcode,
                            copy.deepcopy(self.args, memodict),
                            self.pc,
                            self.block)
        return new_op


class TACAssignOp(TACOp):
    """
    A TAC operation that additionally takes a variable to which
    this operation's result is implicitly bound.
    """
    def __init__(self, lhs: mem.Variable, opcode: opcodes.OpCode,
                 args: t.List['TACArg'], pc: int, block=None,
                 print_name: bool = True, value_extra: int = None,
                 loc: int = None, call_depth: int = None, call_number: int = None):
        """
        Args:
          lhs: The Variable that will receive the result of this operation.
          print_name: Some operations (e.g. CONST) don't need to print their
                      name in order to be readable.
          value_extra: store the value_extra for CALL CALLCODE STATICCALL DELEGATECALL
          loc: the position of the opcode
          call_depth: the depth of the called smart contracts
          call_number: the number of the called smart contracts so far
        """
        super().__init__(opcode, args, pc, block)
        self.lhs = lhs
        self.print_name = print_name
        self.value_extra = value_extra
        self.loc = loc
        self.call_depth = call_depth
        self.call_number = call_number

    # Special case TAC expression
    # For example V4 = CALLVALUE to V4 = value content
    def __str__(self):
        if self.opcode in [opcodes.SLOAD, opcodes.MLOAD]:
            if self.opcode == opcodes.SLOAD:
                rhs = "S[{}]".format(self.args[0])
            else:
                rhs = "M[{}]".format(self.args[0])

            return "{}: {} = {}".format(hex(self.pc), self.lhs.identifier, rhs)
        elif self.opcode.is_kind_one() or self.opcode.is_kind_two():
            return "{}: {} = {}".format(hex(self.pc), self.lhs.identifier, self.lhs.values)

        arglist = ([str(self.opcode)] if self.print_name else []) \
                  + [str(arg) for arg in self.args]
        return "{}: {} = {}".format(hex(self.pc), self.lhs.identifier, " ".join(arglist))

    def __deepcopy__(self, memodict={}):
        """
        Return a copy of this TACAssignOp, deep copying the args and vars,
        but leaving block references unchanged.
        """
        new_op = type(self)(copy.deepcopy(self.lhs, memodict),
                            self.opcode,
                            copy.deepcopy(self.args, memodict),
                            self.pc,
                            self.block,
                            self.print_name)
        return new_op

    @staticmethod
    def has_lhs() -> bool:
        return True


class TACArg:
    """
    Contains information held in an argument to a TACOp.
    In particular, a TACArg may hold both the current value of an argument,
    if it exists; along with the entry stack position it came from, if it did.
    This allows updated/refined stack data to be propagated into the body
    of a TACBasicBlock.
    """

    def __init__(self, var: mem.Variable = None, stack_var: mem.MetaVariable = None):
        self.var = var
        """The actual variable this arg contains."""
        self.stack_var = stack_var
        """The stack position this variable came from."""

    def __str__(self):
        return str(self.value)

    @property
    def value(self):
        """
        Return this arg's value if it has one, otherwise return its stack variable.
        """
        if self.var is None:
            if self.stack_var is None:
                raise ValueError("TAC Argument has no value.")
            else:
                return self.stack_var
        else:
            return self.var

    @classmethod
    def from_var(cls, var: mem.Variable):
        if isinstance(var, mem.MetaVariable):
            return cls(stack_var=var)
        return cls(var=var)


class TACLocRef:
    """Contains a reference to a program counter within a particular block."""

    def __init__(self, block, pc):
        self.block = block
        """The block that contains the referenced instruction."""
        self.pc = pc
        """The program counter of the referenced instruction."""

    def __deepcopy__(self, memodict={}):
        return type(self)(self.block, self.pc)

    def __str__(self):
        return "{}.{}".format(self.block.ident(), hex(self.pc))

    def __eq__(self, other):
        return self.block == other.block and self.pc == other.pc

    def __hash__(self):
        return hash(self.block) ^ hash(self.pc)

    def get_instruction(self):
        """Return the TACOp referred to by this TACLocRef, if it exists."""
        for i in self.block.tac_ops:
            if i.pc == self.pc:
                return i
        return None


class Destackifier:
    """Converts EVMBasicBlocks into corresponding TACBasicBlocks.

    Most instructions get mapped over directly, except:
        POP: generates no TAC op, but pops the symbolic stack;
        PUSH: generates a CONST TAC assignment operation;
        DUP, SWAP: these simply permute the symbolic stack, generate no ops;
        LOG0 ... LOG4: all translated to a generic LOG instruction

    Additionally, there is a NOP TAC instruction that does nothing, to represent
    a block containing EVM instructions with no corresponding TAC code.
    """

    def __init__(self):
        # A sequence of three-address operations
        self.ops = []

        # The symbolic variable stack we'll be operating on.
        self.stack = mem.VariableStack()

        # Entry address of the current block being converted
        self.block_entry = None

        # The number of TAC variables we've assigned,
        # in order to produce unique identifiers. Typically the same as
        # the number of items pushed to the stack.
        # We increment it so that variable names will be globally unique.
        self.stack_vars = 0

    def __fresh_init(self, evm_block: evm_efg.EVMBasicBlock) -> None:
        """Reinitialise all structures in preparation for converting a block."""
        self.ops = []
        self.stack = mem.VariableStack()
        self.block_entry = evm_block.evm_ops[0].pc \
            if len(evm_block.evm_ops) > 0 else None

    def __new_var(self) -> mem.Variable:
        """Construct and return a new variable with the next free identifier."""

        # Generate the new variable, numbering it by the implicit stack location
        # it came from.
        var = mem.Variable.top(name="V{}".format(self.stack_vars),
                               def_sites=ssle([TACLocRef(None, self.block_entry)]))
        self.stack_vars += 1
        return var


    # Add the last block's stack into the following one
    def convert_block(self, evm_block: evm_efg.EVMBasicBlock, stacks: [mem.VariableStack]) -> (TACBasicBlock):
        """
        Given a EVMBasicBlock, produce an equivalent three-address code sequence and return the resulting TACBasicBlock.
        """
        # Step1: How to use the stack
        if len(evm_block.evm_ops) > 0:
            first_opcode = evm_block.evm_ops[0]
            if first_opcode.pc == 0:
                pre_stack = mem.VariableStack(call_depth=first_opcode.call_depth)
            elif first_opcode.opcode.is_kind_four() or first_opcode.opcode.is_kind_five():
                pre_stack = stacks.pop()
                if first_opcode.call_depth != pre_stack.call_depth:
                    pre_stack = stacks.pop()

        self.__fresh_init(evm_block)

        self.stack = pre_stack
        for op in evm_block.evm_ops:
            self.__handle_evm_op(op)

        entry = evm_block.evm_ops[0].pc if len(evm_block.evm_ops) > 0 else None
        exit = evm_block.evm_ops[-1].pc + evm_block.evm_ops[-1].opcode.push_len() \
            if len(evm_block.evm_ops) > 0 else None

        # If the block is empty, append a NOP before continuing.
        if len(self.ops) == 0:
            self.ops.append(TACOp(opcodes.NOP, [], entry))

        new_block = TACBasicBlock(entry, exit, self.ops, evm_block.evm_ops,
                                  self.stack)

        # Link up new ops and def sites to the block that contains them.
        new_block.reset_block_refs()

        # Step2: How to add the stack
        if len(evm_block.evm_ops) > 0:
            first_opcode = evm_block.evm_ops[0]
            last_opcode = evm_block.evm_ops[len(evm_block.evm_ops) - 1]
            if first_opcode.pc == 0 and not last_opcode.opcode.possibly_halts():
                stacks.append(self.stack)
            if (first_opcode.opcode.is_kind_four() or first_opcode.opcode.is_kind_five())\
                and not last_opcode.opcode.possibly_halts():
                stacks.append(self.stack)

        return new_block

    def __handle_evm_op(self, op: evm_efg.EVMOp) -> None:
        """
        Produce from an EVM line its corresponding TAC instruction, if there is one,
        appending it to the current TAC sequence.
        """
        if op.opcode.is_swap():
            self.stack.swap(op.opcode.pop)
        elif op.opcode.is_dup():
            self.stack.dup(op.opcode.pop)
        elif op.opcode == opcodes.POP:
            self.stack.pop()
        else:
            # When generating TAC operation from evm opcode, making use of value and value_extra generated from geth
            self.__gen_instruction(op)

    # Use values from geth
    def __gen_instruction(self, op: evm_efg.EVMOp) -> None:
        """
        Given a line, generate its corresponding TAC operation,
        append it to the op sequence, and push any generated
        variables to the stack.
        """
        inst = None
        new_var = self.__new_var() if op.opcode.push == 1 else None

        # Set this variable's def site
        if new_var is not None:
            for site in new_var.def_sites:
                site.pc = op.pc

        # Generate the appropriate TAC operation.
        # Special cases first, followed by the fallback to generic instructions.
        # Although the opcode is PUSH, vandal still marks it as CONST to do arithemetic operations.
        if op.opcode.is_push():
            args = [TACArg(var=mem.Variable(values=[op.value], name="C"))]
            inst = TACAssignOp(new_var, opcodes.CONST, args, op.pc, print_name=False)
        elif op.opcode.is_missing():
            args = [TACArg(var=mem.Variable(values=[op.value], name="C"))]
            inst = TACOp(op.opcode, args, op.pc)
        elif op.opcode.is_log():
            args = [TACArg.from_var(var) for var in self.stack.pop_many(op.opcode.pop)]
            inst = TACOp(opcodes.LOG, args, op.pc)
        elif op.opcode == opcodes.MSTORE:
            args = [TACArg.from_var(var) for var in self.stack.pop_many(opcodes.MSTORE.pop)]
            inst = TACOp(op.opcode, args, op.pc)
        elif op.opcode == opcodes.MSTORE8:
            args = [TACArg.from_var(var) for var in self.stack.pop_many(opcodes.MSTORE8.pop)]
            inst = TACOp(op.opcode, args, op.pc)

        # SLOAD is same as MLOAD, they both hasve value in the tempt file
        # We will assign the real value to the storage variable
        elif op.opcode == opcodes.SLOAD or op.opcode == opcodes.MLOAD:
            new_var = mem.Variable(values=[op.value], name=new_var.name)
            args = [TACArg.from_var(self.stack.pop())]
            inst = TACAssignOp(new_var, op.opcode, args, op.pc)
        elif op.opcode == opcodes.SSTORE:
            args = [TACArg.from_var(var) for var in self.stack.pop_many(opcodes.SSTORE.pop)]
            inst = TACOp(op.opcode, args, op.pc)

        # Special cases for kind one, such as CALLVALUE
        # For kind one, there are no arguments for the previous vandal, so the inst will be incomplete
        # For example, 0xa CALLVALUE 0x0 will be transalated into V4 =
        # Now we assign the real value to this opcode and keep its opcode
        elif op.opcode.is_kind_one():
            new_var = mem.Variable(values=[op.value], name=new_var.name)
            args = []
            inst = TACAssignOp(new_var, op.opcode, args, op.pc, print_name=False)

        # Special cases for kind two, such as CALLDATALOAD
        # Args have all the stack arguments, those information (stack arguments) are useless
        # Since we just get the values from geth, not using them.
        elif op.opcode.is_kind_two():
            new_var = mem.Variable(values=[op.value], name=new_var.name)
            args = [TACArg.from_var(var) for var in self.stack.pop_many(op.opcode.pop)]
            inst = TACAssignOp(new_var, op.opcode, args, op.pc, print_name=False)

        # Special cases for kind three store two, such as CALLDATACOPY
        # There are multiple arguments in this kind of opcodes
        elif op.opcode.is_kind_three_store_two():
            args = [TACArg.from_var(var) for var in self.stack.pop_many(op.opcode.pop)]
            inst = TACOp(op.opcode, args, op.pc, None, op.value)

        # Special cases for kind four, such as call
        # Field value_extra is the memory content
        elif op.opcode.is_kind_four():
            # op.value is success flag, value_extra is the memory content.
            new_var = mem.Variable(values=[op.value], name=new_var.name)
            args = [TACArg.from_var(var) for var in self.stack.pop_many(op.opcode.pop)]
            inst = TACAssignOp(new_var, op.opcode, args, op.pc, None, True, op.value_extra)

        elif op.opcode.is_kind_five():
            new_var = mem.Variable(values=[op.value], name=new_var.name)
            args = [TACArg.from_var(var) for var in self.stack.pop_many(op.opcode.pop)]
            inst = TACAssignOp(new_var, op.opcode, args, op.pc, None, True, None)

        elif new_var is not None:
            args = [TACArg.from_var(var) for var in self.stack.pop_many(op.opcode.pop)]
            inst = TACAssignOp(new_var, op.opcode, args, op.pc)
        else:
            args = [TACArg.from_var(var) for var in self.stack.pop_many(op.opcode.pop)]
            inst = TACOp(op.opcode, args, op.pc)

        # This var must only be pushed after the operation is performed.
        if new_var is not None:
            self.stack.push(new_var)

        inst.loc = op.loc
        inst.call_depth = op.call_depth
        inst.call_number = op.call_number

        self.ops.append(inst)
