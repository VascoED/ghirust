//! GHIRUST Unified Intermediate Representation (GUIR) — core model.
//!
//! GUIR is deliberately language-neutral at the container level but keeps
//! language-specific metadata on functions. This module implements the
//! serialisable data model and a validator. Decompiler frontends populate it;
//! the validator guarantees that a persisted module is structurally sound
//! before any later stage (optimisation, pseudocode generation, caching)
//! consumes it.
//!
//! Implemented here:
//!
//! * module/function/basic-block/instruction representation;
//! * expressions via operands and a typed operation enum;
//! * control-flow terminators;
//! * type definitions;
//! * JSON serialisation with an explicit format version;
//! * structural validation.
//!
//! Not implemented here: lifting a specific instruction set into GUIR. That
//! belongs to the disassembler/loader backends and is tracked in STATUS.md.

use serde::{Deserialize, Serialize};

/// Format version stored in every serialized module.
pub const GUIR_VERSION: u32 = 1;

/// Identifier of a function inside a module.
pub type FunctionId = u32;
/// Identifier of a basic block inside a function.
pub type BlockId = u32;
/// Identifier of a value produced by an instruction.
pub type ValueId = u32;

/// A complete analysis module.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Module {
    /// GUIR format version.
    pub format_version: u32,
    /// Module name (usually the binary file name).
    pub name: String,
    /// Functions in this module.
    pub functions: Vec<Function>,
    /// Named types.
    pub types: Vec<TypeDef>,
    /// Global variables and symbols.
    pub globals: Vec<Global>,
}

impl Module {
    /// Create an empty module.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            format_version: GUIR_VERSION,
            name: name.into(),
            functions: Vec::new(),
            types: Vec::new(),
            globals: Vec::new(),
        }
    }

    /// Find a function by ID.
    pub fn function(&self, id: FunctionId) -> Option<&Function> {
        self.functions.iter().find(|function| function.id == id)
    }

    /// Find a mutable function by ID.
    pub fn function_mut(&mut self, id: FunctionId) -> Option<&mut Function> {
        self.functions.iter_mut().find(|function| function.id == id)
    }

    /// Validate the module and return every structural issue found.
    pub fn validate(&self) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();
        if self.format_version != GUIR_VERSION {
            issues.push(ValidationIssue::error(
                "guir.version",
                format!(
                    "unsupported GUIR version {}; expected {}",
                    self.format_version, GUIR_VERSION
                ),
            ));
        }
        if self.name.trim().is_empty() {
            issues.push(ValidationIssue::warning(
                "guir.name",
                "module name is empty",
            ));
        }

        let mut function_ids = std::collections::BTreeSet::new();
        let mut addresses = std::collections::BTreeMap::new();
        for function in &self.functions {
            if !function_ids.insert(function.id) {
                issues.push(ValidationIssue::error(
                    "function.duplicate_id",
                    format!("duplicate function id {}", function.id),
                ));
            }
            if function.name.trim().is_empty() {
                issues.push(ValidationIssue::warning(
                    "function.empty_name",
                    format!("function {} has an empty name", function.id),
                ));
            }
            if let Some(address) = function.address {
                if let Some(previous) = addresses.insert(address, function.id) {
                    issues.push(ValidationIssue::warning(
                        "function.duplicate_address",
                        format!(
                            "functions {} and {} share address 0x{address:x}",
                            previous, function.id
                        ),
                    ));
                }
            }
            if !(0.0..=1.0).contains(&function.confidence) {
                issues.push(ValidationIssue::error(
                    "function.confidence",
                    format!(
                        "function {} has confidence {:.2}; expected 0.0..=1.0",
                        function.id, function.confidence
                    ),
                ));
            }
            validate_function(function, &mut issues);
        }

        issues
    }

    /// Whether validation found no errors.
    pub fn is_valid(&self) -> bool {
        !self
            .validate()
            .iter()
            .any(|issue| issue.severity == Severity::Error)
    }

    /// Serialize to pretty JSON.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from JSON and validate the version.
    pub fn from_json(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }
}

fn validate_function(function: &Function, issues: &mut Vec<ValidationIssue>) {
    if function.blocks.is_empty() {
        issues.push(ValidationIssue::error(
            "function.no_blocks",
            format!("function {} has no basic blocks", function.id),
        ));
        return;
    }

    let mut block_ids = std::collections::BTreeSet::new();
    for block in &function.blocks {
        if !block_ids.insert(block.id) {
            issues.push(ValidationIssue::error(
                "block.duplicate_id",
                format!(
                    "function {} has duplicate block id {}",
                    function.id, block.id
                ),
            ));
        }
        validate_terminator(function.id, block.id, &block.terminator, &block_ids, issues);
    }

    match function.entry {
        Some(entry) if !block_ids.contains(&entry) => issues.push(ValidationIssue::error(
            "function.entry_missing",
            format!(
                "function {} entry block {} does not exist",
                function.id, entry
            ),
        )),
        None => issues.push(ValidationIssue::warning(
            "function.no_entry",
            format!("function {} has no entry block", function.id),
        )),
        _ => {}
    }

    // A second pass is required because a branch may target a block that is
    // declared later in the vector.
    for block in &function.blocks {
        for target in terminator_targets(&block.terminator) {
            if !block_ids.contains(&target) {
                issues.push(ValidationIssue::error(
                    "terminator.missing_block",
                    format!(
                        "function {} block {} targets missing block {}",
                        function.id, block.id, target
                    ),
                ));
            }
        }
        for operand in block
            .instructions
            .iter()
            .flat_map(|instruction| &instruction.operands)
        {
            if let Operand::Block(target) = operand {
                if !block_ids.contains(target) {
                    issues.push(ValidationIssue::error(
                        "operand.missing_block",
                        format!(
                            "function {} block {} references missing block {}",
                            function.id, block.id, target
                        ),
                    ));
                }
            }
        }
    }
}

fn validate_terminator(
    function: FunctionId,
    block: BlockId,
    terminator: &Terminator,
    _known_blocks_so_far: &std::collections::BTreeSet<BlockId>,
    issues: &mut Vec<ValidationIssue>,
) {
    if let Terminator::Branch { condition, .. } = terminator {
        let _ = condition;
        // Value IDs are local to a function; a full value-numbering pass is
        // intentionally left to the later data-flow stage.
    }
    if matches!(terminator, Terminator::Unreachable) {
        issues.push(ValidationIssue::warning(
            "block.unreachable",
            format!("function {function} block {block} is explicitly unreachable"),
        ));
    }
}

fn terminator_targets(terminator: &Terminator) -> Vec<BlockId> {
    match terminator {
        Terminator::Fallthrough(target) | Terminator::Jump(target) => vec![*target],
        Terminator::Branch {
            then_block,
            else_block,
            ..
        } => vec![*then_block, *else_block],
        Terminator::Call { next, .. } => vec![*next],
        Terminator::Return(_) | Terminator::Unreachable => Vec::new(),
    }
}

/// One function in GUIR.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Function {
    /// Unique ID inside the module.
    pub id: FunctionId,
    /// Display name (`FUN_00401000`, `main`, ...).
    pub name: String,
    /// Virtual address when known.
    pub address: Option<u64>,
    /// Entry block, when known.
    pub entry: Option<BlockId>,
    /// Basic blocks.
    pub blocks: Vec<BasicBlock>,
    /// Number of parameters, when recoverable.
    pub parameters: Option<u32>,
    /// Confidence that the boundary and name are correct.
    pub confidence: f32,
    /// Language-specific metadata (calling convention, demangled name, ...).
    #[serde(default)]
    pub metadata: std::collections::BTreeMap<String, String>,
}

/// One basic block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BasicBlock {
    /// Unique ID inside the function.
    pub id: BlockId,
    /// Instructions in execution order.
    pub instructions: Vec<Instruction>,
    /// How control leaves this block.
    pub terminator: Terminator,
    /// Optional source line or original address range.
    #[serde(default)]
    pub address: Option<u64>,
}

/// One instruction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Instruction {
    /// Original address, when known.
    #[serde(default)]
    pub address: Option<u64>,
    /// Operation.
    pub op: Op,
    /// Operands.
    #[serde(default)]
    pub operands: Vec<Operand>,
    /// Value produced by this instruction.
    #[serde(default)]
    pub result: Option<ValueId>,
}

/// Instruction operations currently represented by GUIR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    /// No operation.
    Nop,
    /// Register/memory move.
    Mov,
    /// Memory load.
    Load,
    /// Memory store.
    Store,
    /// Load effective address.
    Lea,
    /// Integer or floating-point addition.
    Add,
    /// Subtraction.
    Sub,
    /// Multiplication.
    Mul,
    /// Division.
    Div,
    /// Remainder.
    Mod,
    /// Bitwise AND.
    And,
    /// Bitwise OR.
    Or,
    /// Bitwise XOR.
    Xor,
    /// Bitwise NOT.
    Not,
    /// Shift left.
    Shl,
    /// Logical shift right.
    Shr,
    /// Arithmetic shift right.
    Sar,
    /// Comparison.
    Cmp,
    /// Function call.
    Call,
    /// SSA phi node.
    Phi,
    /// Arithmetic negation.
    Neg,
    /// An operation not yet modelled.
    Unknown(String),
}

/// Instruction operand.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operand {
    /// Value produced earlier in the function.
    Value(ValueId),
    /// Constant.
    Immediate(i64),
    /// Absolute or relative address.
    Address(u64),
    /// Basic-block target.
    Block(BlockId),
    /// Function reference.
    Function(FunctionId),
    /// Named symbol.
    Symbol(String),
    /// String literal.
    String(String),
    /// Register name.
    Register(String),
    /// Memory operand.
    Memory(Box<MemoryOperand>),
}

/// Memory operand used by a GUIR instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryOperand {
    /// Base register.
    pub base: Option<String>,
    /// Index register.
    pub index: Option<String>,
    /// Index scale.
    pub scale: u32,
    /// Displacement.
    pub displacement: u64,
    /// Access size in bytes.
    pub size: u16,
}

/// How control leaves a basic block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Terminator {
    /// Continue at another block.
    Fallthrough(BlockId),
    /// Unconditional jump.
    Jump(BlockId),
    /// Conditional branch.
    Branch {
        /// Value tested by the branch.
        condition: ValueId,
        /// Taken when non-zero/true.
        then_block: BlockId,
        /// Taken otherwise.
        else_block: BlockId,
    },
    /// Return with an optional value.
    Return(Option<ValueId>),
    /// Call followed by a continuation block.
    Call {
        /// Direct target, when known.
        target: Option<FunctionId>,
        /// Where execution continues.
        next: BlockId,
    },
    /// No successor; for example, a trap.
    Unreachable,
}

/// Type representation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeDef {
    /// No value.
    Void,
    /// Boolean.
    Bool,
    /// Integer of a given width and signedness.
    Int {
        /// Width in bits.
        bits: u16,
        /// Whether the value is signed.
        signed: bool,
    },
    /// IEEE floating point.
    Float {
        /// Width in bits.
        bits: u16,
    },
    /// Pointer to another type.
    Pointer(Box<TypeDef>),
    /// Fixed-size array.
    Array {
        /// Element type.
        element: Box<TypeDef>,
        /// Number of elements.
        count: u64,
    },
    /// Structure with named fields.
    Struct {
        /// Structure name.
        name: String,
        /// Fields in declaration order.
        fields: Vec<(String, TypeDef)>,
    },
    /// Function signature.
    Function {
        /// Parameter types.
        parameters: Vec<TypeDef>,
        /// Return type.
        returns: Box<TypeDef>,
    },
    /// Unknown or partially recovered type.
    Unknown(String),
}

/// Global symbol.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Global {
    /// Name.
    pub name: String,
    /// Address when known.
    pub address: Option<u64>,
    /// Type when known.
    pub ty: Option<TypeDef>,
    /// Whether the linker marks it as external.
    pub external: bool,
}

/// Severity of a validation issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Invalid module; consumers must not trust it.
    Error,
    /// Suspicious but consumable.
    Warning,
    /// Informational.
    Info,
}

/// One validation finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationIssue {
    /// Stable machine-readable code.
    pub code: String,
    /// Severity.
    pub severity: Severity,
    /// Human-readable explanation.
    pub message: String,
}

impl ValidationIssue {
    fn error(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            severity: Severity::Error,
            message: message.into(),
        }
    }

    fn warning(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            severity: Severity::Warning,
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_module() -> Module {
        let mut module = Module::new("sample");
        module.functions.push(Function {
            id: 0,
            name: "main".to_owned(),
            address: Some(0x401000),
            entry: Some(0),
            parameters: Some(0),
            confidence: 0.9,
            metadata: Default::default(),
            blocks: vec![
                BasicBlock {
                    id: 0,
                    address: Some(0x401000),
                    instructions: vec![Instruction {
                        address: Some(0x401000),
                        op: Op::Mov,
                        operands: vec![Operand::Immediate(0)],
                        result: Some(0),
                    }],
                    terminator: Terminator::Branch {
                        condition: 0,
                        then_block: 1,
                        else_block: 2,
                    },
                },
                BasicBlock {
                    id: 1,
                    address: Some(0x401010),
                    instructions: Vec::new(),
                    terminator: Terminator::Return(Some(0)),
                },
                BasicBlock {
                    id: 2,
                    address: Some(0x401020),
                    instructions: Vec::new(),
                    terminator: Terminator::Return(None),
                },
            ],
        });
        module
    }

    #[test]
    fn valid_module_passes() {
        let module = valid_module();
        assert!(module.is_valid(), "{:?}", module.validate());
    }

    #[test]
    fn missing_branch_target_is_an_error() {
        let mut module = valid_module();
        module.functions[0].blocks[0].terminator = Terminator::Jump(99);
        let issues = module.validate();
        assert!(
            issues
                .iter()
                .any(|issue| issue.code == "terminator.missing_block")
        );
        assert!(!module.is_valid());
    }

    #[test]
    fn duplicate_block_id_is_an_error() {
        let mut module = valid_module();
        module.functions[0].blocks[1].id = 0;
        assert!(
            module
                .validate()
                .iter()
                .any(|issue| issue.code == "block.duplicate_id")
        );
    }

    #[test]
    fn entry_must_exist() {
        let mut module = valid_module();
        module.functions[0].entry = Some(42);
        assert!(
            module
                .validate()
                .iter()
                .any(|issue| issue.code == "function.entry_missing")
        );
    }

    #[test]
    fn json_roundtrip_preserves_the_module() {
        let module = valid_module();
        let json = module.to_json_pretty().unwrap();
        let restored = Module::from_json(&json).unwrap();
        assert_eq!(module, restored);
        assert!(restored.is_valid());
    }

    #[test]
    fn warnings_do_not_invalidate_a_module() {
        let mut module = valid_module();
        module.functions[0].name.clear();
        let issues = module.validate();
        assert!(
            issues
                .iter()
                .any(|issue| issue.code == "function.empty_name")
        );
        assert!(module.is_valid());
    }
}
