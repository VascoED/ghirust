//! Heuristic pseudocode reconstruction from decoded x86/x86-64 functions.
//!
//! This is a real decompiler stage, not a re-formatted instruction listing. It
//! interprets the semantics of the supported instruction subset, tracks register
//! and stack-slot values, recognizes comparisons, calls and simple structured
//! control flow, and renders C-like pseudocode.
//!
//! Honest limitations:
//!
//! * SSE/AVX, x87, string operations and some system instructions are not
//!   modelled; they are reported and never silently treated as no-ops.
//! * Structured output covers forward if/else diamonds and natural loops with a
//!   comparison-only header. Irreducible or unusual control flow falls back to
//!   explicit labels and `goto` statements, which preserves semantics.
//! * Types are conservative. Registers and stack slots default to unsigned
//!   64-bit integers with explicit access widths where known.
//! * The result is semantically oriented pseudocode, not reconstructed source.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use iced_x86::{FlowControl, Instruction, Mnemonic, OpKind, Register};
use serde::{Deserialize, Serialize};

use crate::analysis::{DecodedBlock, DecodedFunction, DecodedInstruction, DecodedTerminator};
use crate::loader::LoadedProgram;

/// One recovered parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompiledParameter {
    /// Name used in the signature.
    pub name: String,
    /// Conservative C type.
    pub ty: String,
}

/// One recovered local or temporary variable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompiledVariable {
    /// Name used in the body.
    pub name: String,
    /// Conservative C type.
    pub ty: String,
    /// Evidence for the variable (`stack`, `register`, `temporary`).
    pub origin: String,
}

/// Result of the pseudocode stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompiledFunction {
    /// C-like signature.
    pub signature: String,
    /// Full annotated pseudocode.
    pub text: String,
    /// Parameters included in the signature.
    pub parameters: Vec<DecompiledParameter>,
    /// Declared locals and temporaries.
    pub locals: Vec<DecompiledVariable>,
    /// Return type.
    pub return_type: String,
    /// Confidence in the reconstruction.
    pub confidence: f32,
    /// Non-fatal limitations.
    pub warnings: Vec<String>,
    /// Instruction mnemonics that had no semantic model.
    pub unsupported_instructions: Vec<String>,
}

impl DecompiledFunction {
    /// Placeholder used when analysis explicitly disables decompilation.
    pub fn not_decompiled() -> Self {
        Self {
            signature: String::new(),
            text: "// Decompilation disabled for this analysis.\n".to_owned(),
            parameters: Vec::new(),
            locals: Vec::new(),
            return_type: "void".to_owned(),
            confidence: 0.0,
            warnings: vec!["decompilation was disabled by the analysis options".to_owned()],
            unsupported_instructions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallingConvention {
    Win64,
    SysV,
}

impl CallingConvention {
    fn argument_registers(self) -> [Register; 6] {
        match self {
            Self::Win64 => [
                Register::RCX,
                Register::RDX,
                Register::R8,
                Register::R9,
                Register::None,
                Register::None,
            ],
            Self::SysV => [
                Register::RDI,
                Register::RSI,
                Register::RDX,
                Register::RCX,
                Register::R8,
                Register::R9,
            ],
        }
    }

    fn argument_limit(self) -> usize {
        match self {
            Self::Win64 => 4,
            Self::SysV => 6,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Sar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnOp {
    Neg,
    Not,
    LogicalNot,
}

#[derive(Debug, Clone, PartialEq)]
enum Expr {
    Const(u64, u16),
    Var(String),
    Str(String),
    Addr(u64, Option<String>),
    Bin {
        op: BinOp,
        left: Box<Expr>,
        right: Box<Expr>,
        bits: u16,
    },
    Un {
        op: UnOp,
        value: Box<Expr>,
        bits: u16,
    },
    Load {
        address: Box<Expr>,
        bits: u16,
        signed: bool,
    },
    Cast {
        value: Box<Expr>,
        bits: u16,
        signed: bool,
    },
    Call {
        target: String,
        args: Vec<Expr>,
    },
    Select {
        condition: Box<Expr>,
        yes: Box<Expr>,
        no: Box<Expr>,
    },
    Cmp {
        op: CmpOp,
        left: Box<Expr>,
        right: Box<Expr>,
        bits: u16,
        signed: bool,
    },
    AddrOf(String),
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq)]
enum Target {
    Var(String),
    Memory { address: Expr, bits: u16 },
}

#[derive(Debug, Clone, PartialEq)]
enum Stmt {
    Assign(Target, Expr),
    #[allow(dead_code)]
    Expr(Expr),
    If {
        condition: Expr,
        then_body: Vec<Stmt>,
        else_body: Vec<Stmt>,
    },
    While {
        condition: Expr,
        body: Vec<Stmt>,
    },
    Return(Option<Expr>),
    Goto(String),
    Label(String),
    Break,
    Continue,
    Comment(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlagKind {
    Cmp,
    Test,
    Value,
}

#[derive(Debug, Clone)]
struct Flags {
    kind: FlagKind,
    left: Expr,
    right: Expr,
    bits: u16,
}

#[derive(Debug, Clone)]
struct LoopInfo {
    body_entry: usize,
    exit: usize,
    body: BTreeSet<usize>,
    latches: Vec<usize>,
}

#[derive(Debug, Clone, Copy)]
struct LoopFrame {
    header: usize,
    exit: usize,
}

impl Expr {
    fn is_zero(&self) -> bool {
        matches!(self, Expr::Const(0, _))
    }

    fn bin(op: BinOp, left: Expr, right: Expr, bits: u16) -> Self {
        if let (Expr::Const(a, _), Expr::Const(b, _)) = (&left, &right) {
            let value = match op {
                BinOp::Add => a.wrapping_add(*b),
                BinOp::Sub => a.wrapping_sub(*b),
                BinOp::Mul => a.wrapping_mul(*b),
                BinOp::And => a & b,
                BinOp::Or => a | b,
                BinOp::Xor => a ^ b,
                BinOp::Shl => a.wrapping_shl((*b as u32).min(63)),
                BinOp::Shr => a.wrapping_shr((*b as u32).min(63)),
                BinOp::Sar => ((*a as i64) >> ((*b as u32).min(63))) as u64,
                BinOp::Div | BinOp::Mod => 0,
            };
            if !matches!(op, BinOp::Div | BinOp::Mod) {
                return Expr::Const(value, bits);
            }
        }
        match op {
            BinOp::Add if right.is_zero() => return left,
            BinOp::Sub if right.is_zero() => return left,
            BinOp::Mul if matches!(right, Expr::Const(1, _)) => return left,
            BinOp::Or if right.is_zero() => return left,
            BinOp::Xor if right.is_zero() => return left,
            BinOp::And if left == right => return left,
            _ => {}
        }
        Expr::Bin {
            op,
            left: Box::new(left),
            right: Box::new(right),
            bits,
        }
    }

    fn cast(self, bits: u16, signed: bool) -> Self {
        if bits == 0 {
            return self;
        }
        Expr::Cast {
            value: Box::new(self),
            bits,
            signed,
        }
    }

    fn negate(self) -> Self {
        match self {
            Expr::Cmp {
                op,
                left,
                right,
                bits,
                signed,
            } => Expr::Cmp {
                op: match op {
                    CmpOp::Eq => CmpOp::Ne,
                    CmpOp::Ne => CmpOp::Eq,
                    CmpOp::Lt => CmpOp::Ge,
                    CmpOp::Le => CmpOp::Gt,
                    CmpOp::Gt => CmpOp::Le,
                    CmpOp::Ge => CmpOp::Lt,
                },
                left,
                right,
                bits,
                signed,
            },
            other => Expr::Un {
                op: UnOp::LogicalNot,
                value: Box::new(other),
                bits: 1,
            },
        }
    }

    fn render(&self) -> String {
        match self {
            Expr::Const(value, _) => {
                if *value <= 9 {
                    value.to_string()
                } else {
                    format!("0x{value:x}")
                }
            }
            Expr::Var(name) => name.clone(),
            Expr::Str(value) => c_string_literal(value),
            Expr::Addr(_address, Some(name)) => name.clone(),
            Expr::Addr(address, None) => format!("0x{address:x}"),
            Expr::Bin {
                op, left, right, ..
            } => format!(
                "({} {} {})",
                left.render(),
                match op {
                    BinOp::Add => "+",
                    BinOp::Sub => "-",
                    BinOp::Mul => "*",
                    BinOp::Div => "/",
                    BinOp::Mod => "%",
                    BinOp::And => "&",
                    BinOp::Or => "|",
                    BinOp::Xor => "^",
                    BinOp::Shl => "<<",
                    BinOp::Shr => ">>",
                    BinOp::Sar => ">>",
                },
                right.render()
            ),
            Expr::Un { op, value, .. } => format!(
                "{}{}",
                match op {
                    UnOp::Neg => "-",
                    UnOp::Not => "~",
                    UnOp::LogicalNot => "!",
                },
                value.render()
            ),
            Expr::Load {
                address,
                bits,
                signed,
            } => format!("*({} *)({})", int_type(*bits, *signed), address.render()),
            Expr::Cast {
                value,
                bits,
                signed,
            } => format!("({}){}", int_type(*bits, *signed), parenthesize(value)),
            Expr::Call { target, args } => format!(
                "{}({})",
                target,
                args.iter()
                    .map(|arg| arg.render())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Expr::Select { condition, yes, no } => format!(
                "({} ? {} : {})",
                condition.render(),
                yes.render(),
                no.render()
            ),
            Expr::Cmp {
                op, left, right, ..
            } => {
                let symbol = match op {
                    CmpOp::Eq => "==",
                    CmpOp::Ne => "!=",
                    CmpOp::Lt => "<",
                    CmpOp::Le => "<=",
                    CmpOp::Gt => ">",
                    CmpOp::Ge => ">=",
                };
                format!("({} {} {})", left.render(), symbol, right.render())
            }
            Expr::AddrOf(name) => format!("&{name}"),
            Expr::Unknown(text) => format!("/* {text} */"),
        }
    }
}

fn parenthesize(expr: &Expr) -> String {
    match expr {
        Expr::Var(_) | Expr::Const(_, _) | Expr::Addr(_, _) | Expr::Call { .. } => expr.render(),
        _ => format!("({})", expr.render()),
    }
}

fn int_type(bits: u16, signed: bool) -> String {
    let prefix = if signed { "int" } else { "uint" };
    match bits {
        1 => "bool".to_owned(),
        8 => format!("{prefix}8_t"),
        16 => format!("{prefix}16_t"),
        32 => format!("{prefix}32_t"),
        64 => format!("{prefix}64_t"),
        other => format!("{prefix}{other}_t"),
    }
}

fn c_string_literal(value: &str) -> String {
    let mut output = String::from("\"");
    for character in value.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '"' => output.push_str("\\\""),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => output.push('?'),
            character => output.push(character),
        }
    }
    output.push('"');
    output
}

fn full_register_name(register: Register) -> String {
    format!("{:?}", register.full_register()).to_ascii_lowercase()
}

fn register_bits(register: Register) -> u16 {
    (register.size() * 8) as u16
}

/// Decompile one decoded function.
pub fn decompile_function(
    program: &LoadedProgram,
    function: &DecodedFunction,
) -> DecompiledFunction {
    let convention = if program.format == "PE" {
        CallingConvention::Win64
    } else {
        CallingConvention::SysV
    };
    let mut decompiler = Decompiler::new(program, function, convention);
    let (body, used_parameters, locals, return_type, warnings, unsupported) = decompiler.run();
    let confidence = (function.confidence
        - 0.03 * unsupported.len() as f32
        - 0.01 * warnings.len().min(10) as f32)
        .clamp(0.05, 0.95);
    let parameters: Vec<DecompiledParameter> = (0..used_parameters)
        .map(|index| DecompiledParameter {
            name: format!("a{index}"),
            ty: "uint64_t".to_owned(),
        })
        .collect();
    let safe_name =
        safe_identifier(&function.name).unwrap_or_else(|| format!("FUN_{:x}", function.address));
    let signature = format!(
        "{} {}({})",
        return_type,
        safe_name,
        if parameters.is_empty() {
            "void".to_owned()
        } else {
            parameters
                .iter()
                .map(|parameter| format!("{} {}", parameter.ty, parameter.name))
                .collect::<Vec<_>>()
                .join(", ")
        }
    )
    .replace(" (void)", "(void)");

    let mut text = String::new();
    text.push_str("// Reconstructed by GHIRUST (heuristic decompiler)\n");
    text.push_str(&format!("// Address: 0x{:x}\n", function.address));
    text.push_str(&format!(
        "// Discovery: {} · confidence {:.0}%\n",
        function.discovery,
        confidence * 100.0
    ));
    text.push_str(
        "// This is pseudocode, not the original source. Verify semantics before reuse.\n",
    );
    if safe_name != function.name {
        text.push_str(&format!("// Symbol: {}\n", function.name));
    }
    for warning in &warnings {
        text.push_str(&format!("// warning: {warning}\n"));
    }
    if !unsupported.is_empty() {
        text.push_str(&format!(
            "// unsupported instruction models: {}\n",
            unsupported.join(", ")
        ));
    }
    text.push('\n');
    text.push_str(&signature);
    text.push_str("\n{\n");
    for local in &locals {
        text.push_str(&format!(
            "    {} {}; // {}\n",
            local.ty, local.name, local.origin
        ));
    }
    if !locals.is_empty() {
        text.push('\n');
    }
    let mut rendered = String::new();
    render_statements(&body, 1, &mut rendered);
    if rendered.is_empty() {
        text.push_str("    // no modelled operations\n");
    } else {
        text.push_str(&rendered);
    }
    text.push_str("}\n");

    DecompiledFunction {
        signature,
        text,
        parameters,
        locals,
        return_type,
        confidence,
        warnings,
        unsupported_instructions: unsupported,
    }
}

fn safe_identifier(name: &str) -> Option<String> {
    let mut output = String::new();
    for (index, character) in name.chars().enumerate() {
        let valid = character.is_ascii_alphanumeric() || character == '_';
        if index == 0 && character.is_ascii_digit() {
            return None;
        }
        if valid {
            output.push(character);
        } else {
            return None;
        }
    }
    if output.is_empty() || is_reserved(&output) {
        None
    } else {
        Some(output)
    }
}

fn is_reserved(name: &str) -> bool {
    matches!(
        name,
        "if" | "else"
            | "while"
            | "for"
            | "do"
            | "switch"
            | "case"
            | "return"
            | "goto"
            | "break"
            | "continue"
            | "int"
            | "char"
            | "void"
            | "long"
            | "short"
            | "unsigned"
            | "signed"
            | "struct"
            | "union"
            | "enum"
            | "typedef"
            | "static"
            | "extern"
            | "const"
            | "volatile"
            | "sizeof"
    )
}

struct Decompiler<'a> {
    program: &'a LoadedProgram,
    function: &'a DecodedFunction,
    convention: CallingConvention,
    env: HashMap<String, Expr>,
    flags: Option<Flags>,
    output: Vec<Stmt>,
    blocks: Vec<&'a DecodedBlock>,
    block_index: HashMap<u64, usize>,
    successors: Vec<Vec<usize>>,
    predecessors: Vec<Vec<usize>>,
    reachable: Vec<bool>,
    dominators: Vec<BTreeSet<usize>>,
    postdominators: Vec<BTreeSet<usize>>,
    immediate_postdominator: Vec<Option<usize>>,
    loops: HashMap<usize, LoopInfo>,
    rendered: Vec<bool>,
    labels: Vec<bool>,
    active_loops: Vec<LoopFrame>,
    locals: BTreeMap<String, (u16, String)>,
    used_parameters: BTreeSet<usize>,
    return_expressions: Vec<Option<Expr>>,
    warnings: Vec<String>,
    unsupported: BTreeSet<String>,
    unknown_flag_warned: bool,
}

impl<'a> Decompiler<'a> {
    fn new(
        program: &'a LoadedProgram,
        function: &'a DecodedFunction,
        convention: CallingConvention,
    ) -> Self {
        let blocks: Vec<&DecodedBlock> = function.blocks.iter().collect();
        let block_count = blocks.len();
        let block_index: HashMap<u64, usize> = blocks
            .iter()
            .enumerate()
            .map(|(index, block)| (block.start, index))
            .collect();
        let mut env = HashMap::new();
        for (index, register) in convention.argument_registers().iter().enumerate() {
            if *register != Register::None && index < convention.argument_limit() {
                env.insert(
                    full_register_name(*register),
                    Expr::Var(format!("a{index}")),
                );
            }
        }
        let mut decompiler = Self {
            program,
            function,
            convention,
            env,
            flags: None,
            output: Vec::new(),
            blocks,
            block_index,
            successors: Vec::new(),
            predecessors: Vec::new(),
            reachable: Vec::new(),
            dominators: Vec::new(),
            postdominators: Vec::new(),
            immediate_postdominator: Vec::new(),
            loops: HashMap::new(),
            rendered: vec![false; block_count],
            labels: vec![false; block_count],
            active_loops: Vec::new(),
            locals: BTreeMap::new(),
            used_parameters: BTreeSet::new(),
            return_expressions: Vec::new(),
            warnings: function.warnings.clone(),
            unsupported: BTreeSet::new(),
            unknown_flag_warned: false,
        };
        decompiler.compute_cfg();
        decompiler.compute_loops();
        decompiler.compute_labels();
        decompiler
    }

    fn run(
        &mut self,
    ) -> (
        Vec<Stmt>,
        usize,
        Vec<DecompiledVariable>,
        String,
        Vec<String>,
        Vec<String>,
    ) {
        let Some(entry) = self
            .block_index
            .get(&self.function.address)
            .copied()
            .or_else(|| self.blocks.first().map(|_| 0))
        else {
            return (
                vec![Stmt::Comment("function has no decoded blocks".to_owned())],
                0,
                Vec::new(),
                "void".to_owned(),
                vec!["function has no decoded blocks".to_owned()],
                Vec::new(),
            );
        };
        self.emit_block(entry, None);
        // Render blocks that were not reached by the structured walk. They are
        // still part of the recovered function and must not disappear silently.
        for index in 0..self.blocks.len() {
            if !self.rendered[index] {
                self.output.push(Stmt::Comment(format!(
                    "unreachable block at 0x{:x}",
                    self.blocks[index].start
                )));
                self.emit_block(index, None);
            }
        }
        if self.output.is_empty() {
            self.output.push(Stmt::Comment(
                "no operations could be reconstructed".to_owned(),
            ));
        }
        let has_return = self.return_expressions.iter().any(|expr| expr.is_some());
        let return_type = if has_return { "uint64_t" } else { "void" };
        let used_parameters = self
            .used_parameters
            .iter()
            .copied()
            .max()
            .map(|index| index + 1)
            .unwrap_or(0)
            .min(self.convention.argument_limit());
        let locals = self.declared_variables(used_parameters);
        let mut warnings = self.warnings.clone();
        warnings.sort();
        warnings.dedup();
        warnings.truncate(64);
        let unsupported: Vec<String> = self.unsupported.iter().cloned().collect();
        (
            std::mem::take(&mut self.output),
            used_parameters,
            locals,
            return_type.to_owned(),
            warnings,
            unsupported,
        )
    }

    fn compute_cfg(&mut self) {
        let count = self.blocks.len();
        let mut successors = vec![Vec::new(); count];
        let mut predecessors = vec![Vec::new(); count];
        for (index, block) in self.blocks.iter().enumerate() {
            let targets = match &block.terminator {
                DecodedTerminator::Fallthrough(target) => vec![*target],
                DecodedTerminator::Jump(target) => vec![*target],
                DecodedTerminator::Conditional {
                    target,
                    fallthrough,
                    ..
                } => vec![*target, *fallthrough],
                _ => Vec::new(),
            };
            for target in targets {
                if let Some(target) = self.block_index.get(&target).copied() {
                    successors[index].push(target);
                    predecessors[target].push(index);
                }
            }
        }
        for targets in &mut successors {
            targets.sort_unstable();
            targets.dedup();
        }
        for targets in &mut predecessors {
            targets.sort_unstable();
            targets.dedup();
        }
        let entry = self
            .block_index
            .get(&self.function.address)
            .copied()
            .unwrap_or(0);
        let mut reachable = vec![false; count];
        let mut queue = VecDeque::new();
        if count > 0 {
            reachable[entry] = true;
            queue.push_back(entry);
        }
        while let Some(node) = queue.pop_front() {
            for successor in &successors[node] {
                if !reachable[*successor] {
                    reachable[*successor] = true;
                    queue.push_back(*successor);
                }
            }
        }
        let reachable_set: BTreeSet<usize> = reachable
            .iter()
            .enumerate()
            .filter(|(_, value)| **value)
            .map(|(index, _)| index)
            .collect();
        let mut dominators = vec![BTreeSet::new(); count];
        for index in 0..count {
            if reachable[index] {
                if index == entry {
                    dominators[index].insert(index);
                } else {
                    dominators[index] = reachable_set.clone();
                }
            }
        }
        loop {
            let mut changed = false;
            for index in 0..count {
                if !reachable[index] || index == entry {
                    continue;
                }
                let mut intersection: Option<BTreeSet<usize>> = None;
                for predecessor in &predecessors[index] {
                    if !reachable[*predecessor] {
                        continue;
                    }
                    intersection = Some(match intersection {
                        None => dominators[*predecessor].clone(),
                        Some(current) => current
                            .intersection(&dominators[*predecessor])
                            .copied()
                            .collect(),
                    });
                }
                let mut next = intersection.unwrap_or_default();
                next.insert(index);
                if next != dominators[index] {
                    dominators[index] = next;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        let exits: Vec<usize> = (0..count)
            .filter(|index| reachable[*index] && successors[*index].is_empty())
            .collect();
        let mut postdominators = vec![BTreeSet::new(); count];
        for index in 0..count {
            if reachable[index] {
                if exits.contains(&index) {
                    postdominators[index].insert(index);
                } else {
                    postdominators[index] = reachable_set.clone();
                }
            }
        }
        loop {
            let mut changed = false;
            for index in (0..count).rev() {
                if !reachable[index] || exits.contains(&index) {
                    continue;
                }
                let mut intersection: Option<BTreeSet<usize>> = None;
                for successor in &successors[index] {
                    if !reachable[*successor] {
                        continue;
                    }
                    intersection = Some(match intersection {
                        None => postdominators[*successor].clone(),
                        Some(current) => current
                            .intersection(&postdominators[*successor])
                            .copied()
                            .collect(),
                    });
                }
                let mut next = intersection.unwrap_or_else(|| reachable_set.clone());
                next.insert(index);
                if next != postdominators[index] {
                    postdominators[index] = next;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        let mut immediate = vec![None; count];
        for index in 0..count {
            if !reachable[index] {
                continue;
            }
            let candidates: Vec<usize> = postdominators[index]
                .iter()
                .copied()
                .filter(|candidate| *candidate != index)
                .collect();
            immediate[index] = candidates
                .into_iter()
                .min_by_key(|candidate| (postdominators[*candidate].len(), *candidate));
        }
        self.successors = successors;
        self.predecessors = predecessors;
        self.reachable = reachable;
        self.dominators = dominators;
        self.postdominators = postdominators;
        self.immediate_postdominator = immediate;
    }

    fn compute_loops(&mut self) {
        for (source, targets) in self.successors.iter().enumerate() {
            for target in targets {
                if !self.reachable[source] || !self.reachable[*target] {
                    continue;
                }
                if !self.dominators[source].contains(target) {
                    continue;
                }
                let mut body = BTreeSet::new();
                body.insert(*target);
                body.insert(source);
                let mut stack = vec![source];
                while let Some(node) = stack.pop() {
                    for predecessor in &self.predecessors[node] {
                        if *predecessor != *target && !body.contains(predecessor) {
                            body.insert(*predecessor);
                            stack.push(*predecessor);
                        }
                    }
                }
                if body.len() > 512 {
                    continue;
                }
                let loop_info = self.loops.entry(*target).or_insert_with(|| LoopInfo {
                    body_entry: *target,
                    exit: *target,
                    body: BTreeSet::new(),
                    latches: Vec::new(),
                });
                loop_info.body.extend(body);
                loop_info.latches.push(source);
                let block = self.blocks[*target];
                if let DecodedTerminator::Conditional {
                    target: taken,
                    fallthrough,
                    ..
                } = &block.terminator
                {
                    let taken_index = self.block_index.get(taken).copied();
                    let fall_index = self.block_index.get(fallthrough).copied();
                    if let (Some(taken_index), Some(fall_index)) = (taken_index, fall_index) {
                        if loop_info.body.contains(&taken_index)
                            && !loop_info.body.contains(&fall_index)
                        {
                            loop_info.body_entry = taken_index;
                            loop_info.exit = fall_index;
                        } else if loop_info.body.contains(&fall_index)
                            && !loop_info.body.contains(&taken_index)
                        {
                            loop_info.body_entry = fall_index;
                            loop_info.exit = taken_index;
                        }
                    }
                } else if let DecodedTerminator::Conditional {
                    target: taken,
                    fallthrough,
                    ..
                } = &self.blocks[source].terminator
                {
                    // The header is a plain body block; the latch carries the
                    // condition. The exit is the latch successor that does not
                    // jump back to the header.
                    let taken_index = self.block_index.get(taken).copied();
                    let fall_index = self.block_index.get(fallthrough).copied();
                    if taken_index == Some(*target) {
                        if let Some(fall_index) = fall_index {
                            loop_info.exit = fall_index;
                        }
                    } else if fall_index == Some(*target) {
                        if let Some(taken_index) = taken_index {
                            loop_info.exit = taken_index;
                        }
                    }
                }
            }
        }
        // Keep only loops with a usable header and exit.
        self.loops
            .retain(|header, info| *header != info.exit && !info.latches.is_empty());
    }

    fn compute_labels(&mut self) {
        let mut labels = vec![false; self.blocks.len()];
        for (index, block) in self.blocks.iter().enumerate() {
            match &block.terminator {
                DecodedTerminator::Jump(target) => {
                    if let Some(target) = self.block_index.get(target) {
                        if self.immediate_postdominator[index] != Some(*target) {
                            labels[*target] = true;
                        }
                    }
                }
                DecodedTerminator::Conditional {
                    target,
                    fallthrough,
                    ..
                } if self.immediate_postdominator[index].is_none() => {
                    if let Some(target) = self.block_index.get(target) {
                        labels[*target] = true;
                    }
                    if let Some(target) = self.block_index.get(fallthrough) {
                        labels[*target] = true;
                    }
                }
                _ => {}
            }
        }
        for header in self.loops.keys() {
            labels[*header] = true;
        }
        self.labels = labels;
    }

    fn emit_block(&mut self, index: usize, stop: Option<usize>) -> bool {
        if Some(index) == stop {
            return true;
        }
        if index >= self.blocks.len() {
            return true;
        }
        if self.rendered[index] {
            self.output.push(Stmt::Goto(self.label_name(index)));
            return false;
        }
        if let Some(loop_info) = self.loops.get(&index).cloned() {
            if self.try_emit_loop(index, &loop_info, stop) {
                return true;
            }
        }
        self.rendered[index] = true;
        if self.labels[index] {
            self.output.push(Stmt::Label(self.label_name(index)));
        }
        self.execute_block(index);
        let block = self.blocks[index];
        match &block.terminator {
            DecodedTerminator::Fallthrough(target) => {
                if let Some(target) = self.block_index.get(target).copied() {
                    self.emit_block(target, stop)
                } else {
                    true
                }
            }
            DecodedTerminator::Jump(target) => {
                let Some(target_index) = self.block_index.get(target).copied() else {
                    self.output.push(Stmt::Comment(format!(
                        "jump outside the recovered function to 0x{target:x}"
                    )));
                    return false;
                };
                if Some(target_index) == stop {
                    return true;
                }
                if self.is_loop_continue(target_index) {
                    self.output.push(Stmt::Continue);
                    return false;
                }
                if self.is_loop_exit(target_index) {
                    self.output.push(Stmt::Break);
                    return false;
                }
                if self.is_sequential_next(index, target_index) && !self.rendered[target_index] {
                    return self.emit_block(target_index, stop);
                }
                self.output.push(Stmt::Goto(self.label_name(target_index)));
                false
            }
            DecodedTerminator::Conditional {
                mnemonic,
                target,
                fallthrough,
            } => self.emit_conditional(index, *mnemonic, *target, *fallthrough, stop),
            DecodedTerminator::Return => {
                let expression = self.env.get("rax").cloned();
                self.return_expressions.push(expression.clone());
                self.output.push(Stmt::Return(expression));
                false
            }
            DecodedTerminator::IndirectJump => {
                self.output.push(Stmt::Comment(
                    "indirect jump; target is not statically known".to_owned(),
                ));
                false
            }
            DecodedTerminator::TailCall(target) => {
                self.output.push(Stmt::Comment(format!(
                    "tail call to 0x{target:x}; the callee returns to the caller"
                )));
                false
            }
            DecodedTerminator::Unreachable => {
                self.output.push(Stmt::Comment(
                    "execution stops here (trap or unsupported flow)".to_owned(),
                ));
                false
            }
        }
    }

    fn try_emit_loop(&mut self, index: usize, info: &LoopInfo, stop: Option<usize>) -> bool {
        let block = self.blocks[index];
        let (mnemonic, target, fallthrough) = match &block.terminator {
            DecodedTerminator::Conditional {
                mnemonic,
                target,
                fallthrough,
            } => (*mnemonic, *target, *fallthrough),
            _ => return false,
        };
        let taken_index = self.block_index.get(&target).copied();
        let fall_index = self.block_index.get(&fallthrough).copied();
        // Do-while shape: the header block contains the body and branches back
        // to itself. Loop-carried registers must be treated as variables, never
        // as the constants seen on the first iteration.
        if taken_index == Some(index) || fall_index == Some(index) {
            let exit = if taken_index == Some(index) {
                fall_index
            } else {
                taken_index
            };
            let Some(exit) = exit else {
                return false;
            };
            if exit == index {
                return false;
            }
            self.rendered[index] = true;
            if self.labels[index] {
                self.output.push(Stmt::Label(self.label_name(index)));
            }
            for register in modified_registers(block) {
                self.env.insert(register.clone(), Expr::Var(register));
            }
            let saved_output = std::mem::take(&mut self.output);
            self.execute_block(index);
            let mut body = std::mem::replace(&mut self.output, saved_output);
            let Some(condition) = self.condition_for(mnemonic) else {
                self.warnings.push(format!(
                    "loop at 0x{:x} has no modelled condition",
                    block.start
                ));
                return false;
            };
            let continue_condition = if taken_index == Some(index) {
                condition
            } else {
                condition.negate()
            };
            body.push(Stmt::If {
                condition: continue_condition.negate(),
                then_body: vec![Stmt::Break],
                else_body: Vec::new(),
            });
            for register in modified_registers(block) {
                self.env.insert(register.clone(), Expr::Var(register));
            }
            self.flags = None;
            self.output.push(Stmt::While {
                condition: Expr::Const(1, 64),
                body,
            });
            if Some(exit) == stop {
                return true;
            }
            return self.emit_block(exit, stop);
        }
        // Two-block do-while: the header falls through to a latch that tests the
        // condition and branches back. This is the shape produced for simple
        // scalar loops by optimizing compilers.
        if info.body_entry == index {
            for latch in info.latches.iter().copied() {
                if latch == index {
                    continue;
                }
                let latch_block = self.blocks[latch];
                let (latch_mnemonic, latch_target, latch_fallthrough) =
                    match &latch_block.terminator {
                        DecodedTerminator::Conditional {
                            mnemonic,
                            target,
                            fallthrough,
                        } => (*mnemonic, *target, *fallthrough),
                        _ => continue,
                    };
                let latch_taken = self.block_index.get(&latch_target).copied();
                let latch_fall = self.block_index.get(&latch_fallthrough).copied();
                let continues_on_taken = if latch_taken == Some(index) {
                    true
                } else if latch_fall == Some(index) {
                    false
                } else {
                    continue;
                };
                let header_falls_to_latch = match &block.terminator {
                    DecodedTerminator::Fallthrough(target) | DecodedTerminator::Jump(target) => {
                        self.block_index.get(target).copied() == Some(latch)
                    }
                    _ => false,
                };
                if !header_falls_to_latch {
                    continue;
                }
                let exit = if continues_on_taken {
                    latch_fall
                } else {
                    latch_taken
                };
                let Some(exit) = exit else {
                    continue;
                };
                if exit == index || exit == latch {
                    continue;
                }
                let latch_start = latch_block.start;
                let modified: BTreeSet<String> = modified_registers(block)
                    .into_iter()
                    .chain(modified_registers(latch_block))
                    .collect();
                self.rendered[index] = true;
                self.rendered[latch] = true;
                if self.labels[index] {
                    self.output.push(Stmt::Label(self.label_name(index)));
                }
                for register in &modified {
                    self.env
                        .insert(register.clone(), Expr::Var(register.clone()));
                }
                let saved_output = std::mem::take(&mut self.output);
                self.execute_block(index);
                self.execute_block(latch);
                let mut body = std::mem::replace(&mut self.output, saved_output);
                let Some(condition) = self.condition_for(latch_mnemonic) else {
                    self.warnings.push(format!(
                        "loop latch at 0x{:x} has no modelled condition",
                        latch_start
                    ));
                    return false;
                };
                let continue_condition = if continues_on_taken {
                    condition
                } else {
                    condition.negate()
                };
                body.push(Stmt::If {
                    condition: continue_condition.negate(),
                    then_body: vec![Stmt::Break],
                    else_body: Vec::new(),
                });
                for register in &modified {
                    self.env
                        .insert(register.clone(), Expr::Var(register.clone()));
                }
                self.flags = None;
                self.output.push(Stmt::While {
                    condition: Expr::Const(1, 64),
                    body,
                });
                if Some(exit) == stop {
                    return true;
                }
                return self.emit_block(exit, stop);
            }
        }
        // The loop condition is only reconstructed when the header's operations
        // are pure comparisons. Otherwise the block is rendered normally and the
        // CFG falls back to labels, which is still semantically faithful.
        if block.instructions.iter().any(|item| {
            !matches!(
                item.instruction.mnemonic(),
                Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Nop
            )
        }) {
            return false;
        }
        let (Some(taken_index), Some(fall_index)) = (taken_index, fall_index) else {
            return false;
        };
        let body_entry = if taken_index == info.body_entry {
            taken_index
        } else if fall_index == info.body_entry {
            fall_index
        } else {
            return false;
        };
        let exit = if body_entry == taken_index {
            fall_index
        } else {
            taken_index
        };
        if exit == body_entry || exit == index {
            return false;
        }
        self.rendered[index] = true;
        if self.labels[index] {
            self.output.push(Stmt::Label(self.label_name(index)));
        }
        // Comparison-only header: executing it produces no statements, but sets
        // the flags used by the loop condition.
        self.execute_block(index);
        let Some(condition) = self.condition_for(mnemonic) else {
            self.warnings.push(format!(
                "loop header at 0x{:x} has no modelled condition",
                block.start
            ));
            return false;
        };
        let condition = if body_entry == taken_index {
            condition
        } else {
            condition.negate()
        };
        let environment_before = self.env.clone();
        self.active_loops.push(LoopFrame {
            header: index,
            exit,
        });
        let (body, end_env, _) = self.capture_region(body_entry, Some(index));
        self.active_loops.pop();
        let body_is_empty = body.is_empty();
        self.env = merge_environments(&environment_before, &end_env, &environment_before);
        self.flags = None;
        self.output.push(Stmt::While { condition, body });
        if body_is_empty {
            self.warnings.push(format!(
                "loop at 0x{:x} has an empty reconstructed body",
                block.start
            ));
        }
        if Some(exit) == stop {
            return true;
        }
        // A loop may be nested in a branch region; continue after it only when
        // it is not the region terminator.
        self.emit_block(exit, stop)
    }

    fn emit_conditional(
        &mut self,
        index: usize,
        mnemonic: Mnemonic,
        target: u64,
        fallthrough: u64,
        stop: Option<usize>,
    ) -> bool {
        let Some(condition) = self.condition_for(mnemonic) else {
            self.warnings.push(format!(
                "conditional branch at 0x{:x} could not be reconstructed; using labels",
                self.blocks[index].end
            ));
            let target_index = self.block_index.get(&target).copied();
            let fall_index = self.block_index.get(&fallthrough).copied();
            if let Some(target_index) = target_index {
                self.output.push(Stmt::If {
                    condition: Expr::Unknown("unmodelled condition".to_owned()),
                    then_body: vec![Stmt::Goto(self.label_name(target_index))],
                    else_body: Vec::new(),
                });
            }
            if let Some(fall_index) = fall_index {
                return self.emit_block(fall_index, stop);
            }
            return false;
        };
        let target_index = self.block_index.get(&target).copied();
        let fall_index = self.block_index.get(&fallthrough).copied();
        if let Some(target_index) = target_index {
            if self.is_loop_continue(target_index) {
                self.output.push(Stmt::If {
                    condition,
                    then_body: vec![Stmt::Continue],
                    else_body: Vec::new(),
                });
                if let Some(fall_index) = fall_index {
                    return self.emit_block(fall_index, stop);
                }
                return true;
            }
            if self.is_loop_exit(target_index) {
                self.output.push(Stmt::If {
                    condition,
                    then_body: vec![Stmt::Break],
                    else_body: Vec::new(),
                });
                if let Some(fall_index) = fall_index {
                    return self.emit_block(fall_index, stop);
                }
                return true;
            }
        }
        if target_index == stop {
            // Branch leaves the current structured region; the other path
            // continues inside it.
            if let Some(fall_index) = fall_index {
                return self.emit_block(fall_index, stop);
            }
            return true;
        }
        if let Some(fall_index) = fall_index {
            if stop == Some(fall_index) {
                self.output.push(Stmt::If {
                    condition: condition.negate(),
                    then_body: vec![Stmt::Goto(
                        self.label_name(target_index.unwrap_or(fall_index)),
                    )],
                    else_body: Vec::new(),
                });
                return true;
            }
        }
        let join = self.immediate_postdominator[index]
            .filter(|join| *join != index)
            .filter(|join| Some(*join) != stop);
        let Some(join) = join else {
            // No postdominator: emit an explicit branch and continue at the
            // fallthrough. Gotos preserve the real CFG.
            if let Some(target_index) = target_index {
                self.output.push(Stmt::If {
                    condition,
                    then_body: vec![Stmt::Goto(self.label_name(target_index))],
                    else_body: Vec::new(),
                });
            }
            if let Some(fall_index) = fall_index {
                return self.emit_block(fall_index, stop);
            }
            return false;
        };
        let (Some(target_index), Some(fall_index)) = (target_index, fall_index) else {
            return false;
        };
        let environment = self.env.clone();
        let flags = self.flags.clone();
        let (then_body, then_env, then_falls) = self.capture_region(target_index, Some(join));
        let (else_body, else_env, else_falls) = self.capture_region(fall_index, Some(join));
        self.env = merge_environments(&environment, &then_env, &else_env);
        self.flags = flags;
        self.flags = None;
        self.output.push(Stmt::If {
            condition,
            then_body,
            else_body,
        });
        if then_falls || else_falls {
            self.emit_block(join, stop)
        } else {
            false
        }
    }

    fn capture_region(
        &mut self,
        entry: usize,
        stop: Option<usize>,
    ) -> (Vec<Stmt>, HashMap<String, Expr>, bool) {
        let saved_output = std::mem::take(&mut self.output);
        let saved_env = self.env.clone();
        let saved_flags = self.flags.clone();
        let saved_loops = self.active_loops.clone();
        let falls = self.emit_block(entry, stop);
        let body = std::mem::replace(&mut self.output, saved_output);
        let end_env = std::mem::replace(&mut self.env, saved_env);
        self.flags = saved_flags;
        self.active_loops = saved_loops;
        (body, end_env, falls)
    }

    fn execute_block(&mut self, index: usize) {
        let instructions = self.blocks[index].instructions.clone();
        for item in instructions {
            self.execute_instruction(&item);
        }
    }

    fn execute_instruction(&mut self, item: &DecodedInstruction) {
        let instruction = &item.instruction;
        if instruction.is_invalid() {
            return;
        }
        let mnemonic = instruction.mnemonic();
        match mnemonic {
            Mnemonic::Nop | Mnemonic::Endbr64 | Mnemonic::Endbr32 => {}
            Mnemonic::Push | Mnemonic::Pop => {
                // Stack bookkeeping. `push` arguments to calls are not modelled
                // on x86-64 because the supported ABIs pass the first arguments
                // in registers; extra stack arguments are reported as unsupported.
                if matches!(
                    instruction.flow_control(),
                    FlowControl::Call | FlowControl::IndirectCall
                ) {
                    self.unsupported.insert(format!("{mnemonic:?}"));
                }
            }
            Mnemonic::Leave => {}
            Mnemonic::Mov => self.execute_mov(instruction),
            Mnemonic::Lea => self.execute_lea(instruction),
            Mnemonic::Movzx => self.execute_movx(instruction, false),
            Mnemonic::Movsx | Mnemonic::Movsxd => self.execute_movx(instruction, true),
            Mnemonic::Add
            | Mnemonic::Sub
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Xor
            | Mnemonic::Shl
            | Mnemonic::Sal
            | Mnemonic::Shr
            | Mnemonic::Sar => self.execute_arithmetic(instruction),
            Mnemonic::Inc | Mnemonic::Dec | Mnemonic::Neg | Mnemonic::Not => {
                self.execute_unary(instruction)
            }
            Mnemonic::Imul if instruction.op_count() >= 2 => self.execute_arithmetic(instruction),
            Mnemonic::Imul => self.execute_mul_div(instruction),
            Mnemonic::Mul | Mnemonic::Div | Mnemonic::Idiv => self.execute_mul_div(instruction),
            Mnemonic::Cmp | Mnemonic::Test => self.execute_compare(instruction),
            Mnemonic::Call => self.execute_call(instruction),
            Mnemonic::Cdqe | Mnemonic::Cwde | Mnemonic::Cbw => {
                // Sign extension of the accumulator; the next use carries the
                // full-width value already, so no output statement is needed.
            }
            Mnemonic::Cdq | Mnemonic::Cqo => {}
            Mnemonic::Sete
            | Mnemonic::Setne
            | Mnemonic::Setb
            | Mnemonic::Setae
            | Mnemonic::Setbe
            | Mnemonic::Seta
            | Mnemonic::Sets
            | Mnemonic::Setns
            | Mnemonic::Setl
            | Mnemonic::Setge
            | Mnemonic::Setle
            | Mnemonic::Setg
            | Mnemonic::Cmove
            | Mnemonic::Cmovne
            | Mnemonic::Cmovb
            | Mnemonic::Cmovae
            | Mnemonic::Cmovbe
            | Mnemonic::Cmova
            | Mnemonic::Cmovs
            | Mnemonic::Cmovns
            | Mnemonic::Cmovl
            | Mnemonic::Cmovge
            | Mnemonic::Cmovle
            | Mnemonic::Cmovg => self.execute_setcmov(instruction),
            Mnemonic::Ret
            | Mnemonic::Jmp
            | Mnemonic::Je
            | Mnemonic::Jne
            | Mnemonic::Jb
            | Mnemonic::Jae
            | Mnemonic::Jbe
            | Mnemonic::Ja
            | Mnemonic::Js
            | Mnemonic::Jns
            | Mnemonic::Jl
            | Mnemonic::Jge
            | Mnemonic::Jle
            | Mnemonic::Jg
            | Mnemonic::Jo
            | Mnemonic::Jno
            | Mnemonic::Jp
            | Mnemonic::Jnp
            | Mnemonic::Jrcxz
            | Mnemonic::Jecxz
            | Mnemonic::Jcxz => {}
            other => {
                let name = format!("{other:?}").to_ascii_lowercase();
                if !self.unsupported.contains(&name) {
                    self.unsupported.insert(name.clone());
                    self.warnings.push(format!(
                        "instruction '{name}' at 0x{:x} has no semantic model",
                        instruction.ip()
                    ));
                }
            }
        }
    }

    fn execute_mov(&mut self, instruction: &Instruction) {
        if instruction.op_count() < 2 {
            return;
        }
        let destination = self.destination(instruction, 0);
        let bits = operand_bits(instruction, 1).max(operand_bits(instruction, 0));
        let source = self.read_operand(instruction, 1, bits);
        // Drop frame construction: mov rbp, rsp / mov rsp, rbp.
        if is_register(instruction, 0, Register::RBP) && is_register(instruction, 1, Register::RSP)
        {
            return;
        }
        if is_register(instruction, 0, Register::RSP) && is_register(instruction, 1, Register::RBP)
        {
            return;
        }
        if is_stack_pointer(instruction, 0) && matches!(source, Expr::Const(_, _)) {
            return;
        }
        let Some(destination) = destination else {
            self.unsupported
                .insert("mov-to-unsupported-operand".to_owned());
            return;
        };
        if let Target::Var(name) = &destination {
            if source == Expr::Var(name.clone()) {
                return;
            }
        }
        self.emit_assign(destination, source);
    }

    /// Emit an assignment and keep the symbolic environment in sync. Without
    /// this, later reads would keep using entry-state parameter expressions and
    /// the pseudocode would be wrong even though it looked plausible.
    fn emit_assign(&mut self, target: Target, value: Expr) {
        if let Target::Var(name) = &target {
            // `x = x + 1` changes the meaning of `x`. Keeping the expanded
            // expression in the environment would make later reads inside or
            // after a loop add the increment twice. Fall back to the variable
            // itself for self-referential updates.
            if expression_contains_variable(&value, name) {
                self.env.insert(name.clone(), Expr::Var(name.clone()));
            } else {
                self.env.insert(name.clone(), value.clone());
            }
        }
        self.output.push(Stmt::Assign(target, value));
    }

    fn execute_lea(&mut self, instruction: &Instruction) {
        if instruction.op_count() < 2 || instruction.op_kind(1) != OpKind::Memory {
            return;
        }
        let Some(destination) = self.destination(instruction, 0) else {
            return;
        };
        let address = self.memory_address(instruction);
        let value = if let Some(name) = stack_local_from_destination(&destination) {
            Expr::AddrOf(name)
        } else {
            address
        };
        self.emit_assign(destination, value);
    }

    fn execute_movx(&mut self, instruction: &Instruction, signed: bool) {
        if instruction.op_count() < 2 {
            return;
        }
        let Some(destination) = self.destination(instruction, 0) else {
            return;
        };
        let source_bits = operand_bits(instruction, 1);
        let source = self.read_operand(instruction, 1, source_bits);
        let destination_bits = operand_bits(instruction, 0);
        self.emit_assign(
            destination,
            source.cast(destination_bits.max(source_bits), signed),
        );
    }

    fn execute_arithmetic(&mut self, instruction: &Instruction) {
        let mnemonic = instruction.mnemonic();
        if instruction.op_count() == 0 {
            return;
        }
        // Stack allocation/adjustment is frame bookkeeping, not user logic.
        if is_stack_pointer(instruction, 0)
            && matches!(mnemonic, Mnemonic::Add | Mnemonic::Sub)
            && instruction.op_count() >= 2
            && matches!(
                instruction.op_kind(1),
                OpKind::Immediate8
                    | OpKind::Immediate16
                    | OpKind::Immediate32
                    | OpKind::Immediate64
                    | OpKind::Immediate8to16
                    | OpKind::Immediate8to32
                    | OpKind::Immediate8to64
                    | OpKind::Immediate32to64
            )
        {
            return;
        }
        let bits = operand_bits(instruction, 0).max(operand_bits(instruction, 1));
        let Some(destination) = self.destination(instruction, 0) else {
            return;
        };
        // `xor r, r` and `sub r, r` do not semantically use the old value. Do
        // not mark an argument register as consumed when it is only zeroed.
        if instruction.op_count() >= 2
            && same_operand(instruction, 0, 1)
            && matches!(mnemonic, Mnemonic::Xor | Mnemonic::Sub)
        {
            self.emit_assign(destination, Expr::Const(0, bits));
            self.flags = Some(Flags {
                kind: FlagKind::Value,
                left: Expr::Const(0, bits),
                right: Expr::Const(0, bits),
                bits,
            });
            return;
        }
        let current = self.read_destination(instruction, 0, bits);
        let right = self.read_operand(instruction, 1, bits);
        let op = match mnemonic {
            Mnemonic::Add => BinOp::Add,
            Mnemonic::Sub => BinOp::Sub,
            Mnemonic::And => BinOp::And,
            Mnemonic::Or => BinOp::Or,
            Mnemonic::Xor => BinOp::Xor,
            Mnemonic::Shl | Mnemonic::Sal => BinOp::Shl,
            Mnemonic::Shr => BinOp::Shr,
            Mnemonic::Sar => BinOp::Sar,
            Mnemonic::Imul => {
                let right2 = if instruction.op_count() >= 3 {
                    self.read_operand(instruction, 2, bits)
                } else {
                    right.clone()
                };
                let value = Expr::bin(BinOp::Mul, current, right2, bits);
                self.assign_arithmetic(destination, value, instruction, bits);
                return;
            }
            _ => return,
        };
        let mut value = Expr::bin(op, current, right, bits);
        if mnemonic == Mnemonic::Xor
            && instruction.op_count() >= 2
            && same_operand(instruction, 0, 1)
        {
            value = Expr::Const(0, bits);
        }
        if mnemonic == Mnemonic::Sub
            && instruction.op_count() >= 2
            && same_operand(instruction, 0, 1)
        {
            value = Expr::Const(0, bits);
        }
        self.assign_arithmetic(destination, value, instruction, bits);
        if matches!(mnemonic, Mnemonic::And | Mnemonic::Or | Mnemonic::Xor) {
            self.flags = Some(Flags {
                kind: FlagKind::Value,
                left: self.read_destination(instruction, 0, bits),
                right: Expr::Const(0, bits),
                bits,
            });
        }
    }

    fn assign_arithmetic(
        &mut self,
        destination: Target,
        value: Expr,
        instruction: &Instruction,
        bits: u16,
    ) {
        // Track stack-slot widths for declarations.
        if let Target::Var(name) = &destination {
            if name.starts_with("local_") {
                self.locals
                    .entry(name.clone())
                    .or_insert_with(|| (bits, "stack".to_owned()));
            }
        }
        if let Target::Memory {
            address,
            bits: access_bits,
        } = &destination
        {
            self.emit_assign(
                Target::Memory {
                    address: address.clone(),
                    bits: *access_bits,
                },
                value,
            );
            return;
        }
        let _ = instruction;
        let _ = bits;
        self.emit_assign(destination, value);
    }

    fn execute_unary(&mut self, instruction: &Instruction) {
        if instruction.op_count() == 0 {
            return;
        }
        let bits = operand_bits(instruction, 0);
        let Some(destination) = self.destination(instruction, 0) else {
            return;
        };
        let current = self.read_destination(instruction, 0, bits);
        let value = match instruction.mnemonic() {
            Mnemonic::Inc => Expr::bin(BinOp::Add, current, Expr::Const(1, bits), bits),
            Mnemonic::Dec => Expr::bin(BinOp::Sub, current, Expr::Const(1, bits), bits),
            Mnemonic::Neg => Expr::Un {
                op: UnOp::Neg,
                value: Box::new(current),
                bits,
            },
            Mnemonic::Not => Expr::Un {
                op: UnOp::Not,
                value: Box::new(current),
                bits,
            },
            _ => return,
        };
        self.emit_assign(destination, value);
    }

    fn execute_mul_div(&mut self, instruction: &Instruction) {
        if instruction.op_count() == 0 {
            return;
        }
        let mnemonic = instruction.mnemonic();
        let source = self.read_operand(instruction, 0, operand_bits(instruction, 0));
        let accumulator = self
            .env
            .get("rax")
            .cloned()
            .unwrap_or_else(|| Expr::Var("rax".to_owned()));
        let bits = 64;
        match mnemonic {
            Mnemonic::Mul | Mnemonic::Imul => {
                let value = Expr::bin(BinOp::Mul, accumulator, source, bits);
                self.emit_assign(Target::Var("rax".to_owned()), value);
            }
            Mnemonic::Div | Mnemonic::Idiv => {
                let quotient = Expr::bin(BinOp::Div, accumulator.clone(), source.clone(), bits);
                let remainder = Expr::bin(BinOp::Mod, accumulator, source, bits);
                self.emit_assign(Target::Var("rax".to_owned()), quotient);
                self.emit_assign(Target::Var("rdx".to_owned()), remainder);
            }
            _ => {}
        }
    }

    fn execute_compare(&mut self, instruction: &Instruction) {
        if instruction.op_count() < 2 {
            return;
        }
        let bits = operand_bits(instruction, 0).max(operand_bits(instruction, 1));
        let left = self.read_operand(instruction, 0, bits);
        let right = self.read_operand(instruction, 1, bits);
        self.flags = Some(Flags {
            kind: if instruction.mnemonic() == Mnemonic::Test {
                FlagKind::Test
            } else {
                FlagKind::Cmp
            },
            left,
            right,
            bits,
        });
    }

    fn execute_call(&mut self, instruction: &Instruction) {
        let target = self.call_target(instruction);
        let mut args = Vec::new();
        for register in self.convention.argument_registers() {
            if register == Register::None {
                break;
            }
            let key = full_register_name(register);
            if let Some(expression) = self.env.get(&key) {
                // Do not pass an unresolved register as a fabricated argument.
                if !matches!(expression, Expr::Var(name) if name == &key) {
                    args.push(expression.clone());
                }
            }
        }
        let call = Expr::Call {
            target: target.clone(),
            args,
        };
        self.emit_assign(Target::Var("rax".to_owned()), call.clone());
        // Calling conventions clobber volatile registers.
        let volatile = if self.convention == CallingConvention::Win64 {
            &["rcx", "rdx", "r8", "r9", "r10", "r11"][..]
        } else {
            &["rdi", "rsi", "rdx", "rcx", "r8", "r9", "r10", "r11"][..]
        };
        for register in volatile {
            self.env
                .insert((*register).to_owned(), Expr::Var((*register).to_owned()));
        }
        self.env.insert("rax".to_owned(), call);
        if self.convention == CallingConvention::Win64 {
            for register in ["rbx", "rbp", "r12", "r13", "r14", "r15"] {
                if !self.env.contains_key(register) {
                    self.env
                        .insert(register.to_owned(), Expr::Var(register.to_owned()));
                }
            }
        }
    }

    fn call_target(&self, instruction: &Instruction) -> String {
        if instruction.op_count() > 0 {
            if instruction.op_kind(0) == OpKind::NearBranch64 {
                let address = instruction.near_branch_target();
                return self.program.name_for(address);
            }
            if instruction.op_kind(0) == OpKind::Memory {
                if instruction.is_ip_rel_memory_operand() {
                    let address = instruction.ip_rel_memory_address();
                    if let Some(symbol) = self.program.symbol_at(address) {
                        return symbol.name.clone();
                    }
                    if let Some(import) = self.program.imports.iter().find(|import| {
                        import.name == format!("{}", address) || import.name.is_empty()
                    }) {
                        return import.name.clone();
                    }
                    return format!("(*0x{address:x})");
                }
                return "(*indirect)".to_owned();
            }
        }
        "(*indirect)".to_owned()
    }

    fn execute_setcmov(&mut self, instruction: &Instruction) {
        let Some(condition) = self.condition_for(instruction.mnemonic()) else {
            return;
        };
        if instruction.op_count() == 0 {
            return;
        }
        if format!("{:?}", instruction.mnemonic()).starts_with("Cmov") {
            if instruction.op_count() < 2 {
                return;
            }
            let bits = operand_bits(instruction, 0);
            let Some(destination) = self.destination(instruction, 0) else {
                return;
            };
            let current = self.read_destination(instruction, 0, bits);
            let source = self.read_operand(instruction, 1, bits);
            self.emit_assign(
                destination,
                Expr::Select {
                    condition: Box::new(condition),
                    yes: Box::new(source),
                    no: Box::new(current),
                },
            );
        } else {
            let bits = operand_bits(instruction, 0);
            let Some(destination) = self.destination(instruction, 0) else {
                return;
            };
            self.emit_assign(
                destination,
                Expr::Select {
                    condition: Box::new(condition),
                    yes: Box::new(Expr::Const(1, bits)),
                    no: Box::new(Expr::Const(0, bits)),
                },
            );
        }
    }

    fn condition_for(&mut self, mnemonic: Mnemonic) -> Option<Expr> {
        let flags = self.flags.clone()?;
        let (op, signed) = match mnemonic {
            Mnemonic::Je | Mnemonic::Sete | Mnemonic::Cmove => (CmpOp::Eq, false),
            Mnemonic::Jne | Mnemonic::Setne | Mnemonic::Cmovne => (CmpOp::Ne, false),
            Mnemonic::Jb | Mnemonic::Setb | Mnemonic::Cmovb => (CmpOp::Lt, false),
            Mnemonic::Jae | Mnemonic::Setae | Mnemonic::Cmovae => (CmpOp::Ge, false),
            Mnemonic::Jbe | Mnemonic::Setbe | Mnemonic::Cmovbe => (CmpOp::Le, false),
            Mnemonic::Ja | Mnemonic::Seta | Mnemonic::Cmova => (CmpOp::Gt, false),
            Mnemonic::Jl | Mnemonic::Setl | Mnemonic::Cmovl => (CmpOp::Lt, true),
            Mnemonic::Jge | Mnemonic::Setge | Mnemonic::Cmovge => (CmpOp::Ge, true),
            Mnemonic::Jle | Mnemonic::Setle | Mnemonic::Cmovle => (CmpOp::Le, true),
            Mnemonic::Jg | Mnemonic::Setg | Mnemonic::Cmovg => (CmpOp::Gt, true),
            Mnemonic::Js | Mnemonic::Sets | Mnemonic::Cmovs => {
                return Some(Expr::Cmp {
                    op: CmpOp::Lt,
                    left: Box::new(flags.left.clone()),
                    right: Box::new(Expr::Const(0, flags.bits)),
                    bits: flags.bits,
                    signed: true,
                });
            }
            Mnemonic::Jns | Mnemonic::Setns | Mnemonic::Cmovns => {
                return Some(Expr::Cmp {
                    op: CmpOp::Ge,
                    left: Box::new(flags.left.clone()),
                    right: Box::new(Expr::Const(0, flags.bits)),
                    bits: flags.bits,
                    signed: true,
                });
            }
            Mnemonic::Jo | Mnemonic::Jno | Mnemonic::Jp | Mnemonic::Jnp => {
                if !self.unknown_flag_warned {
                    self.warnings
                        .push("overflow/parity conditions are not reconstructed".to_owned());
                    self.unknown_flag_warned = true;
                }
                return None;
            }
            _ => return None,
        };
        let (left, right) = match flags.kind {
            FlagKind::Cmp => (flags.left, flags.right),
            FlagKind::Test | FlagKind::Value => {
                let tested = if flags.kind == FlagKind::Test {
                    Expr::bin(BinOp::And, flags.left, flags.right, flags.bits)
                } else {
                    flags.left
                };
                (tested, Expr::Const(0, flags.bits))
            }
        };
        Some(Expr::Cmp {
            op,
            left: Box::new(left),
            right: Box::new(right),
            bits: flags.bits,
            signed,
        })
    }

    fn read_operand(&mut self, instruction: &Instruction, index: u32, bits_hint: u16) -> Expr {
        if index >= instruction.op_count() {
            return Expr::Unknown("missing operand".to_owned());
        }
        match instruction.op_kind(index) {
            OpKind::Register => self.register_expression(instruction.op_register(index)),
            OpKind::Memory => {
                let bits = if instruction.memory_size().size() > 0 {
                    (instruction.memory_size().size() * 8) as u16
                } else {
                    bits_hint
                };
                if let Some(local) = self.stack_local(instruction) {
                    self.locals
                        .entry(local.clone())
                        .or_insert_with(|| (bits, "stack".to_owned()));
                    return Expr::Var(local);
                }
                Expr::Load {
                    address: Box::new(self.memory_address(instruction)),
                    bits,
                    signed: false,
                }
            }
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                let address = instruction.near_branch_target();
                Expr::Addr(
                    address,
                    self.program
                        .symbol_at(address)
                        .map(|symbol| symbol.name.clone()),
                )
            }
            OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64 => {
                Expr::Const(instruction.immediate(index), bits_hint.max(8))
            }
            _ => Expr::Unknown(format!("operand kind {:?}", instruction.op_kind(index))),
        }
    }

    fn read_destination(&mut self, instruction: &Instruction, index: u32, bits: u16) -> Expr {
        if index >= instruction.op_count() {
            return Expr::Unknown("missing destination".to_owned());
        }
        match instruction.op_kind(index) {
            OpKind::Register => self.register_expression(instruction.op_register(index)),
            OpKind::Memory => {
                if let Some(local) = self.stack_local(instruction) {
                    self.locals
                        .entry(local.clone())
                        .or_insert_with(|| (bits, "stack".to_owned()));
                    return Expr::Var(local);
                }
                Expr::Load {
                    address: Box::new(self.memory_address(instruction)),
                    bits,
                    signed: false,
                }
            }
            _ => Expr::Unknown("unsupported destination".to_owned()),
        }
    }

    fn destination(&mut self, instruction: &Instruction, index: u32) -> Option<Target> {
        if index >= instruction.op_count() {
            return None;
        }
        match instruction.op_kind(index) {
            OpKind::Register => {
                let key = full_register_name(instruction.op_register(index));
                if let Some(parameter) = self.parameter_index(instruction.op_register(index)) {
                    // The first write to an argument register replaces the
                    // parameter value; do not reintroduce `aN`.
                    let _ = parameter;
                }
                Some(Target::Var(key))
            }
            OpKind::Memory => {
                let bits = if instruction.memory_size().size() > 0 {
                    (instruction.memory_size().size() * 8) as u16
                } else {
                    64
                };
                if let Some(local) = self.stack_local(instruction) {
                    self.locals
                        .entry(local.clone())
                        .or_insert_with(|| (bits, "stack".to_owned()));
                    return Some(Target::Var(local));
                }
                Some(Target::Memory {
                    address: self.memory_address(instruction),
                    bits,
                })
            }
            _ => None,
        }
    }

    fn register_expression(&mut self, register: Register) -> Expr {
        let key = full_register_name(register);
        if let Some(expression) = self.env.get(&key).cloned() {
            if let Some(index) = self.parameter_index(register)
                && expression == Expr::Var(format!("a{index}"))
            {
                self.used_parameters.insert(index);
            }
            return expression;
        }
        if let Some(index) = self.parameter_index(register) {
            self.used_parameters.insert(index);
            return Expr::Var(format!("a{index}"));
        }
        Expr::Var(key)
    }

    fn memory_address(&mut self, instruction: &Instruction) -> Expr {
        if instruction.is_ip_rel_memory_operand() {
            let address = instruction.ip_rel_memory_address();
            if let Some(text) = self.program.read_c_string(address, 200) {
                return Expr::Str(text);
            }
            return Expr::Addr(
                address,
                self.program
                    .symbol_at(address)
                    .map(|symbol| symbol.name.clone()),
            );
        }
        let base = instruction.memory_base();
        let index = instruction.memory_index();
        let displacement = instruction.memory_displacement64();
        let mut expression = if base == Register::None {
            Expr::Const(displacement, 64)
        } else {
            self.register_expression(base)
        };
        if index != Register::None {
            let index_expression = self.register_expression(index);
            let scale = instruction.memory_index_scale().max(1);
            let scaled = if scale == 1 {
                index_expression
            } else {
                Expr::bin(
                    BinOp::Mul,
                    index_expression,
                    Expr::Const(scale as u64, 64),
                    64,
                )
            };
            expression = Expr::bin(BinOp::Add, expression, scaled, 64);
        }
        if displacement != 0 || base == Register::None && index == Register::None {
            expression = Expr::bin(BinOp::Add, expression, Expr::Const(displacement, 64), 64);
        }
        expression
    }

    fn stack_local(&self, instruction: &Instruction) -> Option<String> {
        if instruction.memory_index() != Register::None {
            return None;
        }
        let base = instruction.memory_base().full_register();
        if base != Register::RBP && base != Register::RSP {
            return None;
        }
        let displacement = instruction.memory_displacement64() as i64;
        Some(format!("local_{:x}", displacement.unsigned_abs()))
    }

    fn parameter_index(&self, register: Register) -> Option<usize> {
        self.convention
            .argument_registers()
            .iter()
            .take(self.convention.argument_limit())
            .position(|candidate| candidate.full_register() == register.full_register())
    }

    fn is_sequential_next(&self, index: usize, target: usize) -> bool {
        if target >= self.blocks.len() || index >= self.blocks.len() {
            return false;
        }
        let current_end = self.blocks[index].end;
        self.blocks
            .iter()
            .enumerate()
            .filter(|(_, block)| block.start > current_end)
            .min_by_key(|(_, block)| block.start)
            .map(|(candidate, _)| candidate == target)
            .unwrap_or(false)
    }

    fn is_loop_continue(&self, target: usize) -> bool {
        self.active_loops
            .iter()
            .rev()
            .any(|frame| frame.header == target)
    }

    fn is_loop_exit(&self, target: usize) -> bool {
        self.active_loops
            .iter()
            .rev()
            .any(|frame| frame.exit == target)
    }

    fn label_name(&self, index: usize) -> String {
        format!("LAB_{:x}", self.blocks[index].start)
    }

    fn declared_variables(&mut self, used_parameters: usize) -> Vec<DecompiledVariable> {
        let mut variables: BTreeMap<String, (String, String)> = BTreeMap::new();
        let mut seen = HashSet::new();
        collect_variables_from_statements(&self.output, &mut seen);
        for name in seen {
            if let Some(index) = parameter_name_index(&name) {
                let _ = index;
                continue;
            }
            if variables.contains_key(&name) {
                continue;
            }
            let (bits, origin) = self
                .locals
                .get(&name)
                .cloned()
                .unwrap_or((64, "register".to_owned()));
            variables.insert(name, (int_type(bits, false), origin));
        }
        let mut output: Vec<DecompiledVariable> = variables
            .into_iter()
            .map(|(name, (ty, origin))| DecompiledVariable { name, ty, origin })
            .collect();
        // Parameters are declared in the signature, not as locals.
        output.retain(|variable| {
            variable
                .name
                .strip_prefix('a')
                .and_then(|digits| digits.parse::<usize>().ok())
                .map(|index| index >= used_parameters)
                .unwrap_or(true)
        });
        output
    }
}

fn merge_environments(
    base: &HashMap<String, Expr>,
    left: &HashMap<String, Expr>,
    right: &HashMap<String, Expr>,
) -> HashMap<String, Expr> {
    let mut keys: BTreeSet<String> = BTreeSet::new();
    keys.extend(base.keys().cloned());
    keys.extend(left.keys().cloned());
    keys.extend(right.keys().cloned());
    let mut output = HashMap::new();
    for key in keys {
        let left_value = left.get(&key);
        let right_value = right.get(&key);
        if left_value == right_value {
            if let Some(value) = left_value {
                output.insert(key, value.clone());
            }
        } else if let Some(value) = base.get(&key) {
            if left_value == Some(value) && right_value == Some(value) {
                output.insert(key, value.clone());
            } else {
                output.insert(key.clone(), Expr::Var(key));
            }
        } else {
            output.insert(key.clone(), Expr::Var(key));
        }
    }
    output
}

fn collect_variables_from_statements(statements: &[Stmt], seen: &mut HashSet<String>) {
    for statement in statements {
        match statement {
            Stmt::Assign(target, expression) => {
                match target {
                    Target::Var(name) => {
                        seen.insert(name.clone());
                    }
                    Target::Memory { address, .. } => collect_variables(address, seen),
                }
                collect_variables(expression, seen);
            }
            Stmt::Expr(expression) => collect_variables(expression, seen),
            Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                collect_variables(condition, seen);
                collect_variables_from_statements(then_body, seen);
                collect_variables_from_statements(else_body, seen);
            }
            Stmt::While { condition, body } => {
                collect_variables(condition, seen);
                collect_variables_from_statements(body, seen);
            }
            Stmt::Return(Some(expression)) => collect_variables(expression, seen),
            _ => {}
        }
    }
}

fn expression_contains_variable(expression: &Expr, name: &str) -> bool {
    let mut seen = HashSet::new();
    collect_variables(expression, &mut seen);
    seen.contains(name)
}

/// Registers written by a block. Used to avoid carrying first-iteration
/// constants into a loop body.
fn modified_registers(block: &DecodedBlock) -> BTreeSet<String> {
    let mut registers = BTreeSet::new();
    for item in &block.instructions {
        let instruction = &item.instruction;
        match instruction.mnemonic() {
            Mnemonic::Cmp
            | Mnemonic::Test
            | Mnemonic::Nop
            | Mnemonic::Push
            | Mnemonic::Pop
            | Mnemonic::Ret
            | Mnemonic::Jmp
            | Mnemonic::Je
            | Mnemonic::Jne
            | Mnemonic::Jb
            | Mnemonic::Jae
            | Mnemonic::Jbe
            | Mnemonic::Ja
            | Mnemonic::Js
            | Mnemonic::Jns
            | Mnemonic::Jl
            | Mnemonic::Jge
            | Mnemonic::Jle
            | Mnemonic::Jg
            | Mnemonic::Jo
            | Mnemonic::Jno
            | Mnemonic::Jp
            | Mnemonic::Jnp
            | Mnemonic::Jrcxz
            | Mnemonic::Jecxz
            | Mnemonic::Jcxz => continue,
            Mnemonic::Call => {
                registers.insert("rax".to_owned());
                continue;
            }
            _ => {}
        }
        if instruction.op_count() > 0 && instruction.op_kind(0) == OpKind::Register {
            registers.insert(full_register_name(instruction.op_register(0)));
        }
    }
    registers
}

fn collect_variables(expression: &Expr, seen: &mut HashSet<String>) {
    match expression {
        Expr::Var(name) => {
            seen.insert(name.clone());
        }
        Expr::Bin { left, right, .. } => {
            collect_variables(left, seen);
            collect_variables(right, seen);
        }
        Expr::Un { value, .. } => collect_variables(value, seen),
        Expr::Load { address, .. } => collect_variables(address, seen),
        Expr::Cast { value, .. } => collect_variables(value, seen),
        Expr::Call { args, .. } => {
            for arg in args {
                collect_variables(arg, seen);
            }
        }
        Expr::Select { condition, yes, no } => {
            collect_variables(condition, seen);
            collect_variables(yes, seen);
            collect_variables(no, seen);
        }
        Expr::Cmp { left, right, .. } => {
            collect_variables(left, seen);
            collect_variables(right, seen);
        }
        _ => {}
    }
}

fn parameter_name_index(name: &str) -> Option<usize> {
    if let Some(digits) = name.strip_prefix('a') {
        if !digits.is_empty() && digits.chars().all(|character| character.is_ascii_digit()) {
            return digits.parse().ok();
        }
    }
    None
}

fn render_statements(statements: &[Stmt], indent: usize, output: &mut String) {
    let padding = "    ".repeat(indent);
    for statement in statements {
        match statement {
            Stmt::Assign(target, expression) => {
                output.push_str(&format!(
                    "{}{} = {};\n",
                    padding,
                    render_target(target),
                    expression.render()
                ));
            }
            Stmt::Expr(expression) => {
                output.push_str(&format!("{}{};\n", padding, expression.render()));
            }
            Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                if then_body.is_empty() && else_body.is_empty() {
                    continue;
                }
                if then_body.is_empty() {
                    output.push_str(&format!(
                        "{}if ({}) {{\n",
                        padding,
                        condition.clone().negate().render()
                    ));
                    render_statements(else_body, indent + 1, output);
                    output.push_str(&format!("{}}}\n", padding));
                } else {
                    output.push_str(&format!("{}if ({}) {{\n", padding, condition.render()));
                    render_statements(then_body, indent + 1, output);
                    if else_body.is_empty() {
                        output.push_str(&format!("{}}}\n", padding));
                    } else {
                        output.push_str(&format!("{}}} else {{\n", padding));
                        render_statements(else_body, indent + 1, output);
                        output.push_str(&format!("{}}}\n", padding));
                    }
                }
            }
            Stmt::While { condition, body } => {
                output.push_str(&format!("{}while ({}) {{\n", padding, condition.render()));
                render_statements(body, indent + 1, output);
                output.push_str(&format!("{}}}\n", padding));
            }
            Stmt::Return(Some(expression)) => {
                output.push_str(&format!("{}return {};\n", padding, expression.render()));
            }
            Stmt::Return(None) => output.push_str(&format!("{}return;\n", padding)),
            Stmt::Goto(label) => output.push_str(&format!("{}goto {};\n", padding, label)),
            Stmt::Label(label) => output.push_str(&format!("{}{}:;\n", padding, label)),
            Stmt::Break => output.push_str(&format!("{}break;\n", padding)),
            Stmt::Continue => output.push_str(&format!("{}continue;\n", padding)),
            Stmt::Comment(text) => output.push_str(&format!("{}// {text}\n", padding)),
        }
    }
}

fn render_target(target: &Target) -> String {
    match target {
        Target::Var(name) => name.clone(),
        Target::Memory { address, bits } => {
            format!("*({} *)({})", int_type(*bits, false), address.render())
        }
    }
}

fn operand_bits(instruction: &Instruction, index: u32) -> u16 {
    if index >= instruction.op_count() {
        return 64;
    }
    match instruction.op_kind(index) {
        OpKind::Register => register_bits(instruction.op_register(index)),
        OpKind::Memory => {
            let size = instruction.memory_size().size();
            if size == 0 { 64 } else { (size * 8) as u16 }
        }
        _ => instruction
            .op_count()
            .checked_sub(1)
            .map(|other| {
                if other != index {
                    match instruction.op_kind(other) {
                        OpKind::Register => register_bits(instruction.op_register(other)),
                        OpKind::Memory => {
                            let size = instruction.memory_size().size();
                            if size == 0 { 64 } else { (size * 8) as u16 }
                        }
                        _ => 64,
                    }
                } else {
                    64
                }
            })
            .unwrap_or(64),
    }
}

fn is_register(instruction: &Instruction, index: u32, register: Register) -> bool {
    index < instruction.op_count()
        && instruction.op_kind(index) == OpKind::Register
        && instruction.op_register(index).full_register() == register.full_register()
}

fn is_stack_pointer(instruction: &Instruction, index: u32) -> bool {
    index < instruction.op_count()
        && instruction.op_kind(index) == OpKind::Register
        && instruction.op_register(index).full_register() == Register::RSP
}

fn same_operand(instruction: &Instruction, left: u32, right: u32) -> bool {
    if left >= instruction.op_count() || right >= instruction.op_count() {
        return false;
    }
    if instruction.op_kind(left) != instruction.op_kind(right) {
        return false;
    }
    match instruction.op_kind(left) {
        OpKind::Register => {
            instruction.op_register(left).full_register()
                == instruction.op_register(right).full_register()
        }
        OpKind::Memory => {
            instruction.memory_base() == instruction.memory_base()
                && instruction.memory_index() == instruction.memory_index()
                && instruction.memory_displacement64() == instruction.memory_displacement64()
        }
        _ => instruction.immediate(left) == instruction.immediate(right),
    }
}

fn stack_local_from_destination(target: &Target) -> Option<String> {
    match target {
        Target::Var(name) if name.starts_with("local_") => Some(name.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_folding_and_identities_hold() {
        let expression = Expr::bin(BinOp::Add, Expr::Const(2, 64), Expr::Const(3, 64), 64);
        assert_eq!(expression, Expr::Const(5, 64));
        let expression = Expr::bin(
            BinOp::Add,
            Expr::Var("x".to_owned()),
            Expr::Const(0, 64),
            64,
        );
        assert_eq!(expression, Expr::Var("x".to_owned()));
    }

    #[test]
    fn conditions_negate_correctly() {
        let condition = Expr::Cmp {
            op: CmpOp::Eq,
            left: Box::new(Expr::Var("x".to_owned())),
            right: Box::new(Expr::Const(0, 64)),
            bits: 64,
            signed: false,
        };
        let negated = condition.negate();
        assert!(negated.render().contains("!="));
    }

    #[test]
    fn type_names_are_stable() {
        assert_eq!(int_type(64, false), "uint64_t");
        assert_eq!(int_type(8, true), "int8_t");
    }

    #[test]
    fn unsafe_symbols_are_rejected_as_identifiers() {
        assert!(safe_identifier("demo_add").is_some());
        assert!(safe_identifier("std::process").is_none());
        assert!(safe_identifier("if").is_none());
    }
}
