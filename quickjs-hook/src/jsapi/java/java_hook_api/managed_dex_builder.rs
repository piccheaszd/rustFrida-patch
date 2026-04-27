use std::collections::{BTreeMap, BTreeSet};

use super::super::jni_core::JniEnv;
use super::super::reflect::{enumerate_methods, enumerate_methods_declared_only};

pub(super) const ACC_PUBLIC: u32 = 0x0001;
pub(super) const ACC_PRIVATE: u32 = 0x0002;
pub(super) const ACC_PROTECTED: u32 = 0x0004;
pub(super) const ACC_STATIC: u32 = 0x0008;
pub(super) const ACC_FINAL: u32 = 0x0010;
pub(super) const ACC_BRIDGE: u32 = 0x0040;
pub(super) const ACC_VOLATILE: u32 = 0x0040;
pub(super) const ACC_NATIVE: u32 = 0x0100;
pub(super) const ACC_SYNTHETIC: u32 = 0x1000;
pub(super) const ACC_CONSTRUCTOR: u32 = 0x0001_0000;
pub(super) const ACC_DECLARED_SYNCHRONIZED: u32 = 0x0002_0000;

const TYPE_HEADER_ITEM: u16 = 0x0000;
const TYPE_STRING_ID_ITEM: u16 = 0x0001;
const TYPE_TYPE_ID_ITEM: u16 = 0x0002;
const TYPE_PROTO_ID_ITEM: u16 = 0x0003;
const TYPE_FIELD_ID_ITEM: u16 = 0x0004;
const TYPE_METHOD_ID_ITEM: u16 = 0x0005;
const TYPE_CLASS_DEF_ITEM: u16 = 0x0006;
const TYPE_MAP_LIST: u16 = 0x1000;
const TYPE_TYPE_LIST: u16 = 0x1001;
const TYPE_CLASS_DATA_ITEM: u16 = 0x2000;
const TYPE_CODE_ITEM: u16 = 0x2001;
const TYPE_STRING_DATA_ITEM: u16 = 0x2002;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ProtoSpec {
    pub return_type: String,
    pub params: Vec<String>,
}

impl ProtoSpec {
    pub(super) fn new(return_type: impl Into<String>, params: Vec<String>) -> Self {
        Self {
            return_type: return_type.into(),
            params,
        }
    }

    fn shorty(&self) -> String {
        let mut out = String::with_capacity(self.params.len() + 1);
        out.push(shorty_char(&self.return_type));
        for param in &self.params {
            out.push(shorty_char(param));
        }
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct FieldRef {
    pub class_type: String,
    pub type_name: String,
    pub name: String,
}

impl FieldRef {
    pub(super) fn new(class_type: impl Into<String>, type_name: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            class_type: class_type.into(),
            type_name: type_name.into(),
            name: name.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct MethodRef {
    pub class_type: String,
    pub proto: ProtoSpec,
    pub name: String,
}

impl MethodRef {
    pub(super) fn new(
        class_type: impl Into<String>,
        name: impl Into<String>,
        return_type: impl Into<String>,
        params: Vec<String>,
    ) -> Self {
        Self {
            class_type: class_type.into(),
            proto: ProtoSpec::new(return_type, params),
            name: name.into(),
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct DexCode {
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub insns: Vec<CodeWord>,
}

impl DexCode {
    pub(super) fn new(registers_size: u16, ins_size: u16, outs_size: u16) -> Self {
        Self {
            registers_size,
            ins_size,
            outs_size,
            insns: Vec::new(),
        }
    }

    pub(super) fn raw(&mut self, word: u16) {
        self.insns.push(CodeWord::Raw(word));
    }

    pub(super) fn type_idx(&mut self, ty: impl Into<String>) {
        self.insns.push(CodeWord::Type(ty.into()));
    }

    pub(super) fn string_idx(&mut self, value: impl Into<String>) {
        self.insns.push(CodeWord::String(value.into()));
    }

    pub(super) fn field_idx(&mut self, field: FieldRef) {
        self.insns.push(CodeWord::Field(field));
    }

    pub(super) fn method_idx(&mut self, method: MethodRef) {
        self.insns.push(CodeWord::Method(method));
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct DexLabel(usize);

pub(super) struct DexIrBuilder {
    registers_size: u16,
    ins_size: u16,
    outs_size: u16,
    instrs: Vec<IrInstr>,
    labels: Vec<Option<usize>>,
}

impl DexIrBuilder {
    pub(super) fn new(registers_size: u16, ins_size: u16, outs_size: u16) -> Self {
        Self {
            registers_size,
            ins_size,
            outs_size,
            instrs: Vec::new(),
            labels: Vec::new(),
        }
    }

    pub(super) fn new_label(&mut self) -> DexLabel {
        let id = self.labels.len();
        self.labels.push(None);
        DexLabel(id)
    }

    pub(super) fn bind(&mut self, label: DexLabel) -> Result<(), String> {
        let offset = self.current_offset();
        let slot = self
            .labels
            .get_mut(label.0)
            .ok_or_else(|| format!("invalid dex label {}", label.0))?;
        if slot.is_some() {
            return Err(format!("dex label {} bound twice", label.0));
        }
        *slot = Some(offset);
        Ok(())
    }

    pub(super) fn const4(&mut self, dst: u8, literal: i8) {
        self.instrs.push(IrInstr::Const4 { dst, literal });
    }

    pub(super) fn const16(&mut self, dst: u8, literal: i16) {
        self.instrs.push(IrInstr::Const16 { dst, literal });
    }

    pub(super) fn const_string(&mut self, dst: u8, value: impl Into<String>) {
        self.instrs.push(IrInstr::ConstString {
            dst,
            value: value.into(),
        });
    }

    pub(super) fn move_from16(&mut self, dst: u8, src: u16, kind: ValueKind) {
        self.instrs.push(IrInstr::MoveFrom16 { dst, src, kind });
    }

    pub(super) fn if_cmp(&mut self, op: IfCmpOp, left: u8, right: u8, target: DexLabel) {
        self.instrs.push(IrInstr::IfCmp {
            op,
            left,
            right,
            target,
        });
    }

    pub(super) fn if_eqz(&mut self, reg: u8, target: DexLabel) {
        self.instrs.push(IrInstr::IfEqz { reg, target });
    }

    pub(super) fn if_nez(&mut self, reg: u8, target: DexLabel) {
        self.instrs.push(IrInstr::IfNez { reg, target });
    }

    pub(super) fn goto16(&mut self, target: DexLabel) {
        self.instrs.push(IrInstr::Goto16 { target });
    }

    pub(super) fn packed_switch(&mut self, reg: u8, first_key: i32, targets: Vec<DexLabel>, default_target: DexLabel) {
        self.instrs.push(IrInstr::PackedSwitch {
            reg,
            first_key,
            targets,
            default_target,
        });
    }

    pub(super) fn sparse_switch(&mut self, reg: u8, keys: Vec<i32>, targets: Vec<DexLabel>, default_target: DexLabel) {
        self.instrs.push(IrInstr::SparseSwitch {
            reg,
            keys,
            targets,
            default_target,
        });
    }

    pub(super) fn new_instance(&mut self, dst: u8, ty: impl Into<String>) {
        self.instrs.push(IrInstr::NewInstance { dst, ty: ty.into() });
    }

    pub(super) fn check_cast(&mut self, reg: u8, ty: impl Into<String>) {
        self.instrs.push(IrInstr::CheckCast { reg, ty: ty.into() });
    }

    pub(super) fn instance_of(&mut self, dst: u8, obj: u8, ty: impl Into<String>) {
        self.instrs.push(IrInstr::InstanceOf {
            dst,
            obj,
            ty: ty.into(),
        });
    }

    pub(super) fn array_length(&mut self, dst: u8, array: u8) {
        self.instrs.push(IrInstr::ArrayLength { dst, array });
    }

    pub(super) fn new_array(&mut self, dst: u8, size: u8, ty: impl Into<String>) {
        self.instrs.push(IrInstr::NewArray {
            dst,
            size,
            ty: ty.into(),
        });
    }

    pub(super) fn aget(&mut self, dst: u8, array: u8, index: u8, kind: ValueKind) {
        self.instrs.push(IrInstr::Aget {
            dst,
            array,
            index,
            kind,
        });
    }

    pub(super) fn aput(&mut self, src: u8, array: u8, index: u8, kind: ValueKind) {
        self.instrs.push(IrInstr::Aput {
            src,
            array,
            index,
            kind,
        });
    }

    pub(super) fn invoke_direct(&mut self, args: Vec<u8>, method: MethodRef) {
        self.instrs.push(IrInstr::InvokeDirect { args, method });
    }

    pub(super) fn invoke_virtual(&mut self, args: Vec<u8>, method: MethodRef) {
        self.instrs.push(IrInstr::InvokeVirtual { args, method });
    }

    pub(super) fn invoke_static(&mut self, args: Vec<u8>, method: MethodRef) {
        self.instrs.push(IrInstr::InvokeStatic { args, method });
    }

    pub(super) fn invoke_interface(&mut self, args: Vec<u8>, method: MethodRef) {
        self.instrs.push(IrInstr::InvokeInterface { args, method });
    }

    pub(super) fn invoke_direct_range(&mut self, first_reg: u16, arg_words: u8, method: MethodRef) {
        self.instrs.push(IrInstr::InvokeDirectRange {
            first_reg,
            arg_words,
            method,
        });
    }

    pub(super) fn invoke_static_range(&mut self, first_reg: u16, arg_words: u8, method: MethodRef) {
        self.instrs.push(IrInstr::InvokeStaticRange {
            first_reg,
            arg_words,
            method,
        });
    }

    pub(super) fn invoke_virtual_range(&mut self, first_reg: u16, arg_words: u8, method: MethodRef) {
        self.instrs.push(IrInstr::InvokeVirtualRange {
            first_reg,
            arg_words,
            method,
        });
    }

    pub(super) fn invoke_interface_range(&mut self, first_reg: u16, arg_words: u8, method: MethodRef) {
        self.instrs.push(IrInstr::InvokeInterfaceRange {
            first_reg,
            arg_words,
            method,
        });
    }

    pub(super) fn sput_object(&mut self, src: u8, field: FieldRef) {
        self.instrs.push(IrInstr::SputObject { src, field });
    }

    pub(super) fn iget(&mut self, dst: u8, obj: u8, field: FieldRef, kind: ValueKind) {
        self.instrs.push(IrInstr::Iget { dst, obj, field, kind });
    }

    pub(super) fn iput(&mut self, src: u8, obj: u8, field: FieldRef, kind: ValueKind) {
        self.instrs.push(IrInstr::Iput { src, obj, field, kind });
    }

    pub(super) fn sget(&mut self, dst: u8, field: FieldRef, kind: ValueKind) {
        self.instrs.push(IrInstr::Sget { dst, field, kind });
    }

    pub(super) fn sput(&mut self, src: u8, field: FieldRef, kind: ValueKind) {
        self.instrs.push(IrInstr::Sput { src, field, kind });
    }

    pub(super) fn add_int_lit8(&mut self, dst: u8, src: u8, literal: i8) {
        self.instrs.push(IrInstr::AddIntLit8 { dst, src, literal });
    }

    pub(super) fn move_result_object(&mut self, dst: u8) {
        self.instrs.push(IrInstr::MoveResultObject { dst });
    }

    pub(super) fn move_result(&mut self, dst: u8) {
        self.instrs.push(IrInstr::MoveResult { dst });
    }

    pub(super) fn move_result_wide(&mut self, dst: u8) {
        self.instrs.push(IrInstr::MoveResultWide { dst });
    }

    pub(super) fn return_object(&mut self, src: u8) {
        self.instrs.push(IrInstr::ReturnObject { src });
    }

    pub(super) fn return_value(&mut self, src: u8) {
        self.instrs.push(IrInstr::Return { src });
    }

    pub(super) fn return_wide(&mut self, src: u8) {
        self.instrs.push(IrInstr::ReturnWide { src });
    }

    pub(super) fn return_void(&mut self) {
        self.instrs.push(IrInstr::ReturnVoid);
    }

    pub(super) fn finish(self) -> Result<DexCode, String> {
        let mut offsets = Vec::with_capacity(self.instrs.len());
        let mut offset = 0usize;
        for instr in &self.instrs {
            offsets.push(offset);
            offset += instr.width_at(offset);
        }

        for (idx, label) in self.labels.iter().enumerate() {
            if label.is_none() {
                return Err(format!("dex label {} was never bound", idx));
            }
        }

        let mut code = DexCode::new(self.registers_size, self.ins_size, self.outs_size);
        for (idx, instr) in self.instrs.into_iter().enumerate() {
            instr.emit(&mut code, offsets[idx], &self.labels)?;
        }
        Ok(code)
    }

    fn current_offset(&self) -> usize {
        let mut offset = 0usize;
        for instr in &self.instrs {
            offset += instr.width_at(offset);
        }
        offset
    }
}

enum IrInstr {
    Const4 {
        dst: u8,
        literal: i8,
    },
    Const16 {
        dst: u8,
        literal: i16,
    },
    ConstString {
        dst: u8,
        value: String,
    },
    MoveFrom16 {
        dst: u8,
        src: u16,
        kind: ValueKind,
    },
    IfCmp {
        op: IfCmpOp,
        left: u8,
        right: u8,
        target: DexLabel,
    },
    IfEqz {
        reg: u8,
        target: DexLabel,
    },
    IfNez {
        reg: u8,
        target: DexLabel,
    },
    Goto16 {
        target: DexLabel,
    },
    PackedSwitch {
        reg: u8,
        first_key: i32,
        targets: Vec<DexLabel>,
        default_target: DexLabel,
    },
    SparseSwitch {
        reg: u8,
        keys: Vec<i32>,
        targets: Vec<DexLabel>,
        default_target: DexLabel,
    },
    NewInstance {
        dst: u8,
        ty: String,
    },
    CheckCast {
        reg: u8,
        ty: String,
    },
    InstanceOf {
        dst: u8,
        obj: u8,
        ty: String,
    },
    ArrayLength {
        dst: u8,
        array: u8,
    },
    NewArray {
        dst: u8,
        size: u8,
        ty: String,
    },
    Aget {
        dst: u8,
        array: u8,
        index: u8,
        kind: ValueKind,
    },
    Aput {
        src: u8,
        array: u8,
        index: u8,
        kind: ValueKind,
    },
    InvokeDirect {
        args: Vec<u8>,
        method: MethodRef,
    },
    InvokeVirtual {
        args: Vec<u8>,
        method: MethodRef,
    },
    InvokeStatic {
        args: Vec<u8>,
        method: MethodRef,
    },
    InvokeInterface {
        args: Vec<u8>,
        method: MethodRef,
    },
    InvokeDirectRange {
        first_reg: u16,
        arg_words: u8,
        method: MethodRef,
    },
    InvokeStaticRange {
        first_reg: u16,
        arg_words: u8,
        method: MethodRef,
    },
    InvokeVirtualRange {
        first_reg: u16,
        arg_words: u8,
        method: MethodRef,
    },
    InvokeInterfaceRange {
        first_reg: u16,
        arg_words: u8,
        method: MethodRef,
    },
    SputObject {
        src: u8,
        field: FieldRef,
    },
    Iget {
        dst: u8,
        obj: u8,
        field: FieldRef,
        kind: ValueKind,
    },
    Iput {
        src: u8,
        obj: u8,
        field: FieldRef,
        kind: ValueKind,
    },
    Sget {
        dst: u8,
        field: FieldRef,
        kind: ValueKind,
    },
    Sput {
        src: u8,
        field: FieldRef,
        kind: ValueKind,
    },
    AddIntLit8 {
        dst: u8,
        src: u8,
        literal: i8,
    },
    MoveResult {
        dst: u8,
    },
    MoveResultWide {
        dst: u8,
    },
    MoveResultObject {
        dst: u8,
    },
    Return {
        src: u8,
    },
    ReturnWide {
        src: u8,
    },
    ReturnObject {
        src: u8,
    },
    ReturnVoid,
}

#[derive(Clone, Copy)]
pub(super) enum IfCmpOp {
    Eq,
    Ne,
    Lt,
    Ge,
    Gt,
    Le,
}

impl IfCmpOp {
    fn opcode(self) -> u16 {
        match self {
            IfCmpOp::Eq => 0x0032,
            IfCmpOp::Ne => 0x0033,
            IfCmpOp::Lt => 0x0034,
            IfCmpOp::Ge => 0x0035,
            IfCmpOp::Gt => 0x0036,
            IfCmpOp::Le => 0x0037,
        }
    }

    fn name(self) -> &'static str {
        match self {
            IfCmpOp::Eq => "if-eq",
            IfCmpOp::Ne => "if-ne",
            IfCmpOp::Lt => "if-lt",
            IfCmpOp::Ge => "if-ge",
            IfCmpOp::Gt => "if-gt",
            IfCmpOp::Le => "if-le",
        }
    }

    fn invert(self) -> Self {
        match self {
            IfCmpOp::Eq => IfCmpOp::Ne,
            IfCmpOp::Ne => IfCmpOp::Eq,
            IfCmpOp::Lt => IfCmpOp::Ge,
            IfCmpOp::Ge => IfCmpOp::Lt,
            IfCmpOp::Gt => IfCmpOp::Le,
            IfCmpOp::Le => IfCmpOp::Gt,
        }
    }
}

impl IrInstr {
    fn width_at(&self, offset: usize) -> usize {
        match self {
            IrInstr::Const4 { .. } => 1,
            IrInstr::Const16 { .. } => 2,
            IrInstr::ConstString { .. } => 2,
            IrInstr::MoveFrom16 { .. } => 2,
            IrInstr::IfCmp { .. } => 2,
            IrInstr::IfEqz { .. } | IrInstr::IfNez { .. } => 2,
            IrInstr::Goto16 { .. } => 2,
            IrInstr::PackedSwitch { targets, .. } => 5 + switch_payload_padding(offset + 5) + 4 + targets.len() * 2,
            IrInstr::SparseSwitch { keys, .. } => 5 + switch_payload_padding(offset + 5) + 2 + keys.len() * 4,
            IrInstr::NewInstance { .. } => 2,
            IrInstr::CheckCast { .. } => 2,
            IrInstr::InstanceOf { .. } => 2,
            IrInstr::ArrayLength { .. } => 1,
            IrInstr::NewArray { .. } => 2,
            IrInstr::Aget { .. } | IrInstr::Aput { .. } => 2,
            IrInstr::InvokeDirect { .. }
            | IrInstr::InvokeVirtual { .. }
            | IrInstr::InvokeStatic { .. }
            | IrInstr::InvokeInterface { .. } => 3,
            IrInstr::InvokeDirectRange { .. }
            | IrInstr::InvokeStaticRange { .. }
            | IrInstr::InvokeVirtualRange { .. }
            | IrInstr::InvokeInterfaceRange { .. } => 3,
            IrInstr::SputObject { .. } => 2,
            IrInstr::Iget { .. } | IrInstr::Iput { .. } | IrInstr::Sget { .. } | IrInstr::Sput { .. } => 2,
            IrInstr::AddIntLit8 { .. } => 2,
            IrInstr::MoveResult { .. } | IrInstr::MoveResultWide { .. } => 1,
            IrInstr::MoveResultObject { .. } => 1,
            IrInstr::Return { .. } | IrInstr::ReturnWide { .. } => 1,
            IrInstr::ReturnObject { .. } => 1,
            IrInstr::ReturnVoid => 1,
        }
    }

    fn emit(self, code: &mut DexCode, offset: usize, labels: &[Option<usize>]) -> Result<(), String> {
        match self {
            IrInstr::Const4 { dst, literal } => {
                require_nibble(dst, "const/4 dst")?;
                if !(-8..=7).contains(&literal) {
                    return Err(format!("const/4 literal out of range: {}", literal));
                }
                code.raw(0x0012 | ((dst as u16) << 8) | (((literal as i16 as u16) & 0x0f) << 12));
            }
            IrInstr::Const16 { dst, literal } => {
                require_byte(dst, "const/16 dst")?;
                code.raw(0x0013 | ((dst as u16) << 8));
                code.raw(literal as u16);
            }
            IrInstr::ConstString { dst, value } => {
                require_byte(dst, "const-string dst")?;
                code.raw(0x001a | ((dst as u16) << 8));
                code.string_idx(value);
            }
            IrInstr::MoveFrom16 { dst, src, kind } => {
                require_byte(dst, "move/from16 dst")?;
                let opcode = match kind {
                    ValueKind::Wide => 0x0005,
                    ValueKind::Object => 0x0008,
                    ValueKind::Narrow | ValueKind::Boolean | ValueKind::Byte | ValueKind::Char | ValueKind::Short => {
                        0x0002
                    }
                };
                code.raw(opcode | ((dst as u16) << 8));
                code.raw(src);
            }
            IrInstr::IfCmp {
                op,
                left,
                right,
                target,
            } => {
                require_nibble(left, "if-cmp left")?;
                require_nibble(right, "if-cmp right")?;
                code.raw(op.opcode() | ((left as u16) << 8) | ((right as u16) << 12));
                code.raw(branch_offset(offset, target, labels, op.name())? as u16);
            }
            IrInstr::IfEqz { reg, target } => {
                require_byte(reg, "if-eqz reg")?;
                code.raw(0x0038 | ((reg as u16) << 8));
                code.raw(branch_offset(offset, target, labels, "if-eqz")? as u16);
            }
            IrInstr::IfNez { reg, target } => {
                require_byte(reg, "if-nez reg")?;
                code.raw(0x0039 | ((reg as u16) << 8));
                code.raw(branch_offset(offset, target, labels, "if-nez")? as u16);
            }
            IrInstr::Goto16 { target } => {
                code.raw(0x0029);
                code.raw(branch_offset(offset, target, labels, "goto/16")? as u16);
            }
            IrInstr::PackedSwitch {
                reg,
                first_key,
                targets,
                default_target,
            } => {
                require_byte(reg, "packed-switch reg")?;
                code.raw(0x002b | ((reg as u16) << 8));
                let payload_offset = 5 + switch_payload_padding(offset + 5);
                write_i32_code_units(code, payload_offset as i32);
                code.raw(0x0029);
                code.raw(branch_offset(offset + 3, default_target, labels, "packed-switch default goto")? as u16);
                if payload_offset > 5 {
                    code.raw(0x0000);
                }
                code.raw(0x0100);
                code.raw(targets.len() as u16);
                write_i32_code_units(code, first_key);
                for target in targets {
                    write_i32_code_units(code, branch_offset_i32(offset, target, labels, "packed-switch target")?);
                }
            }
            IrInstr::SparseSwitch {
                reg,
                keys,
                targets,
                default_target,
            } => {
                require_byte(reg, "sparse-switch reg")?;
                if keys.len() != targets.len() {
                    return Err("sparse-switch key/target count mismatch".to_string());
                }
                code.raw(0x002c | ((reg as u16) << 8));
                let payload_offset = 5 + switch_payload_padding(offset + 5);
                write_i32_code_units(code, payload_offset as i32);
                code.raw(0x0029);
                code.raw(branch_offset(offset + 3, default_target, labels, "sparse-switch default goto")? as u16);
                if payload_offset > 5 {
                    code.raw(0x0000);
                }
                code.raw(0x0200);
                code.raw(keys.len() as u16);
                for key in &keys {
                    write_i32_code_units(code, *key);
                }
                for target in targets {
                    write_i32_code_units(code, branch_offset_i32(offset, target, labels, "sparse-switch target")?);
                }
            }
            IrInstr::NewInstance { dst, ty } => {
                require_byte(dst, "new-instance dst")?;
                code.raw(0x0022 | ((dst as u16) << 8));
                code.type_idx(ty);
            }
            IrInstr::CheckCast { reg, ty } => {
                require_byte(reg, "check-cast reg")?;
                code.raw(0x001f | ((reg as u16) << 8));
                code.type_idx(ty);
            }
            IrInstr::InstanceOf { dst, obj, ty } => {
                require_nibble(dst, "instance-of dst")?;
                require_nibble(obj, "instance-of obj")?;
                code.raw(0x0020 | ((dst as u16) << 8) | ((obj as u16) << 12));
                code.type_idx(ty);
            }
            IrInstr::ArrayLength { dst, array } => {
                require_nibble(dst, "array-length dst")?;
                require_nibble(array, "array-length array")?;
                code.raw(0x0021 | ((dst as u16) << 8) | ((array as u16) << 12));
            }
            IrInstr::NewArray { dst, size, ty } => {
                require_nibble(dst, "new-array dst")?;
                require_nibble(size, "new-array size")?;
                code.raw(0x0023 | ((dst as u16) << 8) | ((size as u16) << 12));
                code.type_idx(ty);
            }
            IrInstr::Aget {
                dst,
                array,
                index,
                kind,
            } => {
                require_byte(dst, "aget dst")?;
                require_byte(array, "aget array")?;
                require_byte(index, "aget index")?;
                code.raw(array_opcode(false, kind) | ((dst as u16) << 8));
                code.raw((array as u16) | ((index as u16) << 8));
            }
            IrInstr::Aput {
                src,
                array,
                index,
                kind,
            } => {
                require_byte(src, "aput src")?;
                require_byte(array, "aput array")?;
                require_byte(index, "aput index")?;
                code.raw(array_opcode(true, kind) | ((src as u16) << 8));
                code.raw((array as u16) | ((index as u16) << 8));
            }
            IrInstr::InvokeDirect { args, method } => {
                emit_invoke35c(code, 0x70, &args, method)?;
            }
            IrInstr::InvokeVirtual { args, method } => {
                emit_invoke35c(code, 0x6e, &args, method)?;
            }
            IrInstr::InvokeStatic { args, method } => {
                emit_invoke35c(code, 0x71, &args, method)?;
            }
            IrInstr::InvokeInterface { args, method } => {
                emit_invoke35c(code, 0x72, &args, method)?;
            }
            IrInstr::InvokeDirectRange {
                first_reg,
                arg_words,
                method,
            } => {
                emit_invoke3rc(code, 0x76, first_reg, arg_words, method)?;
            }
            IrInstr::InvokeStaticRange {
                first_reg,
                arg_words,
                method,
            } => {
                emit_invoke3rc(code, 0x77, first_reg, arg_words, method)?;
            }
            IrInstr::InvokeVirtualRange {
                first_reg,
                arg_words,
                method,
            } => {
                emit_invoke3rc(code, 0x74, first_reg, arg_words, method)?;
            }
            IrInstr::InvokeInterfaceRange {
                first_reg,
                arg_words,
                method,
            } => {
                emit_invoke3rc(code, 0x78, first_reg, arg_words, method)?;
            }
            IrInstr::SputObject { src, field } => {
                require_byte(src, "sput-object src")?;
                code.raw(0x0069 | ((src as u16) << 8));
                code.field_idx(field);
            }
            IrInstr::Iget { dst, obj, field, kind } => {
                require_nibble(dst, "iget dst")?;
                require_nibble(obj, "iget obj")?;
                code.raw(field_opcode(false, false, kind) | ((dst as u16) << 8) | ((obj as u16) << 12));
                code.field_idx(field);
            }
            IrInstr::Iput { src, obj, field, kind } => {
                require_nibble(src, "iput src")?;
                require_nibble(obj, "iput obj")?;
                code.raw(field_opcode(false, true, kind) | ((src as u16) << 8) | ((obj as u16) << 12));
                code.field_idx(field);
            }
            IrInstr::Sget { dst, field, kind } => {
                require_byte(dst, "sget dst")?;
                code.raw(field_opcode(true, false, kind) | ((dst as u16) << 8));
                code.field_idx(field);
            }
            IrInstr::Sput { src, field, kind } => {
                require_byte(src, "sput src")?;
                code.raw(field_opcode(true, true, kind) | ((src as u16) << 8));
                code.field_idx(field);
            }
            IrInstr::AddIntLit8 { dst, src, literal } => {
                require_byte(dst, "add-int/lit8 dst")?;
                require_byte(src, "add-int/lit8 src")?;
                code.raw(0x00d8 | ((dst as u16) << 8));
                code.raw((src as u16) | (((literal as i16 as u16) & 0xff) << 8));
            }
            IrInstr::MoveResult { dst } => {
                require_byte(dst, "move-result dst")?;
                code.raw(0x000a | ((dst as u16) << 8));
            }
            IrInstr::MoveResultWide { dst } => {
                require_byte(dst, "move-result-wide dst")?;
                code.raw(0x000b | ((dst as u16) << 8));
            }
            IrInstr::MoveResultObject { dst } => {
                require_byte(dst, "move-result-object dst")?;
                code.raw(0x000c | ((dst as u16) << 8));
            }
            IrInstr::Return { src } => {
                require_byte(src, "return src")?;
                code.raw(0x000f | ((src as u16) << 8));
            }
            IrInstr::ReturnWide { src } => {
                require_byte(src, "return-wide src")?;
                code.raw(0x0010 | ((src as u16) << 8));
            }
            IrInstr::ReturnObject { src } => {
                require_byte(src, "return-object src")?;
                code.raw(0x0011 | ((src as u16) << 8));
            }
            IrInstr::ReturnVoid => {
                code.raw(0x000e);
            }
        }
        Ok(())
    }
}

fn emit_invoke35c(code: &mut DexCode, opcode: u16, args: &[u8], method: MethodRef) -> Result<(), String> {
    if args.len() > 5 {
        return Err(format!("invoke supports at most 5 args, got {}", args.len()));
    }
    for (idx, reg) in args.iter().enumerate() {
        require_nibble(*reg, &format!("invoke arg {}", idx))?;
    }
    let mut regs = [0u8; 5];
    for (idx, reg) in args.iter().enumerate() {
        regs[idx] = *reg;
    }
    let g = if args.len() == 5 { regs[4] } else { 0 };
    code.raw(opcode | ((g as u16) << 8) | ((args.len() as u16) << 12));
    code.method_idx(method);
    code.raw((regs[0] as u16) | ((regs[1] as u16) << 4) | ((regs[2] as u16) << 8) | ((regs[3] as u16) << 12));
    Ok(())
}

fn emit_invoke3rc(
    code: &mut DexCode,
    opcode: u16,
    first_reg: u16,
    arg_words: u8,
    method: MethodRef,
) -> Result<(), String> {
    code.raw(opcode | ((arg_words as u16) << 8));
    code.method_idx(method);
    code.raw(first_reg);
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub(super) enum ValueKind {
    Narrow,
    Wide,
    Object,
    Boolean,
    Byte,
    Char,
    Short,
}

fn value_kind_from_descriptor(desc: &str) -> Result<ValueKind, String> {
    match desc {
        "Z" => Ok(ValueKind::Boolean),
        "B" => Ok(ValueKind::Byte),
        "C" => Ok(ValueKind::Char),
        "S" => Ok(ValueKind::Short),
        "I" | "F" => Ok(ValueKind::Narrow),
        "J" | "D" => Ok(ValueKind::Wide),
        value if return_is_object(value) => Ok(ValueKind::Object),
        other => Err(format!("unsupported value descriptor '{}'", other)),
    }
}

fn field_opcode(is_static: bool, is_put: bool, kind: ValueKind) -> u16 {
    match (is_static, is_put, kind) {
        (false, false, ValueKind::Narrow) => 0x52,
        (false, false, ValueKind::Wide) => 0x53,
        (false, false, ValueKind::Object) => 0x54,
        (false, false, ValueKind::Boolean) => 0x55,
        (false, false, ValueKind::Byte) => 0x56,
        (false, false, ValueKind::Char) => 0x57,
        (false, false, ValueKind::Short) => 0x58,
        (false, true, ValueKind::Narrow) => 0x59,
        (false, true, ValueKind::Wide) => 0x5a,
        (false, true, ValueKind::Object) => 0x5b,
        (false, true, ValueKind::Boolean) => 0x5c,
        (false, true, ValueKind::Byte) => 0x5d,
        (false, true, ValueKind::Char) => 0x5e,
        (false, true, ValueKind::Short) => 0x5f,
        (true, false, ValueKind::Narrow) => 0x60,
        (true, false, ValueKind::Wide) => 0x61,
        (true, false, ValueKind::Object) => 0x62,
        (true, false, ValueKind::Boolean) => 0x63,
        (true, false, ValueKind::Byte) => 0x64,
        (true, false, ValueKind::Char) => 0x65,
        (true, false, ValueKind::Short) => 0x66,
        (true, true, ValueKind::Narrow) => 0x67,
        (true, true, ValueKind::Wide) => 0x68,
        (true, true, ValueKind::Object) => 0x69,
        (true, true, ValueKind::Boolean) => 0x6a,
        (true, true, ValueKind::Byte) => 0x6b,
        (true, true, ValueKind::Char) => 0x6c,
        (true, true, ValueKind::Short) => 0x6d,
    }
}

fn array_opcode(is_put: bool, kind: ValueKind) -> u16 {
    match (is_put, kind) {
        (false, ValueKind::Narrow) => 0x44,
        (false, ValueKind::Wide) => 0x45,
        (false, ValueKind::Object) => 0x46,
        (false, ValueKind::Boolean) => 0x47,
        (false, ValueKind::Byte) => 0x48,
        (false, ValueKind::Char) => 0x49,
        (false, ValueKind::Short) => 0x4a,
        (true, ValueKind::Narrow) => 0x4b,
        (true, ValueKind::Wide) => 0x4c,
        (true, ValueKind::Object) => 0x4d,
        (true, ValueKind::Boolean) => 0x4e,
        (true, ValueKind::Byte) => 0x4f,
        (true, ValueKind::Char) => 0x50,
        (true, ValueKind::Short) => 0x51,
    }
}

fn branch_offset(
    source_offset: usize,
    target: DexLabel,
    labels: &[Option<usize>],
    opname: &str,
) -> Result<i16, String> {
    let target_offset = labels
        .get(target.0)
        .and_then(|v| *v)
        .ok_or_else(|| format!("{} target label {} is not bound", opname, target.0))?;
    let delta = target_offset as isize - source_offset as isize;
    if delta < i16::MIN as isize || delta > i16::MAX as isize {
        return Err(format!("{} branch offset out of range: {}", opname, delta));
    }
    Ok(delta as i16)
}

fn branch_offset_i32(
    source_offset: usize,
    target: DexLabel,
    labels: &[Option<usize>],
    opname: &str,
) -> Result<i32, String> {
    let target_offset = labels
        .get(target.0)
        .and_then(|v| *v)
        .ok_or_else(|| format!("{} target label {} is not bound", opname, target.0))?;
    let delta = target_offset as isize - source_offset as isize;
    if delta < i32::MIN as isize || delta > i32::MAX as isize {
        return Err(format!("{} branch offset out of range: {}", opname, delta));
    }
    Ok(delta as i32)
}

fn switch_payload_padding(offset_after_goto: usize) -> usize {
    offset_after_goto & 1
}

fn write_i32_code_units(code: &mut DexCode, value: i32) {
    let value = value as u32;
    code.raw((value & 0xffff) as u16);
    code.raw((value >> 16) as u16);
}

fn require_nibble(value: u8, what: &str) -> Result<(), String> {
    if value > 0x0f {
        return Err(format!(
            "{} register out of range for nibble encoding: v{}",
            what, value
        ));
    }
    Ok(())
}

fn require_byte(value: u8, what: &str) -> Result<(), String> {
    if value == u8::MAX {
        return Err(format!("{} invalid register v{}", what, value));
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub(super) enum CodeWord {
    Raw(u16),
    String(String),
    Type(String),
    Field(FieldRef),
    Method(MethodRef),
}

#[derive(Clone, Debug)]
pub(super) struct ClassField {
    pub field: FieldRef,
    pub access_flags: u32,
}

#[derive(Clone, Debug)]
pub(super) struct ClassMethod {
    pub method: MethodRef,
    pub access_flags: u32,
    pub code: Option<DexCode>,
}

#[derive(Clone, Debug)]
pub(super) struct DexClass {
    pub class_type: String,
    pub access_flags: u32,
    pub super_type: String,
    pub source_file: Option<String>,
    pub static_fields: Vec<ClassField>,
    pub instance_fields: Vec<ClassField>,
    pub direct_methods: Vec<ClassMethod>,
    pub virtual_methods: Vec<ClassMethod>,
}

impl DexClass {
    pub(super) fn new(class_type: impl Into<String>) -> Self {
        Self {
            class_type: class_type.into(),
            access_flags: ACC_PUBLIC | ACC_FINAL,
            super_type: "Ljava/lang/Object;".to_string(),
            source_file: None,
            static_fields: Vec::new(),
            instance_fields: Vec::new(),
            direct_methods: Vec::new(),
            virtual_methods: Vec::new(),
        }
    }

    pub(super) fn source_file(mut self, source_file: impl Into<String>) -> Self {
        self.source_file = Some(source_file.into());
        self
    }

    pub(super) fn static_field(&mut self, name: &str, type_name: &str, access_flags: u32) -> FieldRef {
        let field = FieldRef::new(self.class_type.clone(), type_name.to_string(), name.to_string());
        self.static_fields.push(ClassField {
            field: field.clone(),
            access_flags,
        });
        field
    }

    pub(super) fn direct_method(
        &mut self,
        name: &str,
        return_type: &str,
        params: Vec<String>,
        access_flags: u32,
        code: DexCode,
    ) -> MethodRef {
        let method = MethodRef::new(
            self.class_type.clone(),
            name.to_string(),
            return_type.to_string(),
            params,
        );
        self.direct_methods.push(ClassMethod {
            method: method.clone(),
            access_flags,
            code: Some(code),
        });
        method
    }

    pub(super) fn native_direct_method(
        &mut self,
        name: &str,
        return_type: &str,
        params: Vec<String>,
        access_flags: u32,
    ) -> MethodRef {
        let method = MethodRef::new(
            self.class_type.clone(),
            name.to_string(),
            return_type.to_string(),
            params,
        );
        self.direct_methods.push(ClassMethod {
            method: method.clone(),
            access_flags,
            code: None,
        });
        method
    }
}

pub(super) struct DexBuilder {
    classes: Vec<DexClass>,
    field_refs: BTreeSet<FieldRef>,
    method_refs: BTreeSet<MethodRef>,
}

impl DexBuilder {
    pub(super) fn new() -> Self {
        Self {
            classes: Vec::new(),
            field_refs: BTreeSet::new(),
            method_refs: BTreeSet::new(),
        }
    }

    pub(super) fn add_class(&mut self, class: DexClass) {
        self.classes.push(class);
    }

    pub(super) fn add_field_ref(&mut self, field: FieldRef) -> FieldRef {
        self.field_refs.insert(field.clone());
        field
    }

    pub(super) fn add_method_ref(&mut self, method: MethodRef) -> MethodRef {
        self.method_refs.insert(method.clone());
        method
    }

    pub(super) fn build(mut self) -> Result<Vec<u8>, String> {
        if self.classes.is_empty() {
            return Err("dex builder requires at least one class".to_string());
        }

        for class in &self.classes {
            for field in class.static_fields.iter().chain(class.instance_fields.iter()) {
                self.field_refs.insert(field.field.clone());
            }
            for method in class.direct_methods.iter().chain(class.virtual_methods.iter()) {
                self.method_refs.insert(method.method.clone());
                if let Some(code) = &method.code {
                    for word in &code.insns {
                        match word {
                            CodeWord::Field(field) => {
                                self.field_refs.insert(field.clone());
                            }
                            CodeWord::Method(method) => {
                                self.method_refs.insert(method.clone());
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        let mut string_set = BTreeSet::<String>::new();
        let mut type_set = BTreeSet::<String>::new();
        let mut proto_set = BTreeSet::<ProtoSpec>::new();

        for class in &self.classes {
            type_set.insert(class.class_type.clone());
            type_set.insert(class.super_type.clone());
            if let Some(source_file) = &class.source_file {
                string_set.insert(source_file.clone());
            }
        }
        for field in &self.field_refs {
            type_set.insert(field.class_type.clone());
            type_set.insert(field.type_name.clone());
            string_set.insert(field.name.clone());
        }
        for method in &self.method_refs {
            type_set.insert(method.class_type.clone());
            type_set.insert(method.proto.return_type.clone());
            for param in &method.proto.params {
                type_set.insert(param.clone());
            }
            string_set.insert(method.name.clone());
            string_set.insert(method.proto.shorty());
            proto_set.insert(method.proto.clone());
        }
        for class in &self.classes {
            for method in class.direct_methods.iter().chain(class.virtual_methods.iter()) {
                if let Some(code) = &method.code {
                    for word in &code.insns {
                        match word {
                            CodeWord::String(value) => {
                                string_set.insert(value.clone());
                            }
                            CodeWord::Type(ty) => {
                                type_set.insert(ty.clone());
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        for ty in &type_set {
            string_set.insert(ty.clone());
        }

        let strings: Vec<String> = string_set.into_iter().collect();
        let string_idx: BTreeMap<String, u32> =
            strings.iter().enumerate().map(|(i, s)| (s.clone(), i as u32)).collect();

        let mut types: Vec<String> = type_set.into_iter().collect();
        types.sort_by_key(|ty| string_idx[ty]);
        let type_idx: BTreeMap<String, u32> = types.iter().enumerate().map(|(i, s)| (s.clone(), i as u32)).collect();

        let mut protos: Vec<ProtoSpec> = proto_set.into_iter().collect();
        protos.sort_by_key(|p| {
            (
                type_idx[&p.return_type],
                p.params.iter().map(|ty| type_idx[ty]).collect::<Vec<_>>(),
                string_idx[&p.shorty()],
            )
        });
        let proto_idx: BTreeMap<ProtoSpec, u32> =
            protos.iter().enumerate().map(|(i, p)| (p.clone(), i as u32)).collect();

        let mut fields: Vec<FieldRef> = self.field_refs.into_iter().collect();
        fields.sort_by_key(|f| (type_idx[&f.class_type], string_idx[&f.name], type_idx[&f.type_name]));
        let field_idx: BTreeMap<FieldRef, u32> =
            fields.iter().enumerate().map(|(i, f)| (f.clone(), i as u32)).collect();

        let mut methods: Vec<MethodRef> = self.method_refs.into_iter().collect();
        methods.sort_by_key(|m| (type_idx[&m.class_type], string_idx[&m.name], proto_idx[&m.proto]));
        let method_idx: BTreeMap<MethodRef, u32> =
            methods.iter().enumerate().map(|(i, m)| (m.clone(), i as u32)).collect();

        let mut type_lists = BTreeSet::<Vec<u32>>::new();
        for proto in &protos {
            if !proto.params.is_empty() {
                type_lists.insert(proto.params.iter().map(|p| type_idx[p]).collect());
            }
        }

        let header_size = 0x70usize;
        let string_ids_off = header_size;
        let type_ids_off = align4(string_ids_off + strings.len() * 4);
        let proto_ids_off = align4(type_ids_off + types.len() * 4);
        let field_ids_off = align4(proto_ids_off + protos.len() * 12);
        let method_ids_off = align4(field_ids_off + fields.len() * 8);
        let class_defs_off = align4(method_ids_off + methods.len() * 8);
        let data_off = align4(class_defs_off + self.classes.len() * 32);

        let mut data = Vec::new();
        let mut type_list_offsets = BTreeMap::<Vec<u32>, u32>::new();
        let first_type_list_off = if type_lists.is_empty() { 0 } else { data_off as u32 };
        for key in &type_lists {
            align_vec4(&mut data);
            let off = (data_off + data.len()) as u32;
            write_u32(&mut data, key.len() as u32);
            for idx in key {
                write_u16(&mut data, *idx as u16);
            }
            if key.len() % 2 != 0 {
                write_u16(&mut data, 0);
            }
            type_list_offsets.insert(key.clone(), off);
        }

        let first_string_data_off = (data_off + data.len()) as u32;
        let mut string_data_offsets = Vec::with_capacity(strings.len());
        for s in &strings {
            string_data_offsets.push((data_off + data.len()) as u32);
            write_uleb128(&mut data, s.chars().count() as u32);
            data.extend_from_slice(s.as_bytes());
            data.push(0);
        }

        let mut class_data_offsets = Vec::<u32>::with_capacity(self.classes.len());
        let mut code_patch_offsets = Vec::<(usize, DexCode)>::new();
        for class in &self.classes {
            align_vec4(&mut data);
            let class_data_off = (data_off + data.len()) as u32;
            class_data_offsets.push(class_data_off);
            write_class_data_item(&mut data, class, &field_idx, &method_idx, &mut code_patch_offsets)?;
        }

        let mut code_offsets = Vec::<u32>::new();
        for (patch_pos, code) in code_patch_offsets {
            align_vec4(&mut data);
            let code_off = (data_off + data.len()) as u32;
            data[patch_pos..patch_pos + 5].copy_from_slice(&uleb128_padded5(code_off));
            code_offsets.push(code_off);
            write_code_item(&mut data, &code, &string_idx, &type_idx, &field_idx, &method_idx)?;
        }

        align_vec4(&mut data);
        let map_off = (data_off + data.len()) as u32;
        write_map_list(
            &mut data,
            &[
                (TYPE_HEADER_ITEM, 1, 0),
                (TYPE_STRING_ID_ITEM, strings.len() as u32, string_ids_off as u32),
                (TYPE_TYPE_ID_ITEM, types.len() as u32, type_ids_off as u32),
                (TYPE_PROTO_ID_ITEM, protos.len() as u32, proto_ids_off as u32),
                (TYPE_FIELD_ID_ITEM, fields.len() as u32, field_ids_off as u32),
                (TYPE_METHOD_ID_ITEM, methods.len() as u32, method_ids_off as u32),
                (TYPE_CLASS_DEF_ITEM, self.classes.len() as u32, class_defs_off as u32),
                (TYPE_MAP_LIST, 1, map_off),
                (TYPE_TYPE_LIST, type_lists.len() as u32, first_type_list_off),
                (TYPE_CLASS_DATA_ITEM, self.classes.len() as u32, class_data_offsets[0]),
                (
                    TYPE_CODE_ITEM,
                    code_offsets.len() as u32,
                    code_offsets.first().copied().unwrap_or(0),
                ),
                (TYPE_STRING_DATA_ITEM, strings.len() as u32, first_string_data_off),
            ],
        );

        let file_size = data_off + data.len();
        let mut out = vec![0u8; data_off];
        out.extend_from_slice(&data);

        out[0..8].copy_from_slice(b"dex\n035\0");
        write_u32_at(&mut out, 32, file_size as u32);
        write_u32_at(&mut out, 36, header_size as u32);
        write_u32_at(&mut out, 40, 0x1234_5678);
        write_u32_at(&mut out, 52, map_off);
        write_u32_at(&mut out, 56, strings.len() as u32);
        write_u32_at(&mut out, 60, string_ids_off as u32);
        write_u32_at(&mut out, 64, types.len() as u32);
        write_u32_at(&mut out, 68, type_ids_off as u32);
        write_u32_at(&mut out, 72, protos.len() as u32);
        write_u32_at(&mut out, 76, proto_ids_off as u32);
        write_u32_at(&mut out, 80, fields.len() as u32);
        write_u32_at(&mut out, 84, field_ids_off as u32);
        write_u32_at(&mut out, 88, methods.len() as u32);
        write_u32_at(&mut out, 92, method_ids_off as u32);
        write_u32_at(&mut out, 96, self.classes.len() as u32);
        write_u32_at(&mut out, 100, class_defs_off as u32);
        write_u32_at(&mut out, 104, (file_size - data_off) as u32);
        write_u32_at(&mut out, 108, data_off as u32);

        for (i, off) in string_data_offsets.iter().enumerate() {
            write_u32_at(&mut out, string_ids_off + i * 4, *off);
        }
        for (i, ty) in types.iter().enumerate() {
            write_u32_at(&mut out, type_ids_off + i * 4, string_idx[ty]);
        }
        for (i, proto) in protos.iter().enumerate() {
            let params: Vec<u32> = proto.params.iter().map(|p| type_idx[p]).collect();
            let params_off = if params.is_empty() {
                0
            } else {
                type_list_offsets[&params]
            };
            let off = proto_ids_off + i * 12;
            write_u32_at(&mut out, off, string_idx[&proto.shorty()]);
            write_u32_at(&mut out, off + 4, type_idx[&proto.return_type]);
            write_u32_at(&mut out, off + 8, params_off);
        }
        for (i, field) in fields.iter().enumerate() {
            let off = field_ids_off + i * 8;
            write_u16_at(&mut out, off, type_idx[&field.class_type] as u16);
            write_u16_at(&mut out, off + 2, type_idx[&field.type_name] as u16);
            write_u32_at(&mut out, off + 4, string_idx[&field.name]);
        }
        for (i, method) in methods.iter().enumerate() {
            let off = method_ids_off + i * 8;
            write_u16_at(&mut out, off, type_idx[&method.class_type] as u16);
            write_u16_at(&mut out, off + 2, proto_idx[&method.proto] as u16);
            write_u32_at(&mut out, off + 4, string_idx[&method.name]);
        }

        for (i, class) in self.classes.iter().enumerate() {
            let off = class_defs_off + i * 32;
            write_u32_at(&mut out, off, type_idx[&class.class_type]);
            write_u32_at(&mut out, off + 4, class.access_flags);
            write_u32_at(&mut out, off + 8, type_idx[&class.super_type]);
            write_u32_at(&mut out, off + 12, 0);
            let source_idx = class.source_file.as_ref().map(|s| string_idx[s]).unwrap_or(0xffff_ffff);
            write_u32_at(&mut out, off + 16, source_idx);
            write_u32_at(&mut out, off + 20, 0);
            write_u32_at(&mut out, off + 24, class_data_offsets[i]);
            write_u32_at(&mut out, off + 28, 0);
        }

        let signature = sha1_digest(&out[32..]);
        out[12..32].copy_from_slice(&signature);
        let checksum = adler32(&out[12..]);
        write_u32_at(&mut out, 8, checksum);

        Ok(out)
    }
}

pub(super) struct GeneratedManagedDex {
    pub dex: Vec<u8>,
    pub class_name: String,
    pub method_name: String,
    pub method_sig: String,
    pub uses_orig: bool,
    pub string_literals: Vec<GeneratedStringLiteral>,
}

#[derive(Clone, Debug)]
pub(super) struct GeneratedStringLiteral {
    pub field_name: String,
    pub value: String,
}

mod descriptor;
use descriptor::{
    array_component_descriptor, build_method_sig, build_params_sig, descriptor_list_word_count,
    descriptor_to_java_class_name, descriptor_word_count, java_class_to_descriptor,
    java_class_to_descriptor_or_primitive, parse_call_params, parse_method_params_signature, parse_method_signature,
    return_is_object,
};

fn emit_return_from_orig(ir: &mut DexIrBuilder, return_type: &str) -> Result<(), String> {
    match return_type {
        "V" => ir.return_void(),
        "J" | "D" => {
            ir.move_result_wide(0);
            ir.return_wide(0);
        }
        ret if return_is_object(ret) => {
            ir.move_result_object(0);
            ir.return_object(0);
        }
        "Z" | "B" | "C" | "S" | "I" | "F" => {
            ir.move_result(0);
            ir.return_value(0);
        }
        other => return Err(format!("unsupported return type '{}'", other)),
    }
    Ok(())
}

mod semantic;
use semantic::validate_semantics;

fn resolve_call_proto(
    env: JniEnv,
    stmt: &DslCallStmt,
    class_type: &str,
) -> Result<(Vec<String>, String, String), String> {
    if let Ok((params, return_type)) = parse_method_signature(&stmt.sig) {
        return Ok((params, return_type, stmt.sig.clone()));
    }

    let params = parse_method_params_signature(&stmt.sig)?;
    let params_sig = build_params_sig(&params);
    let class_name = descriptor_to_java_class_name(class_type)?;
    let is_static = matches!(stmt.kind, DslCallKind::Static);
    let collect_matches = |declared_only: bool, include_synthetic: bool| -> Result<BTreeSet<String>, String> {
        let methods = unsafe {
            if declared_only {
                enumerate_methods_declared_only(env, &class_name)
            } else {
                enumerate_methods(env, &class_name)
            }
        }?;
        let mut matches = BTreeSet::new();
        for method in methods {
            if method.name != stmt.method_name || method.is_static != is_static {
                continue;
            }
            if !include_synthetic && (method.modifiers & (ACC_BRIDGE as i32 | ACC_SYNTHETIC as i32)) != 0 {
                continue;
            }
            let Ok((method_params, _)) = parse_method_signature(&method.sig) else {
                continue;
            };
            if build_params_sig(&method_params) == params_sig {
                matches.insert(method.sig);
            }
        }
        Ok(matches)
    };

    let declared_matches = collect_matches(true, false)?;
    let matches = if declared_matches.is_empty() {
        let inherited_matches = collect_matches(false, false)?;
        if inherited_matches.is_empty() {
            collect_matches(false, true)?
        } else {
            inherited_matches
        }
    } else {
        declared_matches
    };

    match matches.len() {
        1 => {
            let full_sig = matches.into_iter().next().unwrap();
            let (params, return_type) = parse_method_signature(&full_sig)?;
            Ok((params, return_type, full_sig))
        }
        0 => Err(format!(
            "method not found for {}.{}{}; use a full JNI signature if reflection cannot resolve it",
            class_name, stmt.method_name, params_sig
        )),
        _ => Err(format!(
            "ambiguous method return for {}.{}{}; use overload(\"full JNI signature\")",
            class_name, stmt.method_name, params_sig
        )),
    }
}

mod emitter;
use emitter::{
    collect_local_slots, emit_statements, helper_param_layout, program_max_invoke_words, program_uses_orig,
    validate_orig_bypass_flow, DslBuildContext, EmitContext, BASE_LOCAL_REG_COUNT,
};

pub(super) unsafe fn build_managed_dsl_dex(
    env: JniEnv,
    class_id: u64,
    target_class_name: &str,
    target_method_name: &str,
    target_sig: &str,
    is_static: bool,
    dsl: &str,
) -> Result<GeneratedManagedDex, String> {
    let program = parse_managed_dsl(dsl)?;
    let uses_orig = program_uses_orig(&program);
    if uses_orig {
        validate_orig_bypass_flow(&program)?;
    }
    let target_type = java_class_to_descriptor(target_class_name)?;
    let object_type = "Ljava/lang/Object;".to_string();
    let (target_params, return_type) = parse_method_signature(target_sig)?;
    validate_semantics(env, &program, is_static, target_type.clone(), target_params.clone())?;
    let mut helper_params = Vec::new();
    if !is_static {
        helper_params.push(target_type.clone());
    }
    helper_params.extend(target_params.clone());

    let ins_size = descriptor_list_word_count(&helper_params)?;
    if ins_size > u8::MAX as u16 {
        return Err(format!("too many invoke argument words: {}", ins_size));
    }
    let max_invoke_words = program_max_invoke_words(&program, &target_params, is_static)?;
    if max_invoke_words > u8::MAX as u16 {
        return Err(format!("too many DSL invoke argument words: {}", max_invoke_words));
    }
    let locals_start = BASE_LOCAL_REG_COUNT
        .checked_add(max_invoke_words)
        .ok_or_else(|| "too many dex registers".to_string())?;
    let (local_slots, local_words) = collect_local_slots(&program, locals_start)?;
    let local_count = locals_start
        .checked_add(local_words)
        .ok_or_else(|| "too many dex registers".to_string())?;
    let registers_size = local_count
        .checked_add(ins_size)
        .ok_or_else(|| "too many dex registers".to_string())?;
    let outs_size = std::cmp::max(1u16, std::cmp::max(ins_size, max_invoke_words));
    if registers_size > u8::MAX as u16 {
        return Err(format!(
            "too many dex registers for generated helper: {}",
            registers_size
        ));
    }

    let generated_type = format!("Lrustfrida/DynManagedHook{};", class_id);
    let generated_class_name = format!("rustfrida.DynManagedHook{}", class_id);
    let sink = FieldRef::new(generated_type.clone(), object_type.clone(), "sink");
    let mut dsl_ctx = DslBuildContext::new(env, generated_type.clone(), BASE_LOCAL_REG_COUNT);
    let target = MethodRef::new(
        target_type.clone(),
        target_method_name.to_string(),
        return_type.clone(),
        target_params.clone(),
    );
    let mut ir = DexIrBuilder::new(registers_size, ins_size, outs_size);
    let layout = helper_param_layout(is_static, &target_type, &target_params, local_count, local_slots)?;
    let mut emit_ctx = EmitContext {
        layout: &layout,
        dsl_ctx: &mut dsl_ctx,
        is_static,
        local_count,
        ins_size,
        target: &target,
        return_type: &return_type,
        sink: &sink,
    };
    let saw_return = emit_statements(&mut ir, &program.stmts, &mut emit_ctx)?;
    if !saw_return {
        return Err("managed DSL must end with return statement".to_string());
    }
    let code = ir.finish()?;

    let mut class = DexClass::new(generated_type.clone()).source_file("RustFridaDynamicManagedHook.java");
    class.static_field("sink", &object_type, ACC_PUBLIC | ACC_STATIC | ACC_VOLATILE);
    for lit in &dsl_ctx.string_literals {
        class.static_field(
            &lit.field_name,
            "Ljava/lang/String;",
            ACC_PUBLIC | ACC_STATIC | ACC_VOLATILE,
        );
    }
    class.direct_method(
        "hook",
        &return_type,
        helper_params.clone(),
        ACC_PUBLIC | ACC_STATIC,
        code,
    );

    let mut builder = DexBuilder::new();
    builder.add_class(class);
    builder.add_method_ref(target);
    let dex = builder.build()?;

    Ok(GeneratedManagedDex {
        dex,
        class_name: generated_class_name,
        method_name: "hook".to_string(),
        method_sig: build_method_sig(&helper_params, &return_type),
        uses_orig,
        string_literals: dsl_ctx.string_literals,
    })
}

mod dsl;
use dsl::{parse_managed_dsl, DslCallKind, DslCallStmt};

fn write_class_data_item(
    out: &mut Vec<u8>,
    class: &DexClass,
    field_idx: &BTreeMap<FieldRef, u32>,
    method_idx: &BTreeMap<MethodRef, u32>,
    code_patch_offsets: &mut Vec<(usize, DexCode)>,
) -> Result<(), String> {
    write_uleb128(out, class.static_fields.len() as u32);
    write_uleb128(out, class.instance_fields.len() as u32);
    write_uleb128(out, class.direct_methods.len() as u32);
    write_uleb128(out, class.virtual_methods.len() as u32);

    write_encoded_fields(out, &class.static_fields, field_idx)?;
    write_encoded_fields(out, &class.instance_fields, field_idx)?;
    write_encoded_methods(out, &class.direct_methods, method_idx, code_patch_offsets)?;
    write_encoded_methods(out, &class.virtual_methods, method_idx, code_patch_offsets)?;
    Ok(())
}

fn write_encoded_fields(
    out: &mut Vec<u8>,
    fields: &[ClassField],
    field_idx: &BTreeMap<FieldRef, u32>,
) -> Result<(), String> {
    let mut entries = fields
        .iter()
        .map(|f| {
            let idx = *field_idx
                .get(&f.field)
                .ok_or_else(|| format!("missing field index for {}", f.field.name))?;
            Ok((idx, f.access_flags))
        })
        .collect::<Result<Vec<_>, String>>()?;
    entries.sort_by_key(|(idx, _)| *idx);

    let mut prev = 0u32;
    for (idx, access) in entries {
        write_uleb128(out, idx - prev);
        write_uleb128(out, access);
        prev = idx;
    }
    Ok(())
}

fn write_encoded_methods(
    out: &mut Vec<u8>,
    methods: &[ClassMethod],
    method_idx: &BTreeMap<MethodRef, u32>,
    code_patch_offsets: &mut Vec<(usize, DexCode)>,
) -> Result<(), String> {
    let mut entries = methods
        .iter()
        .map(|m| {
            let idx = *method_idx
                .get(&m.method)
                .ok_or_else(|| format!("missing method index for {}", m.method.name))?;
            Ok((idx, m.access_flags, m.code.clone()))
        })
        .collect::<Result<Vec<_>, String>>()?;
    entries.sort_by_key(|(idx, _, _)| *idx);

    let mut prev = 0u32;
    for (idx, access, code) in entries {
        write_uleb128(out, idx - prev);
        write_uleb128(out, access);
        if let Some(code) = code {
            let patch_pos = out.len();
            out.extend_from_slice(&[0, 0, 0, 0, 0]);
            code_patch_offsets.push((patch_pos, code));
        } else {
            write_uleb128(out, 0);
        }
        prev = idx;
    }
    Ok(())
}

fn write_code_item(
    out: &mut Vec<u8>,
    code: &DexCode,
    string_idx: &BTreeMap<String, u32>,
    type_idx: &BTreeMap<String, u32>,
    field_idx: &BTreeMap<FieldRef, u32>,
    method_idx: &BTreeMap<MethodRef, u32>,
) -> Result<(), String> {
    write_u16(out, code.registers_size);
    write_u16(out, code.ins_size);
    write_u16(out, code.outs_size);
    write_u16(out, 0);
    write_u32(out, 0);
    write_u32(out, code.insns.len() as u32);
    for word in &code.insns {
        match word {
            CodeWord::Raw(value) => write_u16(out, *value),
            CodeWord::String(value) => write_u16(out, lookup_u16(string_idx, value, "string")?),
            CodeWord::Type(ty) => write_u16(out, lookup_u16(type_idx, ty, "type")?),
            CodeWord::Field(field) => write_u16(out, lookup_u16(field_idx, field, "field")?),
            CodeWord::Method(method) => write_u16(out, lookup_u16(method_idx, method, "method")?),
        }
    }
    Ok(())
}

fn lookup_u16<K: Ord + std::fmt::Debug>(map: &BTreeMap<K, u32>, key: &K, kind: &str) -> Result<u16, String> {
    let value = *map
        .get(key)
        .ok_or_else(|| format!("missing {} index for {:?}", kind, key))?;
    if value > u16::MAX as u32 {
        return Err(format!("{} index too large: {}", kind, value));
    }
    Ok(value as u16)
}

fn shorty_char(descriptor: &str) -> char {
    match descriptor.as_bytes().first().copied() {
        Some(b'V') => 'V',
        Some(b'Z') => 'Z',
        Some(b'B') => 'B',
        Some(b'S') => 'S',
        Some(b'C') => 'C',
        Some(b'I') => 'I',
        Some(b'J') => 'J',
        Some(b'F') => 'F',
        Some(b'D') => 'D',
        _ => 'L',
    }
}

fn write_map_list(out: &mut Vec<u8>, entries: &[(u16, u32, u32)]) {
    let mut filtered: Vec<(u16, u32, u32)> = entries
        .iter()
        .copied()
        .filter(|(_, size, off)| *size != 0 || *off == 0)
        .collect();
    filtered.sort_by_key(|(_, _, off)| *off);
    write_u32(out, filtered.len() as u32);
    for (ty, size, off) in filtered {
        write_u16(out, ty);
        write_u16(out, 0);
        write_u32(out, size);
        write_u32(out, off);
    }
}

fn uleb128_padded5(mut value: u32) -> [u8; 5] {
    let mut out = [0u8; 5];
    let mut i = 0;
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out[i] = byte;
        i += 1;
        if value == 0 {
            break;
        }
    }
    out
}

fn write_uleb128(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

fn align_vec4(out: &mut Vec<u8>) {
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u16_at(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32_at(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn adler32(bytes: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    let mut a = 1u32;
    let mut b = 0u32;
    for byte in bytes {
        a = (a + *byte as u32) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

fn sha1_digest(bytes: &[u8]) -> [u8; 20] {
    let mut h0 = 0x6745_2301u32;
    let mut h1 = 0xefcd_ab89u32;
    let mut h2 = 0x98ba_dcfeu32;
    let mut h3 = 0x1032_5476u32;
    let mut h4 = 0xc3d2_e1f0u32;

    let bit_len = (bytes.len() as u64) * 8;
    let mut msg = bytes.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            let off = i * 4;
            w[i] = u32::from_be_bytes([chunk[off], chunk[off + 1], chunk[off + 2], chunk[off + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}
