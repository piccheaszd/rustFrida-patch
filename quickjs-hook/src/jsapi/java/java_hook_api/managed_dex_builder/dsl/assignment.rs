use super::*;

impl<'a> DslParser<'a> {
    pub(super) fn local_increment_stmt(&self, name: String, delta: i16) -> DslStmt {
        let op = if delta >= 0 { DslIntBinOp::Add } else { DslIntBinOp::Sub };
        self.local_compound_assign_stmt(name, op, DslValue::Int(delta.abs()))
    }

    pub(super) fn local_compound_assign_stmt(&self, name: String, op: DslIntBinOp, rhs: DslValue) -> DslStmt {
        let left = DslValue::Target(DslTarget::Local(name.clone()));
        DslStmt::Assign {
            name,
            value: fold_int_binop(op, left, rhs),
        }
    }

    pub(super) fn increment_value_stmt(&self, value: DslValue, delta: i16) -> Result<DslStmt, String> {
        let op = if delta >= 0 { DslIntBinOp::Add } else { DslIntBinOp::Sub };
        self.compound_assign_value_stmt(value, op, DslValue::Int(delta.abs()))
    }

    pub(super) fn compound_assign_value_stmt(
        &self,
        value: DslValue,
        op: DslIntBinOp,
        rhs: DslValue,
    ) -> Result<DslStmt, String> {
        match value {
            DslValue::FieldGet { stmt, is_static } => Ok(DslStmt::FieldUpdate {
                stmt: *stmt,
                is_static,
                op,
                value: rhs,
            }),
            DslValue::ArrayGet {
                array,
                index,
                type_name,
            } => Ok(DslStmt::ArrayUpdate {
                array: *array,
                index: *index,
                type_name,
                op,
                value: rhs,
            }),
            DslValue::Target(DslTarget::Local(name)) => Ok(self.local_compound_assign_stmt(name, op, rhs)),
            _ => Err(self.err("compound assignment supports locals, fields, and array elements")),
        }
    }
}
