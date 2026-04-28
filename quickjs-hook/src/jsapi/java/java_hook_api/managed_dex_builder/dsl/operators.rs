use super::*;

const INT_BINARY_TOKEN_OPS: &[(&str, DslIntBinOp, u8)] = &[
    (">>>", DslIntBinOp::Ushr, 5),
    ("<<", DslIntBinOp::Shl, 5),
    (">>", DslIntBinOp::Shr, 5),
];

const INT_BINARY_CHAR_OPS: &[(char, DslIntBinOp, u8)] = &[
    ('|', DslIntBinOp::Or, 1),
    ('^', DslIntBinOp::Xor, 2),
    ('&', DslIntBinOp::And, 3),
    ('+', DslIntBinOp::Add, 6),
    ('-', DslIntBinOp::Sub, 6),
    ('*', DslIntBinOp::Mul, 7),
    ('/', DslIntBinOp::Div, 7),
    ('%', DslIntBinOp::Rem, 7),
];

const COMPOUND_ASSIGN_OPS: &[(&str, DslIntBinOp)] = &[
    (">>>=", DslIntBinOp::Ushr),
    ("<<=", DslIntBinOp::Shl),
    (">>=", DslIntBinOp::Shr),
    ("+=", DslIntBinOp::Add),
    ("-=", DslIntBinOp::Sub),
    ("*=", DslIntBinOp::Mul),
    ("/=", DslIntBinOp::Div),
    ("%=", DslIntBinOp::Rem),
    ("&=", DslIntBinOp::And),
    ("|=", DslIntBinOp::Or),
    ("^=", DslIntBinOp::Xor),
];

impl<'a> DslParser<'a> {
    pub(super) fn peek_int_binary_op(&mut self) -> Option<(DslIntBinOp, u8)> {
        self.skip_ws();
        for (token, op, prec) in INT_BINARY_TOKEN_OPS {
            if self.peek_op(token) {
                return Some((*op, *prec));
            }
        }
        let ch = self.peek()?;
        INT_BINARY_CHAR_OPS
            .iter()
            .find_map(|(candidate, op, prec)| (*candidate == ch).then_some((*op, *prec)))
    }

    pub(super) fn consume_int_binary_op(&mut self, op: DslIntBinOp) -> Result<(), String> {
        if let Some((token, _, _)) = INT_BINARY_TOKEN_OPS.iter().find(|(_, candidate, _)| *candidate == op) {
            return self.expect_op(token);
        }
        if let Some((ch, _, _)) = INT_BINARY_CHAR_OPS.iter().find(|(_, candidate, _)| *candidate == op) {
            return self.expect_char(*ch);
        }
        Err(self.err("unsupported integer binary operator"))
    }

    pub(super) fn peek_compound_assign_op(&self) -> Option<DslIntBinOp> {
        COMPOUND_ASSIGN_OPS
            .iter()
            .find_map(|(token, op)| self.peek_op(token).then_some(*op))
    }

    pub(super) fn consume_compound_assign_op(&mut self, op: DslIntBinOp) -> Result<(), String> {
        let Some((token, _)) = COMPOUND_ASSIGN_OPS.iter().find(|(_, candidate)| *candidate == op) else {
            return Err(self.err("unsupported compound assignment operator"));
        };
        self.expect_op(token)
    }
}
