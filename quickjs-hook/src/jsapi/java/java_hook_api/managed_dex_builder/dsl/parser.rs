use std::collections::BTreeMap;

use super::lexer::{lex as dsl_lex, Token as DslToken};
use super::*;

pub(super) struct DslParser<'a> {
    input: &'a str,
    tokens: Vec<DslToken>,
    pos: usize,
    pub(super) local_scopes: Vec<BTreeMap<String, String>>,
    pub(super) next_local_id: usize,
}

impl<'a> DslParser<'a> {
    pub(super) fn new(input: &'a str) -> Result<Self, String> {
        Ok(Self {
            input,
            tokens: dsl_lex(input)?,
            pos: 0,
            local_scopes: vec![BTreeMap::new()],
            next_local_id: 0,
        })
    }

    pub(super) fn skip_ws(&mut self) {}

    pub(super) fn mark(&self) -> usize {
        self.pos
    }

    pub(super) fn restore(&mut self, mark: usize) {
        self.pos = mark;
    }

    pub(super) fn rewind_one(&mut self) {
        self.pos = self.pos.saturating_sub(1);
    }

    pub(super) fn expect_ident(&mut self, expected: &str) -> Result<(), String> {
        match self.tokens.get(self.pos).map(|token| &token.kind) {
            Some(DslTokenKind::Ident(value)) if value == expected => {
                self.pos += 1;
                Ok(())
            }
            _ => Err(self.err(&format!("expected identifier {}", expected))),
        }
    }

    pub(super) fn peek_ident(&self, expected: &str) -> bool {
        matches!(self.tokens.get(self.pos).map(|token| &token.kind), Some(DslTokenKind::Ident(value)) if value == expected)
    }

    pub(super) fn parse_ident(&mut self) -> Result<String, String> {
        match self.tokens.get(self.pos).map(|token| &token.kind) {
            Some(DslTokenKind::Ident(value)) => {
                self.pos += 1;
                Ok(value.clone())
            }
            _ => Err(self.err("expected identifier")),
        }
    }

    pub(super) fn expect_char(&mut self, expected: char) -> Result<(), String> {
        match self.peek() {
            Some(ch) if ch == expected => {
                self.pos += 1;
                Ok(())
            }
            _ => Err(self.err(&format!("expected '{}'", expected))),
        }
    }

    pub(super) fn parse_string_arg(&mut self) -> Result<String, String> {
        self.skip_ws();
        let value = self.parse_string()?;
        self.skip_ws();
        Ok(value)
    }

    pub(super) fn parse_string(&mut self) -> Result<String, String> {
        match self.tokens.get(self.pos).map(|token| &token.kind) {
            Some(DslTokenKind::String(value)) => {
                self.pos += 1;
                Ok(value.clone())
            }
            _ => Err(self.err("expected string")),
        }
    }

    pub(super) fn parse_type_name(&mut self) -> Result<String, String> {
        self.skip_ws();
        if self.peek_string() {
            return self.parse_string_arg();
        }
        let mut name = self.parse_ident()?;
        loop {
            self.skip_ws();
            match self.peek() {
                Some('.') => {
                    self.expect_char('.')?;
                    let part = self.parse_ident()?;
                    name.push('.');
                    name.push_str(&part);
                }
                Some('[') => {
                    self.expect_char('[')?;
                    self.expect_char(']')?;
                    name.push_str("[]");
                }
                _ => break,
            }
        }
        self.skip_ws();
        Ok(name)
    }

    pub(super) fn parse_i16(&mut self) -> Result<i16, String> {
        self.skip_ws();
        let negative = if self.peek() == Some('-') {
            self.pos += 1;
            true
        } else {
            false
        };
        let value_text = match self.tokens.get(self.pos).map(|token| &token.kind) {
            Some(DslTokenKind::Number(value)) => {
                self.pos += 1;
                value.clone()
            }
            _ => return Err(self.err("expected integer")),
        };
        let value: i32 = value_text.parse().map_err(|_| self.err("invalid integer"))?;
        let signed = if negative { -value } else { value };
        if signed < i16::MIN as i32 || signed > i16::MAX as i32 {
            return Err(self.err("integer must fit int16"));
        }
        self.skip_ws();
        Ok(signed as i16)
    }

    pub(super) fn peek_compound_assign_op(&self) -> Option<DslIntBinOp> {
        if self.peek_op(">>>=") {
            return Some(DslIntBinOp::Ushr);
        }
        if self.peek_op("<<=") {
            return Some(DslIntBinOp::Shl);
        }
        if self.peek_op(">>=") {
            return Some(DslIntBinOp::Shr);
        }
        if self.peek_op("+=") {
            return Some(DslIntBinOp::Add);
        }
        if self.peek_op("-=") {
            return Some(DslIntBinOp::Sub);
        }
        if self.peek_op("*=") {
            return Some(DslIntBinOp::Mul);
        }
        if self.peek_op("/=") {
            return Some(DslIntBinOp::Div);
        }
        if self.peek_op("%=") {
            return Some(DslIntBinOp::Rem);
        }
        if self.peek_op("&=") {
            return Some(DslIntBinOp::And);
        }
        if self.peek_op("|=") {
            return Some(DslIntBinOp::Or);
        }
        if self.peek_op("^=") {
            return Some(DslIntBinOp::Xor);
        }
        None
    }

    pub(super) fn consume_compound_assign_op(&mut self, op: DslIntBinOp) -> Result<(), String> {
        match op {
            DslIntBinOp::Ushr => self.expect_op(">>>="),
            DslIntBinOp::Shl => self.expect_op("<<="),
            DslIntBinOp::Shr => self.expect_op(">>="),
            DslIntBinOp::Add => self.expect_op("+="),
            DslIntBinOp::Sub => self.expect_op("-="),
            DslIntBinOp::Mul => self.expect_op("*="),
            DslIntBinOp::Div => self.expect_op("/="),
            DslIntBinOp::Rem => self.expect_op("%="),
            DslIntBinOp::And => self.expect_op("&="),
            DslIntBinOp::Or => self.expect_op("|="),
            DslIntBinOp::Xor => self.expect_op("^="),
        }
    }

    pub(super) fn expect_eof(&self) -> Result<(), String> {
        if self.pos == self.tokens.len() {
            Ok(())
        } else {
            Err(self.err("unexpected trailing input"))
        }
    }

    pub(super) fn peek(&self) -> Option<char> {
        match self.tokens.get(self.pos).map(|token| &token.kind) {
            Some(DslTokenKind::Symbol(ch)) => Some(*ch),
            _ => None,
        }
    }

    pub(super) fn peek_string(&self) -> bool {
        matches!(
            self.tokens.get(self.pos).map(|token| &token.kind),
            Some(DslTokenKind::String(_))
        )
    }

    pub(super) fn peek_number(&self) -> bool {
        matches!(
            self.tokens.get(self.pos).map(|token| &token.kind),
            Some(DslTokenKind::Number(_))
        )
    }

    pub(super) fn peek_op(&self, expected: &str) -> bool {
        matches!(self.tokens.get(self.pos).map(|token| &token.kind), Some(DslTokenKind::Op(value)) if *value == expected)
    }

    pub(super) fn expect_op(&mut self, expected: &str) -> Result<(), String> {
        if self.peek_op(expected) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.err(&format!("expected operator {}", expected)))
        }
    }

    pub(super) fn is_eof(&self) -> bool {
        self.pos == self.tokens.len()
    }

    pub(super) fn err(&self, msg: &str) -> String {
        let byte = self
            .tokens
            .get(self.pos)
            .map(|token| token.byte)
            .unwrap_or_else(|| self.input.len());
        format!("managed dex DSL parse error at byte {}: {}", byte, msg)
    }
}
