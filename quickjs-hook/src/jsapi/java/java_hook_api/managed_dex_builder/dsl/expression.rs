use super::*;

impl<'a> DslParser<'a> {
    pub(super) fn parse_value_from_ident(&mut self, ident: String) -> Result<DslValue, String> {
        self.skip_ws();
        if ident == "orig" && self.peek() == Some('(') {
            return Ok(DslValue::OrigCall(self.parse_orig_args()?));
        }
        let value = if self.peek() == Some('.') {
            self.parse_js_member_value(ident)?
        } else {
            let target = self.scoped_target_name(&ident);
            let target = target.unwrap_or_else(|| DslTarget::Local(ident));
            DslValue::Target(target)
        };
        self.parse_value_postfix(value)
    }

    pub(super) fn parse_array_literal(&mut self) -> Result<DslValue, String> {
        self.expect_char('[')?;
        let mut elements = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(']') {
                self.expect_char(']')?;
                break;
            }
            elements.push(self.parse_value_arg()?);
            self.skip_ws();
            match self.peek() {
                Some(',') => {
                    self.expect_char(',')?;
                    self.skip_ws();
                    if self.peek() == Some(']') {
                        self.expect_char(']')?;
                        break;
                    }
                }
                Some(']') => {
                    self.expect_char(']')?;
                    break;
                }
                _ => return Err(self.err("array literal expects ',' or ']'")),
            }
        }
        Ok(DslValue::ArrayLiteral { elements })
    }

    pub(super) fn parse_value_postfix(&mut self, mut value: DslValue) -> Result<DslValue, String> {
        loop {
            self.skip_ws();
            if self.peek_ident("as") {
                self.expect_ident("as")?;
                let class_name = self.parse_type_name()?;
                value = DslValue::Cast {
                    value: Box::new(value),
                    class_name,
                };
            } else if self.peek() == Some('[') {
                self.expect_char('[')?;
                let index = self.parse_value_arg()?;
                let type_name = if self.peek() == Some(':') {
                    self.expect_char(':')?;
                    Some(self.parse_type_name()?)
                } else {
                    None
                };
                self.expect_char(']')?;
                value = DslValue::ArrayGet {
                    array: Box::new(value),
                    index: Box::new(index),
                    type_name,
                };
            } else if self.peek_op("?.") {
                value = self.parse_postfix_member_value(value, true)?;
            } else if self.peek() == Some('.') {
                value = self.parse_postfix_member_value(value, false)?;
            } else {
                return Ok(value);
            }
        }
    }

    pub(super) fn parse_value_arg_list_until_close(&mut self) -> Result<Vec<DslValue>, String> {
        let mut args = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(')') {
                break;
            }
            args.push(self.parse_value_arg()?);
            self.skip_ws();
            if self.peek() != Some(',') {
                break;
            }
            self.expect_char(',')?;
        }
        Ok(args)
    }

    pub(super) fn parse_optional_value_args(&mut self) -> Result<Vec<DslValue>, String> {
        let mut args = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() != Some(',') {
                break;
            }
            self.expect_char(',')?;
            args.push(self.parse_value_arg()?);
        }
        Ok(args)
    }
}
