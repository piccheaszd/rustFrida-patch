use super::*;

impl<'a> DslParser<'a> {
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
            self.expect_char('-')?;
            true
        } else {
            false
        };
        let value_text = self.parse_number_text()?;
        let value: i32 = value_text.parse().map_err(|_| self.err("invalid integer"))?;
        let signed = if negative { -value } else { value };
        if signed < i16::MIN as i32 || signed > i16::MAX as i32 {
            return Err(self.err("integer must fit int16"));
        }
        self.skip_ws();
        Ok(signed as i16)
    }
}
