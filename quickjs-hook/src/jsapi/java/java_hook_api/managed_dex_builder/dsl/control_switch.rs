use super::*;

impl<'a> DslParser<'a> {
    pub(super) fn parse_js_switch_statement(&mut self) -> Result<DslStmt, String> {
        self.expect_ident("switch")?;
        self.skip_ws();
        self.expect_char('(')?;
        let value = self.parse_value_arg()?;
        self.expect_char(')')?;
        self.skip_ws();
        self.expect_char('{')?;

        let mut cases = Vec::<(i16, Vec<DslStmt>)>::new();
        let mut default_stmts = None::<Vec<DslStmt>>;
        loop {
            self.skip_ws();
            if self.peek() == Some('}') {
                self.expect_char('}')?;
                break;
            }
            if self.peek_ident("case") {
                self.expect_ident("case")?;
                let literal = self.parse_i16()?;
                self.expect_char(':')?;
                let stmts = self.parse_block()?;
                cases.push((literal, stmts));
            } else if self.peek_ident("default") {
                if default_stmts.is_some() {
                    return Err(self.err("switch supports only one default block"));
                }
                self.expect_ident("default")?;
                self.skip_ws();
                self.expect_char(':')?;
                default_stmts = Some(self.parse_block()?);
            } else {
                return Err(self.err("expected switch case/default block"));
            }
        }
        if cases.is_empty() {
            return Err(self.err("switch requires at least one case"));
        }

        Ok(DslStmt::Switch {
            value,
            cases,
            default_stmts,
        })
    }
}
