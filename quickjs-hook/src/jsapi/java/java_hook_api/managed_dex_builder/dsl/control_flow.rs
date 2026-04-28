use super::*;

impl<'a> DslParser<'a> {
    pub(super) fn parse_js_if_statement(&mut self) -> Result<DslStmt, String> {
        self.expect_ident("if")?;
        self.skip_ws();
        self.expect_char('(')?;
        let condition = self.parse_js_if_condition()?;
        self.expect_char(')')?;
        let then_stmts = self.parse_statement_body()?;
        self.skip_ws();
        let else_stmts = if self.peek_ident("else") {
            self.expect_ident("else")?;
            self.skip_ws();
            if self.peek_ident("if") {
                vec![self.parse_js_if_statement()?]
            } else {
                self.parse_statement_body()?
            }
        } else {
            Vec::new()
        };
        Ok(condition.into_if_stmt(then_stmts, else_stmts))
    }
}
