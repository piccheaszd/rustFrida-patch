use super::*;

impl<'a> DslParser<'a> {
    pub(super) fn parse_js_try_catch_statement(&mut self) -> Result<DslStmt, String> {
        self.expect_ident("try")?;
        let try_stmts = self.parse_block()?;
        let mut catches = Vec::new();
        loop {
            self.skip_ws();
            if !self.peek_ident("catch") {
                break;
            }
            self.expect_ident("catch")?;
            self.skip_ws();
            self.expect_char('(')?;
            let (catch_type, catch_name) = self.parse_catch_param()?;
            self.skip_ws();
            self.expect_char(')')?;
            let (catch_name, catch_stmts) = self.with_local_scope(|parser| {
                let catch_name = parser.declare_local(catch_name)?;
                let catch_stmts = parser.parse_block()?;
                Ok((catch_name, catch_stmts))
            })?;
            catches.push(DslCatch {
                catch_type,
                catch_name,
                catch_stmts,
            });
        }
        if catches.is_empty() {
            return Err(self.err("try requires at least one catch block"));
        }
        Ok(DslStmt::TryCatch { try_stmts, catches })
    }

    fn parse_catch_param(&mut self) -> Result<(String, String), String> {
        self.skip_ws();
        let checkpoint = self.mark();
        if let Ok(catch_name) = self.parse_ident() {
            self.skip_ws();
            if self.peek() == Some(')') {
                return Ok(("java.lang.Throwable".to_string(), catch_name));
            }
        }
        self.restore(checkpoint);
        let catch_type = self.parse_type_name()?;
        self.skip_ws();
        let catch_name = self.parse_ident()?;
        Ok((catch_type, catch_name))
    }
}
