use super::*;

impl<'a> DslParser<'a> {
    pub(super) fn skip_ws(&mut self) {}

    pub(super) fn mark(&self) -> DslMark {
        DslMark(self.pos)
    }

    pub(super) fn restore(&mut self, mark: DslMark) {
        self.pos = mark.0;
    }

    pub(super) fn expect_ident(&mut self, expected: &str) -> Result<(), String> {
        match self.current_kind() {
            Some(DslTokenKind::Ident(value)) if value == expected => {
                self.advance();
                Ok(())
            }
            _ => Err(self.err(&format!("expected identifier {}", expected))),
        }
    }

    pub(super) fn peek_ident(&self, expected: &str) -> bool {
        matches!(self.current_kind(), Some(DslTokenKind::Ident(value)) if value == expected)
    }

    pub(super) fn parse_ident(&mut self) -> Result<String, String> {
        match self.current_kind() {
            Some(DslTokenKind::Ident(value)) => {
                let value = value.clone();
                self.advance();
                Ok(value)
            }
            _ => Err(self.err("expected identifier")),
        }
    }

    pub(super) fn expect_char(&mut self, expected: char) -> Result<(), String> {
        match self.peek() {
            Some(ch) if ch == expected => {
                self.advance();
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
        match self.current_kind() {
            Some(DslTokenKind::String(value)) => {
                let value = value.clone();
                self.advance();
                Ok(value)
            }
            _ => Err(self.err("expected string")),
        }
    }

    pub(super) fn parse_number_text(&mut self) -> Result<String, String> {
        match self.current_kind() {
            Some(DslTokenKind::Number(value)) => {
                let value = value.clone();
                self.advance();
                Ok(value)
            }
            _ => Err(self.err("expected integer")),
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
        match self.current_kind() {
            Some(DslTokenKind::Symbol(ch)) => Some(*ch),
            _ => None,
        }
    }

    pub(super) fn peek_string(&self) -> bool {
        matches!(self.current_kind(), Some(DslTokenKind::String(_)))
    }

    pub(super) fn peek_number(&self) -> bool {
        matches!(self.current_kind(), Some(DslTokenKind::Number(_)))
    }

    pub(super) fn peek_op(&self, expected: &str) -> bool {
        matches!(self.current_kind(), Some(DslTokenKind::Op(value)) if *value == expected)
    }

    pub(super) fn expect_op(&mut self, expected: &str) -> Result<(), String> {
        if self.peek_op(expected) {
            self.advance();
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

    fn current_kind(&self) -> Option<&DslTokenKind> {
        self.tokens.get(self.pos).map(|token| &token.kind)
    }

    fn advance(&mut self) {
        self.pos += 1;
    }
}
