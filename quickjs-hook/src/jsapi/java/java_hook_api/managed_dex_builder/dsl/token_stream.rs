use super::*;

pub(super) struct DslTokenStream<'a> {
    input: &'a str,
    tokens: &'a [lexer::Token],
    pos: usize,
}

impl<'a> DslTokenStream<'a> {
    pub(super) fn new(input: &'a str, tokens: &'a [lexer::Token], pos: usize) -> Self {
        Self { input, tokens, pos }
    }

    pub(super) fn pos(&self) -> usize {
        self.pos
    }

    pub(super) fn current_kind(&self) -> Option<&DslTokenKind> {
        self.tokens.get(self.pos).map(|token| &token.kind)
    }

    pub(super) fn advance(&mut self) {
        self.pos += 1;
    }

    pub(super) fn peek_char(&self, expected: char) -> bool {
        matches!(self.current_kind(), Some(DslTokenKind::Symbol(ch)) if *ch == expected)
    }

    pub(super) fn consume_char(&mut self, expected: char) -> bool {
        if self.peek_char(expected) {
            self.advance();
            true
        } else {
            false
        }
    }

    pub(super) fn peek_op(&self, expected: &str) -> bool {
        matches!(self.current_kind(), Some(DslTokenKind::Op(value)) if *value == expected)
    }

    pub(super) fn consume_op(&mut self, expected: &str) -> bool {
        if self.peek_op(expected) {
            self.advance();
            true
        } else {
            false
        }
    }

    pub(super) fn peek_ident(&self, expected: &str) -> bool {
        matches!(self.current_kind(), Some(DslTokenKind::Ident(value)) if value == expected)
    }

    pub(super) fn consume_ident(&mut self, expected: &str) -> bool {
        if self.peek_ident(expected) {
            self.advance();
            true
        } else {
            false
        }
    }

    pub(super) fn parse_ident(&mut self) -> Result<String, String> {
        let value = match self.current_kind() {
            Some(DslTokenKind::Ident(value)) => value.clone(),
            _ => return Err(self.err("expected identifier")),
        };
        self.advance();
        Ok(value)
    }

    pub(super) fn parse_string(&mut self) -> Result<String, String> {
        let value = match self.current_kind() {
            Some(DslTokenKind::String(value)) => value.clone(),
            _ => return Err(self.err("expected string")),
        };
        self.advance();
        Ok(value)
    }

    pub(super) fn parse_i16_after_sign(&mut self, negative: bool) -> Result<i16, String> {
        let value_text = match self.current_kind() {
            Some(DslTokenKind::Number(value)) => value.clone(),
            _ => return Err(self.err("expected integer")),
        };
        self.advance();
        let value: i32 = value_text.parse().map_err(|_| self.err("invalid integer"))?;
        let signed = if negative { -value } else { value };
        if signed < i16::MIN as i32 || signed > i16::MAX as i32 {
            return Err(self.err("integer must fit int16"));
        }
        Ok(signed as i16)
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
