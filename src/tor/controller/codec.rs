use tokio::io::{AsyncBufRead, AsyncBufReadExt};

use super::TorControlError;

/// One complete Control Port reply (a status code and its lines).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlReply {
    /// The three-digit control protocol status code.
    pub code: u16,
    /// The reply's body lines.
    pub lines: Vec<ControlLine>,
}

impl ControlReply {
    /// Whether the status code indicates success (`250`).
    pub fn is_success(&self) -> bool {
        self.code == 250
    }

    /// Joins the reply's lines into one human-readable message.
    pub fn message(&self) -> String {
        self.lines
            .iter()
            .map(|line| match line {
                ControlLine::Text(text) => text.clone(),
                ControlLine::KeyValue { key, value } | ControlLine::Data { key, value } => {
                    format!("{key}={value}")
                }
            })
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// One line within a [`ControlReply`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlLine {
    /// A free-form text line.
    Text(String),
    /// A `key=value` line.
    KeyValue {
        /// The key.
        key: String,
        /// The value.
        value: String,
    },
    /// A multi-line data block (a `key=` line followed by a dot-terminated
    /// body), joined into one value.
    Data {
        /// The key.
        key: String,
        /// The joined body text.
        value: String,
    },
}

/// Reads and parses one complete control reply, or `None` at EOF.
pub async fn read_reply<R>(reader: &mut R) -> Result<Option<ControlReply>, TorControlError>
where
    R: AsyncBufRead + Unpin,
{
    let Some(first) = read_protocol_line(reader).await? else {
        return Ok(None);
    };
    let (code, separator, payload) = parse_status_line(&first)?;
    let mut lines = Vec::new();
    consume_line(reader, code, separator, payload, &mut lines).await?;

    if separator == ' ' {
        return Ok(Some(ControlReply { code, lines }));
    }

    loop {
        let line = read_protocol_line(reader)
            .await?
            .ok_or_else(|| TorControlError::Protocol("unexpected EOF in reply".to_string()))?;
        let (line_code, separator, payload) = parse_status_line(&line)?;
        if line_code != code {
            return Err(TorControlError::Protocol(format!(
                "reply status changed from {code} to {line_code}"
            )));
        }
        consume_line(reader, code, separator, payload, &mut lines).await?;
        if separator == ' ' {
            break;
        }
    }

    Ok(Some(ControlReply { code, lines }))
}

async fn consume_line<R>(
    reader: &mut R,
    _code: u16,
    separator: char,
    payload: String,
    lines: &mut Vec<ControlLine>,
) -> Result<(), TorControlError>
where
    R: AsyncBufRead + Unpin,
{
    if separator == '+' {
        let key = payload.strip_suffix('=').unwrap_or(&payload).to_string();
        let mut data = Vec::new();
        loop {
            let line = read_protocol_line(reader).await?.ok_or_else(|| {
                TorControlError::Protocol("unexpected EOF in data reply".to_string())
            })?;
            if line == "." {
                break;
            }
            data.push(
                line.strip_prefix("..")
                    .map(|line| format!(".{line}"))
                    .unwrap_or(line),
            );
        }
        lines.push(ControlLine::Data {
            key,
            value: data.join("\n"),
        });
    } else {
        lines.push(parse_payload(payload));
    }
    Ok(())
}

fn parse_payload(payload: String) -> ControlLine {
    if let Some((key, value)) = payload.split_once('=')
        && !key.is_empty()
        && !key.chars().any(char::is_whitespace)
    {
        return ControlLine::KeyValue {
            key: key.to_string(),
            value: value.to_string(),
        };
    }
    ControlLine::Text(payload)
}

fn parse_status_line(line: &str) -> Result<(u16, char, String), TorControlError> {
    if line.len() < 4 || !line.is_char_boundary(3) {
        return Err(TorControlError::Protocol(format!(
            "malformed status line: {line:?}"
        )));
    }
    let code = line[..3]
        .parse::<u16>()
        .map_err(|_| TorControlError::Protocol(format!("invalid status code: {line:?}")))?;
    let separator = line.as_bytes()[3] as char;
    if !matches!(separator, ' ' | '-' | '+') {
        return Err(TorControlError::Protocol(format!(
            "invalid status separator: {line:?}"
        )));
    }
    Ok((code, separator, line[4..].to_string()))
}

async fn read_protocol_line<R>(reader: &mut R) -> Result<Option<String>, TorControlError>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = String::new();
    if reader.read_line(&mut line).await? == 0 {
        return Ok(None);
    }
    while matches!(line.as_bytes().last(), Some(b'\n' | b'\r')) {
        line.pop();
    }
    Ok(Some(line))
}

#[cfg(test)]
mod tests {
    use tokio::io::BufReader;

    use super::*;

    async fn parse(input: &str) -> ControlReply {
        let mut reader = BufReader::new(input.as_bytes());
        read_reply(&mut reader).await.unwrap().unwrap()
    }

    #[tokio::test]
    async fn parses_single_line_reply() {
        assert_eq!(
            parse("250 OK\r\n").await,
            ControlReply {
                code: 250,
                lines: vec![ControlLine::Text("OK".to_string())],
            }
        );
    }

    #[tokio::test]
    async fn parses_multiline_reply() {
        assert_eq!(
            parse("250-key=value\r\n250-second=two\r\n250 OK\r\n").await,
            ControlReply {
                code: 250,
                lines: vec![
                    ControlLine::KeyValue {
                        key: "key".to_string(),
                        value: "value".to_string(),
                    },
                    ControlLine::KeyValue {
                        key: "second".to_string(),
                        value: "two".to_string(),
                    },
                    ControlLine::Text("OK".to_string()),
                ],
            }
        );
    }

    #[tokio::test]
    async fn parses_data_reply_and_unescapes_leading_dot() {
        assert_eq!(
            parse("250+config-text=\r\nfirst\r\n..second\r\n.\r\n250 OK\r\n").await,
            ControlReply {
                code: 250,
                lines: vec![
                    ControlLine::Data {
                        key: "config-text".to_string(),
                        value: "first\n.second".to_string(),
                    },
                    ControlLine::Text("OK".to_string()),
                ],
            }
        );
    }
}
