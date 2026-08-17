use super::{ControlLine, ControlReply};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapEvent {
    pub progress: u8,
    pub tag: Option<String>,
    pub summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TorEvent {
    Bootstrap(BootstrapEvent),
    Unknown(ControlReply),
}

pub(crate) fn parse_event(reply: ControlReply) -> TorEvent {
    parse_bootstrap_reply(&reply)
        .map(TorEvent::Bootstrap)
        .unwrap_or(TorEvent::Unknown(reply))
}

pub(crate) fn parse_bootstrap_reply(reply: &ControlReply) -> Option<BootstrapEvent> {
    reply.lines.iter().find_map(|line| {
        let value = match line {
            ControlLine::Text(value) => value.as_str(),
            ControlLine::KeyValue { key, value } if key == "status/bootstrap-phase" => {
                value.as_str()
            }
            _ => return None,
        };
        parse_bootstrap_text(value)
    })
}

fn parse_bootstrap_text(value: &str) -> Option<BootstrapEvent> {
    let marker = value.find("BOOTSTRAP")?;
    let fields = control_words(&value[marker + "BOOTSTRAP".len()..]);
    let progress = field(&fields, "PROGRESS")?.parse().ok()?;
    Some(BootstrapEvent {
        progress,
        tag: field(&fields, "TAG").map(ToOwned::to_owned),
        summary: field(&fields, "SUMMARY").map(ToOwned::to_owned),
    })
}

pub(crate) fn control_words(input: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut chars = input.trim().chars().peekable();
    let mut quoted = false;

    while let Some(character) = chars.next() {
        match character {
            '"' => quoted = !quoted,
            '\\' if quoted => {
                if let Some(escaped) = chars.next() {
                    current.push(escaped);
                }
            }
            character if character.is_whitespace() && !quoted => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(character),
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

pub(crate) fn field<'a>(words: &'a [String], name: &str) -> Option<&'a str> {
    words
        .iter()
        .find_map(|word| word.strip_prefix(name)?.strip_prefix('='))
}
