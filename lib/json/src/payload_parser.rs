///
/// We put some trust in the JSON provided by grafana-agent-flow and
/// passed along by Vector. Because it should be the same always, we're
/// confident that we can parse the json blob as a simple string,
/// instead of going full fledged serde_json on it. This saves us many
/// precious microseconds.
///
/// (1) We expect the {"attributes":{ map to be first. [But this is not
///     mandatory.]
/// (2) We expect no excess spaces. [Also not mandatory.]
/// (3) The fields inside the "attributes" map should have no funny
///     characters, like "section":"section\"ha, there is more".
///     [Also not mandatory.]
/// (4) I don't think you can abuse it enough to spoil other hosts logs,
///     but you might spoil/break your own log parsing. But if you wanted
///     to do that, you might as well just stop the grafana-agent.
///
/// TODO: Double check that we cannot intentionaly panic the
/// BytesAttributes parser.
///
/// Input payload:
///
/// {
///   "attributes": {
///     "host": "mgmt.example",
///     "job": "loki.source.journal.logs_journald_generic",
///     "observed_time_unix_nano": 1708349372637827462,
///     "section": "section-dmz-cat4",
///     "systemd_unit": "session-7889.scope",
///     "time_unix_nano": 1708349372636882340
///   },
///   "dropped_attributes_count": 0,
///   "message": <900 bytes>,
///   "observed_timestamp": "2024-02-16T16:46:38.674019861Z",
///   "source_type": "opentelemetry",
///   "timestamp": "2024-02-16T16:46:38.323659Z"
/// }
///


///
/// The data is guaranteed to be JSON, so we should not panic here.
///
fn force_string(data: &[u8]) -> &str {
    std::str::from_utf8(data).unwrap()
}

///
/// Result of the fast parser.
///
#[derive(Debug)]
#[derive(PartialEq)]
pub struct BytesAttributes<'a> {
    pub tenant: &'a [u8],
    pub section: &'a [u8],
    pub timens: &'a [u8],
    pub hostname: &'a [u8],
    pub cluster: &'a [u8],          // optional
    pub systemd_unit: &'a [u8],     // optional
    pub filename: &'a [u8],         // optional
    pub message: &'a [u8],
}

///
/// Result of the safe parser.
///
#[cfg(feature = "benchmark")]
#[derive(Debug)]
#[derive(PartialEq)]
pub struct StringAttributes {
    pub tenant: String,
    pub section: String,
    pub timens: String,
    pub hostname: String,
    pub cluster: String,        // optional
    pub systemd_unit: String,   // optional
    pub filename: String,       // optional
    pub message: String,
}


impl<'a> BytesAttributes<'a> {
    pub fn from_payload(payload: &'a [u8]) -> Result<BytesAttributes, &str> {
        Self::consume_special_root(payload)
    }

    pub fn get_section(&self) -> &str {
        force_string(self.section)
    }

    pub fn has_no_origin(&self) -> bool {
        self.systemd_unit.len() == 0 && self.filename.len() == 0
    }

    /// Parse the entire payload.
    fn consume_special_root(payload: &'a [u8]) -> Result<BytesAttributes, &str> {
        let mut bingo: u32 = 0; // 1(attributes) + 2(message)

        let mut partial = BytesAttributes {
            tenant: &payload[0..0],
            section: &payload[0..0],
            timens: &payload[0..0],
            hostname: &payload[0..0],
            cluster: &payload[0..0],         // optional
            systemd_unit: &payload[0..0],    // optional
            filename: &payload[0..0],        // optional
            message: &payload[0..0],
        };

        let mut i: usize = 0usize;

        Self::consume_token(payload, &mut i, b'{')?;
        while i < payload.len() {
            let key = Self::consume_key(payload, &mut i)?;
            Self::consume_token(payload, &mut i, b':')?;

            if key == b"attributes" {
                Self::consume_special_attributes(payload, &mut i, &mut partial)?;
                //println!("[{}] {} from_payload after special", i, payload[i]);
               bingo |= 1;
            } else if key == b"message" {
                partial.message = Self::consume_string(payload, &mut i)?;
               bingo |= 2;
            } else {
                Self::consume_value(payload, &mut i)?;
            }
            if bingo == 3 {
                break;
            }
            let ch = Self::skip_whitespace(payload, &mut i)?;
            //println!("[{}] {} from_payload in root", i, ch);
            if ch == b',' {
                i += 1;
            } else if ch == b'}' {
                break;
            } else {
                return Err("unexpected token in from_payload");
            }
        }

        if bingo != 3 {
            return Err("attributes or message not found in from_payload");
        }

        Ok(partial)
    }

    /// Parse the attributes dict where the relevant information it.
    fn consume_special_attributes(
            payload: &'a [u8],
            i: &mut usize,
            partial: &mut BytesAttributes<'a>,
            ) -> Result<(), &'static str> {

        Self::consume_token(payload, i, b'{')?;
        //let begin = *i;

        while *i < payload.len() {
            let key = Self::consume_key(payload, i)?;
            Self::consume_token(payload, i, b':')?;
            match key {
                b"tenant" => {
                    partial.tenant = Self::consume_string(payload, i)?;
                },
                b"section" => {
                    partial.section = Self::consume_string(payload, i)?;
                },
                b"time_unix_nano" => {
                    partial.timens = Self::consume_other(payload, i)?;
                },
                b"host" => {
                    partial.hostname = Self::consume_string(payload, i)?;
                },
                b"cluster" => {
                    partial.cluster = Self::consume_string(payload, i)?;
                },
                b"systemd_unit" => {
                    partial.systemd_unit = Self::consume_string(payload, i)?;
                },
                b"filename" => {
                    partial.filename = Self::consume_string(payload, i)?;
                },
                _ => {
                    Self::consume_value(payload, i)?;
                }
            }

            let ch = Self::skip_whitespace(payload, i)?;
            if ch == b'}' {
                *i += 1;
                return Ok(());
            } else if ch == b',' {
                *i += 1;
            } else {
                //println!("[{}] {} consume_special_attributes", *i, ch as char);
                return Err("unexpected token in consume_special_attributes");
            }
        }
        Err("unexpected EOF in consume_special_attributes")
    }

    /// Expect a json dict key (after optional whitespace).
    fn consume_key(payload: &'a [u8], i: &mut usize) -> Result<&'a [u8], &'static str> {
        //println!("[consume_key]");
        Self::consume_string(payload, i)
    }

    /// Expect a json string (after optional whitespace).
    fn consume_string(payload: &'a [u8], i: &mut usize) -> Result<&'a [u8], &'static str> {
        //println!("[consume_string]");
        Self::consume_token(payload, i, b'"')?;
        let begin = *i;

        while *i < payload.len() {
            //println!("[{}] {} consume_string(...)", *i, payload[*i] as char);
            let ch = payload[*i];
            if ch == b'"' {
                *i += 1;
                return Ok(&payload[begin..(*i - 1)]);
            } else if ch == b'\\' {
                *i += 1;
            }
            *i += 1;
        }
        Err("unexpected EOF in consume_string")
    }

    /// Expect a specific token (after optional whitespace).
    fn consume_token(payload: &'a [u8], i: &mut usize, token: u8) -> Result<(), &'static str> {
        Self::skip_whitespace(payload, i)?;
        //println!("[{}] {} consume_token({})", *i, payload[*i] as char, token as char);
        if payload[*i] == token {
            *i += 1;
            return Ok(());
        }
        Err("expected token, found something else")
    }

    /// Expect any json value (string, non-string, list, dict) (after optional whitespace).
    fn consume_value(payload: &'a [u8], i: &mut usize) -> Result<&'a [u8], &'static str> {
        //println!("[consume_value]");
        let ch = Self::skip_whitespace(payload, i)?;
        match ch {
            b'{' => { return Self::consume_dict(payload, i);  },
            b'[' => { return Self::consume_list(payload, i); },
            b'"' => { return Self::consume_string(payload, i); },
            _ => { return Self::consume_other(payload, i); },
        }
    }

    /// Expect a json dictionary (immediately).
    fn consume_dict(payload: &'a [u8], i: &mut usize) -> Result<&'a [u8], &'static str> {
        //println!("[consume_dict]");
        //let first = Self::skip_whitespace(payload, i)?;

        let begin = *i;
        debug_assert_eq!(payload[begin], b'{');

        *i += 1;
        //Self::consume_token(payload, i, b'{')?;

        let mut ch = Self::skip_whitespace(payload, i)?;
        while *i < payload.len() {
            if ch == b'}' {
                *i += 1;
                return Ok(&payload[begin..(*i)]);
            }
            Self::consume_string(payload, i)?;
            Self::consume_token(payload, i, b':')?;
            Self::consume_value(payload, i)?;
            ch = Self::skip_whitespace(payload, i)?;
            if ch == b',' {
                *i += 1;
            } else if ch != b'}' {
                return Err("garbage in consume_dict");
            }
        }

        Err("unexpected EOF in consume_dict")
    }

    /// Expect a json list (immediately).
    fn consume_list(payload: &'a [u8], i: &mut usize) -> Result<&'a [u8], &'static str> {
        //println!("[consume_list]");
        //let first = Self::skip_whitespace(payload, i)?;

        let begin = *i;
        debug_assert_eq!(payload[begin], b'[');

        *i += 1;
        //Self::consume_token(payload, i, b'[')?;

        let mut ch = Self::skip_whitespace(payload, i)?;
        while *i < payload.len() {
            if ch == b']' {
                *i += 1;
                return Ok(&payload[begin..(*i)]);
            }
            Self::consume_value(payload, i)?;
            ch = Self::skip_whitespace(payload, i)?;
            if ch == b',' {
                *i += 1;
            } else if ch != b']' {
                return Err("garbage in consume_list");
            }
        }

        Err("unexpected EOF in consume_list")
    }

    /// Anything that is not whitespace/json, might be an identifier
    /// or number or truthy value.
    fn consume_other(payload: &'a [u8], i: &mut usize) -> Result<&'a [u8], &'static str> {
        //println!("[consume_other]");
        let begin = *i;

        while *i < payload.len() {
            let ch = payload[*i];
            //println!("[{}] {} consume_other(...)", *i, payload[*i] as char);
            if ch == b',' || ch == b']' || ch == b'}' {
                return Ok(&payload[begin..(*i)]);
            }
            *i += 1;
        }
        Err("unexpected EOF")
    }

    /// Skip past whitespace. Return the character where we're at.
    fn skip_whitespace(payload: &'a [u8], i: &mut usize) -> Result<u8, &'static str> {
        while *i < payload.len() {
            let ch = payload[*i];
            if ch == b' ' || ch == b'\t' || ch == b'\r' || ch == b'\n' {
                *i += 1;
            } else {
                break;
            }
        }
        if *i == payload.len() {
            return Err("unexpected EOF in skip_whitespace");
        }
        Ok(payload[*i])
    }
}


#[cfg(feature = "benchmark")]
impl StringAttributes {
    pub fn from_payload(payload: &[u8]) -> Result<StringAttributes, &str> {
        let root: serde_json::Value = serde_json::from_slice(payload).map_err(|_| "json parse error")?;

        let tenant: String;
        let section: String;
        let timens: String;
        let hostname: String;
        let cluster: String;        // optional
        let systemd_unit: String;   // optional
        let filename: String;       // optional
        let message: String;

        if let Some(attributes) = root.get("attributes") {
            tenant = attributes.get("tenant").and_then(|v| v.as_str()).unwrap_or("").to_string();
            section = attributes.get("section").and_then(|v| v.as_str()).unwrap_or("").to_string();
            timens = attributes.get("time_unix_nano").and_then(|v| v.as_i64()).unwrap_or(0).to_string();
            hostname = attributes.get("host").and_then(|v| v.as_str()).unwrap_or("").to_string();
            cluster = attributes.get("cluster").and_then(|v| v.as_str()).unwrap_or("").to_string();
            systemd_unit = attributes.get("systemd_unit").and_then(|v| v.as_str()).unwrap_or("").to_string();
            filename = attributes.get("filename").and_then(|v| v.as_str()).unwrap_or("").to_string();
            message = attributes.get("message").and_then(|v| v.as_str()).unwrap_or("").to_string();
        } else {
            return Err("one or more attributes not found");
        }

        // FIXME: check the non-optional ones?

        Ok(StringAttributes {
            tenant,
            section,
            timens,
            hostname,
            cluster,
            systemd_unit,
            filename,
            message,
        })
    }

    pub fn get_section(&self) -> &str {
        &self.section
    }
}


#[allow(dead_code)]
///
/// This is an older version of BytesAttributes::from_xxx() designed to
/// show that there are speed gains to be had.
///
pub fn get_section_fast(payload: &[u8]) -> &str {
    // We expect payload to look like this:
    //   {"attributes":{"...":"...","section":"the_section",...
    // We want "the_section".
    //
    // If someone has the power to reorder the json, then they could manipulate things, but we're
    // pretty confident that we're okay. Especially the {"attributes":{ block should be completely
    // in our hands. So let's confirm.
    if &payload[0..15] != br#"{"attributes":{"# {
        return "ERR_bad_start";
    }
    let section_start = match memmem(&payload[15..], br#""section":""#) {
        Some(idx) => { 15 + idx + 11 },
        None => { return "ERR_no_section"; },
    };
    let section_end = match memchr(&payload[section_start..], b'"') {
        Some(idx) => { section_start + idx }
        None => { return "ERR_no_trailing_dq"; },
    };
    let slice = &payload[section_start..section_end];
    force_string(slice)
}

///
/// Returns subsequence index i or None if not found
///
fn memmem(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    (0..=(haystack.len() - needle.len())).find(|&i| &haystack[i..i + needle.len()] == needle)
}

///
/// Returns subsequence index i or None if not found
///
fn memchr(haystack: &[u8], needle: u8) -> Option<usize> {
    (0..=(haystack.len() - 1)).find(|&i| haystack[i] == needle)
}


#[cfg(test)]
mod tests {
    use super::*;

    static EXPECTED_JSB: &[u8] = br#"{"attributes":{"filename":"/var/log/auth.log","host":"mgmt.example","observed_time_unix_nano":1708349372637827462,"section":"SCT","job":"loki","systemd_unit":"ssh.service","time_unix_nano":1708349372636882340}
        ,"message":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ,"message1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ,"message2":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ,"message3":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ,"message4":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ,"message5":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ,"message6":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ,"message7":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ,"message8":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ,"message9":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ,"observed_timestamp":"2024-02-19T13:29:32.637827462Z"
        ,"somedict":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21]
        ,"timestamp":"2024-02-19T13:29:32.636882340Z"}"#;

    static REORDERED_JSB: &[u8] = br#"
        {"message":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ,"message1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ,"message2":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ,"message3":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ,"message4":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ,"message5":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ,"message6":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ,"message7":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ,"message8":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ,"message9":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ,"observed_timestamp":"2024-02-19T13:29:32.637827462Z"
        ,"somedict":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21]
        ,"timestamp":"2024-02-19T13:29:32.636882340Z"
        ,"attributes":{"filename":"/var/log/auth.log","host":"mgmt.example"
         ,"observed_time_unix_nano":1708349372637827462,"section":"SCT"
         ,"job":"loki","systemd_unit":"ssh.service"
         ,"time_unix_nano":1708349372636882340}}"#;

    #[cfg(feature = "benchmark")]
    #[test]
    fn test_safe() {
        let attrs = StringAttributes::from_payload(EXPECTED_JSB).expect("parse error");
        assert_eq!(attrs.hostname, r#"mgmt.example"#);
        assert_eq!(attrs.timens, r#"1708349372636882340"#);
        assert_eq!(attrs.get_section(), "SCT");

        let attrs2 = StringAttributes::from_payload(REORDERED_JSB).expect("parse error");
        assert_eq!(attrs, attrs2);
    }

    #[test]
    fn test_fast() {
        let attrs = BytesAttributes::from_payload(EXPECTED_JSB).expect("parse error");
        assert_eq!(force_string(attrs.hostname), r#"mgmt.example"#);
        assert_eq!(force_string(attrs.timens), r#"1708349372636882340"#);
        assert_eq!(attrs.get_section(), "SCT");

        let attrs2 = BytesAttributes::from_payload(REORDERED_JSB).expect("parse error");
        assert_eq!(attrs, attrs2);
    }

    #[test]
    fn test_fast_does_not_stack_overflow() {
        const ARRAY_SIZE: usize = 1024 * 1024; /* 1MB times '{' */
        let crazy_js: [u8; ARRAY_SIZE] = [b'{'; ARRAY_SIZE];
        match BytesAttributes::from_payload(&crazy_js) {
            Ok(_) => { assert_eq!(0, 1); },
            Err(_) => { },
        }
    }

    #[test]
    fn test_fast_old_section_only() {
        assert_eq!(get_section_fast(EXPECTED_JSB), "SCT");
        assert_eq!(get_section_fast(REORDERED_JSB), "ERR_bad_start");
    }
}
