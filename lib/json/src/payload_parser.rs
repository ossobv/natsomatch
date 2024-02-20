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


fn force_string(data: &[u8]) -> &str {
    std::str::from_utf8(data).unwrap()
}

///
/// Result of the fast parser.
///
#[derive(Debug)]
#[derive(PartialEq)]
pub struct BytesAttributes<'a> {
    pub hostname: &'a [u8],
    pub section: &'a [u8],
    pub rep_timestamp: &'a [u8],
    pub obs_timestamp: &'a [u8],
}

///
/// Result of the safe parser.
///
#[cfg(feature = "benchmark")]
#[derive(Debug)]
#[derive(PartialEq)]
pub struct StringAttributes {
    pub hostname: String,
    pub section: String,
    pub rep_timestamp: String,
    pub obs_timestamp: String,
}


impl<'a> BytesAttributes<'a> {
    pub fn from_payload(payload: &'a [u8]) -> Result<BytesAttributes, &str> {
        Self::consume_special_root(payload)
    }

    pub fn get_unique_id(&self) -> String {
        format!(
            "T{}O{}H{}", force_string(self.rep_timestamp),
            force_string(self.obs_timestamp), force_string(self.hostname))
    }

    pub fn get_section(&self) -> &str {
        force_string(self.section)
    }

    /// Parse the entire payload.
    fn consume_special_root(payload: &'a [u8]) -> Result<BytesAttributes, &str> {
        let zeroptr = payload.as_ptr();
        let isunset = |slice: &[u8]| { slice.as_ptr() == zeroptr };

        let mut hostname: &'a [u8] = &payload[0..0];
        let mut section: &'a [u8] = &payload[0..0];
        let mut rep_timestamp: &'a [u8] = &payload[0..0];
        let mut obs_timestamp: &'a [u8] = &payload[0..0];

        let mut i: usize = 0usize;

        Self::consume_token(payload, &mut i, b'{')?;
        while (isunset(hostname) || isunset(section) || isunset(rep_timestamp)
                    || isunset(obs_timestamp))
                && i < payload.len() {

            let key = Self::consume_key(payload, &mut i)?;
            Self::consume_token(payload, &mut i, b':')?;
            if key == b"attributes" {
                Self::consume_special_attributes(
                    payload, &mut i, &mut hostname, &mut section,
                    &mut rep_timestamp, &mut obs_timestamp)?;
                //println!("[{}] {} from_payload after special", i, payload[i]);
            } else if key == b"timestamp" {
                // This is only used if the "attributes" dict has no
                // "time_unix_nano". Otherwise the
                // consume_special_attributes() already completes the
                // while condition.
                rep_timestamp = Self::consume_string(payload, &mut i)?;
            } else if key == b"observed_timestamp" {
                // This is only used if the "attributes" dict has no
                // "observed_time_unix_nano". Otherwise the
                // consume_special_attributes() already completes the
                // while condition.
                obs_timestamp = Self::consume_string(payload, &mut i)?;
            } else {
                Self::consume_value(payload, &mut i)?;
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

        if isunset(hostname) || isunset(section) || isunset(rep_timestamp) || isunset(obs_timestamp) {
            return Err("one or more missing attributes in from_payload");
        }

        Ok(BytesAttributes {
            hostname: hostname,
            section: section,
            rep_timestamp: rep_timestamp,
            obs_timestamp: obs_timestamp,
        })
    }

    /// Parse the attributes dict where the relevant information it.
    fn consume_special_attributes(
            payload: &'a [u8],
            i: &mut usize,
            hostname: &mut &'a [u8],
            section: &mut &'a [u8],
            rep_timestamp: &mut &'a [u8],
            obs_timestamp: &mut &'a [u8]
            ) -> Result<(), &'static str> {

        Self::consume_token(payload, i, b'{')?;
        //let begin = *i;

        // We use this check instead of checking whether hostname,
        // section and timestamp all have a non-0 start. That way, the
        // timestamp from the attributes will get precedence over the
        // timestamp from the root json dict.
        let mut bingo: u32 = 0; // 1 /* hostname */ + 2 /* section */ + 4 /* rep_timestamp */ + 8 /* obs_timestamp */;

        while *i < payload.len() {
            let key = Self::consume_key(payload, i)?;
            Self::consume_token(payload, i, b':')?;
            match key {
                b"host" => {
                    *hostname = Self::consume_string(payload, i)?;
                    bingo |= 1;
                },
                b"section" => {
                    *section = Self::consume_string(payload, i)?;
                    bingo |= 2;
                },
                b"time_unix_nano" => {
                    *rep_timestamp = Self::consume_other(payload, i)?;
                    bingo |= 4;
                },
                b"observed_time_unix_nano" => {
                    *obs_timestamp = Self::consume_other(payload, i)?;
                    bingo |= 8;
                },
                _ => {
                    Self::consume_value(payload, i)?;
                }
            }

            // Quick exit if we have all needed values.
            if bingo == 15 {
                return Ok(());
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
        return Err("expected token, found something else")
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

        let hostname: String;
        let section: String;
        let rep_timestamp: String;
        let obs_timestamp: String;

        if let Some(attributes) = root.get("attributes") {
            hostname = attributes.get("host").and_then(|v| v.as_str()).map(|s| s.to_string())
                .ok_or("host parse error")?;
            section = attributes.get("section").and_then(|v| v.as_str()).map(|s| s.to_string())
                .ok_or("section parse error")?;
            if let Some(ts) = attributes.get("time_unix_nano") {
                rep_timestamp = ts.as_i64().map(|s| s.to_string())
                    .ok_or("nano timestamp parse error")?;
            } else {
                rep_timestamp = root.get("timestamp").and_then(|v| v.as_str()).map(|s| s.to_string())
                    .ok_or("timestamp parse error")?;
            }
            if let Some(ts) = attributes.get("observed_time_unix_nano") {
                obs_timestamp = ts.as_i64().map(|s| s.to_string())
                    .ok_or("nano observed timestamp parse error")?;
            } else {
                obs_timestamp = root.get("observed_timestamp").and_then(|v| v.as_str()).map(|s| s.to_string())
                    .ok_or("observed_timestamp parse error")?;
            }
        } else {
            return Err("one or more attributes not found");
        }

        Ok(StringAttributes {
            hostname: hostname.to_string(),
            section: section.to_string(),
            rep_timestamp: rep_timestamp.to_string(),
            obs_timestamp: obs_timestamp.to_string(),
        })
    }

    pub fn get_unique_id(&self) -> String {
        format!("T{}O{}H{}", self.rep_timestamp, self.obs_timestamp, self.hostname)
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
    let section_start: usize;
    match memmem(&payload[15..], br#""section":""#) {
        Some(idx) => { section_start = 15 + idx + 11; },
        None => { return "ERR_no_section"; },
    }
    let section_end: usize;
    match memchr(&payload[section_start..], b'"') {
        Some(idx) => { section_end = section_start + idx; }
        None => { return "ERR_no_trailing_dq"; },
    }
    let slice = &payload[section_start..section_end];
    force_string(slice)
}

fn memmem(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    // Iterate through the bytes of the haystack
    for i in 0..=(haystack.len() - needle.len()) {
        // Compare the bytes starting from index i
        if &haystack[i..i + needle.len()] == needle {
            return Some(i); // Return the index if the subsequence is found
        }
    }
    None // Return None if the subsequence is not found
}

fn memchr(haystack: &[u8], needle: u8) -> Option<usize> {
    // Iterate through the bytes of the haystack
    for i in 0..=(haystack.len() - 1) {
        // Compare the byte starting from index i
        if haystack[i] == needle {
            return Some(i); // Return the index if the character is found
        }
    }
    None // Return None if the subsequence is not found
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
        {"message":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
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

    static NO_TIME_NANO_JSB: &[u8] = br#"
        {"attributes":{"filename":"/var/log/auth.log","host":"mgmt.example"
         ,"section":"SCT","job":"loki","systemd_unit":"ssh.service"}
        ,"message":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ,"observed_timestamp":"2024-02-19T13:29:32.637827462Z"
        ,"somedict":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21]
        ,"timestamp":"2024-02-19T13:29:32.636882340Z"}"#;

    #[cfg(feature = "benchmark")]
    #[test]
    fn test_safe() {
        let attrs = StringAttributes::from_payload(EXPECTED_JSB).expect("parse error");
        assert_eq!(attrs.hostname, r#"mgmt.example"#);
        assert_eq!(attrs.rep_timestamp, r#"1708349372636882340"#);
        assert_eq!(attrs.obs_timestamp, r#"1708349372637827462"#);
        assert_eq!(attrs.get_section(), "SCT");
        assert_eq!(attrs.get_unique_id(), "T1708349372636882340O1708349372637827462Hmgmt.example");

        let attrs2 = StringAttributes::from_payload(REORDERED_JSB).expect("parse error");
        assert_eq!(attrs, attrs2);
    }

    #[cfg(feature = "benchmark")]
    #[test]
    fn test_safe_ts_from_root() {
        let attrs = StringAttributes::from_payload(NO_TIME_NANO_JSB).expect("parse error");
        assert_eq!(attrs.hostname, r#"mgmt.example"#);
        assert_eq!(attrs.rep_timestamp, r#"2024-02-19T13:29:32.636882340Z"#);
        assert_eq!(attrs.obs_timestamp, r#"2024-02-19T13:29:32.637827462Z"#);
        assert_eq!(attrs.get_section(), "SCT");
        assert_eq!(attrs.get_unique_id(), "T2024-02-19T13:29:32.636882340ZO2024-02-19T13:29:32.637827462ZHmgmt.example");
    }

    #[test]
    fn test_fast() {
        let attrs = BytesAttributes::from_payload(EXPECTED_JSB).expect("parse error");
        assert_eq!(force_string(attrs.hostname), r#"mgmt.example"#);
        assert_eq!(force_string(attrs.rep_timestamp), r#"1708349372636882340"#);
        assert_eq!(force_string(attrs.obs_timestamp), r#"1708349372637827462"#);
        assert_eq!(attrs.get_section(), "SCT");
        assert_eq!(attrs.get_unique_id(), "T1708349372636882340O1708349372637827462Hmgmt.example");

        let attrs2 = BytesAttributes::from_payload(REORDERED_JSB).expect("parse error");
        assert_eq!(attrs, attrs2);
    }

    #[test]
    fn test_fast_ts_from_root() {
        let attrs = BytesAttributes::from_payload(NO_TIME_NANO_JSB).expect("parse error");
        assert_eq!(force_string(attrs.hostname), r#"mgmt.example"#);
        assert_eq!(force_string(attrs.rep_timestamp), r#"2024-02-19T13:29:32.636882340Z"#);
        assert_eq!(force_string(attrs.obs_timestamp), r#"2024-02-19T13:29:32.637827462Z"#);
        assert_eq!(attrs.get_section(), "SCT");
        assert_eq!(attrs.get_unique_id(), "T2024-02-19T13:29:32.636882340ZO2024-02-19T13:29:32.637827462ZHmgmt.example");
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
