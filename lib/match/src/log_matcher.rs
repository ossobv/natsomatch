///
/// This matches log messages that are passed from journald/files
/// through Grafana Alloy (or flow) and sets the following subject:
///   bulk.{match}.{tenant}.{section}.{hostname}
/// where hostname has the dots replaced with hyphens.
///
/// The NATS recipient has to ensure that these subject have valid
/// listeners, otherwise waiting for an ack on publish will fail:
///   error on publish(2) of subject <S>: timed out: didn't receive ack in time
///

use natsomatch_json::payload_parser::BytesAttributes;


#[derive(Debug)]
pub struct Match {
    pub subject: String,  // subject to use when publishing
}


impl Match {
    pub fn from_attributes(attrs: &BytesAttributes) -> Result<Match, &'static str> {
        // TIPS:
        //
        // - for SYSLOG_FACILITY see:
        //   https://github.com/ossobv/syslog2stdout/blob/ae5ca1ef277a8f4e5e652c0bf541be0dfed27a6a/syslog2stdout.c#L84-L121
        //
        // - We have these at our disposal:
        //
        //   {tenant}  .attributes.tenant <string>
        //   {section} .attributes.section <string>
        //   {timens}  .attributes.time_unix_nano <digits>
        //   {cluster} .attributes.cluster <string> (optional)
        //   {systemd_unit} .attributes.systemd_unit (optional)
        //   {host}    .attributes.host <string>
        //   {message} .message
        //
        // - Maybe we also want something like this:
        //
        //   {origin} =
        //     systemd_unit (with everything after @ skipped) ||
        //     filename ||
        //     '{TRANSPORT}.{SYSLOG_FACILITY}[.{SYSLOG_PRIO}[.{SYSLOG_TAG}]]'
        //
        // TODO:
        //
        // - Below, there are substring matches like:
        //   br#"\"_TRANSPORT\":\"syslog\""#
        //   We could consider decoding the json instead. That would
        //   provide slower but more accurate matching.
        //

        let tenant = replace_dots_with_dashes(attrs.tenant);
        let section = replace_dots_with_dashes(attrs.section);
        let hostname = replace_dots_with_dashes(attrs.hostname);

        // ==============================================================
        // One giant if here
        // - somewhat sorted by occurrence (haproxy@ most common)
        // ==============================================================

        if starts_with(attrs.systemd_unit, b"haproxy@") {
            return Ok(Match {
                // destination: "bulk_match_haproxy",
                subject: format!("bulk.haproxy.{tenant}.{section}.{hostname}"),
            });
        }

        if starts_with(attrs.filename, b"/var/log/nginx/") {
            return Ok(Match {
                // destination: "bulk_match_nginx",
                subject: format!("bulk.nginx.{tenant}.{section}.{hostname}"),
            });
        }

        #[allow(clippy::collapsible_if)]
        if memmem(attrs.message, br#"\"_TRANSPORT\":\"syslog\""#).is_some() {
            if memmem(attrs.message, br#"\"MESSAGE\":\"pam_unix("#).is_some() ||
                    (attrs.systemd_unit == b"xinetd.service" &&
                     memmem(attrs.message, br#"\"SYSLOG_FACILITY\":\"4\""#).is_some()) ||
                    (attrs.systemd_unit == b"zabbix-agent.service" &&
                     memmem(attrs.message, br#"\"SYSLOG_FACILITY\":\"10\""#).is_some()) ||
                    attrs.systemd_unit == b"auditd.service" {
                return Ok(Match {
                    // destination: "bulk_match_audit",
                    subject: format!("bulk.audit.{tenant}.{section}.{hostname}"),
                });
            }
        }

        if attrs.systemd_unit == b"kube-apiserver.service"  ||
                attrs.systemd_unit == b"kube-controller-manager.service" ||
                attrs.systemd_unit == b"kube-scheduler.service" ||
                attrs.systemd_unit == b"kubelet.service" {
            return Ok(Match {
                // destination: "bulk_match_k8s",
                subject: format!("bulk.k8s.{tenant}.{section}.{hostname}"),
            });
        }

        if attrs.systemd_unit == b"tetragon-cat.service" {
            return Ok(Match {
                // destination: "bulk_match_execve",
                subject: format!("bulk.execve.{tenant}.{section}.{hostname}"),
            });
        }

        if attrs.filename == b"/var/log/vault/audit.log" ||
                attrs.systemd_unit == b"vault.service" {
            return Ok(Match {
                // destination: "bulk_match_vault",
                subject: format!("bulk.vault.{tenant}.{section}.{hostname}"),
            });
        }

        if attrs.filename == b"/var/log/kubernetes/audit/audit.log" {
            return Ok(Match {
                // destination: "bulk_match_k8s-audit",
                subject: format!("bulk.k8s-audit.{tenant}.{section}.{hostname}"),
            });
        }

        if (starts_with(attrs.systemd_unit, b"systemd-") &&
                ends_with(attrs.systemd_unit, b".service")) ||
                (starts_with(attrs.systemd_unit, b"user@") &&
                 ends_with(attrs.systemd_unit, b".service")) {
            // There are also "init.scope" and "session-xxx.scope", but
            // they have _TRANSPORT=syslog and
            // SYSLOG_IDENTIFIER=systemd. They are handled below.
            return Ok(Match {
                // destination: "bulk_match_systemd",
                subject: format!("bulk.systemd.{tenant}.{section}.{hostname}"),
            });
        }

        if attrs.systemd_unit == b"etcd.service" {
            return Ok(Match {
                // destination: "bulk_match_etcd",
                subject: format!("bulk.etcd.{tenant}.{section}.{hostname}"),
            });
        }

        if attrs.systemd_unit == b"suricata.service" {
            return Ok(Match {
                // destination: "bulk_match_nids",
                subject: format!("bulk.nids.{tenant}.{section}.{hostname}"),
            });
        }

        if attrs.systemd_unit == b"containerd.service" ||
                attrs.systemd_unit == b"ctre.service" ||
                attrs.systemd_unit == b"docker.service" ||
                (starts_with(attrs.systemd_unit, b"docker@") &&
                 ends_with(attrs.systemd_unit, b".service")) {
            return Ok(Match {
                // destination: "bulk_match_v12n",
                subject: format!("bulk.v12n.{tenant}.{section}.{hostname}"),
            });
        }

        if attrs.systemd_unit == b"zabbix-agent.service" ||
                attrs.systemd_unit == b"zabbix-proxy.service" ||
                attrs.systemd_unit == b"zabbix-server.service" ||
                attrs.systemd_unit == b"gocollect.service" {
            return Ok(Match {
                // destination: "bulk_match_monitoring",
                subject: format!("bulk.monitoring.{tenant}.{section}.{hostname}"),
            });
        }

        if attrs.systemd_unit == b"ssh.service" {
            return Ok(Match {
                // destination: "bulk_match_ssh",
                subject: format!("bulk.ssh.{tenant}.{section}.{hostname}"),
            });
        }

        if attrs.systemd_unit == b"tetragon.service" ||
                (starts_with(attrs.systemd_unit, b"clamav-") &&
                 ends_with(attrs.systemd_unit, b".service")) {
            return Ok(Match {
                // destination: "bulk_match_hids",
                subject: format!("bulk.hids.{tenant}.{section}.{hostname}"),
            });
        }

        if attrs.systemd_unit == b"gitea.service" ||
                attrs.systemd_unit == b"gitlab-runner.service" {
            return Ok(Match {
                // destination: "bulk_match_devinfra",
                subject: format!("bulk.devinfra.{tenant}.{section}.{hostname}"),
            });
        }

        if attrs.systemd_unit == b"cron.service" {
            return Ok(Match {
                // destination: "bulk_match_cron",
                subject: format!("bulk.cron.{tenant}.{section}.{hostname}"),
            });
        }

        if attrs.systemd_unit == b"aide.service" ||
                attrs.systemd_unit == b"aidecheck.service" ||
                attrs.systemd_unit == b"aidecheck.timer" ||
                attrs.systemd_unit == b"dailyaidecheck.service" ||
                attrs.systemd_unit == b"dailyaidecheck.timer" {
            return Ok(Match {
                // destination: "bulk_match_aide",
                subject: format!("bulk.aide.{tenant}.{section}.{hostname}"),
            });
        }

        if attrs.has_no_origin() || ends_with(attrs.systemd_unit, b".scope") {
            #[allow(clippy::collapsible_if)]
            if memmem(attrs.message, br#"\"_TRANSPORT\":\"kernel\""#).is_some() &&
                        memmem(attrs.message, br#"\"MESSAGE\":\"#).is_some() {
                if memmem(attrs.message, br#"IN="#).is_some() &&
                        memmem(attrs.message, br#" OUT="#).is_some() {
                    return Ok(Match {
                        // destination: "bulk_match_audit",
                        subject: format!("bulk.firewall.{tenant}.{section}.{hostname}"),
                    });
                }
            }

            if memmem(attrs.message, br#"\"_TRANSPORT\":\"audit\""#).is_some() {
                return Ok(Match {
                    // destination: "bulk_match_audit",
                    subject: format!("bulk.audit.{tenant}.{section}.{hostname}"),
                });
            }

            if memmem(attrs.message, br#"\"_TRANSPORT\":\"syslog\""#).is_some() {
                if memmem(attrs.message, br#"\"SYSLOG_IDENTIFIER\":\"systemd\""#).is_some() {
                    return Ok(Match {
                        // destination: "bulk_match_systemd",
                        subject: format!("bulk.systemd.{tenant}.{section}.{hostname}"),
                    });
                }
                if memmem(attrs.message, br#"\"SYSLOG_IDENTIFIER\":\"sshd\""#).is_some() {
                    return Ok(Match {
                        // destination: "bulk_match_ssh",
                        subject: format!("bulk.ssh.{tenant}.{section}.{hostname}"),
                    });
                }
                if memmem(attrs.message, br#"\"SYSLOG_IDENTIFIER\":\"osso-change\""#).is_some() {
                    return Ok(Match {
                        // destination: "bulk_match_execve",
                        subject: format!("bulk.execve.{tenant}.{section}.{hostname}"),
                    });
                }
            }
        }

        if starts_with(attrs.systemd_unit, b"getty@") &&
                ends_with(attrs.systemd_unit, b".service") {
            return Ok(Match {
                // destination: "bulk_match_audit",
                subject: format!("bulk.audit.{tenant}.{section}.{hostname}"),
            });
        }

        // Lastly. Although this is probably picked up above with
        // SYSLOG_IDENTIFIER=systemd.
        if (starts_with(attrs.systemd_unit, b"session-") &&
                ends_with(attrs.systemd_unit, b".scope")) ||
                attrs.systemd_unit == b"init.scope" {
            return Ok(Match {
                // destination: "bulk_match_systemd",
                subject: format!("bulk.systemd.{tenant}.{section}.{hostname}"),
            });
        }

        Ok(Match {
            // destination: "bulk_match_unknown",
            subject: format!("bulk.unknown.{tenant}.{section}.{hostname}"),
        })
    }
}


///
/// Convert a byteslice to a String with dots replaced by dashes.
///
/// Useful for hostnames when using them in a NATS subject: prefix.example-com
///
fn replace_dots_with_dashes(input: &[u8]) -> String {
    let mut result = String::with_capacity(input.len());

    for &byte in input {
        if byte == b'.' {
            result.push('-');
        } else {
            // This is safe because we are dealing with valid UTF-8 bytes
            result.push(byte as char);
        }
    }

    result
}


///
/// Check whether bytes starts with prefix.
///
fn starts_with(bytes: &[u8], prefix: &[u8]) -> bool {
    bytes.len() >= prefix.len() && &bytes[0..prefix.len()] == prefix
}


///
/// Check whether bytes ends with suffix.
///
fn ends_with(bytes: &[u8], suffix: &[u8]) -> bool {
    bytes.len() >= suffix.len() && &bytes[bytes.len()-suffix.len()..] == suffix
}


///
/// Returns subsequence index i or None if not found
///
fn memmem(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    (0..=(haystack.len() - needle.len())).find(|&i| &haystack[i..i + needle.len()] == needle)
}


#[cfg(any(test, feature = "benchmark"))]
pub mod samples {
    pub static AUDITD: &[u8] = br#"
    {"attributes":{"cluster":"C","host":"H"
    ,"job":"loki.source.journal.logs_journald_generic"
    ,"loki.attribute.labels":"job,systemd_unit"
    ,"observed_time_unix_nano":1717602602596264580,"section":"S"
    ,"systemd_unit":"auditd.service","tenant":"T"
    ,"time_unix_nano":1717602602570258000},"dropped_attributes_count":0
    ,"message":"{\"MESSAGE\":\"Audit daemon rotating log files\",\"PRIORITY\":\"5\",\"SYSLOG_FACILITY\":\"3\",\"SYSLOG_IDENTIFIER\":\"auditd\",\"SYSLOG_PID\":\"298087\",\"SYSLOG_TIMESTAMP\":\"Jun  5 17:50:02 \",\"_BOOT_ID\":\"adc\",\"_CAP_EFFECTIVE\":\"1fffffeffff\",\"_CMDLINE\":\"/sbin/auditd\",\"_COMM\":\"auditd\",\"_EXE\":\"/usr/sbin/auditd\",\"_GID\":\"0\",\"_HOSTNAME\":\"H\",\"_MACHINE_ID\":\"9df\",\"_PID\":\"298087\",\"_SELINUX_CONTEXT\":\"unconfined\\n\",\"_SOURCE_REALTIME_TIMESTAMP\":\"1717602602570069\",\"_SYSTEMD_CGROUP\":\"/system.slice/auditd.service\",\"_SYSTEMD_INVOCATION_ID\":\"598\",\"_SYSTEMD_SLICE\":\"system.slice\",\"_SYSTEMD_UNIT\":\"auditd.service\",\"_TRANSPORT\":\"syslog\",\"_UID\":\"0\"}"'
    ,"observed_timestamp":"2024-06-05T15:50:02.596264580Z"
    ,"source_type":"opentelemetry","timestamp":"2024-06-05T15:50:02.570258Z"}
    "#;

    pub static CRON: &[u8] = br#"
    {"attributes":{"cluster":"C","host":"H"
    ,"job":"loki.source.journal.logs_journald_generic"
    ,"loki.attribute.labels":"job,systemd_unit"
    ,"observed_time_unix_nano":1720535019066341120,"section":"S"
    ,"systemd_unit":"cron.service","tenant":"T"
    ,"time_unix_nano":1720499702010964000},"dropped_attributes_count":0
    ,"message":"{\"MESSAGE\":\"(root) CMD (ETCDCTL_API=3 etcdctl --cert /etc/kubernetes/pki/etcd/healthcheck-client.crt --key /etc/kubernetes/pki/etcd/healthcheck-client.key --cacert /etc/kubernetes/pki/etcd/ca.crt --endpoints=https://10.20.30.40:2379 endpoint health --write-out='json' \\u003e /tmp/zabbix-etcd3-endpointhealth.json.part 2\\u003e /dev/null; mv /tmp/zabbix-etcd3-endpointhealth.json.part /tmp/zabbix-etcd3-endpointhealth.json)\",\"PRIORITY\":\"6\",\"SYSLOG_FACILITY\":\"9\",\"SYSLOG_IDENTIFIER\":\"CRON\",\"SYSLOG_PID\":\"2626748\",\"SYSLOG_TIMESTAMP\":\"Jul  9 06:35:02 \",\"_AUDIT_LOGINUID\":\"0\",\"_AUDIT_SESSION\":\"55294\",\"_BOOT_ID\":\"689\",\"_CAP_EFFECTIVE\":\"1ffffffffff\",\"_CMDLINE\":\"/usr/sbin/CRON -f -P\",\"_COMM\":\"cron\",\"_EXE\":\"/usr/sbin/cron\",\"_GID\":\"0\",\"_HOSTNAME\":\"H\",\"_MACHINE_ID\":\"9ed\",\"_PID\":\"2626748\",\"_SELINUX_CONTEXT\":\"unconfined\\n\",\"_SOURCE_REALTIME_TIMESTAMP\":\"1720499702010926\",\"_SYSTEMD_CGROUP\":\"/system.slice/cron.service\",\"_SYSTEMD_INVOCATION_ID\":\"ecd\",\"_SYSTEMD_SLICE\":\"system.slice\",\"_SYSTEMD_UNIT\":\"cron.service\",\"_TRANSPORT\":\"syslog\",\"_UID\":\"0\"}"
    ,"observed_timestamp":"2024-07-09T14:23:39.066341120Z"
    ,"source_type":"opentelemetry","timestamp":"2024-07-09T04:35:02.010964Z"}
    "#;

    pub static ETCD: &[u8] = br#"
    {"attributes":{"cluster":"C","host":"H"
    ,"job":"loki.source.journal.logs_journald_generic"
    ,"loki.attribute.labels":"systemd_unit,job"
    ,"observed_time_unix_nano":1717621593140205531,"section":"S"
    ,"systemd_unit":"etcd.service","tenant":"T"
    ,"time_unix_nano":1717621592861591000},"dropped_attributes_count":0
    ,"message":"{\"MESSAGE\":\"{\\\"level\\\":\\\"info\\\",\\\"ts\\\":\\\"2024-06-05T23:06:32.861431+0200\\\",\\\"caller\\\":\\\"mvcc/kvstore_compaction.go:66\\\",\\\"msg\\\":\\\"finished scheduled compaction\\\",\\\"compact-revision\\\":647109883,\\\"took\\\":\\\"184.636903ms\\\",\\\"hash\\\":3144936833}\",\"PRIORITY\":\"6\",\"SYSLOG_FACILITY\":\"3\",\"SYSLOG_IDENTIFIER\":\"etcd\",\"_BOOT_ID\":\"b0b\",\"_CAP_EFFECTIVE\":\"0\",\"_CMDLINE\":\"/usr/bin/etcd\",\"_COMM\":\"etcd\",\"_EXE\":\"/usr/bin/etcd\",\"_GID\":\"65534\",\"_HOSTNAME\":\"H\",\"_MACHINE_ID\":\"bf0\",\"_PID\":\"347\",\"_SELINUX_CONTEXT\":\"unconfined\\n\",\"_STREAM_ID\":\"e38\",\"_SYSTEMD_CGROUP\":\"/system.slice/etcd.service\",\"_SYSTEMD_INVOCATION_ID\":\"b3a\",\"_SYSTEMD_SLICE\":\"system.slice\",\"_SYSTEMD_UNIT\":\"etcd.service\",\"_TRANSPORT\":\"stdout\",\"_UID\":\"111\"}"
    ,"observed_timestamp":"2024-06-05T21:06:33.140205531Z"
    ,"source_type":"opentelemetry","timestamp":"2024-06-05T21:06:32.861591Z"}
    "#;

    pub static HAPROXY: &[u8] = br#"
    {"attributes":{"host":"lb1.dr.example.com"
    ,"job":"loki.source.journal.logs_journald_generic"
    ,"loki.attribute.labels":"job,systemd_unit"
    ,"observed_time_unix_nano":1716915534776220907,"section":"example-dmz-cat4"
    ,"systemd_unit":"haproxy@example_dmz.service","tenant":"wilee"
    ,"time_unix_nano":1716915534575273000},"dropped_attributes_count":0
    ,"message":"{\"MESSAGE\":\"TCP 1.2.3.4:37164 -\\u003e 1.2.3.4:3100(loki-haproxy-tcp-3100-in) -\\u003e 10.1.2.3:443(loki-haproxy-tcp-3100-in) i=3943/o=3477/r=0 tw=1/tc=0/t=43 state=CD conns=1155/1154/1155/1154\",\"PRIORITY\":\"6\",\"SYSLOG_FACILITY\":\"16\",\"SYSLOG_IDENTIFIER\":\"haproxy\",\"SYSLOG_PID\":\"4151570\",\"SYSLOG_RAW\":\"\\u003c134\\u003eMay 28 18:58:54 haproxy[4151570]: TCP 1.2.3.4:37164 -\\u003e 1.2.3.4:3100(loki-haproxy-tcp-3100-in) -\\u003e 10.1.2.3:443(loki-haproxy-tcp-3100-in) i=3943/o=3477/r=0 tw=1/tc=0/t=43 state=CD conns=1155/1154/1155/1154\\n\",\"SYSLOG_TIMESTAMP\":\"May 28 18:58:54 \",\"_BOOT_ID\":\"a41\",\"_CAP_EFFECTIVE\":\"0\",\"_CMDLINE\":\"/usr/sbin/haproxy -sf 1688512 -Ws -f /etc/haproxy/example_dmz/loki.cfg -p /run/haproxy/example_dmz/loki.pid -S /run/haproxy/example_dmz/loki-master.sock\",\"_COMM\":\"haproxy\",\"_EXE\":\"/usr/sbin/haproxy\",\"_GID\":\"123\",\"_HOSTNAME\":\"lb1.dr.example.com\",\"_MACHINE_ID\":\"bd2\",\"_PID\":\"4151570\",\"_SELINUX_CONTEXT\":\"unconfined\\n\",\"_SOURCE_REALTIME_TIMESTAMP\":\"1716915534574747\",\"_SYSTEMD_CGROUP\":\"/system.slice/system-haproxy.slice/haproxy@example_dmz-loki.service\",\"_SYSTEMD_INVOCATION_ID\":\"650\",\"_SYSTEMD_SLICE\":\"system-haproxy.slice\",\"_SYSTEMD_UNIT\":\"haproxy@example_dmz-loki.service\",\"_TRANSPORT\":\"syslog\",\"_UID\":\"115\"}"
    ,"observed_timestamp":"2024-05-28T16:58:54.776220907Z"
    ,"source_type":"opentelemetry,"timestamp":"2024-05-28T16:58:54.575273Z"}
    "#;

    pub static HIDS: &[u8] = br#"
    {"attributes":{"host":"H"
    ,"job":"loki.source.journal.logs_journald_generic"
    ,"loki.attribute.labels":"job,systemd_unit"
    ,"observed_time_unix_nano":1716915534776220907,"section":"S"
    ,"systemd_unit":"clamav-clamonacc.service","tenant":"T"
    ,"time_unix_nano":1716915534575273000},"dropped_attributes_count":0
    ,"message":"{\"_SYSTEMD_UNIT\":\"clamav-clamonacc.service\",\"_SYSTEMD_CGROUP\":\"/system.slice/clamav-clamonacc.service\",\"_EXE\":\"/usr/sbin/clamonacc\",\"_PID\":\"3976\",\"_STREAM_ID\":\"d81\",\"_TRANSPORT\":\"stdout\",\"PRIORITY\":\"6\",\"SYSLOG_FACILITY\":\"3\",\"__MONOTONIC_TIMESTAMP\":\"338688292779\",\"_CMDLINE\":\"/usr/sbin/clamonacc --fdpass -F --config-file=/etc/clamav/clamd.conf --log=/var/log/clamav/clamonacc.log\",\"_SYSTEMD_INVOCATION_ID\":\"d87\",\"_UID\":\"0\",\"_CAP_EFFECTIVE\":\"1ffffffffff\",\"__CURSOR\":\"s=9efbf583db084dcc8c596b9371f3c0b1;i=57afb56;b=635fd37f21094113ac0b060a100b941a;m=4edb6537ab;t=61ba690b76907;x=6e7b5f335ef0850f\",\"_GID\":\"0\",\"_SELINUX_CONTEXT\":\"unconfined\n\",\"_SYSTEMD_SLICE\":\"system.slice\",\"_MACHINE_ID\":\"172\",\"MESSAGE\":\"/home/johnq/index.html?wpdmdl=8847&refresh=6679b42a713d71719252010: Win.Test.EICAR_HDB-1 FOUND\",\"_COMM\":\"clamonacc\",\"_BOOT_ID\":\"635\",\"_HOSTNAME\":\"H\",\"SYSLOG_IDENTIFIER\":\"clamonacc\",\"__REALTIME_TIMESTAMP\":\"1719252066724103\"}"
    ,"observed_timestamp":"2024-05-28T16:58:54.776220907Z"
    ,"source_type":"opentelemetry,"timestamp":"2024-05-28T16:58:54.575273Z"}
    "#;

    pub static HIDS2: &[u8] = br#"
    {"attributes":{"host":"H"
    ,"job":"loki.source.journal.logs_journald_generic"
    ,"loki.attribute.labels":"job,systemd_unit"
    ,"observed_time_unix_nano":1716915534776220907,"section":"S"
    ,"systemd_unit":"clamav-clamonacc.service","tenant":"T"
    ,"time_unix_nano":1716915534575273000},"dropped_attributes_count":0
    ,"message":"{\"_CAP_EFFECTIVE\":\"0\",\"_TRANSPORT\":\"stdout\",\"_EXE\":\"/usr/sbin/clamd\",\"__CURSOR\":\"s=9efbf583db084dcc8c596b9371f3c0b1;i=57afb55;b=635fd37f21094113ac0b060a100b941a;m=4edb65366f;t=61ba690b767cb;x=aed0ba22894a4d42\",\"_SYSTEMD_CGROUP\":\"/system.slice/clamav-daemon.service\",\"SYSLOG_FACILITY\":\"3\",\"PRIORITY\":\"6\",\"_MACHINE_ID\":\"172\",\"_STREAM_ID\":\"4d6\",\"_HOSTNAME\":\"H\",\"_SELINUX_CONTEXT\":\"/usr/sbin/clamd (enforce)\n\",\"__MONOTONIC_TIMESTAMP\":\"338688292463\",\"_COMM\":\"clamd\",\"SYSLOG_IDENTIFIER\":\"clamd\",\"_SYSTEMD_UNIT\":\"clamav-daemon.service\",\"_BOOT_ID\":\"635\",\"__REALTIME_TIMESTAMP\":\"1719252066723787\",\"MESSAGE\":\"Mon Jun 24 20:01:06 2024 -> /home/johnq/index.html?wpdmdl=8847&refresh=6679b42a713d71719252010: Win.Test.EICAR_HDB-1(6ce6f415d8475545be5ba114f208b0ff:184) FOUND\",\"_SYSTEMD_SLICE\":\"system.slice\",\"_SYSTEMD_INVOCATION_ID\":\"b1a\",\"_UID\":\"110\",\"_GID\":\"118\",\"_PID\":\"757\",\"_CMDLINE\":\"/usr/sbin/clamd --foreground=true\"}"
    ,"observed_timestamp":"2024-05-28T16:58:54.776220907Z"
    ,"source_type":"opentelemetry,"timestamp":"2024-05-28T16:58:54.575273Z"}
    "#;

    pub static K8S: &[u8] = br#"
    {"attributes":{"cluster":"k8s-starwars","host":"master.sith.starwars"
    ,"job":"loki.source.journal.logs_journald_generic"
    ,"loki.attribute.labels":"job,systemd_unit"
    ,"observed_time_unix_nano":1716915530887807787,"section":"starwars"
    ,"systemd_unit":"kube-apiserver.service","tenant":"acme"
    ,"time_unix_nano":1716915530505521000},"dropped_attributes_count":0
    ,"message":"{\"MESSAGE\":\"W0528 18:58:50.244507 3818486 reflector.go:539] storage/cacher.go:/aquasecurity.github.io/vulnerabilityreports: failed to list aquasecurity.github.io/v1alpha1, Kind=VulnerabilityReport: etcdserver: request timed out\",\"PRIORITY\":\"6\",\"SYSLOG_FACILITY\":\"3\",\"SYSLOG_IDENTIFIER\":\"kube-apiserver\",\"_BOOT_ID\":\"050\",\"_CAP_EFFECTIVE\":\"1ffffffffff\",\"_CMDLINE\":\"/usr/bin/kube-apiserver --allow-privileged=true --anonymous-auth=false --authorization-mode=Node,RBAC --audit-policy-file=/etc/kubernetes/audit-policy.yaml --audit-log-path=/var/log/kubernetes/audit/audit.log --audit-log-maxage=3 --audit-log-maxbackup=0 --audit-log-maxsize=200 --bind-address=127.0.0.1 --client-ca-file=/etc/kubernetes/pki/ca.crt --etcd-servers=https://10.3.2.47:2379,https://10.3.2.49:2379,https://10.3.2.51:2379 --etcd-cafile=/etc/kubernetes/pki/etcd/ca.crt --etcd-certfile=/etc/kubernetes/pki/apiserver-etcd-client.crt --etcd-keyfile=/etc/kubernetes/pki/apiserver-etcd-client.key --etcd-prefix=/registry --kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname --kubelet-client-certificate=/etc/kubernetes/pki/apiserver-kubelet-client.crt --kubelet-client-key=/etc/kubernetes/pki/apiserver-kubelet-client.key --proxy-client-cert-file=/etc/kubernetes/pki/front-proxy-client.crt --proxy-client-key-file=/etc/kubernetes/pki/front-proxy-client.key --requestheader-client-ca-file=/etc/kubernetes/pki/front-proxy-ca.crt --requestheader-allowed-names=front-proxy-client --requestheader-username-headers=X-Remote-User --requestheader-group-headers=X-Remote-Group --requestheader-extra-headers-prefix=X-Remote-Extra- --service-account-issuer=https://kubernetes --service-cluster-ip-range=10.3.0.0/24 --service-account-key-file=/etc/kubernetes/pki/sa.pub --service-account-signing-key-file=/etc/kubernetes/pki/sa.key --tls-cert-file=/etc/kubernetes/pki/apiserver.crt --tls-private-key-file=/etc/kubernetes/pki/apiserver.key\",\"_COMM\":\"kube-apiserver\",\"_EXE\":\"/usr/bin/kube-apiserver\",\"_GID\":\"0\",\"_HOSTNAME\":\"master.sith.starwars\",\"_MACHINE_ID\":\"3ca\",\"_PID\":\"3818486\",\"_SELINUX_CONTEXT\":\"unconfined\\n\",\"_STREAM_ID\":\"ced\",\"_SYSTEMD_CGROUP\":\"/system.slice/kube-apiserver.service\",\"_SYSTEMD_INVOCATION_ID\":\"cdc\",\"_SYSTEMD_SLICE\":\"system.slice\",\"_SYSTEMD_UNIT\":\"kube-apiserver.service\",\"_TRANSPORT\":\"stdout\",\"_UID\":\"0\"}"
    ,"observed_timestamp":"2024-05-28T16:58:50.887807787Z"
    ,"source_type":"opentelemetry","timestamp":"2024-05-28T16:58:50.505521Z"}
    "#;

    pub static KERNEL_AUDIT: &[u8] = br#"
    {"attributes":{"cluster":"k8s-acme-prod-backend1","host":"node1.acme.tld"
    ,"job":"loki.source.journal.logs_journald_generic"
    ,"loki.attribute.labels":"job"
    ,"observed_time_unix_nano":1717588833648370149,"section":"acme"
    ,"tenant":"acme-ops","time_unix_nano":1717588833264832000}
    ,"dropped_attributes_count":0
    ,"message":"{\"AUDIT_FIELD_ACCT\":\"zabbix\",\"AUDIT_FIELD_ADDR\":\"?\",\"AUDIT_FIELD_EXE\":\"/usr/bin/sudo\",\"AUDIT_FIELD_GRANTORS\":\"pam_permit\",\"AUDIT_FIELD_HOSTNAME\":\"?\",\"AUDIT_FIELD_OP\":\"PAM:accounting\",\"AUDIT_FIELD_RES\":\"success\",\"AUDIT_FIELD_TERMINAL\":\"?\",\"MESSAGE\":\"USER_ACCT pid=1417310 uid=110 auid=4294967295 ses=4294967295 subj=unconfined msg='op=PAM:accounting grantors=pam_permit acct=\\\"zabbix\\\" exe=\\\"/usr/bin/sudo\\\" hostname=? addr=? terminal=? res=success'\",\"SYSLOG_FACILITY\":\"4\",\"SYSLOG_IDENTIFIER\":\"audit\",\"_AUDIT_ID\":\"13817439\",\"_AUDIT_LOGINUID\":\"4294967295\",\"_AUDIT_SESSION\":\"4294967295\",\"_AUDIT_TYPE\":\"1101\",\"_AUDIT_TYPE_NAME\":\"USER_ACCT\",\"_BOOT_ID\":\"284\",\"_HOSTNAME\":\"node1.acme.tld\",\"_MACHINE_ID\":\"ca7\",\"_PID\":\"1417310\",\"_SELINUX_CONTEXT\":\"unconfined\",\"_SOURCE_REALTIME_TIMESTAMP\":\"1717588833260000\",\"_TRANSPORT\":\"audit\",\"_UID\":\"110\"}"
    ,"observed_timestamp":"2024-06-05T12:00:33.648370149Z"
    ,"source_type":"opentelemetry","timestamp":"2024-06-05T12:00:33.264832Z"}
    "#;

    pub static KERNEL_IPTABLES: &[u8] = br#"
    {"attributes":{"cluster":"k8s","host":"example.com"
    ,"job":"loki.source.journal.logs_journald_generic"
    ,"loki.attribute.labels":"job"
    ,"observed_time_unix_nano":1717588858433717607,"section":"section2"
    ,"tenant":"tenant2","time_unix_nano":1717588858128394000}
    ,"dropped_attributes_count":0
    ,"message":"{\"MESSAGE\":\"IN= OUT=ens19 SRC=10.1.2.3 DST=10.1.2.4 LEN=177 TOS=0x00 PREC=0x00 TTL=64 ID=35588 PROTO=UDP SPT=49988 DPT=8472 LEN=157 MARK=0xc00 \",\"PRIORITY\":\"4\",\"SYSLOG_FACILITY\":\"0\",\"SYSLOG_IDENTIFIER\":\"kernel\",\"_BOOT_ID\":\"fcb\",\"_HOSTNAME\":\"example.com\",\"_MACHINE_ID\":\"356\",\"_SOURCE_MONOTONIC_TIMESTAMP\":\"8646102285350\",\"_TRANSPORT\":\"kernel\"}"
    ,"observed_timestamp":"2024-06-05T12:00:58.433717607Z"
    ,"source_type":"opentelemetry","timestamp":"2024-06-05T12:00:58.128394Z"}
    "#;

    pub static KERNEL_IPTABLES2: &[u8] = br#"
    {"attributes":{"host":"lb.example.com"
    ,"job":"loki.source.journal.logs_journald_generic"
    ,"loki.attribute.labels":"job"
    ,"observed_time_unix_nano":1717594098353743180,"section":"S","tenant":"T"
    ,"time_unix_nano":1717594098186173000},"dropped_attributes_count":0
    ,"message":"{\"MESSAGE\":\"OUTPUT:DROP: IN= OUT=enp2s0.123 SRC=10.123.1.1 DST=10.123.1.2 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=61632 DF PROTO=TCP SPT=23948 DPT=30080 WINDOW=64240 RES=0x00 SYN URGP=0 \",\"PRIORITY\":\"6\",\"SYSLOG_FACILITY\":\"0\",\"SYSLOG_IDENTIFIER\":\"kernel\",\"_BOOT_ID\":\"27e\",\"_HOSTNAME\":\"lb.example.com\",\"_MACHINE_ID\":\"9e2\",\"_SOURCE_MONOTONIC_TIMESTAMP\":\"41035084405569\",\"_TRANSPORT\":\"kernel\"}"
    ,"observed_timestamp":"2024-06-05T13:28:18.353743180Z"
    ,"source_type":"opentelemetry","timestamp":"2024-06-05T13:28:18.186173Z"}
    "#;

    pub static NGINX: &[u8] = br#"
    {"attributes":{"filename":"/var/log/nginx/cust1/prd-access.log",
    "host":"lb1.zl.example.com","log.file.name":"prd-access.log"
    ,"log.file.path":"/var/log/nginx/cust1/prd-access.log"
    ,"loki.attribute.labels":"filename"
    ,"observed_time_unix_nano":1716915549039502037
    ,"section":"cust1","tenant":"acme"
    ,"time_unix_nano":1716915549039244329}
    ,"dropped_attributes_count":0
    ,"message":"1.2.3.4 - - [28/May/2024:18:59:08 +0200] \"GET /foo/bar/baz HTTP/1.1\" 200 210 \"-\" \"Apache-HttpClient/4.5.6 (Java/1.8.0_402)\" \"-\" \"-\""
    ,"observed_timestamp":"2024-05-28T16:59:09.039502037Z"
    ,"source_type":"opentelemetry"
    ,"timestamp":"2024-05-28T16:59:09.039244329Z"}"#;

    pub static OSSO_CHANGE: &[u8] = br#"
    {"attributes":{"host":"some.server"
    ,"job":"loki.source.journal.logs_journald_generic"
    ,"loki.attribute.labels":"job"
    ,"observed_time_unix_nano":1717080624340039502,"section":"secret"
    ,"tenant":"important","time_unix_nano":1717080624000032000}
    ,"dropped_attributes_count":0
    ,"message":"{\"MESSAGE\":\"{\\\"action\\\":\\\"workon\\\",\\\"user\\\":\\\"johndoe\\\",\\\"ticket\\\":\\\"https://remote-url/issues/69\\\",\\\"description\\\":\\\"natsomatch-work\\\"}\",\"PRIORITY\":\"4\",\"SYSLOG_FACILITY\":\"10\",\"SYSLOG_IDENTIFIER\":\"osso-change\",\"SYSLOG_TIMESTAMP\":\"May 30 16:50:23 \",\"_BOOT_ID\":\"0f7\",\"_COMM\":\"logger\",\"_GID\":\"1005\",\"_HOSTNAME\":\"some.server\",\"_MACHINE_ID\":\"fd4\",\"_PID\":\"105815\",\"_SOURCE_REALTIME_TIMESTAMP\":\"1717080624000014\",\"_TRANSPORT\":\"syslog\",\"_UID\":\"1005\"}"
    ,"observed_timestamp":"2024-05-30T14:50:24.340039502Z"
    ,"source_type":"opentelemetry","timestamp":"2024-05-30T14:50:24.000032Z"}
    "#;

    pub static OSSO_CHANGE_ALTHOUGH_SCOPE: &[u8] = br#"
    {"attributes":{"host":"some.server"
    ,"job":"loki.source.journal.logs_journald_generic"
    ,"loki.attribute.labels":"systemd_unit,job"
    ,"observed_time_unix_nano":1717080624340039502,"section":"secret"
    ,"systemd_unit":"session-1851794.scope","tenant":"important"
    ,"time_unix_nano":1717080624000032000}
    ,"dropped_attributes_count":0
    ,"message":"{\"SYSLOG_FACILITY\":\"10\",\"_GID\":\"1234\",\"_CAP_EFFECTIVE\":\"0\",\"_UID\":\"1234\",\"_MACHINE_ID\":\"599\",\"_SYSTEMD_CGROUP\":\"/user.slice/user-1234.slice/session-1851794.scope\",\"_PID\":\"2762280\",\"_COMM\":\"logger\",\"_TRANSPORT\":\"syslog\",\"_AUDIT_SESSION\":\"1851794\",\"_SYSTEMD_UNIT\":\"session-1851794.scope\",\"_SYSTEMD_SESSION\":\"1851794\",\"_SOURCE_REALTIME_TIMESTAMP\":\"1719471918818348\",\"__MONOTONIC_TIMESTAMP\":\"20797649240313\",\"PRIORITY\":\"4\",\"_SYSTEMD_USER_SLICE\":\"-.slice\",\"_HOSTNAME\":\"some.server\",\"_SYSTEMD_SLICE\":\"user-1234.slice\",\"_BOOT_ID\":\"7d0\",\"_AUDIT_LOGINUID\":\"1234\",\"SYSLOG_TIMESTAMP\":\"Jun 27 09:05:18 \",\"_SYSTEMD_INVOCATION_ID\":\"255\",\"__CURSOR\":\"s=30689a72abbc4412817ecd2b289c3ad0;i=43ee390;b=7d030e2673b447b4a5364034835413c0;m=12ea547ec0f9;t=61bd9c0ec2458;x=202154d2dab6add5\",\"MESSAGE\":\"{\\\"action\\\":\\\"workon\\\",\\\"user\\\":\\\"johnq\\\",\\\"ticket\\\":\\\"TICKET_URL/69\\\",\\\"description\\\":\\\"check-sysobj-log-reasons\\\"}\",\"_SELINUX_CONTEXT\":\"unconfined\\n\",\"SYSLOG_IDENTIFIER\":\"osso-change\",\"__REALTIME_TIMESTAMP\":\"1719471918818392\",\"_SYSTEMD_OWNER_UID\":\"1234\"}"
    ,"observed_timestamp":"2024-05-30T14:50:24.340039502Z"
    ,"source_type":"opentelemetry","timestamp":"2024-05-30T14:50:24.000032Z"}
    "#;

    pub static SSH_ALTHOUGH_SCOPE: &[u8] = br#"
    {"attributes":{"host":"H"
    ,"job":"loki.source.journal.logs_journald_generic"
    ,"loki.attribute.labels":"systemd_unit,job"
    ,"observed_time_unix_nano":1717080624340039502,"section":"S"
    ,"systemd_unit":"session-1851794.scope","tenant":"T"
    ,"time_unix_nano":1717080624000032000}
    ,"dropped_attributes_count":0
    ,"message":"{\"_HOSTNAME\":\"H\",\"__CURSOR\":\"s=30689a72abbc4412817ecd2b289c3ad0;i=43eed1c;b=7d030e2673b447b4a5364034835413c0;m=12ea90810543;t=61bd9fcee68a2;x=e2bdcbdb346ff5c9\",\"_SELINUX_CONTEXT\":\"unconfined\\n\",\"_BOOT_ID\":\"7d0\",\"_GID\":\"1234\",\"_SYSTEMD_OWNER_UID\":\"1234\",\"_SOURCE_REALTIME_TIMESTAMP\":\"1719472925594862\",\"_SYSTEMD_SLICE\":\"user-1234.slice\",\"_CAP_EFFECTIVE\":\"0\",\"_SYSTEMD_UNIT\":\"session-1851794.scope\",\"SYSLOG_FACILITY\":\"4\",\"SYSLOG_IDENTIFIER\":\"sshd\",\"_PID\":\"2762162\",\"_SYSTEMD_SESSION\":\"1851794\",\"_SYSTEMD_USER_SLICE\":\"-.slice\",\"SYSLOG_TIMESTAMP\":\"Jun 27 09:22:05 \",\"_UID\":\"1234\",\"SYSLOG_PID\":\"2762162\",\"_AUDIT_SESSION\":\"1851794\",\"_COMM\":\"sshd\",\"_AUDIT_LOGINUID\":\"1234\",\"MESSAGE\":\"Disconnected from user johnq 10.20.30.40 port 41612\",\"__REALTIME_TIMESTAMP\":\"1719472925599906\",\"_SYSTEMD_CGROUP\":\"/user.slice/user-1234.slice/session-1851794.scope\",\"_MACHINE_ID\":\"599\",\"__MONOTONIC_TIMESTAMP\":\"20798656021827\",\"_SYSTEMD_INVOCATION_ID\":\"255\",\"_TRANSPORT\":\"syslog\",\"PRIORITY\":\"6\"}"
    ,"observed_timestamp":"2024-05-30T14:50:24.340039502Z"
    ,"source_type":"opentelemetry","timestamp":"2024-05-30T14:50:24.000032Z"}
    "#;

    pub static SSH_SERVICE: &[u8] = br#"
    {"attributes":{"host":"H"
    ,"job":"loki.source.journal.logs_journald_generic"
    ,"loki.attribute.labels":"systemd_unit,job"
    ,"observed_time_unix_nano":1717080624340039502,"section":"S"
    ,"systemd_unit":"ssh.service","tenant":"T"
    ,"time_unix_nano":1717080624000032000}
    ,"dropped_attributes_count":0
    ,"message":"{\"_EXE\":\"/usr/sbin/sshd\",\"_HOSTNAME\":\"H\",\"_SELINUX_CONTEXT\":\"unconfined\\n\",\"_BOOT_ID\":\"7d0\",\"_SOURCE_REALTIME_TIMESTAMP\":\"1719471900621313\",\"_UID\":\"0\",\"SYSLOG_FACILITY\":\"4\",\"__REALTIME_TIMESTAMP\":\"1719471900621895\",\"_SYSTEMD_INVOCATION_ID\":\"e1b\",\"PRIORITY\":\"6\",\"_GID\":\"0\",\"_COMM\":\"sshd\",\"SYSLOG_TIMESTAMP\":\"Jun 27 09:05:00 \",\"_CAP_EFFECTIVE\":\"1ffffffffff\",\"_SYSTEMD_CGROUP\":\"/system.slice/ssh.service\",\"_MACHINE_ID\":\"599\",\"_TRANSPORT\":\"syslog\",\"_CMDLINE\":\"\\\"sshd: johnq [priv]\\\"\",\"_SYSTEMD_SLICE\":\"system.slice\",\"SYSLOG_IDENTIFIER\":\"sshd\",\"_PID\":\"2762111\",\"SYSLOG_PID\":\"2762111\",\"MESSAGE\":\"Accepted publickey for johnq from 10.20.30.40 port 41612 ssh2: ED25519 SHA256:CAB...\",\"__CURSOR\":\"s=03a3549774db4c44a00fafd4fa8a1afa;i=43ee2c9;b=7d030e2673b447b4a5364034835413c0;m=12ea536918e8;t=61bd9bfd67c47;x=efdb43ee27f4faec\",\"__MONOTONIC_TIMESTAMP\":\"20797631043816\",\"_SYSTEMD_UNIT\":\"ssh.service\"}"
    ,"observed_timestamp":"2024-05-30T14:50:24.340039502Z"
    ,"source_type":"opentelemetry","timestamp":"2024-05-30T14:50:24.000032Z"}
    "#;

    pub static SYSLOG_AUDIT: &[u8] = br#"
    {"attributes":{"host":"lb.example.com"
    ,"job":"loki.source.journal.logs_journald_generic"
    ,"loki.attribute.labels":"systemd_unit,job"
    ,"observed_time_unix_nano":1717588861410850513
    ,"section":"S","systemd_unit":"cron.service","tenant":"T"
    ,"time_unix_nano":1717588861193959000},"dropped_attributes_count":0
    ,"message":"{\"MESSAGE\":\"pam_unix(cron:session): session opened for user root by (uid=0)\",\"PRIORITY\":\"6\",\"SYSLOG_FACILITY\":\"10\",\"SYSLOG_IDENTIFIER\":\"CRON\",\"SYSLOG_PID\":\"3825520\",\"SYSLOG_TIMESTAMP\":\"Jun  5 14:01:01 \",\"_AUDIT_LOGINUID\":\"0\",\"_AUDIT_SESSION\":\"5133381\",\"_BOOT_ID\":\"f9b\",\"_CAP_EFFECTIVE\":\"3fffffffff\",\"_CMDLINE\":\"/usr/sbin/CRON -f\",\"_COMM\":\"cron\",\"_EXE\":\"/usr/sbin/cron\",\"_GID\":\"0\",\"_HOSTNAME\":\"lb.example.com\",\"_MACHINE_ID\":\"9da\",\"_PID\":\"3825520\",\"_SELINUX_CONTEXT\":\"unconfined\\n\",\"_SOURCE_REALTIME_TIMESTAMP\":\"1717588861193047\",\"_SYSTEMD_CGROUP\":\"/system.slice/cron.service\",\"_SYSTEMD_INVOCATION_ID\":\"f20\",\"_SYSTEMD_SLICE\":\"system.slice\",\"_SYSTEMD_UNIT\":\"cron.service\",\"_TRANSPORT\":\"syslog\",\"_UID\":\"0\"}"
    ,"observed_timestamp":"2024-06-05T12:01:01.410850513Z"
    ,"source_type":"opentelemetry","timestamp":"2024-06-05T12:01:01.193959Z"}
    "#;

    pub static SYSLOG_AUDIT2: &[u8] = br#"
    {"attributes":{"host":"lb.example.com"
    ,"job":"loki.source.journal.logs_journald_generic"
    ,"loki.attribute.labels":"systemd_unit,job"
    ,"observed_time_unix_nano":1717594440522496966,"section":"S"
    ,"systemd_unit":"zabbix-agent.service","tenant":"T"
    ,"time_unix_nano":1717594440187604000},"dropped_attributes_count":0
    ,"message":"{\"MESSAGE\":\"pam_unix(sudo:session): session closed for user root\",\"PRIORITY\":\"6\",\"SYSLOG_FACILITY\":\"10\",\"SYSLOG_IDENTIFIER\":\"sudo\",\"SYSLOG_TIMESTAMP\":\"Jun  5 15:34:00 \",\"_BOOT_ID\":\"f9b\",\"_CAP_EFFECTIVE\":\"3fffffffff\",\"_CMDLINE\":\"sudo iptables -S FORWARD -w\",\"_COMM\":\"sudo\",\"_EXE\":\"/usr/bin/sudo\",\"_GID\":\"0\",\"_HOSTNAME\":\"lb.example.com\",\"_MACHINE_ID\":\"9da\",\"_PID\":\"3871095\",\"_SELINUX_CONTEXT\":\"unconfined\\n\",\"_SOURCE_REALTIME_TIMESTAMP\":\"1717594440187575\",\"_SYSTEMD_CGROUP\":\"/system.slice/zabbix-agent.service\",\"_SYSTEMD_INVOCATION_ID\":\"299\",\"_SYSTEMD_SLICE\":\"system.slice\",\"_SYSTEMD_UNIT\":\"zabbix-agent.service\",\"_TRANSPORT\":\"syslog\",\"_UID\":\"0\"}"
    ,"observed_timestamp":"2024-06-05T13:34:00.522496966Z"
    ,"source_type":"opentelemetry","timestamp":"2024-06-05T13:34:00.187604Z"}
    "#;

    // Not sure where we want this. It has _AUDIT_SESSION, it has sudo.
    // Right now it ends up in systemd.* because it wasn't matched early
    // and it has session-*.scope.
    pub static SYSTEMD_PURELY_BECAUSE_SCOPE: &[u8] = br#"
    {"attributes":{"host":"H"
    ,"job":"loki.source.journal.logs_journald_generic"
    ,"loki.attribute.labels":"systemd_unit,job"
    ,"observed_time_unix_nano":1717605601678748460
    ,"section":"S","systemd_unit":"session-1845976.scope"
    ,"tenant":"T","time_unix_nano":1717605601481345000}
    ,"dropped_attributes_count":0
    ,"message":"{\"_SYSTEMD_SLICE\":\"user-1234.slice\",\"_SYSTEMD_SESSION\":\"1845976\",\"_SYSTEMD_UNIT\":\"session-1845976.scope\",\"_GID\":\"1234\",\"_AUDIT_SESSION\":\"1845976\",\"SYSLOG_TIMESTAMP\":\"Jun 26 16:05:41 \",\"__REALTIME_TIMESTAMP\":\"1719410741532658\",\"_SYSTEMD_INVOCATION_ID\":\"004\",\"_PID\":\"2434090\",\"_HOSTNAME\":\"H\",\"_MACHINE_ID\":\"599\",\"PRIORITY\":\"5\",\"_EXE\":\"/usr/bin/sudo\",\"_AUDIT_LOGINUID\":\"1234\",\"SYSLOG_FACILITY\":\"10\",\"MESSAGE\":\"johnq : PWD=/home/johnq ; USER=root ; COMMAND=/bin/sh -c 'echo BECOME-SUCCESS-tsqosmhzafmhuwxpbajwyzjwkpksnksh ; /usr/bin/python3.10'\",\"_SYSTEMD_USER_SLICE\":\"-.slice\",\"_TRANSPORT\":\"syslog\",\"__MONOTONIC_TIMESTAMP\":\"20736471954579\",\"_COMM\":\"sudo\",\"_SOURCE_REALTIME_TIMESTAMP\":\"1719410741532635\",\"SYSLOG_IDENTIFIER\":\"sudo\",\"_SELINUX_CONTEXT\":\"unconfined\\n\",\"_CAP_EFFECTIVE\":\"1ffffffffff\",\"_SYSTEMD_OWNER_UID\":\"1234\",\"_UID\":\"1234\",\"_SYSTEMD_CGROUP\":\"/user.slice/user-1234.slice/session-1845976.scope\",\"_CMDLINE\":\"sudo -H -S -n -u root /bin/sh -c \\\"echo BECOME-SUCCESS-tsqosmhzafmhuwxpbajwyzjwkpksnksh ; /usr/bin/python3.10\\\"\",\"_BOOT_ID\":\"7d0\",\"__CURSOR\":\"s=99db755e814d47119c5fa7ff29d56244;i=43cc028;b=7d030e2673b447b4a5364034835413c0;m=12dc160b7493;t=61bcb8278d7f2;x=e86a3cda8944392e\"}"
    ,"observed_timestamp":"2024-06-05T16:40:01.678748460Z"
    ,"source_type":"opentelemetry","timestamp":"2024-06-05T16:40:01.481345Z"}
    "#;

    pub static TETRAGON_AUDIT: &[u8] = br#"
    {"attributes":{"cluster":"backup.cloud","host":"abc.backup.cloud"
    ,"job":"loki.source.journal.logs_journald_generic"
    ,"loki.attribute.labels":"systemd_unit,job"
    ,"observed_time_unix_nano":1717078743375327000,"section":"backup"
    ,"systemd_unit":"tetragon-cat.service","tenant":"acme"
    ,"time_unix_nano":1717078743355971000},"dropped_attributes_count":0
    ,"message":"{\"MESSAGE\":\"{\\\"process_exec\\\":{\\\"process\\\":{\\\"pid\\\":3987149,\\\"uid\\\":0,\\\"cwd\\\":\\\"/\\\",\\\"binary\\\":\\\"/usr/bin/find\\\",\\\"arguments\\\":\\\"/var/lib/landscape/landscape-sysinfo.cache -newermt \\\\\\\"now-1 minutes\\\\\\\"\\\",\\\"auid\\\":1000,\\\"process_credentials\\\":{\\\"uid\\\":0,\\\"gid\\\":0,\\\"euid\\\":0,\\\"egid\\\":0,\\\"suid\\\":0,\\\"sgid\\\":0,\\\"fsuid\\\":0,\\\"fsgid\\\":0}},\\\"parent\\\":{\\\"pid\\\":3987148,\\\"cwd\\\":\\\"/\\\",\\\"binary\\\":\\\"/etc/update-motd.d/50-landscape-sysinfo\\\"}},\\\"time\\\":\\\"2024-05-30T14:19:03.355389934Z\\\"}\",\"PRIORITY\":\"6\",\"SYSLOG_FACILITY\":\"3\",\"SYSLOG_IDENTIFIER\":\"tetragon-cat\",\"_BOOT_ID\":\"f6f\",\"_CAP_EFFECTIVE\":\"1ffffffffff\",\"_CMDLINE\":\"grep --line-buffered \\\"\\\\\\\"auid\\\\\\\":[0-9]\\\\\\\\{4\\\\\\\\}[,}]\\\"\",\"_COMM\":\"grep\",\"_EXE\":\"/usr/bin/grep\",\"_GID\":\"0\",\"_HOSTNAME\":\"abc.backup.cloud\",\"_MACHINE_ID\":\"21a\",\"_PID\":\"6499\",\"_SELINUX_CONTEXT\":\"unconfined\\n\",\"_STREAM_ID\":\"eaa\",\"_SYSTEMD_CGROUP\":\"/system.slice/tetragon-cat.service\",\"_SYSTEMD_INVOCATION_ID\":\"e36\",\"_SYSTEMD_SLICE\":\"system.slice\",\"_SYSTEMD_UNIT\":\"tetragon-cat.service\",\"_TRANSPORT\":\"stdout\",\"_UID\":\"0\"}"
    ,"observed_timestamp":"2024-05-30T14:19:03.375327083Z"
    ,"source_type":"opentelemetry","timestamp":"2024-05-30T14:19:03.355971Z"}
    "#;

    pub static XINETD_AUDIT: &[u8] = br#"
    {"attributes":{"host":"H","job":"loki.source.journal.logs_journald_generic"
    ,"loki.attribute.labels":"job,systemd_unit"
    ,"observed_time_unix_nano":1717672932205211587,"section":"S"
    ,"systemd_unit":"xinetd.service","tenant":"T"
    ,"time_unix_nano":1717672931869246000},"dropped_attributes_count":0
    ,"message":"{\"MESSAGE\":\"(to postgres) root on none\",\"PRIORITY\":\"5\",\"SYSLOG_FACILITY\":\"4\",\"SYSLOG_IDENTIFIER\":\"su\",\"SYSLOG_TIMESTAMP\":\"Jun  6 13:22:11 \",\"_BOOT_ID\":\"a30\",\"_CAP_EFFECTIVE\":\"3fffffffff\",\"_CMDLINE\":\"su postgres -c /usr/local/bin/repmgr_node_status.py node_id\",\"_COMM\":\"su\",\"_EXE\":\"/usr/bin/su\",\"_GID\":\"0\",\"_HOSTNAME\":\"H\",\"_MACHINE_ID\":\"aa0\",\"_PID\":\"2832697\",\"_SELINUX_CONTEXT\":\"unconfined\\n\",\"_SOURCE_REALTIME_TIMESTAMP\":\"1717672931869164\",\"_SYSTEMD_CGROUP\":\"/system.slice/xinetd.service\",\"_SYSTEMD_INVOCATION_ID\":\"2f3\",\"_SYSTEMD_SLICE\":\"system.slice\",\"_SYSTEMD_UNIT\":\"xinetd.service\",\"_TRANSPORT\":\"syslog\",\"_UID\":\"0\"}"
    ,"observed_timestamp":"2024-06-06T11:22:12.205211587Z"
    ,"source_type":"opentelemetry","timestamp":"2024-06-06T11:22:11.869246Z"}
    "#;

    pub static UNKNOWN: &[u8] = br#"
    {"attributes":{"filename":"/var/log/unknown.log"
    ,"host":"unknown.example.com","log.file.name":"unknown.log"
    ,"log.file.path":"/var/log/unknown.log"
    ,"loki.attribute.labels":"filename"
    ,"observed_time_unix_nano":1716915545531255460
    ,"section":"unknown-section","tenant":"unknown-tenant"
    ,"time_unix_nano":1716915545530820428}
    ,"dropped_attributes_count":0
    ,"message":"this is an unknown log message"
    ,"observed_timestamp":"2024-05-28T16:59:05.531255460Z"
    ,"source_type":"opentelemetry"
    ,"timestamp":"2024-05-28T16:59:05.530820428Z"}"#;

    // This is generated by logger/systemd-cat from a cron job. This
    // should not end up in any "cron" daemon pile.
    pub static UNKNOWN2: &[u8] = br#"
    {"attributes":{"host":"unknown.example.com"
    ,"job":"loki.source.journal.logs_journald_generic"
    ,"loki.attribute.labels":"systemd_unit,job"
    ,"observed_time_unix_nano":1717605601678748460
    ,"section":"unknown-section","systemd_unit":"notcron.service"
    ,"tenant":"unknown-tenant","time_unix_nano":1717605601481345000}
    ,"dropped_attributes_count":0
    ,"message":"{\"MESSAGE\":\"[REDIS Keyspace] db0:keys=1,expires=0,avg_ttl=0 db1:keys=48142,expires=0,avg_ttl=0 db2:keys=178368,expires=0,avg_ttl=0 db3:keys=5,expires=0,avg_ttl=0 db4:keys=384,expires=0,avg_ttl=0 db5:keys=17,expires=0,avg_ttl=0 db6:keys=17,expires=0,avg_ttl=0 db8:keys=5,expires=0,avg_ttl=0 db9:keys=5,expires=0,avg_ttl=0 db10:keys=17,expires=0,avg_ttl=0 db12:keys=17,expires=0,avg_ttl=0 db13:keys=19082,expires=0,avg_ttl=0 db14:keys=5,expires=0,avg_ttl=0 db15:keys=5,expires=0,avg_ttl=0 db16:keys=24590,expires=0,avg_ttl=0 db18:keys=17,expires=0,avg_ttl=0 db19:keys=8054,expires=0,avg_ttl=0 db20:keys=17,expires=0,avg_ttl=0 db21:keys=4285,expires=0,avg_ttl=0 db23:keys=17,expires=0,avg_ttl=0 db25:keys=15659,expires=0,avg_ttl=0 db26:keys=13985,expires=0,avg_ttl=0 db27:keys=17,expires=0,avg_ttl=0\",\"PRIORITY\":\"6\",\"SYSLOG_IDENTIFIER\":\"redis-stats\",\"_AUDIT_LOGINUID\":\"0\",\"_AUDIT_SESSION\":\"259108\",\"_BOOT_ID\":\"be8\",\"_CAP_EFFECTIVE\":\"1ffffffffff\",\"_COMM\":\"cat\",\"_GID\":\"0\",\"_HOSTNAME\":\"unknown.example.com\",\"_LINE_BREAK\":\"eof\",\"_MACHINE_ID\":\"bb6\",\"_PID\":\"342645\",\"_SELINUX_CONTEXT\":\"unconfined\\n\",\"_STREAM_ID\":\"0c8\",\"_SYSTEMD_CGROUP\":\"/system.slice/notcron.service\",\"_SYSTEMD_INVOCATION_ID\":\"797\",\"_SYSTEMD_SLICE\":\"system.slice\",\"_SYSTEMD_UNIT\":\"notcron.service\",\"_TRANSPORT\":\"stdout\",\"_UID\":\"0\"}"
    ,"observed_timestamp":"2024-06-05T16:40:01.678748460Z"
    ,"source_type":"opentelemetry","timestamp":"2024-06-05T16:40:01.481345Z"}
    "#;
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_starts_with() {
        assert!(starts_with(b"abcdef", b"abc"));
        assert!(starts_with(b"abc", b"abc"));
        assert!(!starts_with(b"ab", b"abc"));
        assert!(!starts_with(b"abdef", b"abc"));
    }

    #[test]
    fn test_ends_with() {
        assert!(ends_with(b"abcdef", b"def"));
        assert!(ends_with(b"def", b"def"));
        assert!(!ends_with(b"ef", b"def"));
        assert!(!ends_with(b"abcef", b"def"));
    }

    #[test]
    fn test_memmem() {
        assert_eq!(memmem(b"abcdef", b"abc"), Some(0));
        assert_eq!(memmem(b"abcdef", b"bcd"), Some(1));
        assert_eq!(memmem(b"abcdef", b"cde"), Some(2));
        assert_eq!(memmem(b"abcdef", b"def"), Some(3));
        assert!(memmem(b"abcdef", b"fgh").is_none());
        assert_eq!(memmem(b"abcdef", b""), Some(0));
        assert_eq!(memmem(b"", b""), Some(0));
        assert!(memmem(b"", b"nope").is_none());
        assert!(memmem(b"ye", b"yea").is_none());
        assert!(memmem(b"yeap", b"nope").is_none());
    }

    #[test]
    fn test_match_aide() {
        let payloads: [&[u8]; 5] = [
            br#"{"attributes":{"systemd_unit":"aide.service","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
            br#"{"attributes":{"systemd_unit":"aidecheck.service","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
            br#"{"attributes":{"systemd_unit":"aidecheck.timer","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
            br#"{"attributes":{"systemd_unit":"dailyaidecheck.service","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
            br#"{"attributes":{"systemd_unit":"dailyaidecheck.timer","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
        ];
        for payload in &payloads {
            let attrs = BytesAttributes::from_payload(payload).expect("parse error");
            let match_ = Match::from_attributes(&attrs).expect("match error");
            assert_eq!(match_.subject, "bulk.aide.T.S.H");
        }
    }

    #[test]
    fn test_match_audit() {
        let attrs = BytesAttributes::from_payload(samples::AUDITD).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        assert_eq!(match_.subject, "bulk.audit.T.S.H");

        let attrs = BytesAttributes::from_payload(samples::KERNEL_AUDIT).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        assert_eq!(match_.subject, "bulk.audit.acme-ops.acme.node1-acme-tld");

        let attrs = BytesAttributes::from_payload(samples::SYSLOG_AUDIT).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        assert_eq!(match_.subject, "bulk.audit.T.S.lb-example-com");

        let attrs = BytesAttributes::from_payload(samples::SYSLOG_AUDIT2).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        assert_eq!(match_.subject, "bulk.audit.T.S.lb-example-com");

        let attrs = BytesAttributes::from_payload(samples::XINETD_AUDIT).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        assert_eq!(match_.subject, "bulk.audit.T.S.H");
    }

    #[test]
    fn test_match_cron() {
        let attrs = BytesAttributes::from_payload(samples::CRON).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        assert_eq!(match_.subject, "bulk.cron.T.S.H");
    }

    #[test]
    fn test_match_devinfra() {
        let payloads: [&[u8]; 2] = [
            br#"{"attributes":{"systemd_unit":"gitea.service","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
            br#"{"attributes":{"systemd_unit":"gitlab-runner.service","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
        ];
        for payload in &payloads {
            let attrs = BytesAttributes::from_payload(payload).expect("parse error");
            let match_ = Match::from_attributes(&attrs).expect("match error");
            assert_eq!(match_.subject, "bulk.devinfra.T.S.H");
        }
    }

    #[test]
    fn test_match_etcd() {
        let attrs = BytesAttributes::from_payload(samples::ETCD).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        assert_eq!(match_.subject, "bulk.etcd.T.S.H");
    }

    #[test]
    fn test_match_execve() {
        let attrs = BytesAttributes::from_payload(samples::OSSO_CHANGE).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        assert_eq!(match_.subject, "bulk.execve.important.secret.some-server");

        let attrs = BytesAttributes::from_payload(samples::OSSO_CHANGE_ALTHOUGH_SCOPE).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        assert_eq!(match_.subject, "bulk.execve.important.secret.some-server");

        let attrs = BytesAttributes::from_payload(samples::TETRAGON_AUDIT).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        assert_eq!(match_.subject, "bulk.execve.acme.backup.abc-backup-cloud");
    }

    #[test]
    fn test_match_firewall() {
        let attrs = BytesAttributes::from_payload(samples::KERNEL_IPTABLES).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        assert_eq!(match_.subject, "bulk.firewall.tenant2.section2.example-com");

        let attrs = BytesAttributes::from_payload(samples::KERNEL_IPTABLES2).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        assert_eq!(match_.subject, "bulk.firewall.T.S.lb-example-com");
    }

    #[test]
    fn test_match_haproxy() {
        let attrs = BytesAttributes::from_payload(samples::HAPROXY).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        assert_eq!(match_.subject, "bulk.haproxy.wilee.example-dmz-cat4.lb1-dr-example-com");
    }

    #[test]
    fn test_match_hids() {
        let payloads: [&[u8]; 5] = [
            br#"{"attributes":{"systemd_unit":"clamav-daemon.service","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
            br#"{"attributes":{"systemd_unit":"clamav-freshclam.service","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
            br#"{"attributes":{"systemd_unit":"tetragon.service","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
            samples::HIDS,
            samples::HIDS2,
        ];
        for payload in &payloads {
            let attrs = BytesAttributes::from_payload(payload).expect("parse error");
            let match_ = Match::from_attributes(&attrs).expect("match error");
            assert_eq!(match_.subject, "bulk.hids.T.S.H");
        }
    }

    #[test]
    fn test_match_k8s() {
        let attrs = BytesAttributes::from_payload(samples::K8S).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        assert_eq!(match_.subject, "bulk.k8s.acme.starwars.master-sith-starwars");

        let payloads: [&[u8]; 4] = [
            br#"{"attributes":{"systemd_unit":"kube-apiserver.service","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
            br#"{"attributes":{"systemd_unit":"kube-controller-manager.service","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
            br#"{"attributes":{"systemd_unit":"kube-scheduler.service","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
            br#"{"attributes":{"systemd_unit":"kubelet.service","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
        ];
        for payload in &payloads {
            let attrs = BytesAttributes::from_payload(payload).expect("parse error");
            let match_ = Match::from_attributes(&attrs).expect("match error");
            assert_eq!(match_.subject, "bulk.k8s.T.S.H");
        }
    }

    #[test]
    fn test_match_k8s_audit() {
        let payloads: [&[u8]; 1] = [
            br#"{"attributes":{"filename":"/var/log/kubernetes/audit/audit.log","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
        ];
        for payload in &payloads {
            let attrs = BytesAttributes::from_payload(payload).expect("parse error");
            let match_ = Match::from_attributes(&attrs).expect("match error");
            assert_eq!(match_.subject, "bulk.k8s-audit.T.S.H");
        }
    }

    #[test]
    fn test_match_monitoring() {
        let payloads: [&[u8]; 4] = [
            br#"{"attributes":{"systemd_unit":"gocollect.service","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
            br#"{"attributes":{"systemd_unit":"zabbix-agent.service","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
            br#"{"attributes":{"systemd_unit":"zabbix-proxy.service","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
            br#"{"attributes":{"systemd_unit":"zabbix-server.service","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
        ];
        for payload in &payloads {
            let attrs = BytesAttributes::from_payload(payload).expect("parse error");
            let match_ = Match::from_attributes(&attrs).expect("match error");
            assert_eq!(match_.subject, "bulk.monitoring.T.S.H");
        }
    }

    #[test]
    fn test_match_nids() {
        let payloads: [&[u8]; 1] = [
            br#"{"attributes":{"systemd_unit":"suricata.service","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
        ];
        for payload in &payloads {
            let attrs = BytesAttributes::from_payload(payload).expect("parse error");
            let match_ = Match::from_attributes(&attrs).expect("match error");
            assert_eq!(match_.subject, "bulk.nids.T.S.H");
        }
    }

    #[test]
    fn test_match_nginx() {
        let attrs = BytesAttributes::from_payload(samples::NGINX).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        assert_eq!(match_.subject, "bulk.nginx.acme.cust1.lb1-zl-example-com");
    }

    #[test]
    fn test_match_ssh() {
        let payloads: [&[u8]; 3] = [
            // $ GEN_BLOB | jq -r .message | jq .MESSAGE |
            //   sed -e 's/ user [^ ]*/ user <U>/;s/port [0-9]\+/port <P>/;s/\([0-9]*[.]\)\{3\}[0-9]*/<A>/' |
            //   sort -u
            // "Accepted publickey for git from <A> port <P> ssh2: ED25519 SHA256:<hash>"
            // "Accepted publickey for remotebackup from <A> port <P> ssh2: ED25519 SHA256:<hash>"
            // "banner exchange: Connection from <A> port <P>: could not read protocol version"
            // "banner exchange: Connection from <A> port <P>: invalid format"
            // "Connection closed by <A> port <P>"
            // "Connection closed by <A> port <P> [preauth]"
            // "Connection closed by invalid user <U> <A> port <P> [preauth]"
            // "Connection reset by <A> port <P>"
            // "Disconnected from authenticating user <U> <A> port <P> [preauth]"
            // "Disconnected from invalid user <U> <A> port <P> [preauth]"
            // "error: kex_exchange_identification: banner line contains invalid characters"
            // "error: kex_exchange_identification: client sent invalid protocol identifier \"${jndi:ldap://<A>#172.21.0.6:19960/a}\""
            // "error: kex_exchange_identification: Connection closed by remote host"
            // "error: kex_exchange_identification: read: Connection reset by peer"
            // "error: Protocol major versions differ: 2 vs. 0"
            // "error: Protocol major versions differ: 2 vs. 1"
            // "Failed none for invalid user <U> from <A> port <P> ssh2"
            // "Failed password for invalid user <U> from <A> port <P> ssh2"
            // "Failed password for root from <A> port <P> ssh2"
            // "Invalid user <U> from <A> port <P>"
            // "Received disconnect from <A> port <P>:11: Bye Bye [preauth]"
            br#"{"attributes":{"systemd_unit":"ssh.service","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
            samples::SSH_ALTHOUGH_SCOPE,
            samples::SSH_SERVICE,
        ];
        for payload in &payloads {
            let attrs = BytesAttributes::from_payload(payload).expect("parse error");
            let match_ = Match::from_attributes(&attrs).expect("match error");
            assert_eq!(match_.subject, "bulk.ssh.T.S.H");
        }
    }

    #[test]
    fn test_match_systemd() {
        let payloads: [&[u8]; 6] = [
            br#"{"attributes":{"systemd_unit":"init.scope","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
            br#"{"attributes":{"systemd_unit":"session-1234.scope","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
            br#"{"attributes":{"systemd_unit":"systemd-networkd.service","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
            br#"{"attributes":{"systemd_unit":"systemd-udev.service","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
            br#"{"attributes":{"systemd_unit":"user@1234.service","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
            samples::SYSTEMD_PURELY_BECAUSE_SCOPE,
        ];
        for payload in &payloads {
            let attrs = BytesAttributes::from_payload(payload).expect("parse error");
            let match_ = Match::from_attributes(&attrs).expect("match error");
            assert_eq!(match_.subject, "bulk.systemd.T.S.H");
        }
    }

    #[test]
    fn test_match_v12n() {
        let payloads: [&[u8]; 4] = [
            br#"{"attributes":{"systemd_unit":"containerd.service","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
            br#"{"attributes":{"systemd_unit":"ctre.service","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
            br#"{"attributes":{"systemd_unit":"docker.service","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
            br#"{"attributes":{"systemd_unit":"docker@someservice.service","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
        ];
        for payload in &payloads {
            let attrs = BytesAttributes::from_payload(payload).expect("parse error");
            let match_ = Match::from_attributes(&attrs).expect("match error");
            assert_eq!(match_.subject, "bulk.v12n.T.S.H");
        }
    }

    #[test]
    fn test_match_vault() {
        let payloads: [&[u8]; 2] = [
            br#"{"attributes":{"filename":"/var/log/vault/audit.log","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
            br#"{"attributes":{"systemd_unit":"vault.service","host":"H","tenant":"T","section":"S"},"message":"M"}"#,
        ];
        for payload in &payloads {
            let attrs = BytesAttributes::from_payload(payload).expect("parse error");
            let match_ = Match::from_attributes(&attrs).expect("match error");
            assert_eq!(match_.subject, "bulk.vault.T.S.H");
        }
    }

    #[test]
    fn test_match_unknown() {
        let payloads: [&[u8]; 2] = [
            samples::UNKNOWN,
            samples::UNKNOWN2,
        ];
        for payload in &payloads {
            let attrs = BytesAttributes::from_payload(payload).expect("parse error");
            let match_ = Match::from_attributes(&attrs).expect("match error");
            assert_eq!(match_.subject, "bulk.unknown.unknown-tenant.unknown-section.unknown-example-com");
        }
    }
}
