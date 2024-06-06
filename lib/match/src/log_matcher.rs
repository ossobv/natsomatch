///
/// Bla bla.. hardcoded stuff here.
///

use nats2jetstream_json::payload_parser::BytesAttributes;


#[derive(Debug)]
pub struct Match {
    pub subject: String,            // subject to use when publishing
}


impl Match {
    pub fn from_attributes(attrs: &BytesAttributes) -> Result<Match, &'static str> {

        // {tenant}  .attributes.tenant <string>
        // {section} .attributes.section <string>
        // {timens}  .attributes.time_unix_nano <digits>
        // {cluster} .attributes.cluster <string> (optional)
        // {systemd_unit} .attributes.systemd_unit (optional)
        // {host}    .attributes.host <string>
        // {message} .message
        // ({origin} = systemd_unit || filename (<- dots) || '{trans}.{syslog.fac}.{syslog.prio}.{syslog.tag}')
        //                 ^- without dots, before first @

        //    817  zabbix-agent.service
        //    863  suricata.service
        //   1249  /var/log/vault/audit.log
        //   1681  unbound.service
        //   2153  kernel:kern.warn:kernel
        //   2244  /var/log/nginx/cust2/prd-access.log
        //   4356  kernel:kern.info:kernel
        //   5394  etcd.service
        //   6253  rsyslog.service
        //  10455  audit:auth.notice:audit
        //  11239  /var/log/nginx/cust1/prod-access.log
        //  16419  kube-apiserver.service
        //  34451  haproxy

        let tenant = replace_dots_with_dashes(attrs.tenant);
        let section = replace_dots_with_dashes(attrs.section);
        let hostname = replace_dots_with_dashes(attrs.hostname);

        // ==============================================================
        // One giant if here
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

        if memmem(attrs.message, br#"\"_TRANSPORT\":\"syslog\""#).is_some() {
            if memmem(attrs.message, br#"\"_AUDIT_SESSION\":\""#).is_some() ||
                    memmem(attrs.message, br#"\"MESSAGE\":\"pam_unix("#).is_some() ||
                    (attrs.systemd_unit == b"zabbix-agent.service" &&
                     memmem(attrs.message, br#"\"SYSLOG_FACILITY\":\"10\""#).is_some()) {
                return Ok(Match {
                    // destination: "bulk_match_audit",
                    subject: format!("bulk.audit.{tenant}.{section}.{hostname}"),
                });
            }
        }

        if attrs.systemd_unit == b"kube-apiserver.service"  ||
                attrs.systemd_unit == b"kube-controller-manager.service" ||
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
                (starts_with(attrs.systemd_unit, b"session-") &&
                 ends_with(attrs.systemd_unit, b".scope")) ||
                (starts_with(attrs.systemd_unit, b"user@") &&
                 ends_with(attrs.systemd_unit, b".service")) ||
                attrs.systemd_unit == b"init.scope" {
            return Ok(Match {
                // destination: "bulk_match_systemd",
                subject: format!("bulk.systemd.{tenant}.{section}.{hostname}"),
            });
        }

        if attrs.systemd_unit == b"suricata.service" {
            return Ok(Match {
                // destination: "bulk_match_nids",
                subject: format!("bulk.nids.{tenant}.{section}.{hostname}"),
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

        if attrs.has_no_origin() {
            // TODO: Do we want to decode .message here? Or just do
            // substring matching like this:

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

            if memmem(attrs.message, br#"\"SYSLOG_IDENTIFIER\":\"osso-change\""#).is_some() {
                return Ok(Match {
                    // destination: "bulk_match_execve",
                    subject: format!("bulk.execve.{tenant}.{section}.{hostname}"),
                });
            }
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
    pub static HAPROXY: &[u8] = br#"
    {"attributes":{"host":"lb1.dr.example.com"
    ,"job":"loki.source.journal.logs_journald_generic"
    ,"loki.attribute.labels":"job,systemd_unit"
    ,"observed_time_unix_nano":1716915534776220907,"section":"example-dmz-cat4"
    ,"systemd_unit":"haproxy@example_dmz.service","tenant":"wilee"
    ,"time_unix_nano":1716915534575273000},"dropped_attributes_count":0
    ,"message":"{\"MESSAGE\":\"TCP 1.2.3.4:37164 -\\u003e 1.2.3.4:3100(loki-haproxy-tcp-3100-in) -\\u003e 10.1.2.3:443(loki-haproxy-tcp-3100-in) i=3943/o=3477/r=0 tw=1/tc=0/t=43 state=CD conns=1155/1154/1155/1154\",\"PRIORITY\":\"6\",\"SYSLOG_FACILITY\":\"16\",\"SYSLOG_IDENTIFIER\":\"haproxy\",\"SYSLOG_PID\":\"4151570\",\"SYSLOG_RAW\":\"\\u003c134\\u003eMay 28 18:58:54 haproxy[4151570]: TCP 1.2.3.4:37164 -\\u003e 1.2.3.4:3100(loki-haproxy-tcp-3100-in) -\\u003e 10.1.2.3:443(loki-haproxy-tcp-3100-in) i=3943/o=3477/r=0 tw=1/tc=0/t=43 state=CD conns=1155/1154/1155/1154\\n\",\"SYSLOG_TIMESTAMP\":\"May 28 18:58:54 \",\"_BOOT_ID\":\"a41\",\"_CAP_EFFECTIVE\":\"0\",\"_CMDLINE\":\"/usr/sbin/haproxy -sf 1688512 -Ws -f /etc/haproxy/example_dmz/loki.cfg -p /run/haproxy/example_dmz/loki.pid -S /run/haproxy/example_dmz/loki-master.sock\",\"_COMM\":\"haproxy\",\"_EXE\":\"/usr/sbin/haproxy\",\"_GID\":\"123\",\"_HOSTNAME\":\"lb1.dr.example.com\",\"_MACHINE_ID\":\"bd2\",\"_PID\":\"4151570\",\"_SELINUX_CONTEXT\":\"unconfined\\n\",\"_SOURCE_REALTIME_TIMESTAMP\":\"1716915534574747\",\"_SYSTEMD_CGROUP\":\"/system.slice/system-haproxy.slice/haproxy@example_dmz-loki.service\",\"_SYSTEMD_INVOCATION_ID\":\"650\",\"_SYSTEMD_SLICE\":\"system-haproxy.slice\",\"_SYSTEMD_UNIT\":\"haproxy@example_dmz-loki.service\",\"_TRANSPORT\":\"syslog\",\"_UID\":\"115\"}"
    ,"observed_timestamp":"2024-05-28T16:58:54.776220907Z"
    ,"source_type":"opentelemetry"
    ,"timestamp":"2024-05-28T16:58:54.575273Z"}"#;

    pub static K8S: &[u8] = br#"
    {"attributes":{"cluster":"k8s-starwars","host":"master.sith.starwars"
    ,"job":"loki.source.journal.logs_journald_generic"
    ,"loki.attribute.labels":"job,systemd_unit"
    ,"observed_time_unix_nano":1716915530887807787,"section":"starwars"
    ,"systemd_unit":"kube-apiserver.service","tenant":"acme"
    ,"time_unix_nano":1716915530505521000},"dropped_attributes_count":0
    ,"message":"{\"MESSAGE\":\"W0528 18:58:50.244507 3818486 reflector.go:539] storage/cacher.go:/aquasecurity.github.io/vulnerabilityreports: failed to list aquasecurity.github.io/v1alpha1, Kind=VulnerabilityReport: etcdserver: request timed out\",\"PRIORITY\":\"6\",\"SYSLOG_FACILITY\":\"3\",\"SYSLOG_IDENTIFIER\":\"kube-apiserver\",\"_BOOT_ID\":\"050\",\"_CAP_EFFECTIVE\":\"1ffffffffff\",\"_CMDLINE\":\"/usr/bin/kube-apiserver --allow-privileged=true --anonymous-auth=false --authorization-mode=Node,RBAC --audit-policy-file=/etc/kubernetes/audit-policy.yaml --audit-log-path=/var/log/kubernetes/audit/audit.log --audit-log-maxage=3 --audit-log-maxbackup=0 --audit-log-maxsize=200 --bind-address=127.0.0.1 --client-ca-file=/etc/kubernetes/pki/ca.crt --etcd-servers=https://10.3.2.47:2379,https://10.3.2.49:2379,https://10.3.2.51:2379 --etcd-cafile=/etc/kubernetes/pki/etcd/ca.crt --etcd-certfile=/etc/kubernetes/pki/apiserver-etcd-client.crt --etcd-keyfile=/etc/kubernetes/pki/apiserver-etcd-client.key --etcd-prefix=/registry --kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname --kubelet-client-certificate=/etc/kubernetes/pki/apiserver-kubelet-client.crt --kubelet-client-key=/etc/kubernetes/pki/apiserver-kubelet-client.key --proxy-client-cert-file=/etc/kubernetes/pki/front-proxy-client.crt --proxy-client-key-file=/etc/kubernetes/pki/front-proxy-client.key --requestheader-client-ca-file=/etc/kubernetes/pki/front-proxy-ca.crt --requestheader-allowed-names=front-proxy-client --requestheader-username-headers=X-Remote-User --requestheader-group-headers=X-Remote-Group --requestheader-extra-headers-prefix=X-Remote-Extra- --service-account-issuer=https://kubernetes --service-cluster-ip-range=10.3.0.0/24 --service-account-key-file=/etc/kubernetes/pki/sa.pub --service-account-signing-key-file=/etc/kubernetes/pki/sa.key --tls-cert-file=/etc/kubernetes/pki/apiserver.crt --tls-private-key-file=/etc/kubernetes/pki/apiserver.key\",\"_COMM\":\"kube-apiserver\",\"_EXE\":\"/usr/bin/kube-apiserver\",\"_GID\":\"0\",\"_HOSTNAME\":\"master.sith.starwars\",\"_MACHINE_ID\":\"3ca\",\"_PID\":\"3818486\",\"_SELINUX_CONTEXT\":\"unconfined\\n\",\"_STREAM_ID\":\"ced\",\"_SYSTEMD_CGROUP\":\"/system.slice/kube-apiserver.service\",\"_SYSTEMD_INVOCATION_ID\":\"cdc\",\"_SYSTEMD_SLICE\":\"system.slice\",\"_SYSTEMD_UNIT\":\"kube-apiserver.service\",\"_TRANSPORT\":\"stdout\",\"_UID\":\"0\"}"
    ,"observed_timestamp":"2024-05-28T16:58:50.887807787Z"
    ,"source_type":"opentelemetry"
    ,"timestamp":"2024-05-28T16:58:50.505521Z"}"#;

    pub static KERNEL_AUDIT: &[u8] = br#"
    {"attributes":{"cluster":"k8s-acme-prod-backend1","host":"node1.acme.tld"
    ,"job":"loki.source.journal.logs_journald_generic"
    ,"loki.attribute.labels":"job"
    ,"observed_time_unix_nano":1717588833648370149,"section":"acme"
    ,"tenant":"acme-ops","time_unix_nano":1717588833264832000}
    ,"dropped_attributes_count":0
    ,"message":"{\"AUDIT_FIELD_ACCT\":\"zabbix\",\"AUDIT_FIELD_ADDR\":\"?\",\"AUDIT_FIELD_EXE\":\"/usr/bin/sudo\",\"AUDIT_FIELD_GRANTORS\":\"pam_permit\",\"AUDIT_FIELD_HOSTNAME\":\"?\",\"AUDIT_FIELD_OP\":\"PAM:accounting\",\"AUDIT_FIELD_RES\":\"success\",\"AUDIT_FIELD_TERMINAL\":\"?\",\"MESSAGE\":\"USER_ACCT pid=1417310 uid=110 auid=4294967295 ses=4294967295 subj=unconfined msg='op=PAM:accounting grantors=pam_permit acct=\\\"zabbix\\\" exe=\\\"/usr/bin/sudo\\\" hostname=? addr=? terminal=? res=success'\",\"SYSLOG_FACILITY\":\"4\",\"SYSLOG_IDENTIFIER\":\"audit\",\"_AUDIT_ID\":\"13817439\",\"_AUDIT_LOGINUID\":\"4294967295\",\"_AUDIT_SESSION\":\"4294967295\",\"_AUDIT_TYPE\":\"1101\",\"_AUDIT_TYPE_NAME\":\"USER_ACCT\",\"_BOOT_ID\":\"284\",\"_HOSTNAME\":\"node1.acme.tld\",\"_MACHINE_ID\":\"ca7\",\"_PID\":\"1417310\",\"_SELINUX_CONTEXT\":\"unconfined\",\"_SOURCE_REALTIME_TIMESTAMP\":\"1717588833260000\",\"_TRANSPORT\":\"audit\",\"_UID\":\"110\"}"
    ,"observed_timestamp":"2024-06-05T12:00:33.648370149Z"
    ,"source_type":"opentelemetry"
    ,"timestamp":"2024-06-05T12:00:33.264832Z"}"#;

    pub static KERNEL_IPTABLES: &[u8] = br#"
    {"attributes":{"cluster":"k8s","host":"example.com"
    ,"job":"loki.source.journal.logs_journald_generic"
    ,"loki.attribute.labels":"job"
    ,"observed_time_unix_nano":1717588858433717607,"section":"section2"
    ,"tenant":"tenant2","time_unix_nano":1717588858128394000}
    ,"dropped_attributes_count":0
    ,"message":"{\"MESSAGE\":\"IN= OUT=ens19 SRC=10.1.2.3 DST=10.1.2.4 LEN=177 TOS=0x00 PREC=0x00 TTL=64 ID=35588 PROTO=UDP SPT=49988 DPT=8472 LEN=157 MARK=0xc00 \",\"PRIORITY\":\"4\",\"SYSLOG_FACILITY\":\"0\",\"SYSLOG_IDENTIFIER\":\"kernel\",\"_BOOT_ID\":\"fcb\",\"_HOSTNAME\":\"example.com\",\"_MACHINE_ID\":\"356\",\"_SOURCE_MONOTONIC_TIMESTAMP\":\"8646102285350\",\"_TRANSPORT\":\"kernel\"}"
    ,"observed_timestamp":"2024-06-05T12:00:58.433717607Z"
    ,"source_type":"opentelemetry"
    ,"timestamp":"2024-06-05T12:00:58.128394Z"}"#;

    pub static KERNEL_IPTABLES2: &[u8] = br#"
    {"attributes":{"host":"lb.example.com"
    ,"job":"loki.source.journal.logs_journald_generic"
    ,"loki.attribute.labels":"job"
    ,"observed_time_unix_nano":1717594098353743180,"section":"S","tenant":"T"
    ,"time_unix_nano":1717594098186173000},"dropped_attributes_count":0
    ,"message":"{\"MESSAGE\":\"OUTPUT:DROP: IN= OUT=enp2s0.123 SRC=10.123.1.1 DST=10.123.1.2 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=61632 DF PROTO=TCP SPT=23948 DPT=30080 WINDOW=64240 RES=0x00 SYN URGP=0 \",\"PRIORITY\":\"6\",\"SYSLOG_FACILITY\":\"0\",\"SYSLOG_IDENTIFIER\":\"kernel\",\"_BOOT_ID\":\"27e\",\"_HOSTNAME\":\"lb.example.com\",\"_MACHINE_ID\":\"9e2\",\"_SOURCE_MONOTONIC_TIMESTAMP\":\"41035084405569\",\"_TRANSPORT\":\"kernel\"}"
    ,"observed_timestamp":"2024-06-05T13:28:18.353743180Z"
    ,"source_type":"opentelemetry"
    ,"timestamp":"2024-06-05T13:28:18.186173Z"}"#;

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
    ,"message":"{\"MESSAGE\":\"{\\\"action\\\":\\\"workon\\\",\\\"user\\\":\\\"johndoe\\\",\\\"ticket\\\":\\\"https://remote-url/issues/69\\\",\\\"description\\\":\\\"nats2jetstream-work\\\"}\",\"PRIORITY\":\"4\",\"SYSLOG_FACILITY\":\"10\",\"SYSLOG_IDENTIFIER\":\"osso-change\",\"SYSLOG_TIMESTAMP\":\"May 30 16:50:23 \",\"_BOOT_ID\":\"0f7\",\"_COMM\":\"logger\",\"_GID\":\"1005\",\"_HOSTNAME\":\"some.server\",\"_MACHINE_ID\":\"fd4\",\"_PID\":\"105815\",\"_SOURCE_REALTIME_TIMESTAMP\":\"1717080624000014\",\"_TRANSPORT\":\"syslog\",\"_UID\":\"1005\"}"
    ,"observed_timestamp":"2024-05-30T14:50:24.340039502Z"
    ,"source_type":"opentelemetry"
    ,"timestamp":"2024-05-30T14:50:24.000032Z"}"#;

    pub static SYSLOG_AUDIT: &[u8] = br#"
    {"attributes":{"host":"lb.example.com"
    ,"job":"loki.source.journal.logs_journald_generic"
    ,"loki.attribute.labels":"systemd_unit,job"
    ,"observed_time_unix_nano":1717588861410850513
    ,"section":"S","systemd_unit":"cron.service","tenant":"T"
    ,"time_unix_nano":1717588861193959000},"dropped_attributes_count":0
    ,"message":"{\"MESSAGE\":\"pam_unix(cron:session): session opened for user root by (uid=0)\",\"PRIORITY\":\"6\",\"SYSLOG_FACILITY\":\"10\",\"SYSLOG_IDENTIFIER\":\"CRON\",\"SYSLOG_PID\":\"3825520\",\"SYSLOG_TIMESTAMP\":\"Jun  5 14:01:01 \",\"_AUDIT_LOGINUID\":\"0\",\"_AUDIT_SESSION\":\"5133381\",\"_BOOT_ID\":\"f9b\",\"_CAP_EFFECTIVE\":\"3fffffffff\",\"_CMDLINE\":\"/usr/sbin/CRON -f\",\"_COMM\":\"cron\",\"_EXE\":\"/usr/sbin/cron\",\"_GID\":\"0\",\"_HOSTNAME\":\"lb.example.com\",\"_MACHINE_ID\":\"9da\",\"_PID\":\"3825520\",\"_SELINUX_CONTEXT\":\"unconfined\\n\",\"_SOURCE_REALTIME_TIMESTAMP\":\"1717588861193047\",\"_SYSTEMD_CGROUP\":\"/system.slice/cron.service\",\"_SYSTEMD_INVOCATION_ID\":\"f20\",\"_SYSTEMD_SLICE\":\"system.slice\",\"_SYSTEMD_UNIT\":\"cron.service\",\"_TRANSPORT\":\"syslog\",\"_UID\":\"0\"}"
    ,"observed_timestamp":"2024-06-05T12:01:01.410850513Z"
    ,"source_type":"opentelemetry"
    ,"timestamp":"2024-06-05T12:01:01.193959Z"}"#;

    pub static SYSLOG_AUDIT2: &[u8] = br#"
    {"attributes":{"host":"lb.example.com"
    ,"job":"loki.source.journal.logs_journald_generic"
    ,"loki.attribute.labels":"systemd_unit,job"
    ,"observed_time_unix_nano":1717594440522496966,"section":"S"
    ,"systemd_unit":"zabbix-agent.service","tenant":"T"
    ,"time_unix_nano":1717594440187604000},"dropped_attributes_count":0
    ,"message":"{\"MESSAGE\":\"pam_unix(sudo:session): session closed for user root\",\"PRIORITY\":\"6\",\"SYSLOG_FACILITY\":\"10\",\"SYSLOG_IDENTIFIER\":\"sudo\",\"SYSLOG_TIMESTAMP\":\"Jun  5 15:34:00 \",\"_BOOT_ID\":\"f9b\",\"_CAP_EFFECTIVE\":\"3fffffffff\",\"_CMDLINE\":\"sudo iptables -S FORWARD -w\",\"_COMM\":\"sudo\",\"_EXE\":\"/usr/bin/sudo\",\"_GID\":\"0\",\"_HOSTNAME\":\"lb.example.com\",\"_MACHINE_ID\":\"9da\",\"_PID\":\"3871095\",\"_SELINUX_CONTEXT\":\"unconfined\\n\",\"_SOURCE_REALTIME_TIMESTAMP\":\"1717594440187575\",\"_SYSTEMD_CGROUP\":\"/system.slice/zabbix-agent.service\",\"_SYSTEMD_INVOCATION_ID\":\"299\",\"_SYSTEMD_SLICE\":\"system.slice\",\"_SYSTEMD_UNIT\":\"zabbix-agent.service\",\"_TRANSPORT\":\"syslog\",\"_UID\":\"0\"}"
    ,"observed_timestamp":"2024-06-05T13:34:00.522496966Z"
    ,"source_type":"opentelemetry"
    ,"timestamp":"2024-06-05T13:34:00.187604Z"}"#;

    pub static TETRAGON_AUDIT: &[u8] = br#"
    {"attributes":{"cluster":"backup.cloud","host":"abc.backup.cloud"
    ,"job":"loki.source.journal.logs_journald_generic"
    ,"loki.attribute.labels":"systemd_unit,job"
    ,"observed_time_unix_nano":1717078743375327000,"section":"backup"
    ,"systemd_unit":"tetragon-cat.service","tenant":"acme"
    ,"time_unix_nano":1717078743355971000},"dropped_attributes_count":0
    ,"message":"{\"MESSAGE\":\"{\\\"process_exec\\\":{\\\"process\\\":{\\\"pid\\\":3987149,\\\"uid\\\":0,\\\"cwd\\\":\\\"/\\\",\\\"binary\\\":\\\"/usr/bin/find\\\",\\\"arguments\\\":\\\"/var/lib/landscape/landscape-sysinfo.cache -newermt \\\\\\\"now-1 minutes\\\\\\\"\\\",\\\"auid\\\":1000,\\\"process_credentials\\\":{\\\"uid\\\":0,\\\"gid\\\":0,\\\"euid\\\":0,\\\"egid\\\":0,\\\"suid\\\":0,\\\"sgid\\\":0,\\\"fsuid\\\":0,\\\"fsgid\\\":0}},\\\"parent\\\":{\\\"pid\\\":3987148,\\\"cwd\\\":\\\"/\\\",\\\"binary\\\":\\\"/etc/update-motd.d/50-landscape-sysinfo\\\"}},\\\"time\\\":\\\"2024-05-30T14:19:03.355389934Z\\\"}\",\"PRIORITY\":\"6\",\"SYSLOG_FACILITY\":\"3\",\"SYSLOG_IDENTIFIER\":\"tetragon-cat\",\"_BOOT_ID\":\"f6f\",\"_CAP_EFFECTIVE\":\"1ffffffffff\",\"_CMDLINE\":\"grep --line-buffered \\\"\\\\\\\"auid\\\\\\\":[0-9]\\\\\\\\{4\\\\\\\\}[,}]\\\"\",\"_COMM\":\"grep\",\"_EXE\":\"/usr/bin/grep\",\"_GID\":\"0\",\"_HOSTNAME\":\"abc.backup.cloud\",\"_MACHINE_ID\":\"21a\",\"_PID\":\"6499\",\"_SELINUX_CONTEXT\":\"unconfined\\n\",\"_STREAM_ID\":\"eaa\",\"_SYSTEMD_CGROUP\":\"/system.slice/tetragon-cat.service\",\"_SYSTEMD_INVOCATION_ID\":\"e36\",\"_SYSTEMD_SLICE\":\"system.slice\",\"_SYSTEMD_UNIT\":\"tetragon-cat.service\",\"_TRANSPORT\":\"stdout\",\"_UID\":\"0\"}"
    ,"observed_timestamp":"2024-05-30T14:19:03.375327083Z"
    ,"source_type":"opentelemetry"
    ,"timestamp":"2024-05-30T14:19:03.355971Z"}"#;

    pub static VAULT_AUDIT: &[u8] = br#"
    {"attributes":{"filename":"/var/log/vault/audit.log","host":"H"
    ,"tenant":"T","section":"S"},"message":"M"}"#;

    pub static VAULT_SERVICE: &[u8] = br#"
    {"attributes":{"systemd_unit":"vault.service","host":"H"
    ,"tenant":"T","section":"S"},"message":"M"}"#;

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
    fn test_match_haproxy() {
        let attrs = BytesAttributes::from_payload(samples::HAPROXY).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        assert_eq!(match_.subject, "bulk.haproxy.wilee.example-dmz-cat4.lb1-dr-example-com");
    }

    #[test]
    fn test_match_k8s() {
        let attrs = BytesAttributes::from_payload(samples::K8S).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        assert_eq!(match_.subject, "bulk.k8s.acme.starwars.master-sith-starwars");
    }

    #[test]
    fn test_match_kernel_audit() {
        let attrs = BytesAttributes::from_payload(samples::KERNEL_AUDIT).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        assert_eq!(match_.subject, "bulk.audit.acme-ops.acme.node1-acme-tld");
    }

    #[test]
    fn test_match_kernel_iptables() {
        let attrs = BytesAttributes::from_payload(samples::KERNEL_IPTABLES).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        assert_eq!(match_.subject, "bulk.firewall.tenant2.section2.example-com");

        let attrs = BytesAttributes::from_payload(samples::KERNEL_IPTABLES2).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        assert_eq!(match_.subject, "bulk.firewall.T.S.lb-example-com");
    }

    #[test]
    fn test_match_nginx() {
        let attrs = BytesAttributes::from_payload(samples::NGINX).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        assert_eq!(match_.subject, "bulk.nginx.acme.cust1.lb1-zl-example-com");
    }

    #[test]
    fn test_match_osso_change() {
        let attrs = BytesAttributes::from_payload(samples::OSSO_CHANGE).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        assert_eq!(match_.subject, "bulk.execve.important.secret.some-server");
    }

    #[test]
    fn test_match_syslog_audit() {
        let attrs = BytesAttributes::from_payload(samples::SYSLOG_AUDIT).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        assert_eq!(match_.subject, "bulk.audit.T.S.lb-example-com");

        let attrs = BytesAttributes::from_payload(samples::SYSLOG_AUDIT2).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        assert_eq!(match_.subject, "bulk.audit.T.S.lb-example-com");
    }

    #[test]
    fn test_match_tetragon_audit() {
        let attrs = BytesAttributes::from_payload(samples::TETRAGON_AUDIT).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        assert_eq!(match_.subject, "bulk.execve.acme.backup.abc-backup-cloud");
    }

    #[test]
    fn test_match_vault() {
        let attrs = BytesAttributes::from_payload(samples::VAULT_AUDIT).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        assert_eq!(match_.subject, "bulk.vault.T.S.H");

        let attrs = BytesAttributes::from_payload(samples::VAULT_SERVICE).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        assert_eq!(match_.subject, "bulk.vault.T.S.H");
    }

    #[test]
    fn test_match_unknown() {
        let attrs = BytesAttributes::from_payload(samples::UNKNOWN).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        assert_eq!(match_.subject, "bulk.unknown.unknown-tenant.unknown-section.unknown-example-com");
    }
}
