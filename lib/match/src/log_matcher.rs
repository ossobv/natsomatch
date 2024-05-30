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

        if attrs.systemd_unit == b"kube-apiserver.service" {
            return Ok(Match {
                // destination: "bulk_match_k8s",
                subject: format!("bulk.k8s.{tenant}.{section}.{hostname}"),
            });
        }

        if starts_with(attrs.filename, b"/var/log/nginx/") {
            return Ok(Match {
                // destination: "bulk_match_nginx",
                subject: format!("bulk.nginx.{tenant}.{section}.{hostname}"),
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


#[cfg(any(test, feature = "benchmark"))]
pub mod samples {
    pub static HAPROXY: &[u8] = br#"{"attributes":{"host":"lb1.dr.example.com"
        ,"job":"loki.source.journal.logs_journald_generic"
        ,"loki.attribute.labels":"job,systemd_unit"
        ,"observed_time_unix_nano":1716915534776220907
        ,"section":"example-dmz-cat4"
        ,"systemd_unit":"haproxy@example_dmz.service","tenant":"wilee"
        ,"time_unix_nano":1716915534575273000},"dropped_attributes_count":0
        ,"message":"{\"MESSAGE\":\"TCP 1.2.3.4:37164 -\\u003e 1.2.3.4:3100(loki-haproxy-tcp-3100-in) -\\u003e 10.1.2.3:443(loki-haproxy-tcp-3100-in) i=3943/o=3477/r=0 tw=1/tc=0/t=43 state=CD conns=1155/1154/1155/1154\",\"PRIORITY\":\"6\",\"SYSLOG_FACILITY\":\"16\",\"SYSLOG_IDENTIFIER\":\"haproxy\",\"SYSLOG_PID\":\"4151570\",\"SYSLOG_RAW\":\"\\u003c134\\u003eMay 28 18:58:54 haproxy[4151570]: TCP 1.2.3.4:37164 -\\u003e 1.2.3.4:3100(loki-haproxy-tcp-3100-in) -\\u003e 10.1.2.3:443(loki-haproxy-tcp-3100-in) i=3943/o=3477/r=0 tw=1/tc=0/t=43 state=CD conns=1155/1154/1155/1154\\n\",\"SYSLOG_TIMESTAMP\":\"May 28 18:58:54 \",\"_BOOT_ID\":\"a4168b7819e44d60ab7a1bcdcb6fdf3f\",\"_CAP_EFFECTIVE\":\"0\",\"_CMDLINE\":\"/usr/sbin/haproxy -sf 1688512 -Ws -f /etc/haproxy/example_dmz/loki.cfg -p /run/haproxy/example_dmz/loki.pid -S /run/haproxy/example_dmz/loki-master.sock\",\"_COMM\":\"haproxy\",\"_EXE\":\"/usr/sbin/haproxy\",\"_GID\":\"123\",\"_HOSTNAME\":\"lb1.dr.example.com\",\"_MACHINE_ID\":\"bd28015ebb024007b507ba21a5c1307b\",\"_PID\":\"4151570\",\"_SELINUX_CONTEXT\":\"unconfined\\n\",\"_SOURCE_REALTIME_TIMESTAMP\":\"1716915534574747\",\"_SYSTEMD_CGROUP\":\"/system.slice/system-haproxy.slice/haproxy@example_dmz-loki.service\",\"_SYSTEMD_INVOCATION_ID\":\"650e73b1ecdc4c4e884980eda782582c\",\"_SYSTEMD_SLICE\":\"system-haproxy.slice\",\"_SYSTEMD_UNIT\":\"haproxy@example_dmz-loki.service\",\"_TRANSPORT\":\"syslog\",\"_UID\":\"115\"}"
        ,"observed_timestamp":"2024-05-28T16:58:54.776220907Z"
        ,"source_type":"opentelemetry"
        ,"timestamp":"2024-05-28T16:58:54.575273Z"}"#;

    pub static K8S: &[u8] = br#"{"attributes":{"cluster":"k8s-starwars"
        ,"host":"master.sith.starwars"
        ,"job":"loki.source.journal.logs_journald_generic"
        ,"loki.attribute.labels":"job,systemd_unit"
        ,"observed_time_unix_nano":1716915530887807787,"section":"starwars"
        ,"systemd_unit":"kube-apiserver.service"
        ,"tenant":"acme","time_unix_nano":1716915530505521000}
        ,"dropped_attributes_count":0
        ,"message":"{\"MESSAGE\":\"W0528 18:58:50.244507 3818486 reflector.go:539] storage/cacher.go:/aquasecurity.github.io/vulnerabilityreports: failed to list aquasecurity.github.io/v1alpha1, Kind=VulnerabilityReport: etcdserver: request timed out\",\"PRIORITY\":\"6\",\"SYSLOG_FACILITY\":\"3\",\"SYSLOG_IDENTIFIER\":\"kube-apiserver\",\"_BOOT_ID\":\"0500a56045174b7ab60694bb06bdb7ba\",\"_CAP_EFFECTIVE\":\"1ffffffffff\",\"_CMDLINE\":\"/usr/bin/kube-apiserver --allow-privileged=true --anonymous-auth=false --authorization-mode=Node,RBAC --audit-policy-file=/etc/kubernetes/audit-policy.yaml --audit-log-path=/var/log/kubernetes/audit/audit.log --audit-log-maxage=3 --audit-log-maxbackup=0 --audit-log-maxsize=200 --bind-address=127.0.0.1 --client-ca-file=/etc/kubernetes/pki/ca.crt --etcd-servers=https://10.3.2.47:2379,https://10.3.2.49:2379,https://10.3.2.51:2379 --etcd-cafile=/etc/kubernetes/pki/etcd/ca.crt --etcd-certfile=/etc/kubernetes/pki/apiserver-etcd-client.crt --etcd-keyfile=/etc/kubernetes/pki/apiserver-etcd-client.key --etcd-prefix=/registry --kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname --kubelet-client-certificate=/etc/kubernetes/pki/apiserver-kubelet-client.crt --kubelet-client-key=/etc/kubernetes/pki/apiserver-kubelet-client.key --proxy-client-cert-file=/etc/kubernetes/pki/front-proxy-client.crt --proxy-client-key-file=/etc/kubernetes/pki/front-proxy-client.key --requestheader-client-ca-file=/etc/kubernetes/pki/front-proxy-ca.crt --requestheader-allowed-names=front-proxy-client --requestheader-username-headers=X-Remote-User --requestheader-group-headers=X-Remote-Group --requestheader-extra-headers-prefix=X-Remote-Extra- --service-account-issuer=https://kubernetes --service-cluster-ip-range=10.3.0.0/24 --service-account-key-file=/etc/kubernetes/pki/sa.pub --service-account-signing-key-file=/etc/kubernetes/pki/sa.key --tls-cert-file=/etc/kubernetes/pki/apiserver.crt --tls-private-key-file=/etc/kubernetes/pki/apiserver.key\",\"_COMM\":\"kube-apiserver\",\"_EXE\":\"/usr/bin/kube-apiserver\",\"_GID\":\"0\",\"_HOSTNAME\":\"master.sith.starwars\",\"_MACHINE_ID\":\"3cad86460f964596a036b2696b6b2413\",\"_PID\":\"3818486\",\"_SELINUX_CONTEXT\":\"unconfined\\n\",\"_STREAM_ID\":\"ced9b9bda8a94cc1b455cb74b1ceb1c0\",\"_SYSTEMD_CGROUP\":\"/system.slice/kube-apiserver.service\",\"_SYSTEMD_INVOCATION_ID\":\"cdc2c204b1a6476c86597dfcc406ff06\",\"_SYSTEMD_SLICE\":\"system.slice\",\"_SYSTEMD_UNIT\":\"kube-apiserver.service\",\"_TRANSPORT\":\"stdout\",\"_UID\":\"0\"}"
        ,"observed_timestamp":"2024-05-28T16:58:50.887807787Z"
        ,"source_type":"opentelemetry"
        ,"timestamp":"2024-05-28T16:58:50.505521Z"}"#;

    pub static NGINX: &[u8] = br#"{"attributes":{"filename":"/var/log/nginx/cust1/prd-access.log",
        "host":"lb1.zl.example.com"
        ,"log.file.name":"prd-access.log"
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

    pub static UNKNOWN: &[u8] = br#"{"attributes":{"filename":"/var/log/unknown.log"
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
    fn test_haproxy() {
        let attrs = BytesAttributes::from_payload(samples::HAPROXY).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        // assert_eq!(match_.destination, "bulk_match_haproxy");
        assert_eq!(match_.subject, "bulk.haproxy.wilee.example-dmz-cat4.lb1-dr-example-com");
    }

    #[test]
    fn test_k8s() {
        let attrs = BytesAttributes::from_payload(samples::K8S).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        // assert_eq!(match_.destination, "bulk_match_k8s");
        assert_eq!(match_.subject, "bulk.k8s.acme.starwars.master-sith-starwars");
    }

    #[test]
    fn test_nginx() {
        let attrs = BytesAttributes::from_payload(samples::NGINX).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        // assert_eq!(match_.destination, "bulk_match_nginx");
        assert_eq!(match_.subject, "bulk.nginx.acme.cust1.lb1-zl-example-com");
    }

    #[test]
    fn test_unknown() {
        let attrs = BytesAttributes::from_payload(samples::UNKNOWN).expect("parse error");
        let match_ = Match::from_attributes(&attrs).expect("match error");
        // assert_eq!(match_.destination, "bulk_match_unknown");
        assert_eq!(match_.subject, "bulk.unknown.unknown-tenant.unknown-section.unknown-example-com");
    }
}
