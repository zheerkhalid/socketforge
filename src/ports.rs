//! A small, hand-written table of the services usually found on common ports.
//! It names the convention, not what is actually running: the process column
//! is the truth.

use crate::model::Proto;

#[derive(Clone, Copy)]
enum On {
    Tcp,
    Udp,
    Both,
}

use On::{Both, Tcp, Udp};

/// `(port, protocol, short name, what it is)`, sorted by port.
const TABLE: &[(u16, On, &str, &str)] = &[
    (20, Tcp, "ftp-data", "FTP data"),
    (21, Tcp, "ftp", "FTP control"),
    (22, Tcp, "ssh", "SSH remote login"),
    (23, Tcp, "telnet", "Telnet"),
    (25, Tcp, "smtp", "Mail transfer (SMTP)"),
    (53, Both, "dns", "DNS"),
    (67, Udp, "dhcp-server", "DHCP server"),
    (68, Udp, "dhcp-client", "DHCP client"),
    (69, Udp, "tftp", "TFTP"),
    (80, Tcp, "http", "Web server (HTTP)"),
    (88, Both, "kerberos", "Kerberos sign-in"),
    (110, Tcp, "pop3", "Mail (POP3)"),
    (111, Both, "rpcbind", "ONC RPC port mapper"),
    (119, Tcp, "nntp", "Usenet news"),
    (123, Udp, "ntp", "Time sync (NTP)"),
    (135, Tcp, "msrpc", "Windows RPC endpoint mapper"),
    (137, Udp, "netbios-ns", "NetBIOS name service"),
    (138, Udp, "netbios-dgm", "NetBIOS datagrams"),
    (139, Tcp, "netbios-ssn", "NetBIOS session (file sharing)"),
    (143, Tcp, "imap", "Mail (IMAP)"),
    (161, Udp, "snmp", "SNMP"),
    (162, Udp, "snmp-trap", "SNMP traps"),
    (179, Tcp, "bgp", "BGP routing"),
    (389, Both, "ldap", "LDAP directory"),
    (427, Both, "slp", "Service Location Protocol"),
    (443, Tcp, "https", "Web server (HTTPS)"),
    (443, Udp, "quic", "HTTP/3 (QUIC)"),
    (445, Tcp, "smb", "Windows file sharing (SMB)"),
    (464, Both, "kpasswd", "Kerberos password change"),
    (465, Tcp, "smtps", "Mail submission over TLS"),
    (500, Udp, "ike", "IPsec key exchange"),
    (514, Udp, "syslog", "Syslog"),
    (515, Tcp, "lpd", "Line printer daemon"),
    (546, Udp, "dhcpv6-client", "DHCPv6 client"),
    (547, Udp, "dhcpv6-server", "DHCPv6 server"),
    (554, Tcp, "rtsp", "Streaming control (RTSP)"),
    (587, Tcp, "submission", "Mail submission"),
    (593, Tcp, "rpc-http", "RPC over HTTP"),
    (631, Both, "ipp", "Internet printing (IPP)"),
    (636, Tcp, "ldaps", "LDAP over TLS"),
    (853, Tcp, "dns-tls", "DNS over TLS"),
    (873, Tcp, "rsync", "rsync"),
    (993, Tcp, "imaps", "IMAP over TLS"),
    (995, Tcp, "pop3s", "POP3 over TLS"),
    (1080, Tcp, "socks", "SOCKS proxy"),
    (1194, Both, "openvpn", "OpenVPN"),
    (1433, Tcp, "mssql", "Microsoft SQL Server"),
    (1434, Udp, "mssql-browser", "SQL Server Browser"),
    (1521, Tcp, "oracle", "Oracle database listener"),
    (1701, Udp, "l2tp", "L2TP VPN"),
    (1723, Tcp, "pptp", "PPTP VPN"),
    (1883, Tcp, "mqtt", "MQTT broker"),
    (1900, Udp, "ssdp", "Device discovery (SSDP / UPnP)"),
    (2049, Both, "nfs", "NFS file sharing"),
    (2179, Tcp, "vmrdp", "Hyper-V console"),
    (2181, Tcp, "zookeeper", "ZooKeeper"),
    (2375, Tcp, "docker", "Docker API (no TLS)"),
    (2376, Tcp, "docker-tls", "Docker API (TLS)"),
    (2379, Tcp, "etcd", "etcd client"),
    (2380, Tcp, "etcd-peer", "etcd peers"),
    (
        3000,
        Tcp,
        "dev-server",
        "Development web server (Node, Rails, Grafana)",
    ),
    (3001, Tcp, "dev-server", "Development web server"),
    (3268, Tcp, "gc", "Active Directory global catalog"),
    (3306, Tcp, "mysql", "MySQL / MariaDB"),
    (3389, Both, "rdp", "Remote Desktop"),
    (3478, Both, "stun", "STUN / TURN"),
    (3702, Udp, "ws-discovery", "Web Services Discovery"),
    (4200, Tcp, "dev-server", "Development web server (Angular)"),
    (4369, Tcp, "epmd", "Erlang port mapper"),
    (4500, Udp, "ipsec-nat-t", "IPsec NAT traversal"),
    (
        5000,
        Tcp,
        "dev-server",
        "Development web server (Flask, ASP.NET)",
    ),
    (
        5001,
        Tcp,
        "dev-server",
        "Development web server (ASP.NET HTTPS)",
    ),
    (5040, Tcp, "cdpsvc", "Windows connected devices platform"),
    (5050, Udp, "cdp", "Windows connected devices discovery"),
    (5060, Both, "sip", "SIP telephony"),
    (5061, Tcp, "sips", "SIP over TLS"),
    (5173, Tcp, "dev-server", "Development web server (Vite)"),
    (5222, Tcp, "xmpp", "XMPP chat client"),
    (5353, Udp, "mdns", "Multicast DNS (Bonjour)"),
    (5355, Both, "llmnr", "Link-local name resolution"),
    (5357, Tcp, "wsdapi", "Web Services for Devices"),
    (5358, Tcp, "wsdapi-s", "Web Services for Devices (secure)"),
    (5432, Tcp, "postgresql", "PostgreSQL"),
    (
        5500,
        Tcp,
        "dev-server",
        "Development web server (Live Server)",
    ),
    (5601, Tcp, "kibana", "Kibana"),
    (5672, Tcp, "amqp", "AMQP message broker (RabbitMQ)"),
    (5900, Tcp, "vnc", "VNC remote desktop"),
    (5985, Tcp, "winrm", "Windows Remote Management (HTTP)"),
    (5986, Tcp, "winrm-s", "Windows Remote Management (HTTPS)"),
    (6379, Tcp, "redis", "Redis"),
    (6443, Tcp, "kubernetes", "Kubernetes API"),
    (6881, Both, "bittorrent", "BitTorrent"),
    (
        7680,
        Tcp,
        "delivery-opt",
        "Windows Update Delivery Optimization",
    ),
    (
        8000,
        Tcp,
        "dev-server",
        "Development web server (Django, Python)",
    ),
    (8008, Tcp, "http-alt", "Alternative HTTP"),
    (8080, Tcp, "http-alt", "Alternative HTTP / proxy / Tomcat"),
    (8081, Tcp, "http-alt", "Alternative HTTP"),
    (8086, Tcp, "influxdb", "InfluxDB"),
    (8088, Tcp, "http-alt", "Alternative HTTP"),
    (8443, Tcp, "https-alt", "Alternative HTTPS"),
    (8888, Tcp, "dev-server", "Jupyter / alternative HTTP"),
    (
        9000,
        Tcp,
        "dev-server",
        "PHP-FPM / SonarQube / object storage",
    ),
    (9042, Tcp, "cassandra", "Cassandra"),
    (9090, Tcp, "prometheus", "Prometheus / web consoles"),
    (9092, Tcp, "kafka", "Kafka broker"),
    (9100, Tcp, "jetdirect", "Raw printing / node exporter"),
    (9200, Tcp, "elasticsearch", "Elasticsearch HTTP"),
    (9229, Tcp, "node-inspect", "Node.js debugger"),
    (9300, Tcp, "elasticsearch", "Elasticsearch transport"),
    (9418, Tcp, "git", "Git protocol"),
    (10000, Tcp, "webmin", "Webmin / backup agents"),
    (11211, Both, "memcached", "Memcached"),
    (11434, Tcp, "llm-server", "Local language-model server"),
    (15672, Tcp, "rabbitmq-mgmt", "RabbitMQ management"),
    (25565, Tcp, "minecraft", "Minecraft server"),
    (27017, Tcp, "mongodb", "MongoDB"),
    (32400, Tcp, "media-server", "Media server"),
    (51820, Udp, "wireguard", "WireGuard VPN"),
];

fn lookup(port: u16, proto: Proto) -> Option<&'static (u16, On, &'static str, &'static str)> {
    TABLE.iter().find(|(p, on, _, _)| {
        *p == port
            && matches!(
                (on, proto),
                (Both, _) | (Tcp, Proto::Tcp) | (Udp, Proto::Udp)
            )
    })
}

/// The description of what usually lives on this port ("PostgreSQL").
pub fn service_name(port: u16, proto: Proto) -> Option<&'static str> {
    lookup(port, proto).map(|e| e.3)
}

/// The short conventional name ("postgresql").
pub fn short_name(port: u16, proto: Proto) -> Option<&'static str> {
    lookup(port, proto).map(|e| e.2)
}

/// Ports whose services normally speak HTTP, for the "open in browser" action.
pub fn looks_like_http(port: u16) -> bool {
    matches!(short_name(port, Proto::Tcp), Some(n) if n.starts_with("http") || n == "dev-server")
        || (3000..=3999).contains(&port)
        || (8000..=8999).contains(&port)
}

/// `https` for the ports that conventionally use TLS, otherwise `http`.
pub fn url_scheme(port: u16) -> &'static str {
    match port {
        443 | 5001 | 8443 | 5986 | 9443 | 6443 => "https",
        _ => "http",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_sorted_and_lookups_respect_protocol() {
        assert!(TABLE.windows(2).all(|w| w[0].0 <= w[1].0));
        assert_eq!(service_name(5432, Proto::Tcp), Some("PostgreSQL"));
        assert_eq!(service_name(5432, Proto::Udp), None);
        assert_eq!(short_name(53, Proto::Udp), Some("dns"));
        assert_eq!(short_name(53, Proto::Tcp), Some("dns"));
        assert_eq!(short_name(443, Proto::Udp), Some("quic"));
        assert_eq!(short_name(443, Proto::Tcp), Some("https"));
        assert_eq!(service_name(1, Proto::Tcp), None);
        assert!(looks_like_http(3000) && looks_like_http(8080) && !looks_like_http(5432));
        assert_eq!(url_scheme(8443), "https");
        assert_eq!(url_scheme(3000), "http");
    }
}
