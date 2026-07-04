use std::{collections::BTreeMap, net::IpAddr, time::Duration};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GuestDnsConfig {
    hosts: Box<[u8]>,
    resolv_conf: Box<[u8]>,
    nsswitch_conf: Box<[u8]>,
}

impl GuestDnsConfig {
    #[must_use]
    pub fn from_guest_file_contents(
        hosts: impl AsRef<[u8]>,
        resolv_conf: impl AsRef<[u8]>,
        nsswitch_conf: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            hosts: hosts.as_ref().into(),
            resolv_conf: resolv_conf.as_ref().into(),
            nsswitch_conf: nsswitch_conf.as_ref().into(),
        }
    }

    #[must_use]
    pub fn hosts(&self) -> &[u8] {
        &self.hosts
    }

    #[must_use]
    pub fn resolv_conf(&self) -> &[u8] {
        &self.resolv_conf
    }

    #[must_use]
    pub fn nsswitch_conf(&self) -> &[u8] {
        &self.nsswitch_conf
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct DnsCacheQuery {
    name: String,
    record_type: DnsRecordType,
}

impl DnsCacheQuery {
    #[must_use]
    pub fn new(name: impl Into<String>, record_type: DnsRecordType) -> Self {
        let mut name = name.into();
        name.make_ascii_lowercase();
        Self { name, record_type }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn record_type(&self) -> DnsRecordType {
        self.record_type
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum DnsRecordType {
    A,
    Aaaa,
}

#[derive(Clone, Debug, Default)]
pub struct DnsCache {
    resolver_config: GuestDnsConfig,
    entries: BTreeMap<DnsCacheQuery, DnsCacheEntry>,
}

impl DnsCache {
    #[must_use]
    pub fn new(resolver_config: GuestDnsConfig) -> Self {
        Self {
            resolver_config,
            entries: BTreeMap::new(),
        }
    }

    #[must_use]
    pub const fn resolver_config(&self) -> &GuestDnsConfig {
        &self.resolver_config
    }

    pub fn update_resolver_config(&mut self, resolver_config: GuestDnsConfig) -> bool {
        if self.resolver_config == resolver_config {
            return false;
        }
        self.resolver_config = resolver_config;
        self.entries.clear();
        true
    }

    pub fn insert_addresses(
        &mut self,
        query: DnsCacheQuery,
        addresses: Vec<IpAddr>,
        ttl: Duration,
        now: Duration,
    ) -> bool {
        if ttl.is_zero() || addresses.is_empty() {
            self.entries.remove(&query);
            return false;
        }

        self.entries.insert(
            query,
            DnsCacheEntry {
                addresses,
                expires_at: now.checked_add(ttl).unwrap_or(Duration::MAX),
            },
        );
        true
    }

    pub fn lookup_addresses(&mut self, query: &DnsCacheQuery, now: Duration) -> Option<&[IpAddr]> {
        if self.entry_expired(query, now) {
            self.entries.remove(query);
            return None;
        }

        self.entries
            .get(query)
            .map(|entry| entry.addresses.as_slice())
    }

    pub fn purge_expired(&mut self, now: Duration) -> usize {
        let original_len = self.entries.len();
        self.entries.retain(|_, entry| !entry.is_expired(now));
        original_len - self.entries.len()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    fn entry_expired(&self, query: &DnsCacheQuery, now: Duration) -> bool {
        self.entries
            .get(query)
            .is_some_and(|entry| entry.is_expired(now))
    }
}

#[derive(Clone, Debug)]
struct DnsCacheEntry {
    addresses: Vec<IpAddr>,
    expires_at: Duration,
}

impl DnsCacheEntry {
    fn is_expired(&self, now: Duration) -> bool {
        now >= self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn config(resolv_conf: &[u8]) -> GuestDnsConfig {
        GuestDnsConfig::from_guest_file_contents(
            b"127.0.0.1 localhost\n",
            resolv_conf,
            b"hosts: files dns\n",
        )
    }

    #[test]
    fn dns_cache_reuses_entry_before_ttl_expires() {
        let mut cache = DnsCache::new(config(b"nameserver 1.1.1.1\n"));
        let query = DnsCacheQuery::new("Example.COM", DnsRecordType::A);
        let addresses = vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))];

        assert!(cache.insert_addresses(
            query.clone(),
            addresses.clone(),
            Duration::from_secs(30),
            Duration::from_secs(10),
        ));

        assert_eq!(
            cache.lookup_addresses(
                &DnsCacheQuery::new("example.com", DnsRecordType::A),
                Duration::from_secs(39),
            ),
            Some(addresses.as_slice())
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn dns_cache_expires_entry_at_ttl_boundary() {
        let mut cache = DnsCache::new(config(b"nameserver 1.1.1.1\n"));
        let query = DnsCacheQuery::new("example.com", DnsRecordType::A);

        assert!(cache.insert_addresses(
            query.clone(),
            vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))],
            Duration::from_secs(5),
            Duration::from_secs(10),
        ));
        assert!(
            cache
                .lookup_addresses(&query, Duration::from_secs(14))
                .is_some()
        );
        assert!(
            cache
                .lookup_addresses(&query, Duration::from_secs(15))
                .is_none()
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn dns_cache_zero_ttl_removes_existing_entry() {
        let mut cache = DnsCache::new(config(b"nameserver 1.1.1.1\n"));
        let query = DnsCacheQuery::new("example.com", DnsRecordType::Aaaa);

        assert!(cache.insert_addresses(
            query.clone(),
            vec![IpAddr::V6(Ipv6Addr::LOCALHOST)],
            Duration::from_secs(30),
            Duration::from_secs(10),
        ));
        assert!(!cache.insert_addresses(
            query.clone(),
            vec![IpAddr::V6(Ipv6Addr::UNSPECIFIED)],
            Duration::ZERO,
            Duration::from_secs(11),
        ));

        assert!(
            cache
                .lookup_addresses(&query, Duration::from_secs(11))
                .is_none()
        );
    }

    #[test]
    fn dns_cache_config_change_invalidates_entries() {
        let mut cache = DnsCache::new(config(b"nameserver 1.1.1.1\n"));
        let query = DnsCacheQuery::new("example.com", DnsRecordType::A);
        let addresses = vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))];

        assert!(cache.insert_addresses(
            query.clone(),
            addresses.clone(),
            Duration::from_secs(30),
            Duration::from_secs(10),
        ));
        assert!(!cache.update_resolver_config(config(b"nameserver 1.1.1.1\n")));
        assert_eq!(
            cache.lookup_addresses(&query, Duration::from_secs(11)),
            Some(addresses.as_slice())
        );

        assert!(cache.update_resolver_config(config(b"nameserver 9.9.9.9\n")));

        assert!(
            cache
                .lookup_addresses(&query, Duration::from_secs(11))
                .is_none()
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn dns_cache_purges_expired_entries_without_touching_live_entries() {
        let mut cache = DnsCache::new(config(b"nameserver 1.1.1.1\n"));
        let live_query = DnsCacheQuery::new("live.example.com", DnsRecordType::A);
        let expired_query = DnsCacheQuery::new("expired.example.com", DnsRecordType::A);
        let address = vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))];

        assert!(cache.insert_addresses(
            live_query.clone(),
            address.clone(),
            Duration::from_secs(60),
            Duration::from_secs(10),
        ));
        assert!(cache.insert_addresses(
            expired_query,
            address.clone(),
            Duration::from_secs(5),
            Duration::from_secs(10),
        ));

        assert_eq!(cache.purge_expired(Duration::from_secs(15)), 1);
        assert_eq!(
            cache.lookup_addresses(&live_query, Duration::from_secs(15)),
            Some(address.as_slice())
        );
        assert_eq!(cache.len(), 1);
    }
}
