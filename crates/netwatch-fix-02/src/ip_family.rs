use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Ip family selection between Ipv4 and Ipv6.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum IpFamily {
    /// Ipv4
    V4,
    /// Ipv6
    V6,
}

impl From<IpAddr> for IpFamily {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(_) => Self::V4,
            IpAddr::V6(_) => Self::V6,
        }
    }
}

impl IpFamily {
    /// Returns the matching default address.
    pub fn unspecified_addr(&self) -> IpAddr {
        match self {
            Self::V4 => Ipv4Addr::UNSPECIFIED.into(),
            Self::V6 => Ipv6Addr::UNSPECIFIED.into(),
        }
    }

    /// Returns the matching localhost address.
    pub fn local_addr(&self) -> IpAddr {
        match self {
            Self::V4 => Ipv4Addr::LOCALHOST.into(),
            Self::V6 => Ipv6Addr::LOCALHOST.into(),
        }
    }
}

impl From<IpFamily> for socket2::Domain {
    fn from(value: IpFamily) -> Self {
        match value {
            IpFamily::V4 => socket2::Domain::IPV4,
            IpFamily::V6 => socket2::Domain::IPV6,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn from_ipv4_addr() {
        let addr: IpAddr = Ipv4Addr::LOCALHOST.into();
        assert_eq!(IpFamily::from(addr), IpFamily::V4);
    }

    #[test]
    fn from_ipv6_addr() {
        let addr: IpAddr = Ipv6Addr::LOCALHOST.into();
        assert_eq!(IpFamily::from(addr), IpFamily::V6);
    }

    #[test]
    fn unspecified_v4() {
        let u = IpFamily::V4.unspecified_addr();
        assert_eq!(u, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn unspecified_v6() {
        let u = IpFamily::V6.unspecified_addr();
        assert_eq!(u, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
    }

    #[test]
    fn local_v4() {
        let l = IpFamily::V4.local_addr();
        assert_eq!(l, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn local_v6() {
        let l = IpFamily::V6.local_addr();
        assert_eq!(l, IpAddr::V6(Ipv6Addr::LOCALHOST));
    }
}
