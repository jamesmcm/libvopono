use anyhow::anyhow;
use ipnet::IpNet;
use log::debug;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;

#[derive(Deserialize, Debug, Serialize, Clone)]
pub struct WireguardInterface {
    #[serde(rename = "PrivateKey")]
    pub private_key: String,
    #[serde(rename = "Address", deserialize_with = "de_vec_ipnet")]
    pub address: Vec<IpNet>,
    #[serde(rename = "DNS", deserialize_with = "de_vec_ipaddr")]
    pub dns: Vec<IpAddr>,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct WireguardPeer {
    #[serde(rename = "PublicKey")]
    pub public_key: String,
    #[serde(rename = "AllowedIPs", deserialize_with = "de_vec_ipnet")]
    pub allowed_ips: Vec<IpNet>,
    #[serde(rename = "Endpoint")]
    pub endpoint: SocketAddr,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct WireguardConfig {
    #[serde(rename = "Interface")]
    pub interface: WireguardInterface,
    #[serde(rename = "Peer")]
    pub peer: WireguardPeer,
}

pub fn de_vec_ipnet<'de, D>(deserializer: D) -> Result<Vec<IpNet>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // serde::de::value::StringDeserializer::deserialize_string(deserializer)?;
    let raw = String::deserialize(deserializer)?;
    let strings = raw.split(',');
    match strings
        .map(|x| x.trim().parse::<IpNet>())
        .collect::<Result<Vec<IpNet>, ipnet::AddrParseError>>()
    {
        Ok(x) => Ok(x),
        Err(x) => Err(serde::de::Error::custom(anyhow!(
            "Wireguard IpNet deserialisation error: {:?}",
            x
        ))),
    }
}

pub fn de_vec_ipaddr<'de, D>(deserializer: D) -> Result<Vec<IpAddr>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    debug!("Deserializing: {} to Vec<IpAddr>", raw);
    let strings = raw.split(',');
    match strings
        .map(|x| x.trim().parse::<IpAddr>())
        .collect::<Result<Vec<IpAddr>, _>>()
    {
        Ok(x) => Ok(x),
        Err(x) => Err(serde::de::Error::custom(anyhow!(
            "Wireguard IpAddr deserialisation error: {:?}",
            x
        ))),
    }
}

pub fn de_socketaddr<'de, D>(deserializer: D) -> Result<std::net::SocketAddr, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    match raw.trim().to_socket_addrs() {
        Ok(mut x) => Ok(x.next().unwrap()),
        Err(x) => Err(serde::de::Error::custom(anyhow!(
            "Wireguard IpAddr deserialisation error: {:?}",
            x
        ))),
    }
}
