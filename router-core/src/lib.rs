use md5;
use pnet::datalink;
use reqwest::blocking::Client;
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RouterError {
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    #[error("authentication failed")]
    AuthFailed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouterInfo {
    pub name: String,
    pub address: String,
    pub login: String,
    #[serde(default)]
    pub network_ip: Option<String>,
    #[serde(default)]
    pub keendns_urls: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyInfo {
    pub description: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ClientInfo {
    pub name: Option<String>,
    pub ip: Option<String>,
    pub mac: String,
    pub policy: Option<String>,
    pub deny: bool,
    pub raw: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub display_name: String,
    pub mac: String,
    pub ip: String,
    pub iface_type: String,
    pub online: bool,
    pub policy: Option<String>,
    pub deny: bool,
}

pub struct KeeneticRouter {
    base_url: String,
    username: String,
    password: String,
    name: String,
    client: Client,
}

impl KeeneticRouter {
    pub fn new(address: &str, username: &str, password: &str, name: &str) -> Self {
        let mut base = address.trim().to_string();
        if !base.starts_with("http") {
            if base.ends_with('/') {
                base.pop();
            }
            base = format!("http://{}", base);
        }
        let client = Client::builder()
            .cookie_store(true)
            .build()
            .expect("reqwest client");
        Self {
            base_url: base,
            username: username.to_string(),
            password: password.to_string(),
            name: name.to_string(),
            client,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn login(&self) -> Result<(), RouterError> {
        let auth_url = format!("{}/auth", self.base_url);
        let initial = self.client.get(auth_url).send()?;
        if initial.status() == reqwest::StatusCode::UNAUTHORIZED {
            let headers = initial.headers();
            let realm = header_value(headers, "X-NDM-Realm")
                .ok_or_else(|| RouterError::InvalidResponse("missing realm".into()))?;
            let challenge = header_value(headers, "X-NDM-Challenge")
                .ok_or_else(|| RouterError::InvalidResponse("missing challenge".into()))?;
            let md5_hex = format!(
                "{:x}",
                md5::compute(format!("{}:{}:{}", self.username, realm, self.password))
            );
            let sha_hex = hex::encode(Sha256::digest(format!("{}{}", challenge, md5_hex)));
            let auth_data = serde_json::json!({
                "login": self.username,
                "password": sha_hex,
            });
            let auth_response = self
                .client
                .post(format!("{}/auth", self.base_url))
                .json(&auth_data)
                .send()?;
            if auth_response.status().is_success() {
                Ok(())
            } else {
                Err(RouterError::AuthFailed)
            }
        } else if initial.status().is_success() {
            Ok(())
        } else {
            Err(RouterError::InvalidResponse(format!(
                "unexpected auth status: {}",
                initial.status()
            )))
        }
    }

    fn keen_request(&self, endpoint: &str, data: Option<Value>) -> Result<Value, RouterError> {
        let url = format!("{}/{}", self.base_url, endpoint);
        let response = if let Some(payload) = data {
            self.client.post(url).json(&payload).send()?
        } else {
            self.client.get(url).send()?
        };
        if !response.status().is_success() {
            return Err(RouterError::InvalidResponse(format!(
                "status {}",
                response.status()
            )));
        }
        let json = response.json::<Value>()?;
        Ok(json)
    }

    pub fn get_keendns_urls(&self) -> Result<Vec<String>, RouterError> {
        self.login()?;
        let data = self
            .keen_request("rci/ip/http/ssl/acme/list/certificate", None)?;
        let list = data.as_array().cloned().unwrap_or_default();
        Ok(list
            .into_iter()
            .filter_map(|item| item.get("domain").and_then(|v| v.as_str()).map(|s| s.to_string()))
            .collect())
    }

    pub fn get_network_ip(&self) -> Result<Option<String>, RouterError> {
        self.login()?;
        let data = self
            .keen_request("rci/sc/interface/Bridge0/ip/address", None)?;
        Ok(data
            .get("address")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()))
    }

    pub fn get_policies(&self) -> Result<HashMap<String, PolicyInfo>, RouterError> {
        self.login()?;
        let data = self.keen_request("rci/show/rc/ip/policy", None)?;
        let mut out = HashMap::new();
        if let Some(obj) = data.as_object() {
            for (name, info) in obj {
                let description = info
                    .get("description")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                out.insert(name.to_string(), PolicyInfo { description });
            }
        }
        Ok(out)
    }

    pub fn get_online_clients(&self) -> Result<Vec<ClientInfo>, RouterError> {
        self.login()?;
        let data = self
            .keen_request("rci/show/ip/hotspot/host", None)?;
        let list = data.as_array().cloned().unwrap_or_default();
        let mut map: HashMap<String, ClientInfo> = HashMap::new();
        for item in list {
            let mac = item
                .get("mac")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_lowercase();
            if mac.is_empty() {
                continue;
            }
            let entry = map.entry(mac.clone()).or_insert(ClientInfo {
                name: None,
                ip: None,
                mac: mac.clone(),
                policy: None,
                deny: false,
                raw: Value::Null,
            });
            if entry.name.is_none() {
                entry.name = item.get("name").and_then(|v| v.as_str()).map(|s| s.to_string());
            }
            if entry.ip.is_none() {
                entry.ip = item.get("ip").and_then(|v| v.as_str()).map(|s| s.to_string());
            }
            if entry.policy.is_none() {
                entry.policy = item
                    .get("policy")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
            if let Some(deny) = item.get("deny").and_then(|v| v.as_bool()) {
                entry.deny = deny;
            }
            if !item.is_null() {
                entry.raw = item;
            }
        }
        Ok(map.into_values().collect())
    }

    pub fn apply_policy_to_client(
        &self,
        mac: &str,
        policy: Option<&str>,
    ) -> Result<(), RouterError> {
        self.login()?;
        let policy_value = match policy {
            Some(name) => serde_json::Value::String(name.to_string()),
            None => serde_json::Value::Bool(false),
        };
        let payload = serde_json::json!({
            "mac": mac,
            "policy": policy_value,
            "permit": true,
            "schedule": false
        });
        self.keen_request("rci/ip/hotspot/host", Some(payload))?;
        Ok(())
    }

    pub fn apply_default_policy(&self, mac: &str) -> Result<(), RouterError> {
        self.apply_policy_to_client(mac, None)
    }

    pub fn set_client_block(&self, mac: &str) -> Result<(), RouterError> {
        self.login()?;
        let payload = serde_json::json!({
            "mac": mac,
            "schedule": false,
            "deny": true
        });
        self.keen_request("rci/ip/hotspot/host", Some(payload))?;
        Ok(())
    }
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(name).and_then(|v| v.to_str().ok()).map(|s| s.to_string())
}

pub fn interface_type(name: &str) -> String {
    let lname = name.to_lowercase();
    if lname.starts_with("wl") || lname.starts_with("wlan") || lname.starts_with("wifi") {
        return "Wi-Fi".to_string();
    }
    if lname.starts_with("en") || lname.starts_with("eth") {
        return "Ethernet".to_string();
    }
    "Unknown".to_string()
}

pub fn local_interfaces(clients: &[ClientInfo]) -> Vec<InterfaceInfo> {
    let mut out = Vec::new();
    let mut by_mac: HashMap<String, &ClientInfo> = HashMap::new();
    for client in clients {
        by_mac.insert(client.mac.to_lowercase(), client);
    }

    for iface in datalink::interfaces() {
        if iface.is_loopback() {
            continue;
        }
        let mac = match iface.mac {
            Some(mac) => mac.to_string().to_lowercase(),
            None => continue,
        };
        if !by_mac.is_empty() && !by_mac.contains_key(&mac) {
            continue;
        }
        let ip = iface
            .ips
            .iter()
            .find_map(|ip| match ip.ip() {
                IpAddr::V4(v4) => Some(v4.to_string()),
                _ => None,
            })
            .unwrap_or_else(|| "N/A".to_string());
        let name = iface.name.clone();
        let mut display_name = name.clone();
        let iface_type = interface_type(&name);
        let mut policy = None;
        let mut deny = false;
        let mut online = false;
        if let Some(client) = by_mac.get(&mac) {
            if let Some(name) = &client.name {
                display_name = name.clone();
            }
            policy = client.policy.clone();
            deny = client.deny;
            online = client_is_online(client);
        }
        out.push(InterfaceInfo {
            name,
            display_name,
            mac,
            ip,
            iface_type,
            online,
            policy,
            deny,
        });
    }
    out
}

fn client_is_online(client: &ClientInfo) -> bool {
    let link = client.raw.get("link").and_then(|v| v.as_str());
    if link == Some("up") {
        return true;
    }
    let mws = client.raw.get("mws");
    let mws_link = mws
        .and_then(|v| v.get("link"))
        .and_then(|v| v.as_str());
    mws_link == Some("up")
}

pub fn local_networks() -> Vec<ipnetwork::IpNetwork> {
    let mut out = Vec::new();
    for iface in datalink::interfaces() {
        for ip in iface.ips {
            if let ipnetwork::IpNetwork::V4(v4) = ip {
                out.push(ipnetwork::IpNetwork::V4(v4));
            }
        }
    }
    out
}

pub fn ip_in_networks(ip: &str, networks: &[ipnetwork::IpNetwork]) -> bool {
    if let Ok(addr) = ip.parse::<IpAddr>() {
        return networks.iter().any(|net| net.contains(addr));
    }
    false
}

pub fn extract_host(address: &str) -> String {
    let mut value = address.trim().to_string();
    if let Some(pos) = value.find("://") {
        value = value[(pos + 3)..].to_string();
    }
    if let Some(pos) = value.find('/') {
        value = value[..pos].to_string();
    }
    value
}
