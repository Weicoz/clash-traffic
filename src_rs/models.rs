//! Data models for Clash connections and accounting.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClashSnapshot {
    pub connections: Option<Vec<ClashConnection>>,
    #[serde(rename = "uploadTotal", default)]
    pub upload_total: u64,
    #[serde(rename = "downloadTotal", default)]
    pub download_total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClashConnection {
    pub id: String,
    #[serde(default)]
    pub upload: u64,
    #[serde(default)]
    pub download: u64,
    pub start: Option<String>,
    pub metadata: Option<ClashMetadata>,
    pub chains: Option<Vec<String>>,
    pub rule: Option<String>,
    #[serde(rename = "rulePayload")]
    pub rule_payload: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClashMetadata {
    pub host: Option<String>,
    #[serde(rename = "sniffHost")]
    pub sniff_host: Option<String>,
    #[serde(rename = "destinationIP")]
    pub destination_ip: Option<String>,
    #[serde(rename = "destinationPort")]
    pub destination_port: Option<String>,
    pub network: Option<String>,
    #[serde(rename = "type")]
    pub conn_type: Option<String>,
    pub process: Option<String>,
    #[serde(rename = "processPath")]
    pub process_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupRow {
    pub domain: String,
    pub rule: String,
    pub chain: String,
    pub protocol: String,
    pub up: i64,
    pub down: i64,
    pub total: i64,
    pub first_seen: f64,
    pub last_seen: f64,
    pub duration_sec: f64,
}
