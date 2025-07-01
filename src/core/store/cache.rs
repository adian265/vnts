use dashmap::DashMap;
use parking_lot::RwLock;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use std::fs::File;
use std::io::Read; // 确保导入 Read 特性
use serde_json::from_str; // 确保导入 from_str 函数


use crate::cipher::Aes256GcmCipher;
use crate::core::entity::{NetworkInfo, WireGuardConfig};
use crate::core::store::expire_map::ExpireMap;

#[derive(Clone)]
pub struct AppCache {
    // group -> NetworkInfo
    pub virtual_network: ExpireMap<String, Arc<RwLock<NetworkInfo>>>,
    // (group,ip) -> addr  用于客户端过期，只有客户端离线才设置
    pub ip_session: ExpireMap<(String, u32), SocketAddr>,
    // 加密密钥
    pub cipher_session: Arc<DashMap<SocketAddr, Arc<Aes256GcmCipher>>>,
    // web登录状态
    pub auth_map: ExpireMap<String, ()>,
    // wg公钥 -> wg配置
    pub wg_group_map: Arc<DashMap<[u8; 32], WireGuardConfig>>,
}

pub struct VntContext {
    pub link_context: Option<LinkVntContext>,
    pub server_cipher: Option<Aes256GcmCipher>,
    pub link_address: SocketAddr,
}
pub struct LinkVntContext {
    pub network_info: Arc<RwLock<NetworkInfo>>,
    pub group: String,
    pub virtual_ip: u32,
    pub broadcast: Ipv4Addr,
    pub timestamp: i64,
}
impl VntContext {
    pub async fn leave(self, cache: &AppCache) {
        if self.server_cipher.is_some() {
            cache.cipher_session.remove(&self.link_address);
        }
        if let Some(context) = self.link_context {
            if let Some(network_info) = cache.virtual_network.get(&context.group) {
                {
                    let mut guard = network_info.write();
                    if let Some(client_info) = guard.clients.get_mut(&context.virtual_ip) {
                        if client_info.address != self.link_address
                            && client_info.timestamp != context.timestamp
                        {
                            return;
                        }
                        client_info.online = false;
                        client_info.tcp_sender = None;
                        guard.epoch += 1;
                    }
                    drop(guard);
                }
                cache
                    .insert_ip_session((context.group, context.virtual_ip), self.link_address)
                    .await;
            }
        }
    }
}

impl AppCache {
    pub fn new() -> Self {
        let wg_group_map: Arc<DashMap<[u8; 32], WireGuardConfig>> = Default::default();
        // 网段7天未使用则回收
        let virtual_network: ExpireMap<String, Arc<RwLock<NetworkInfo>>> =
            ExpireMap::new(|_k, v: &Arc<RwLock<NetworkInfo>>| {
                let lock = v.read();
                if !lock.clients.is_empty() {
                    // 存在客户端的不过期
                    return Some(Duration::from_secs(7 * 24 * 3600));
                }
                None
            });
        let virtual_network_ = virtual_network.clone();
        // ip一天未使用则回收
        let ip_session: ExpireMap<(String, u32), SocketAddr> = ExpireMap::new(move |key, addr| {
            let (group_id, ip) = &key;
            log::info!(
                "ip_session eviction group_id={},ip={},addr={}",
                group_id,
                Ipv4Addr::from(*ip),
                addr
            );
            if let Some(v) = virtual_network_.get(group_id) {
                let mut lock = v.write();
                if let Some(dev) = lock.clients.get(ip) {
                    if !dev.online && &dev.address == addr {
                        lock.clients.remove(ip);
                        lock.epoch += 1;
                    }
                }
            }
            None
        });

        let auth_map = ExpireMap::new(|_k, _v| None);
        let cache = Self {
            virtual_network,
            ip_session,
            cipher_session: Default::default(),
            auth_map,
            wg_group_map,
        };
    // 读取 "wg.json" 文件并填充 wg_group_map
        match File::open("wg.json") { // 修改文件名为 "wg.json"
            Ok(mut file) => {
                let mut content = String::new();
                if let Err(e) = file.read_to_string(&mut content) {
                    println!("读取文件失败: {}", e);
                    return cache;
                }
                match from_str::<Vec<WGData>>(&content) {
                    Ok(wg_data_list) => {
                        println!("read_wg_config: {:#?}", wg_data_list);
                        for wg_data in wg_data_list {
                            if let Some(public_key_str) = wg_data.config.public_key {
                                if let Ok(public_key_bytes) = general_purpose::STANDARD.decode(&public_key_str) {
                                    if let Ok(public_key) = public_key_bytes.try_into() {
                                        let wireguard_config = WireGuardConfig {
                                            vnts_endpoint: wg_data.config.vnts_endpoint.clone(),
                                            vnts_allowed_ips: wg_data.config.vnts_allowed_ips.clone(),
                                            group_id: wg_data.group_id.clone(),
                                            device_id: wg_data.device_id.clone(),
                                            ip: wg_data.virtual_ip,
                                            prefix: wg_data.config.prefix,
                                            persistent_keepalive: wg_data.config.persistent_keepalive,
                                            secret_key: wg_data.config.secret_key.clone().try_into().unwrap_or_else(|_| [0u8; 32]),
                                            public_key,
                                        };
                                        cache.wg_group_map.insert(public_key, wireguard_config);
                                    } else {
                                        println!("公钥转换失败");
                                    }
                                } else {
                                    println!("公钥解析失败");
                                }
                            } else {
                                println!("公钥为空");
                            }
                        }
                    }
                    Err(e) => {
                        println!("反序列化失败: {}", e);
                    }
                }
            }
            Err(e) => {
                println!("打开文件失败: {}", e);
            }
        }
        cache
    }
}

impl AppCache {
    pub async fn insert_cipher_session(&self, key: SocketAddr, value: Aes256GcmCipher) {
        self.cipher_session.insert(key, Arc::new(value));
    }
    pub async fn insert_ip_session(&self, key: (String, u32), value: SocketAddr) {
        self.ip_session
            .insert(key, value, Duration::from_secs(24 * 3600))
            .await
    }
}
