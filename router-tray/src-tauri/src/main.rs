#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use anyhow::Result;
use directories::ProjectDirs;
use keyring::Entry;
use router_core::{
    extract_host, ip_in_networks, local_interfaces, local_networks, InterfaceInfo, KeeneticRouter,
    PolicyInfo, RouterInfo,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{
    CustomMenuItem, Manager, SystemTray, SystemTrayEvent, SystemTrayMenu,
    SystemTrayMenuItem, SystemTraySubmenu,
};

#[derive(Clone, Debug, Serialize)]
struct ActiveState {
    router: RouterInfo,
    interfaces: Vec<InterfaceInfo>,
    policies: HashMap<String, PolicyInfo>,
    active_iface: Option<InterfaceInfo>,
    active_address: String,
}

#[derive(Clone, Debug)]
struct PolicyOverride {
    policy: Option<String>,
    deny: bool,
}

#[derive(Default)]
struct AppState {
    routers: Mutex<Vec<RouterInfo>>,
    policy_overrides: Mutex<HashMap<String, PolicyOverride>>,
}

#[derive(Debug, Deserialize)]
struct SaveRouterPayload {
    name: String,
    address: String,
    login: String,
    password: String,
    original_name: Option<String>,
}

fn config_path() -> PathBuf {
    let dir = ProjectDirs::from("ru", "toxblh", "KeeneticTray")
        .map(|d| d.config_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    if let Err(err) = fs::create_dir_all(&dir) {
        eprintln!("Failed to create config dir: {err}");
    }
    dir.join("routers.json")
}

fn load_routers() -> Vec<RouterInfo> {
    let path = config_path();
    let data = fs::read_to_string(path).unwrap_or_default();
    serde_json::from_str(&data).unwrap_or_default()
}

fn save_routers(routers: &[RouterInfo]) -> Result<()> {
    let path = config_path();
    let data = serde_json::to_string_pretty(routers)?;
    fs::write(path, data)?;
    Ok(())
}

fn get_password(name: &str) -> Option<String> {
    let entry = Entry::new("router_manager", name).ok()?;
    entry.get_password().ok()
}

fn set_password(name: &str, password: &str) -> Result<()> {
    let entry = Entry::new("router_manager", name)?;
    entry.set_password(password)?;
    Ok(())
}

fn delete_password(name: &str) {
    if let Ok(entry) = Entry::new("router_manager", name) {
        let _ = entry.delete_password();
    }
}

fn policy_label(policy: Option<&str>, deny: bool, policies: &HashMap<String, PolicyInfo>) -> String {
    if deny {
        return "Blocked".to_string();
    }
    if policy.is_none() {
        return "Default".to_string();
    }
    let key = policy.unwrap_or_default();
    if let Some(info) = policies.get(key) {
        if let Some(desc) = &info.description {
            return desc.clone();
        }
    }
    key.to_string()
}

fn policy_short(label: &str) -> String {
    label.chars().take(3).collect::<String>()
}

fn encode_mac(mac: &str) -> String {
    mac.replace(':', "")
}

fn decode_mac(value: &str) -> String {
    let cleaned = value.replace(':', "");
    let mut out = String::new();
    for (i, ch) in cleaned.chars().enumerate() {
        if i > 0 && i % 2 == 0 {
            out.push(':');
        }
        out.push(ch);
    }
    out
}

fn build_active_state(routers: &[RouterInfo]) -> Result<Option<ActiveState>> {
    if routers.is_empty() {
        return Ok(None);
    }
    let networks = local_networks();
    let mut candidates: Vec<(RouterInfo, String)> = Vec::new();

    for router in routers.iter().cloned() {
        if let Some(ip) = router.network_ip.clone() {
            if ip_in_networks(&ip, &networks) {
                candidates.push((router, ip));
                continue;
            }
        }
        let host = extract_host(&router.address);
        if !host.is_empty() && ip_in_networks(&host, &networks) {
            let addr = router.address.clone();
            candidates.push((router, addr));
        }
    }

    for (router, addr) in candidates {
        let password = match get_password(&router.name) {
            Some(p) => p,
            None => continue,
        };
        let client = KeeneticRouter::new(&addr, &router.login, &password, &router.name);
        if client.login().is_err() {
            continue;
        }
        let policies = client.get_policies()?;
        let clients = client.get_online_clients()?;
        let interfaces = local_interfaces(&clients);
        let mut active_iface = None;
        for iface in &interfaces {
            if iface.online {
                active_iface = Some(iface.clone());
                break;
            }
        }
        if active_iface.is_none() {
            active_iface = interfaces.get(0).cloned();
        }
        return Ok(Some(ActiveState {
            router,
            interfaces,
            policies,
            active_iface,
            active_address: addr,
        }));
    }

    Ok(None)
}

fn info_item(id: &str, title: &str) -> CustomMenuItem {
    CustomMenuItem::new(id, title).disabled()
}

fn append_interface_section(
    mut menu: SystemTrayMenu,
    iface: &InterfaceInfo,
    policies: &HashMap<String, PolicyInfo>,
    prefix: &str,
    with_header: bool,
) -> SystemTrayMenu {
    if with_header {
        menu = menu.add_item(info_item(
            &format!("{prefix}:header"),
            &iface.display_name,
        ));
    }
    menu = menu.add_item(info_item(
        &format!("{prefix}:iface"),
        &format!("Interface: {}", iface.name),
    ));
    menu = menu.add_item(info_item(
        &format!("{prefix}:ip"),
        &format!("IP: {}", iface.ip),
    ));
    menu = menu.add_item(info_item(
        &format!("{prefix}:mac"),
        &format!("MAC: {}", iface.mac),
    ));
    menu = menu.add_item(info_item(
        &format!("{prefix}:type"),
        &format!("Type: {}", iface.iface_type),
    ));
    let state = if iface.online { "Online" } else { "Offline" };
    menu = menu.add_item(info_item(
        &format!("{prefix}:state"),
        &format!("State: {}", state),
    ));
    menu = menu.add_native_item(SystemTrayMenuItem::Separator);

    let current_label = policy_label(iface.policy.as_deref(), iface.deny, policies);
    let mac_encoded = encode_mac(&iface.mac);
    let default_label = if current_label == "Default" {
        "• Default".to_string()
    } else {
        "Default".to_string()
    };
    let blocked_label = if current_label == "Blocked" {
        "• Blocked".to_string()
    } else {
        "Blocked".to_string()
    };

    menu = menu.add_item(CustomMenuItem::new(
        format!("policy|{}|default", mac_encoded),
        default_label,
    ));
    menu = menu.add_item(CustomMenuItem::new(
        format!("policy|{}|blocked", mac_encoded),
        blocked_label,
    ));

    for (name, info) in policies {
        let label = info
            .description
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or(name);
        let title = if label == current_label {
            format!("• {}", label)
        } else {
            label.to_string()
        };
        menu = menu.add_item(CustomMenuItem::new(
            format!("policy|{}|set|{}", mac_encoded, name),
            title,
        ));
    }

    menu
}

fn build_tray_menu(state: Option<&ActiveState>, has_routers: bool) -> SystemTrayMenu {
    let mut menu = SystemTrayMenu::new();
    if !has_routers {
        menu = menu.add_item(info_item("info:no_routers", "No routers configured."));
        menu = menu.add_native_item(SystemTrayMenuItem::Separator);
        menu = menu.add_item(CustomMenuItem::new("add_router", "Add Router..."));
        menu = menu.add_item(CustomMenuItem::new("quit", "Quit"));
        return menu;
    }

    let Some(active) = state else {
        menu = menu.add_item(info_item(
            "info:none",
            "No available routers in the current network.",
        ));
        menu = menu.add_native_item(SystemTrayMenuItem::Separator);
        menu = menu.add_item(CustomMenuItem::new("add_router", "Add Router..."));
        menu = menu.add_item(CustomMenuItem::new("settings", "Settings..."));
        menu = menu.add_item(CustomMenuItem::new("refresh", "Refresh"));
        menu = menu.add_item(CustomMenuItem::new("quit", "Quit"));
        return menu;
    };

    if let Some(active_iface) = &active.active_iface {
        let prefix = format!("iface{}", encode_mac(&active_iface.mac));
        menu = append_interface_section(
            menu,
            active_iface,
            &active.policies,
            &prefix,
            true,
        );
        menu = menu.add_native_item(SystemTrayMenuItem::Separator);
    }

    for iface in &active.interfaces {
        if let Some(active_iface) = &active.active_iface {
            if iface.mac == active_iface.mac {
                continue;
            }
        }
        let prefix = format!("iface{}", encode_mac(&iface.mac));
        let sub = append_interface_section(
            SystemTrayMenu::new(),
            iface,
            &active.policies,
            &prefix,
            false,
        );
        menu = menu.add_submenu(SystemTraySubmenu::new(
            iface.display_name.clone(),
            sub,
        ));
    }

    menu = menu.add_native_item(SystemTrayMenuItem::Separator);
    menu = menu.add_item(info_item(
        "router:name",
        &format!("Router: {}", active.router.name),
    ));
    menu = menu.add_native_item(SystemTrayMenuItem::Separator);
    menu = menu.add_item(CustomMenuItem::new("settings", "Settings..."));
    menu = menu.add_item(CustomMenuItem::new("refresh", "Refresh"));
    menu = menu.add_item(CustomMenuItem::new("quit", "Quit"));
    menu
}

fn apply_policy(
    mac: &str,
    policy: Option<&str>,
    blocked: bool,
    router: &RouterInfo,
    address: &str,
) -> Result<()> {
    let password = get_password(&router.name).ok_or_else(|| anyhow::anyhow!("no password"))?;
    let client = KeeneticRouter::new(address, &router.login, &password, &router.name);
    if blocked {
        client.set_client_block(mac)?;
    } else if let Some(name) = policy {
        client.apply_policy_to_client(mac, Some(name))?;
    } else {
        client.apply_default_policy(mac)?;
    }
    Ok(())
}

fn refresh_tray(app: &tauri::AppHandle, state: &Arc<AppState>) {
    let routers = state.routers.lock().unwrap().clone();
    let mut active = build_active_state(&routers).ok().flatten();
    if let Some(active_state) = active.as_mut() {
        let mut overrides = state.policy_overrides.lock().unwrap();
        for iface in &mut active_state.interfaces {
            let current_policy = iface.policy.clone();
            let current_deny = iface.deny;
            if let Some(override_policy) = overrides.get(&iface.mac).cloned() {
                if current_policy == override_policy.policy && current_deny == override_policy.deny
                {
                    overrides.remove(&iface.mac);
                } else {
                    iface.policy = override_policy.policy;
                    iface.deny = override_policy.deny;
                }
            }
        }
        if let Some(active_iface) = active_state.active_iface.as_mut() {
            if let Some(override_policy) = overrides.get(&active_iface.mac).cloned() {
                active_iface.policy = override_policy.policy;
                active_iface.deny = override_policy.deny;
            }
        }
    }
    let menu = build_tray_menu(active.as_ref(), !routers.is_empty());

    let tray = app.tray_handle();
    let _ = tray.set_menu(menu);

    if let Some(active) = &active {
        if let Some(iface) = &active.active_iface {
            let label = policy_label(iface.policy.as_deref(), iface.deny, &active.policies);
            let short = policy_short(&label);
            let tooltip = format!("Keenetic Tray - {}", short);
            let _ = tray.set_tooltip(&tooltip);
            #[cfg(target_os = "macos")]
            {
                let _ = tray.set_title(&short);
            }
        } else {
            let _ = tray.set_tooltip("Keenetic Tray");
            #[cfg(target_os = "macos")]
            {
                let _ = tray.set_title("");
            }
        }
    } else {
        let _ = tray.set_tooltip("Keenetic Tray");
        #[cfg(target_os = "macos")]
        {
            let _ = tray.set_title("");
        }
    }
}

fn open_settings_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_window("settings") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

#[tauri::command]
fn list_routers(state: tauri::State<Arc<AppState>>) -> Vec<RouterInfo> {
    state.routers.lock().unwrap().clone()
}

#[tauri::command]
fn save_router(
    payload: SaveRouterPayload,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let SaveRouterPayload {
        name,
        address,
        login,
        password,
        original_name,
    } = payload;
    let address = address.trim_end_matches('/').to_string();

    let mut routers = state.routers.lock().unwrap();
    if let Some(original) = original_name.as_ref() {
        if original != &name && routers.iter().any(|r| r.name == name) {
            return Err("Router with this name already exists".into());
        }
    } else if routers.iter().any(|r| r.name == name) {
        return Err("Router with this name already exists".into());
    }

    let client = KeeneticRouter::new(&address, &login, &password, &name);
    if client.login().is_err() {
        return Err("Authentication failed".into());
    }
    let network_ip = client.get_network_ip().ok().flatten();
    let keendns_urls = client.get_keendns_urls().ok();

    let router_info = RouterInfo {
        name: name.clone(),
        address,
        login,
        network_ip,
        keendns_urls,
    };

    if let Some(original) = original_name {
        if let Some(pos) = routers.iter().position(|r| r.name == original) {
            routers.remove(pos);
        }
        delete_password(&original);
    }

    set_password(&name, &password).map_err(|e| e.to_string())?;
    routers.push(router_info.clone());

    save_routers(&routers).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn delete_router(name: String, state: tauri::State<Arc<AppState>>) -> Result<(), String> {
    let mut routers = state.routers.lock().unwrap();
    routers.retain(|r| r.name != name);
    delete_password(&name);
    save_routers(&routers).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn refresh_tray_cmd(app: tauri::AppHandle, state: tauri::State<Arc<AppState>>) {
    refresh_tray(&app, &state);
}

fn schedule_refresh_after(app: tauri::AppHandle, state: Arc<AppState>, delay: Duration) {
    std::thread::spawn(move || {
        std::thread::sleep(delay);
        refresh_tray(&app, &state);
    });
}

fn main() {
    let app_state = Arc::new(AppState::default());
    {
        let mut routers = app_state.routers.lock().unwrap();
        *routers = load_routers();
    }

    let state_handle = app_state.clone();

    let tray = SystemTray::new();

    tauri::Builder::default()
        .manage(app_state)
        .system_tray(tray)
        .on_system_tray_event(move |app, event| match event {
            SystemTrayEvent::MenuItemClick { id, .. } => {
                let id = id.as_str();
                if id == "quit" {
                    app.exit(0);
                } else if id == "settings" || id == "add_router" {
                    open_settings_window(app);
                } else if id == "refresh" {
                    if let Some(state) = app.try_state::<Arc<AppState>>() {
                        refresh_tray(app, &state);
                    }
                } else if id.starts_with("policy|") {
                    let rest = &id["policy|".len()..];
                    let parts: Vec<&str> = rest.split('|').collect();
                    if parts.len() >= 2 {
                        let mac = decode_mac(parts[0]);
                        let action = parts[1];
                        if let Some(state) = app.try_state::<Arc<AppState>>() {
                            let routers = state.routers.lock().unwrap().clone();
                            if let Ok(Some(active)) = build_active_state(&routers) {
                                let result = match action {
                                    "default" => apply_policy(
                                        &mac,
                                        None,
                                        false,
                                        &active.router,
                                        &active.active_address,
                                    ),
                                    "blocked" => apply_policy(
                                        &mac,
                                        None,
                                        true,
                                        &active.router,
                                        &active.active_address,
                                    ),
                                    "set" => {
                                        let policy = match parts.get(2) {
                                            Some(value) => Some(*value),
                                            None => None,
                                        };
                                        if policy.is_none() {
                                            Err(anyhow::anyhow!("missing policy"))
                                        } else {
                                            apply_policy(
                                                &mac,
                                                policy,
                                                false,
                                                &active.router,
                                                &active.active_address,
                                            )
                                        }
                                    }
                                    _ => Ok(()),
                                };
                                if result.is_err() {
                                    eprintln!("Failed to apply policy");
                                } else if let Some(state) = app.try_state::<Arc<AppState>>() {
                                    let override_policy = match action {
                                        "default" => Some(PolicyOverride {
                                            policy: None,
                                            deny: false,
                                        }),
                                        "blocked" => Some(PolicyOverride {
                                            policy: None,
                                            deny: true,
                                        }),
                                        "set" => parts.get(2).map(|value| PolicyOverride {
                                            policy: Some((*value).to_string()),
                                            deny: false,
                                        }),
                                        _ => None,
                                    };
                                    if let Some(override_policy) = override_policy {
                                        let mut overrides =
                                            state.policy_overrides.lock().unwrap();
                                        overrides.insert(mac.clone(), override_policy);
                                    }
                                }
                                refresh_tray(app, &state);
                            }
                        }
                    }
                }
            }
            SystemTrayEvent::LeftClick { .. }
            | SystemTrayEvent::RightClick { .. }
            | SystemTrayEvent::DoubleClick { .. } => {
                if let Some(state) = app.try_state::<Arc<AppState>>() {
                    refresh_tray(app, &state);
                    schedule_refresh_after(
                        app.clone(),
                        state.inner().clone(),
                        Duration::from_secs(5),
                    );
                }
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            list_routers,
            save_router,
            delete_router,
            refresh_tray_cmd
        ])
        .setup(move |app| {
            refresh_tray(&app.handle(), &state_handle);
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
