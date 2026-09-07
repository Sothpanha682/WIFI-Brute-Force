// WifiBF GUI — WiFi WPA2 Brute Force Tool  (Rust / egui)
// Requires Windows + a WLAN adapter + Administrator privileges.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![cfg(windows)]

mod wifi;

use eframe::egui::{self, Align2, Color32, FontId, Pos2, RichText, Sense, Stroke, Vec2};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

// ── Shared state (GUI thread ↔ worker threads) ─────────────────────────────
pub struct SharedState {
    pub log:          Vec<String>,
    pub running:      bool,
    pub result:       Option<String>,          // Some(pw) = cracked, "__FAIL__" = exhausted
    pub networks:     Vec<wifi::NetworkEntry>, // result of last scan
    pub scanning:     bool,
    pub stop_flag:    Arc<AtomicBool>,         // set to true to abort the attack
}

// ── Application ────────────────────────────────────────────────────────────
struct App {
    ssid:     String,
    wordlist: String,
    state:    Arc<Mutex<SharedState>>,
}

impl App {
    fn new(cc: &eframe::CreationContext) -> Self {
        // Dark blue-grey theme
        let mut style = (*cc.egui_ctx.style()).clone();
        style.visuals = egui::Visuals::dark();
        style.visuals.panel_fill  = Color32::from_rgb(12, 13, 20);
        style.visuals.window_fill = Color32::from_rgb(12, 13, 20);
        cc.egui_ctx.set_style(style);

        Self {
            ssid:     String::new(),
            wordlist: String::new(),
            state: Arc::new(Mutex::new(SharedState {
                log:       Vec::new(),
                running:   false,
                result:    None,
                networks:  Vec::new(),
                scanning:  false,
                stop_flag: Arc::new(AtomicBool::new(false)),
            })),
        }
    }

    // ── Background: WiFi scan ─────────────────────────────────────────────
    fn start_scan(&self) {
        {
            let mut s = self.state.lock().unwrap();
            s.scanning = true;
            s.networks.clear();
        }
        let state = Arc::clone(&self.state);
        std::thread::spawn(move || {
            match wifi::scan_networks() {
                Ok(nets) => {
                    let mut s = state.lock().unwrap();
                    s.networks = nets;
                    s.scanning = false;
                }
                Err(e) => {
                    let mut s = state.lock().unwrap();
                    s.log.push(format!("! Scan error: {e}"));
                    s.scanning = false;
                }
            }
        });
    }

    // ── Background: brute-force attack ─────────────────────────────────────────
    fn start_crack(&self, ssid: String, wordlist: String) {
        let stop_flag = {
            let mut s = self.state.lock().unwrap();
            s.log.clear();
            s.running = true;
            s.result  = None;
            s.stop_flag.store(false, Ordering::Relaxed); // reset before launch
            s.log.push(format!("▶  Attacking \"{}\" ...", ssid));
            Arc::clone(&s.stop_flag)
        };
        let state = Arc::clone(&self.state);
        std::thread::spawn(move || {
            match wifi::try_crack(&ssid, &wordlist, Arc::clone(&state), stop_flag) {
                Ok(Some(pw)) => {
                    let mut s = state.lock().unwrap();
                    s.log.push(format!("✔  Password found: {}", pw));
                    s.result  = Some(pw);
                    s.running = false;
                }
                Ok(None) => {
                    let mut s = state.lock().unwrap();
                    // distinguish stopped vs exhausted
                    let stopped = s.stop_flag.load(Ordering::Relaxed);
                    if !stopped {
                        s.log.push("✘  Wordlist exhausted — password not found.".into());
                        s.result = Some("__FAIL__".into());
                    } else {
                        s.result = Some("__STOPPED__".into());
                    }
                    s.running = false;
                }
                Err(e) => {
                    let mut s = state.lock().unwrap();
                    s.log.push(format!("!  Error: {e}"));
                    s.result  = Some("__FAIL__".into());
                    s.running = false;
                }
            }
        });
    }

    // ── Stop a running attack ─────────────────────────────────────────────────────────
    fn stop_attack(&self) {
        let s = self.state.lock().unwrap();
        s.stop_flag.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

// ── Signal quality helpers ─────────────────────────────────────────────────
fn signal_bars(q: u32) -> &'static str {
    match q {
        80..=100 => "[====]",
        60..=79  => "[=== ]",
        40..=59  => "[==  ]",
        20..=39  => "[=   ]",
        _        => "[    ]",
    }
}

fn signal_color(q: u32) -> Color32 {
    if q >= 70      { Color32::from_rgb(75,  210,  95) }
    else if q >= 40 { Color32::from_rgb(255, 195,  55) }
    else            { Color32::from_rgb(220,  85,  60) }
}

// ── Card helper ────────────────────────────────────────────────────────────
fn card(ui: &mut egui::Ui, body: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(Color32::from_rgb(18, 20, 32))
        .corner_radius(10.0)
        .stroke(Stroke::new(1.0, Color32::from_rgb(40, 46, 66)))
        .inner_margin(egui::Margin::same(14))
        .show(ui, body);
}

// ── Section label ──────────────────────────────────────────────────────────
fn section_label(ui: &mut egui::Ui, text: &str) {
    ui.label(
        RichText::new(text)
            .font(FontId::proportional(13.0))
            .color(Color32::from_rgb(85, 180, 255))
            .strong(),
    );
}

// ── GUI ────────────────────────────────────────────────────────────────────
impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let (running, scanning) = {
            let s = self.state.lock().unwrap();
            (s.running, s.scanning)
        };
        // Keep the UI refreshing while background work is active
        if running || scanning {
            ctx.request_repaint_after(std::time::Duration::from_millis(150));
        }

        // ══════════════════════ BANNER ════════════════════════════════════
        egui::TopBottomPanel::top("banner").exact_height(62.0).show(ctx, |ui| {
            ui.add_space(9.0);
            ui.horizontal(|ui| {
                ui.add_space(16.0);
                ui.label(
                    RichText::new("WifiBF")
                        .font(FontId::proportional(27.0))
                        .color(Color32::from_rgb(85, 180, 255))
                        .strong(),
                );
                ui.add_space(10.0);
                ui.label(
                    RichText::new("WiFi WPA2 Brute Force Tool")
                        .font(FontId::proportional(12.0))
                        .color(Color32::from_rgb(100, 112, 145)),
                );
            });
            ui.add_space(4.0);
            ui.separator();
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(10.0);

            // ══════════════ 1. NETWORK SCANNER ═══════════════════════════
            card(ui, |ui| {
                // ── Header ────────────────────────────────────────────────
                ui.horizontal(|ui| {
                    section_label(ui, "Network Scanner");
                    ui.add_space(8.0);

                    // Scan / Scanning button
                    let lbl  = if scanning { "Scanning..." } else { "  Scan  " };
                    let fill = if scanning {
                        Color32::from_rgb(36, 42, 60)
                    } else {
                        Color32::from_rgb(26, 92, 172)
                    };
                    if ui
                        .add_enabled(
                            !scanning && !running,
                            egui::Button::new(
                                RichText::new(lbl)
                                    .font(FontId::proportional(12.5))
                                    .color(Color32::WHITE),
                            )
                            .fill(fill)
                            .min_size(Vec2::new(86.0, 24.0)),
                        )
                        .clicked()
                    {
                        self.start_scan();
                    }

                    // Network count badge
                    let n = self.state.lock().unwrap().networks.len();
                    if n > 0 {
                        ui.add_space(6.0);
                        ui.label(
                            RichText::new(format!("{n} network(s) found"))
                                .color(Color32::from_rgb(88, 100, 135))
                                .font(FontId::proportional(11.0)),
                        );
                    }
                });

                ui.add_space(8.0);

                // ── Network rows ──────────────────────────────────────────
                let networks: Vec<wifi::NetworkEntry> =
                    self.state.lock().unwrap().networks.clone();

                egui::ScrollArea::vertical()
                    .id_salt("net_list")
                    .max_height(192.0)
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());

                        // --- Scanning placeholder ---
                        if scanning {
                            ui.add_space(22.0);
                            ui.vertical_centered(|ui| {
                                ui.label(
                                    RichText::new("Scanning, please wait ...")
                                        .color(Color32::from_rgb(88, 100, 135))
                                        .font(FontId::proportional(12.5)),
                                );
                            });
                            return;
                        }

                        // --- Empty placeholder ---
                        if networks.is_empty() {
                            ui.add_space(22.0);
                            ui.vertical_centered(|ui| {
                                ui.label(
                                    RichText::new(
                                        "Click  \"Scan\"  to discover nearby WiFi networks",
                                    )
                                    .color(Color32::from_rgb(65, 75, 105))
                                    .font(FontId::proportional(12.0)),
                                );
                            });
                            return;
                        }

                        // --- Clickable network rows ---
                        let mut new_ssid: Option<String> = None;

                        for entry in networks.iter() {
                            let is_sel = self.ssid == entry.ssid;
                            let avail_w = ui.available_width();

                            let (rect, response) = ui.allocate_exact_size(
                                Vec2::new(avail_w, 40.0),
                                Sense::click(),
                            );

                            if ui.is_rect_visible(rect) {
                                // Background + border
                                let bg = if is_sel {
                                    Color32::from_rgb(18, 46, 80)
                                } else if response.hovered() {
                                    Color32::from_rgb(24, 28, 44)
                                } else {
                                    Color32::from_rgb(14, 16, 26)
                                };
                                let border = if is_sel {
                                    Stroke::new(1.5, Color32::from_rgb(46, 125, 215))
                                } else {
                                    Stroke::new(1.0, Color32::from_rgb(34, 38, 56))
                                };
                                let p  = ui.painter();
                                let cy = rect.center().y;
                                p.rect(rect, 6.0, bg, border, egui::StrokeKind::Middle);

                                // Signal bars (left)
                                p.text(
                                    Pos2::new(rect.left() + 8.0, cy),
                                    Align2::LEFT_CENTER,
                                    signal_bars(entry.signal),
                                    FontId::monospace(10.0),
                                    signal_color(entry.signal),
                                );

                                // SSID name
                                p.text(
                                    Pos2::new(rect.left() + 64.0, cy),
                                    Align2::LEFT_CENTER,
                                    &entry.ssid,
                                    FontId::proportional(13.0),
                                    if is_sel {
                                        Color32::from_rgb(115, 192, 255)
                                    } else {
                                        Color32::WHITE
                                    },
                                );

                                // Right side: quality% | band | WPA2/OPEN | ACTIVE
                                let rx = rect.right() - 8.0;
                                p.text(
                                    Pos2::new(rx, cy),
                                    Align2::RIGHT_CENTER,
                                    format!("{}%", entry.signal),
                                    FontId::monospace(10.0),
                                    signal_color(entry.signal),
                                );

                                // Band badge
                                let band_x = rx - 44.0;
                                let (band_label, band_color) = match entry.band {
                                    wifi::Band::GHz5    => ("5G",   Color32::from_rgb(90, 195, 255)),
                                    wifi::Band::GHz2_4  => ("2.4G", Color32::from_rgb(180, 140, 255)),
                                    wifi::Band::Unknown => ("-",    Color32::from_rgb(80, 85, 110)),
                                };
                                p.text(
                                    Pos2::new(band_x, cy),
                                    Align2::RIGHT_CENTER,
                                    band_label,
                                    FontId::monospace(9.0),
                                    band_color,
                                );

                                let sec_x = band_x - 48.0;
                                let (sec_label, sec_color) = if entry.secured {
                                    ("WPA2", Color32::from_rgb(255, 185, 50))
                                } else {
                                    ("OPEN", Color32::from_rgb(85, 200, 105))
                                };
                                p.text(
                                    Pos2::new(sec_x, cy),
                                    Align2::RIGHT_CENTER,
                                    sec_label,
                                    FontId::monospace(9.0),
                                    sec_color,
                                );

                                if entry.connected {
                                    p.text(
                                        Pos2::new(sec_x - 52.0, cy),
                                        Align2::RIGHT_CENTER,
                                        "ACTIVE",
                                        FontId::monospace(9.0),
                                        Color32::from_rgb(65, 205, 85),
                                    );
                                }
                            }

                            // Click → populate SSID field
                            if response.clicked() {
                                new_ssid = Some(entry.ssid.clone());
                            }
                            ui.add_space(2.0);
                        }

                        if let Some(s) = new_ssid {
                            self.ssid = s;
                        }
                    });
            }); // end Network Scanner card

            ui.add_space(10.0);

            // ══════════════ 2. ATTACK CONFIGURATION ══════════════════════
            card(ui, |ui| {
                section_label(ui, "Attack Configuration");
                ui.add_space(8.0);

                // Target SSID (auto-filled by clicking a network row)
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Target SSID ")
                            .color(Color32::from_rgb(145, 158, 195))
                            .font(FontId::proportional(12.5)),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.ssid)
                            .hint_text("Select from scan list above, or type manually")
                            .desired_width(f32::INFINITY),
                    );
                });

                ui.add_space(8.0);

                // Wordlist file
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Wordlist     ")
                            .color(Color32::from_rgb(145, 158, 195))
                            .font(FontId::proportional(12.5)),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.wordlist)
                            .hint_text("Password list (.txt)")
                            .desired_width(ui.available_width() - 84.0),
                    );
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("Browse...").color(Color32::WHITE),
                            )
                            .fill(Color32::from_rgb(30, 34, 52))
                            .min_size(Vec2::new(80.0, 24.0)),
                        )
                        .clicked()
                    {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("Text", &["txt"])
                            .pick_file()
                        {
                            self.wordlist = path.to_string_lossy().into_owned();
                        }
                    }
                });
            }); // end Attack Configuration card

            ui.add_space(10.0);

            // ══════════════ 3. ACTION BUTTONS ════════════════════════════
            ui.horizontal(|ui| {
                let can_start =
                    !running && !self.ssid.is_empty() && !self.wordlist.is_empty();

                // Start Attack
                if ui
                    .add_enabled(
                        can_start,
                        egui::Button::new(
                            RichText::new(if running { "Running..." } else { "▶  Start Attack" })
                                .font(FontId::proportional(14.0))
                                .color(Color32::WHITE),
                        )
                        .fill(if can_start {
                            Color32::from_rgb(26, 98, 188)
                        } else {
                            Color32::from_rgb(30, 34, 52)
                        })
                        .min_size(Vec2::new(150.0, 34.0)),
                    )
                    .clicked()
                {
                    self.start_crack(self.ssid.clone(), self.wordlist.clone());
                }

                ui.add_space(8.0);

                // ⏹ Stop Attack — only visible while running
                if running {
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("⏹  Stop Attack")
                                    .font(FontId::proportional(14.0))
                                    .color(Color32::WHITE),
                            )
                            .fill(Color32::from_rgb(175, 35, 35))
                            .min_size(Vec2::new(140.0, 34.0)),
                        )
                        .clicked()
                    {
                        self.stop_attack();
                    }
                    ui.add_space(8.0);
                }

                // Clear Log
                if ui
                    .add(
                        egui::Button::new(
                            RichText::new("Clear Log")
                                .color(Color32::from_rgb(145, 158, 195)),
                        )
                        .fill(Color32::from_rgb(24, 28, 44))
                        .min_size(Vec2::new(92.0, 34.0)),
                    )
                    .clicked()
                {
                    let mut s = self.state.lock().unwrap();
                    s.log.clear();
                    s.result = None;
                }
            });

            ui.add_space(8.0);

            // ══════════════ 4. RESULT BANNER (conditional) ═══════════════
            let result = self.state.lock().unwrap().result.clone();
            if let Some(ref res) = result {
                if res == "__STOPPED__" {
                    egui::Frame::new()
                        .fill(Color32::from_rgb(38, 22, 8))
                        .corner_radius(8.0)
                        .stroke(Stroke::new(1.5, Color32::from_rgb(180, 100, 30)))
                        .inner_margin(egui::Margin::same(11))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(
                                RichText::new("⏹  Attack stopped by user.")
                                    .font(FontId::proportional(13.5))
                                    .color(Color32::from_rgb(230, 130, 60))
                                    .strong(),
                            );
                        });
                } else if res != "__FAIL__" {
                    egui::Frame::new()
                        .fill(Color32::from_rgb(15, 48, 24))
                        .corner_radius(8.0)
                        .stroke(Stroke::new(1.5, Color32::from_rgb(42, 160, 62)))
                        .inner_margin(egui::Margin::same(11))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(
                                RichText::new(format!("[+]  Password cracked:  {}", res))
                                    .font(FontId::proportional(14.5))
                                    .color(Color32::from_rgb(70, 210, 90))
                                    .strong(),
                            );
                        });
                } else {
                    egui::Frame::new()
                        .fill(Color32::from_rgb(44, 14, 14))
                        .corner_radius(8.0)
                        .stroke(Stroke::new(1.5, Color32::from_rgb(160, 42, 42)))
                        .inner_margin(egui::Margin::same(11))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(
                                RichText::new("[-]  Password not found in wordlist.")
                                    .font(FontId::proportional(13.5))
                                    .color(Color32::from_rgb(210, 72, 72))
                                    .strong(),
                            );
                        });
                }
                ui.add_space(6.0);
            }

            // ══════════════ 5. LIVE LOG ═══════════════════════════════════
            ui.horizontal(|ui| {
                section_label(ui, "Log");
                if running {
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new("● RUNNING")
                            .font(FontId::proportional(11.0))
                            .color(Color32::from_rgb(255, 170, 40)),
                    );
                }
            });
            ui.add_space(4.0);

            egui::Frame::new()
                .fill(Color32::from_rgb(8, 9, 15))
                .corner_radius(8.0)
                .stroke(Stroke::new(1.0, Color32::from_rgb(30, 34, 50)))
                .inner_margin(egui::Margin::same(10))
                .show(ui, |ui| {
                    let log_h = ui.available_height() - 4.0;
                    egui::ScrollArea::vertical()
                        .max_height(log_h)
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width() - 4.0);
                            let state = self.state.lock().unwrap();
                            for line in &state.log {
                                let color = if line.starts_with('✔') {
                                    Color32::from_rgb(70, 210, 90)
                                } else if line.starts_with('✘') || line.starts_with('!') {
                                    Color32::from_rgb(210, 72, 72)
                                } else if line.starts_with('▶') {
                                    Color32::from_rgb(85, 180, 255)
                                } else {
                                    Color32::from_rgb(125, 138, 168)
                                };
                                ui.label(
                                    RichText::new(line)
                                        .font(FontId::monospace(11.5))
                                        .color(color),
                                );
                            }
                        });
                });
        }); // end CentralPanel
    }
}

// ── Entry point ─────────────────────────────────────────────────────────────
fn main() -> eframe::Result {
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("WifiBF — WiFi Brute Force")
            .with_inner_size([720.0, 720.0])
            .with_resizable(false),
        ..Default::default()
    };
    eframe::run_native("WifiBF", opts, Box::new(|cc| Ok(Box::new(App::new(cc)))))
}
