use eframe::egui;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

// Add rfd for native folder selection
use rfd::FileDialog;

use crate::engine::{AntivirusEngine, ScanResult, DeletionRecord, MemoryScanResult};

pub struct AntivirusApp {
    engine: Arc<AntivirusEngine>,
    current_tab: Tab,
    scan_results: Vec<ScanResult>,
    scan_in_progress: bool,
    selected_directory: String,
    deep_scan: bool,
    threats_detected: Vec<ScanResult>,
    
    // 清理选项
    clean_temp: bool,
    clean_zero_byte: bool,
    clean_recycle_bin: bool,
    cleanup_log: String,
    
    // 内存扫描
    memory_scan_results: Vec<MemoryScanResult>,
    memory_scan_log: String,
    
    // 删除记录
    deletion_records: Vec<DeletionRecord>,
    
    // 隔离区
    quarantined_files: Vec<DeletionRecord>,
    selected_quarantine_index: Option<usize>,
}

#[derive(PartialEq)]
enum Tab {
    Scan,
    DeletionLog,
    Cleanup,
    MemoryScan,
    Quarantine,
}

impl AntivirusApp {
    pub fn new(engine: Arc<AntivirusEngine>) -> Self {
        let deletion_records = engine.deleted_files.lock().unwrap().clone();
        let quarantined_files = (*engine).get_quarantined_files();
        
        Self {
            engine,
            current_tab: Tab::Scan,
            scan_results: Vec::new(),
            scan_in_progress: false,
            selected_directory: std::env::var("USERPROFILE")
                .map(|s| s)
                .unwrap_or_else(|_| ".".to_string()),
            deep_scan: true,
            threats_detected: Vec::new(),
            clean_temp: true,
            clean_zero_byte: true,
            clean_recycle_bin: true,
            cleanup_log: String::new(),
            memory_scan_results: Vec::new(),
            memory_scan_log: String::new(),
            deletion_records,
            quarantined_files,
            selected_quarantine_index: None,
        }
    }

    pub fn ui(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("menu").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.current_tab, Tab::Scan, "📁 Scan");
                ui.selectable_value(&mut self.current_tab, Tab::DeletionLog, "📋 Deletion Log");
                ui.selectable_value(&mut self.current_tab, Tab::Cleanup, "🧹 Cleanup");
                ui.selectable_value(&mut self.current_tab, Tab::MemoryScan, "💾 Memory Scan");
                ui.selectable_value(&mut self.current_tab, Tab::Quarantine, "🚫 Quarantine");
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            match self.current_tab {
                Tab::Scan => self.show_scan_tab(ui),
                Tab::DeletionLog => self.show_deletion_log_tab(ui),
                Tab::Cleanup => self.show_cleanup_tab(ui),
                Tab::MemoryScan => self.show_memory_scan_tab(ui),
                Tab::Quarantine => self.show_quarantine_tab(ui),
            }
        });
    }

    fn show_scan_tab(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            ui.heading("File Scanner");
            
            // 目录选择
            ui.horizontal(|ui| {
                ui.label("Scan Directory:");
                ui.text_edit_singleline(&mut self.selected_directory);
                if ui.button("Browse...").clicked() {
                    // Open native folder picker; if user selects, update the field
                    if let Some(dir) = FileDialog::new().pick_folder() {
                        self.selected_directory = dir.to_string_lossy().to_string();
                    } else {
                        // user cancelled; keep existing value (no-op)
                    }
                }
            });
            
            // 扫描选项
            ui.checkbox(&mut self.deep_scan, "Deep Scan (Recursive)");
            
            // 扫描按钮
            ui.horizontal(|ui| {
                if ui.button("Start Scan").clicked() && !self.scan_in_progress {
                    self.start_scan();
                }
                
                if ui.button("Stop Scan").clicked() && self.scan_in_progress {
                    self.engine.stop();
                }
                
                if !self.threats_detected.is_empty() {
                    if ui.button("Handle Threats").clicked() {
                        self.handle_threats();
                    }
                }
            });
            
            // 扫描统计
            let scan_count = *self.engine.scan_count.lock().unwrap();
            let threats_found = *self.engine.threats_found.lock().unwrap();
            
            ui.horizontal(|ui| {
                ui.label(format!("Files scanned: {}", scan_count));
                ui.label(format!("Threats found: {}", threats_found));
            });
            
            // 扫描结果
            ui.heading("Scan Results");
            egui::ScrollArea::vertical().show(ui, |ui| {
                for result in &self.scan_results {
                    let color = if result.risk_score > 70 {
                        egui::Color32::RED
                    } else if result.risk_score > 50 {
                        egui::Color32::YELLOW
                    } else {
                        egui::Color32::GREEN
                    };
                    
                    ui.colored_label(color, 
                        format!("{} -> {} (Risk: {})", 
                            result.file_path.display(), 
                            result.result, 
                            result.risk_score
                        )
                    );
                    
                    if !result.rule_matches.is_empty() {
                        ui.label(format!("Matched rules: {}", result.rule_matches.join(", ")));
                    }
                    
                    ui.separator();
                }
            });
        });
    }

    fn show_deletion_log_tab(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            ui.heading("Deletion Log");
            
            if ui.button("Refresh").clicked() {
                self.refresh_deletion_log();
            }
            
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (i, record) in self.deletion_records.iter().enumerate() {
                    ui.push_id(i, |ui| {
                        ui.horizontal(|ui| {
                            // 文件路径
                            ui.vertical(|ui| {
                                ui.label("File:");
                                ui.monospace(&*record.original_path.to_string_lossy());
                            });
                            
                            // 原因
                            ui.vertical(|ui| {
                                ui.label("Reason:");
                                ui.label(&record.reason);
                            });
                            
                            // 状态
                            ui.vertical(|ui| {
                                ui.label("Status:");
                                if record.quarantined {
                                    ui.colored_label(egui::Color32::YELLOW, "Quarantined");
                                } else if record.deleted {
                                    ui.colored_label(egui::Color32::RED, "Deleted");
                                } else {
                                    ui.label("Unknown");
                                }
                            });
                            
                            // 时间戳
                            ui.vertical(|ui| {
                                ui.label("Time:");
                                ui.label(format!("{}", record.timestamp));
                            });
                        });
                        
                        ui.separator();
                    });
                }
            });
        });
    }

    fn show_cleanup_tab(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            ui.heading("Junk File Cleaner");
            
            ui.label("Select cleanup options:");
            ui.checkbox(&mut self.clean_temp, "🧹 Clean Temporary Files");
            ui.checkbox(&mut self.clean_zero_byte, "📄 Clean Zero-Byte Files (TXT/PDF)");
            ui.checkbox(&mut self.clean_recycle_bin, "🗑️ Empty Recycle Bin");
            
            if ui.button("Start Cleanup").clicked() {
                self.start_cleanup();
            }
            
            // 清理日志
            ui.heading("Cleanup Log");
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.monospace(&self.cleanup_log);
            });
        });
    }

    fn show_memory_scan_tab(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            ui.heading("Memory Scanner");
            
            ui.label("Memory scanning checks running processes for suspicious activities like code injection and malicious memory regions.");
            
            ui.horizontal(|ui| {
                if ui.button("Scan Memory Now").clicked() {
                    self.start_memory_scan();
                }
                
                if ui.button("Terminate Selected Process").clicked() {
                    self.terminate_selected_process();
                }
            });
            
            // 内存扫描结果
            ui.heading("Memory Scan Results");
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (i, result) in self.memory_scan_results.iter().enumerate() {
                    ui.push_id(i, |ui| {
                        let color = if result.is_malicious {
                            egui::Color32::RED
                        } else if result.suspicious_regions > 0 {
                            egui::Color32::YELLOW
                        } else {
                            egui::Color32::GREEN
                        };
                        
                        ui.horizontal(|ui| {
                            ui.colored_label(color, 
                                format!("PID: {} | Process: {}", result.pid, result.process_name)
                            );
                            
                            if result.is_malicious {
                                ui.colored_label(egui::Color32::RED, "⚠️ MALICIOUS");
                            }
                        });
                        
                        ui.label(&result.reason);
                        
                        if result.is_malicious {
                            ui.horizontal(|ui| {
                                if ui.button("Terminate").clicked() {
                                    (*self.engine).terminate_process(result.pid);
                                    self.memory_scan_log.push_str(&format!("Terminated process: {} (PID: {})\n", result.process_name, result.pid));
                                }
                            });
                        }
                        
                        ui.separator();
                    });
                }
            });
            
            // 内存扫描日志
            ui.heading("Memory Scan Log");
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.monospace(&self.memory_scan_log);
            });
        });
    }

    fn show_quarantine_tab(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            ui.heading("Quarantine Management");
            
            if ui.button("Refresh List").clicked() {
                self.refresh_quarantine_list();
            }
            
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (i, record) in self.quarantined_files.iter().enumerate() {
                    ui.push_id(i, |ui| {
                        let is_selected = self.selected_quarantine_index == Some(i);
                        
                        ui.horizontal(|ui| {
                            // 选择框
                            if ui.selectable_label(is_selected, "📁").clicked() {
                                self.selected_quarantine_index = Some(i);
                            }
                            
                            // 文件信息
                            ui.vertical(|ui| {
                                ui.monospace(&*record.original_path.to_string_lossy());
                                ui.small(&record.reason);
                            });
                        });
                        
                        ui.separator();
                    });
                }
            });
            
            // 操作按钮
            ui.horizontal(|ui| {
                if ui.button("Restore Selected").clicked() {
                    self.restore_selected_quarantine();
                }
                
                if ui.button("Delete Permanently").clicked() {
                    self.delete_selected_quarantine();
                }
            });
        });
    }

    fn start_scan(&mut self) {
        self.scan_in_progress = true;
        self.scan_results.clear();
        self.threats_detected.clear();
        
        let engine = self.engine.clone();
        let directory = self.selected_directory.clone();
        let deep_scan = self.deep_scan;
        
        thread::spawn(move || {
            (*engine).reset_stop_signal();
            let _results = (*engine).scan_directory(PathBuf::from(&directory).as_path(), deep_scan);
            
            // 在主线程中更新结果
            // 注意：在实际应用中需要使用线程安全的机制来更新UI
        });
    }

    fn handle_threats(&mut self) {
        let engine = self.engine.clone();
        let threats = self.threats_detected.clone();
        
        thread::spawn(move || {
            for threat in threats {
                (*engine).handle_threat(&threat.file_path, &threat.result);
            }
        });
        
        self.threats_detected.clear();
    }

    fn start_cleanup(&mut self) {
        let engine = self.engine.clone();
        let clean_temp = self.clean_temp;
        let clean_zero_byte = self.clean_zero_byte;
        let clean_recycle_bin = self.clean_recycle_bin;
        
        self.cleanup_log.clear();
        self.cleanup_log.push_str("Starting cleanup...\n");
        
        thread::spawn(move || {
            let (_cleaned_files, freed_space) = (*engine).clean_junk_files(clean_temp, clean_zero_byte, clean_recycle_bin);
            let _freed_mb = freed_space as f64 / (1024.0 * 1024.0);
            
            // 在主线程中更新日志
            // 注意：在实际应用中需要使用线程安全的机制来更新UI
        });
    }

    fn start_memory_scan(&mut self) {
        let engine = self.engine.clone();
        
        self.memory_scan_results.clear();
        self.memory_scan_log.push_str("Starting memory scan...\n");
        
        thread::spawn(move || {
            let _results = (*engine).scan_all_process_memory();
            
            // 在主线程中更新结果
            // 注意：在实际应用中需要使用线程安全的机制来更新UI
        });
    }

    fn terminate_selected_process(&mut self) {
        // 在实际应用中，这里会终止选中的进程
        self.memory_scan_log.push_str("Process termination requested.\n");
    }

    fn refresh_deletion_log(&mut self) {
        let records = self.engine.deleted_files.lock().unwrap().clone();
        self.deletion_records = records;
    }

    fn refresh_quarantine_list(&mut self) {
        self.quarantined_files = (*self.engine).get_quarantined_files();
    }

    fn restore_selected_quarantine(&mut self) {
        if let Some(index) = self.selected_quarantine_index {
            if let Some(record) = self.quarantined_files.get(index) {
                if let Some(ref quarantine_path) = record.quarantine_path {
                    let original_path = &record.original_path;
                    
                    if (*self.engine).restore_quarantined_file(quarantine_path, original_path) {
                        self.refresh_quarantine_list();
                        self.selected_quarantine_index = None;
                    }
                }
            }
        }
    }

    fn delete_selected_quarantine(&mut self) {
        if let Some(index) = self.selected_quarantine_index {
            if let Some(record) = self.quarantined_files.get(index) {
                if let Some(ref quarantine_path) = record.quarantine_path {
                    if (*self.engine).permanently_delete_quarantined_file(quarantine_path) {
                        self.refresh_quarantine_list();
                        self.selected_quarantine_index = None;
                    }
                }
            }
        }
    }
}

impl eframe::App for AntivirusApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.ui(ctx);
    }
}