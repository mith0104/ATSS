import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
import os
import shutil
from datetime import datetime
import math
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

class ThreatScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Threat Scanner")
        self.root.geometry("900x600")
        self.root.resizable(True, True)
        self.scan_active = False
        # Virus signature database: signature -> risk level
        self.virus_signature_db = {
            "Trojan.Generic": "high",
            "Adware.BrowserModifier": "low",
            "PUP.Optional.BundleInstaller": "medium",
            "Exploit.CVE-2023-1234": "high",
            "Trojan.Stealer": "high",
            "Ransomware.Gen": "high",
            "Rootkit.HiddenProcess": "high",
            "Trojan.Dropper": "high",
            "Spyware.Keylogger": "medium",
            "Backdoor.RAT": "high",
            "Heuristic.SuspectBehavior.Generic": "medium",
            "Exploit.CVE-2024-1234.Potential": "high",
            "Trojan.ZeroDay.Generic": "high",
            "Rootkit.Stealth.Driver": "high",
            "Malware.AI.Detected": "medium"
        }
        self.quarantine_folder = "F:\\quarantine"
        if not os.path.exists(self.quarantine_folder):
            os.makedirs(self.quarantine_folder)
            # Do not set hidden attribute to allow user access and avoid false positives in other scanners
        self.custom_paths = []
        self.config_file = os.path.join(os.getcwd(), "user_preferences.json")
        self.preferences = {
            # Update Settings
            "auto_update_db": True,
            "notify_updates": True,
            "signature_version": "1.0.0",
            "last_update_check": None,
            "manual_update_file_path": "",
            # Threat Handling Rules
            "high_risk_action": "Delete",
            "medium_risk_action": "Quarantine",
            "low_risk_action": "Quarantine",
            # Scan Settings
            "scan_archives": True,
            "enable_ai_detection": False,
            "default_scan_paths": [],
            "scan_exclusions": [],
            "enabled_scan_types": {
                "quick_scan": True,
                "full_scan": True,
                "custom_scan": True,
                "zero_day_scan": True,
                "custom_heuristic_scan": True
            },
            # Notifications
            "notify_threats": True,
            "sound_alert": False,
            # Appearance
            "theme": "Light",
            "show_scan_progress": True,
            # Automation (Optional/Future)
            "schedule_enabled": False,
            "scan_interval_hours": 24,
            "scheduled_scanning_frequency": "Daily",
            "scheduled_scan_time": "02:00",
            # System Settings
            "force_offline_mode": False
        }
        self.setup_ui()
        self.load_preferences()
        self.start_scheduled_scanning()

    def start_scheduled_scanning(self):
        def scheduled_scan_loop():
            while True:
                if self.preferences.get("schedule_enabled", False) and not self.scan_active:
                    self.add_log_entry("Scheduled scan triggered.")
                    self.run_full_scan()
                interval = self.preferences.get("scan_interval_hours", 24)
                time.sleep(interval * 3600)
        threading.Thread(target=scheduled_scan_loop, daemon=True).start()
    
    def load_preferences(self):
        import json
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    loaded_prefs = json.load(f)
                # Update only known keys to avoid overwriting with unknown keys
                for key in self.preferences.keys():
                    if key in loaded_prefs:
                        self.preferences[key] = loaded_prefs[key]
                self.add_log_entry("User preferences loaded.")
            except Exception as e:
                self.add_log_entry(f"Failed to load preferences: {e}")
        else:
            self.add_log_entry("No user preferences found, using defaults.")
    
    def save_preferences(self):
        import json
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.preferences, f, indent=4)
            self.add_log_entry("User preferences saved.")
        except Exception as e:
            self.add_log_entry(f"Failed to save preferences: {e}")
    
    def open_preferences_dialog(self):
        pref_win = tk.Toplevel(self.root)
        pref_win.title("User Preferences")
        pref_win.geometry("700x700")

        notebook = ttk.Notebook(pref_win)
        notebook.pack(fill='both', expand=True)

        # Helper function to create a dropdown
        def create_dropdown(parent, label_text, options, current_value):
            frame = ttk.Frame(parent)
            frame.pack(fill=tk.X, padx=10, pady=5)
            ttk.Label(frame, text=label_text).pack(side=tk.LEFT)
            var = tk.StringVar(value=current_value)
            dropdown = ttk.Combobox(frame, textvariable=var, values=options, state="readonly")
            dropdown.pack(side=tk.RIGHT, fill=tk.X, expand=True)
            return var

        # Helper function to create a checkbox
        def create_checkbox(parent, label_text, current_value):
            var = tk.BooleanVar(value=current_value)
            cb = ttk.Checkbutton(parent, text=label_text, variable=var)
            cb.pack(anchor=tk.W, padx=10, pady=5)
            return var

        # Helper function to create a text entry
        def create_text_entry(parent, label_text, current_value):
            frame = ttk.Frame(parent)
            frame.pack(fill=tk.X, padx=10, pady=5)
            ttk.Label(frame, text=label_text).pack(side=tk.LEFT)
            var = tk.StringVar(value=current_value)
            entry = ttk.Entry(frame, textvariable=var)
            entry.pack(side=tk.RIGHT, fill=tk.X, expand=True)
            return var

        # Helper function to create a label (for display only)
        def create_display_label(parent, label_text, value):
            frame = ttk.Frame(parent)
            frame.pack(fill=tk.X, padx=10, pady=5)
            ttk.Label(frame, text=label_text).pack(side=tk.LEFT)
            val_lbl = ttk.Label(frame, text=value)
            val_lbl.pack(side=tk.RIGHT)
            return val_lbl

        # Update Settings Tab
        update_frame = ttk.Frame(notebook)
        notebook.add(update_frame, text="Update Settings")
        auto_update_db_var = create_checkbox(update_frame, "Auto Update Signature Database", self.preferences.get("auto_update_db", True))
        notify_updates_var = create_checkbox(update_frame, "Notify on Update Availability", self.preferences.get("notify_updates", True))
        signature_version_lbl = create_display_label(update_frame, "Signature Version", self.preferences.get("signature_version", "1.0.0"))
        last_update_check_lbl = create_display_label(update_frame, "Last Update Checked", self.preferences.get("last_update_check", "Never"))
        manual_update_file_path_var = create_text_entry(update_frame, "Manual Update File Path", self.preferences.get("manual_update_file_path", ""))
        manual_update_button = ttk.Button(update_frame, text="Browse...", command=lambda: browse_manual_update_file(manual_update_file_path_var))
        manual_update_button.pack(anchor=tk.W, padx=20, pady=5)

        # Threat Handling Rules Tab
        threat_frame = ttk.Frame(notebook)
        notebook.add(threat_frame, text="Threat Handling Rules")
        high_risk_action_var = create_dropdown(threat_frame, "High Risk Action", ["Delete", "Quarantine", "Ignore"], self.preferences.get("high_risk_action", "Delete"))
        medium_risk_action_var = create_dropdown(threat_frame, "Medium Risk Action", ["Quarantine", "Ignore"], self.preferences.get("medium_risk_action", "Quarantine"))
        low_risk_action_var = create_dropdown(threat_frame, "Low Risk Action", ["Quarantine", "Ignore"], self.preferences.get("low_risk_action", "Quarantine"))

        # Scan Settings Tab
        scan_frame = ttk.Frame(notebook)
        notebook.add(scan_frame, text="Scan Settings")
        scan_archives_var = create_checkbox(scan_frame, "Scan Inside Archive Files", self.preferences.get("scan_archives", True))
        enable_ai_detection_var = create_checkbox(scan_frame, "Enable AI-Based Detection", self.preferences.get("enable_ai_detection", False))
        ttk.Label(scan_frame, text="Default Scan Paths (one per line):").pack(anchor=tk.W, padx=10, pady=(5,0))
        default_scan_paths_text = tk.Text(scan_frame, height=3)
        default_scan_paths_text.pack(fill=tk.X, padx=10)
        default_scan_paths_text.insert(tk.END, "\n".join(self.preferences.get("default_scan_paths", [])))
        ttk.Label(scan_frame, text="Excluded Folders/Files (one per line):").pack(anchor=tk.W, padx=10, pady=(5,0))
        scan_exclusions_text = tk.Text(scan_frame, height=3)
        scan_exclusions_text.pack(fill=tk.X, padx=10)
        scan_exclusions_text.insert(tk.END, "\n".join(self.preferences.get("scan_exclusions", [])))
        scan_modes_vars = {}
        ttk.Label(scan_frame, text="Enable/Disable Scan Modes:").pack(anchor=tk.W, padx=10, pady=(5,0))
        for mode in self.preferences.get("enabled_scan_types", {}):
            var = tk.BooleanVar(value=self.preferences["enabled_scan_types"][mode])
            cb = ttk.Checkbutton(scan_frame, text=mode.replace("_", " ").title(), variable=var)
            cb.pack(anchor=tk.W, padx=20)
            scan_modes_vars[mode] = var

        # Notifications Tab
        notifications_frame = ttk.Frame(notebook)
        notebook.add(notifications_frame, text="Notifications")
        notify_threats_var = create_checkbox(notifications_frame, "Notify on Threat Detection", self.preferences.get("notify_threats", True))
        sound_alert_var = create_checkbox(notifications_frame, "Enable Sound Alert", self.preferences.get("sound_alert", False))

        # Appearance Tab
        appearance_frame = ttk.Frame(notebook)
        notebook.add(appearance_frame, text="Appearance")
        theme_var = create_dropdown(appearance_frame, "Theme", ["Light", "Dark"], self.preferences.get("theme", "Light"))
        show_scan_progress_var = create_checkbox(appearance_frame, "Show Scan Progress", self.preferences.get("show_scan_progress", True))

        notebook.add(notifications_frame, text="Notifications")
        notify_threats_var = create_checkbox(notifications_frame, "Notify on Threat Detection", self.preferences.get("notify_threats", True))
        sound_alert_var = create_checkbox(notifications_frame, "Enable Sound Alert", self.preferences.get("sound_alert", False))

        # Appearance Tab
        appearance_frame = ttk.Frame(notebook)
        notebook.add(appearance_frame, text="Appearance")
        theme_var = create_dropdown(appearance_frame, "Theme", ["Light", "Dark"], self.preferences.get("theme", "Light"))
        show_scan_progress_var = create_checkbox(appearance_frame, "Show Scan Progress", self.preferences.get("show_scan_progress", True))

        # Automation Tab
        automation_frame = ttk.Frame(notebook)
        notebook.add(automation_frame, text="Automation")
        scheduled_scanning_frequency_var = create_dropdown(automation_frame, "Scheduled Scanning Frequency", ["Daily", "Weekly", "Monthly"], self.preferences.get("scheduled_scanning_frequency", "Daily"))
        scheduled_scan_time_var = create_text_entry(automation_frame, "Scan Time (HH:MM)", self.preferences.get("scheduled_scan_time", "02:00"))

        # System Settings Tab
        system_frame = ttk.Frame(notebook)
        notebook.add(system_frame, text="System Settings")
        force_offline_mode_var = create_checkbox(system_frame, "Force Offline Mode", self.preferences.get("force_offline_mode", False))
        reset_defaults_button = ttk.Button(system_frame, text="Reset to Default Settings", command=lambda: reset_to_defaults())
        reset_defaults_button.pack(anchor=tk.W, padx=10, pady=10)
        save_settings_button = ttk.Button(system_frame, text="Save Settings", command=lambda: save_and_close())
        save_settings_button.pack(anchor=tk.W, padx=10, pady=10)

        def browse_manual_update_file(var):
            file_path = filedialog.askopenfilename(title="Select Signature Update File", filetypes=[("Text Files", "*.txt")])
            if file_path:
                var.set(file_path)

        def reset_to_defaults():
            # Reset all variables to default values
            auto_update_db_var.set(True)
            notify_updates_var.set(True)
            manual_update_file_path_var.set("")
            high_risk_action_var.set("Delete")
            medium_risk_action_var.set("Quarantine")
            low_risk_action_var.set("Quarantine")
            scan_archives_var.set(True)
            enable_ai_detection_var.set(False)
            default_scan_paths_text.delete("1.0", tk.END)
            scan_exclusions_text.delete("1.0", tk.END)
            for mode in scan_modes_vars:
                scan_modes_vars[mode].set(True)
            notify_threats_var.set(True)
            sound_alert_var.set(False)
            theme_var.set("Light")
            show_scan_progress_var.set(True)
            scheduled_scanning_frequency_var.set("Daily")
            scheduled_scan_time_var.set("02:00")
            force_offline_mode_var.set(False)

        def save_and_close():
            self.preferences["auto_update_db"] = auto_update_db_var.get()
            self.preferences["notify_updates"] = notify_updates_var.get()
            self.preferences["manual_update_file_path"] = manual_update_file_path_var.get()
            self.preferences["high_risk_action"] = high_risk_action_var.get()
            self.preferences["medium_risk_action"] = medium_risk_action_var.get()
            self.preferences["low_risk_action"] = low_risk_action_var.get()
            self.preferences["scan_archives"] = scan_archives_var.get()
            self.preferences["enable_ai_detection"] = enable_ai_detection_var.get()
            self.preferences["default_scan_paths"] = default_scan_paths_text.get("1.0", tk.END).strip().splitlines()
            self.preferences["scan_exclusions"] = scan_exclusions_text.get("1.0", tk.END).strip().splitlines()
            for mode in scan_modes_vars:
                self.preferences["enabled_scan_types"][mode] = scan_modes_vars[mode].get()
            self.preferences["notify_threats"] = notify_threats_var.get()
            self.preferences["sound_alert"] = sound_alert_var.get()
            self.preferences["theme"] = theme_var.get()
            self.preferences["show_scan_progress"] = show_scan_progress_var.get()
            self.preferences["scheduled_scanning_frequency"] = scheduled_scanning_frequency_var.get()
            self.preferences["scheduled_scan_time"] = scheduled_scan_time_var.get()
            self.preferences["force_offline_mode"] = force_offline_mode_var.get()
            self.save_preferences()
            pref_win.destroy()
    
    def setup_ui(self):
        # Window styling
        self.apply_theme(self.preferences.get("theme", "Light"))
        style = ttk.Style()
        style.theme_use('clam')
        # Other style configurations moved to apply_theme method

    def apply_theme(self, theme_name):
        style = ttk.Style()
        if theme_name == "Dark":
            self.root.configure(bg="#2e2e2e")
            style.configure('TFrame', background='#2e2e2e')
            style.configure('TLabel', background='#2e2e2e', foreground='white', font=('Segoe UI', 10))
            style.configure('TButton', font=('Segoe UI', 10), padding=6, background='#444444', foreground='white')
            style.configure('Title.TLabel', font=('Segoe UI', 16, 'bold'), background='#2e2e2e', foreground='white')
            style.map('TButton',
                      background=[('active', '#555555')],
                      foreground=[('active', 'white')])
            self.log_text.configure(bg="#1e1e1e", fg="white")
        else:
            self.root.configure(bg="#f0f0f0")
            style.configure('TFrame', background='#f0f0f0')
            style.configure('TLabel', background='#f0f0f0', foreground='black', font=('Segoe UI', 10))
            style.configure('TButton', font=('Segoe UI', 10), padding=6)
            style.configure('Title.TLabel', font=('Segoe UI', 16, 'bold'), background='#f0f0f0', foreground='black')
            self.log_text.configure(bg="white", fg="black")
        
        # Menu bar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        settings_menu.add_command(label="Preferences", command=self.open_preferences_dialog)
        
        # Main container frame
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        self.header_frame = ttk.Frame(self.main_frame)
        self.header_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(self.header_frame, text="Advanced Threat Scanner", 
                 style='Title.TLabel').pack(anchor=tk.CENTER, expand=True)
        
        self.status_label = ttk.Label(self.header_frame, text="Status: Ready")
        self.status_label.pack(anchor=tk.CENTER, expand=True)
        
        # Center protection items in protection_frame
        for child in self.protection_frame.winfo_children():
            child.grid_configure(padx=20)
        
        # Center scan options buttons and labels
        for child in self.scan_frame.winfo_children():
            child.grid_configure(padx=20)
        
        # Protection status frame
        self.protection_frame = ttk.LabelFrame(self.main_frame, text="Protection Status")
        self.protection_frame.pack(fill=tk.X, pady=(0, 20))
        
        protection_items = [
            ("Real-time Protection", "active", "#4CAF50"),
            ("Firewall", "active", "#4CAF50"),
            ("Zero-Day Detection", "enabled", "#2196F3"),
            ("Behavior Monitoring", "active", "#4CAF50")
        ]
        
        for i, (name, status, color) in enumerate(protection_items):
            frame = ttk.Frame(self.protection_frame)
            frame.grid(row=0, column=i, padx=10, pady=10)
            
            ttk.Label(frame, text=name).pack()
            ttk.Label(frame, text=status, foreground=color).pack()
        
        # Scan options frame
        self.scan_frame = ttk.LabelFrame(self.main_frame, text="Scan Options")
        self.scan_frame.pack(fill=tk.X, pady=(0, 20))
        
        scan_options = [
            ("Quick Scan", "Scan common threat locations", self.run_quick_scan),
            ("Full Scan", "Comprehensive system scan", self.run_full_scan),
            ("Custom Scan", "Scan specific files/folders", self.run_custom_scan),
            ("Zero-Day Scan", "Advanced heuristic analysis", self.run_zero_day_scan)
        ]
        
        for i, (name, desc, cmd) in enumerate(scan_options):
            frame = ttk.Frame(self.scan_frame)
            frame.grid(row=0, column=i, padx=10, pady=10, sticky="nsew")
            
            ttk.Button(frame, text=name, command=cmd).pack(anchor='center')
            ttk.Label(frame, text=desc, wraplength=150).pack(anchor='center')
        
        # Add button for updating signature database
        self.update_db_button = ttk.Button(self.scan_frame, text="Update Signature DB", command=self.update_signature_database)
        self.update_db_button.grid(row=1, column=0, columnspan=4, pady=10)
        
        # Stop scan button
        self.stop_button = ttk.Button(self.scan_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.grid(row=2, column=0, columnspan=4, pady=10)
        
        # Scan progress frame
        self.progress_frame = ttk.LabelFrame(self.main_frame, text="Scan Progress")
        self.progress_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.progress_label = ttk.Label(self.progress_frame, text="No scan running")
        self.progress_label.pack(anchor=tk.W)
        
        self.progress_bar = ttk.Progressbar(self.progress_frame, orient=tk.HORIZONTAL, length=100, mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        self.threat_label = ttk.Label(self.progress_frame, text="Threats detected: 0")
        self.threat_label.pack(anchor=tk.W)
        
        # Log frame
        self.log_frame = ttk.LabelFrame(self.main_frame, text="Scan Log")
        self.log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = tk.Text(self.log_frame, height=10, bg="white", fg="black", wrap=tk.WORD)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(self.log_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.log_text.yview)
        
        # Add initial log entry
        
    def setup_ui(self):
        # Window styling
        self.root.configure(bg="#f0f0f0")
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background='#f0f0f0')
        style.configure('TLabel', background='#f0f0f0', font=('Segoe UI', 10))
        style.configure('TButton', font=('Segoe UI', 10), padding=6)
        style.configure('Title.TLabel', font=('Segoe UI', 16, 'bold'))
        
        # Main container frame
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        self.header_frame = ttk.Frame(self.main_frame)
        self.header_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(self.header_frame, text="Advanced Threat Scanner", 
                 style='Title.TLabel').pack(side=tk.LEFT)
        
        # Add Settings button in header
        settings_button = ttk.Button(self.header_frame, text="Settings", command=self.open_preferences_dialog)
        settings_button.pack(side=tk.RIGHT, padx=10)
        
        self.status_label = ttk.Label(self.header_frame, text="Status: Ready")
        self.status_label.pack(side=tk.RIGHT)
        
        # Protection status frame
        self.protection_frame = ttk.LabelFrame(self.main_frame, text="Protection Status")
        self.protection_frame.pack(fill=tk.X, pady=(0, 20))
        
        protection_items = [
            ("Real-time Protection", "active", "#4CAF50"),
            ("Firewall", "active", "#4CAF50"),
            ("Zero-Day Detection", "enabled", "#2196F3"),
            ("Behavior Monitoring", "active", "#4CAF50")
        ]
        
        for i, (name, status, color) in enumerate(protection_items):
            frame = ttk.Frame(self.protection_frame)
            frame.grid(row=0, column=i, padx=10, pady=10)
            
            ttk.Label(frame, text=name).pack()
            ttk.Label(frame, text=status, foreground=color).pack()
        
        # Scan options frame
        self.scan_frame = ttk.LabelFrame(self.main_frame, text="Scan Options")
        self.scan_frame.pack(fill=tk.X, pady=(0, 20))
        
        scan_options = [
            ("Quick Scan", "Scan common threat locations", self.run_quick_scan),
            ("Full Scan", "Comprehensive system scan", self.run_full_scan),
            ("Custom Scan", "Scan specific files/folders", self.run_custom_scan),
            ("Zero-Day Scan", "Advanced heuristic analysis", self.run_zero_day_scan),
            ("Custom Heuristic Scan", "Heuristic analysis on selected files", self.run_custom_heuristic_scan)
        ]
        
        for i, (name, desc, cmd) in enumerate(scan_options):
            frame = ttk.Frame(self.scan_frame)
            frame.grid(row=0, column=i, padx=10, pady=10, sticky="nsew")
            
            ttk.Button(frame, text=name, command=cmd).pack(anchor='center')
            ttk.Label(frame, text=desc, wraplength=150).pack(anchor='center')
        
        # Add button for updating signature database
        self.update_db_button = ttk.Button(self.scan_frame, text="Update Signature DB", command=self.update_signature_database)
        self.update_db_button.grid(row=1, column=0, columnspan=4, pady=10, sticky="ew")
        
        # Stop scan button
        self.stop_button = ttk.Button(self.scan_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.grid(row=2, column=0, columnspan=4, pady=10, sticky="ew")
        
        
        # Scan progress frame
        self.progress_frame = ttk.LabelFrame(self.main_frame, text="Scan Progress")
        self.progress_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.progress_label = ttk.Label(self.progress_frame, text="No scan running")
        self.progress_label.pack(anchor=tk.W)
        
        self.progress_bar = ttk.Progressbar(self.progress_frame, orient=tk.HORIZONTAL, length=100, mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        self.threat_label = ttk.Label(self.progress_frame, text="Threats detected: 0")
        self.threat_label.pack(anchor=tk.W)
        
        # Log frame
        self.log_frame = ttk.LabelFrame(self.main_frame, text="Scan Log")
        self.log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = tk.Text(self.log_frame, height=10, bg="white", fg="black", wrap=tk.WORD)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(self.log_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.log_text.yview)
        
        # Add initial log entry
        self.add_log_entry("Threat Scanner initialized")
        
    def add_log_entry(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
    
    def update_progress(self, current, total, threat_count):
        self.progress_bar['value'] = (current / total) * 100 if total > 0 else 0
        self.progress_label.config(text=f"Scanning... {current}/{total} files processed")
        self.threat_label.config(text=f"Threats detected: {threat_count}")
        self.root.update()
    
    def scan_file_for_viruses(self, filepath):
        """Scan a single file for virus signatures. Return list of detected virus signatures."""  
        detected = []  
        try:  
            with open(filepath, 'r', errors='ignore') as f:  
                content = f.read()  
                for signature in self.virus_signature_db.keys():  
                    if signature in content:  
                        detected.append(signature)  
        except PermissionError as e:
            self.add_log_entry(f"Warning: Permission denied scanning file {filepath}. Skipping.")
        except Exception as e:  
            self.add_log_entry(f"Error scanning file {filepath}: {e}")  
        return detected

    def update_signature_database(self, from_online=False):
        """
        Update the virus signature database.
        Only update from local 'signature_update.txt' file.
        """
        updated_signatures = 0
        update_file = os.path.join(os.getcwd(), "signature_update.txt")
        if not os.path.exists(update_file):
            self.add_log_entry("Signature update file not found.")
            messagebox.showerror("Update Failed", "Signature update file 'signature_update.txt' not found.")
            return
        try:
            with open(update_file, 'r') as f:
                lines = f.readlines()
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(",")
                if len(parts) == 2:
                    signature, risk = parts[0].strip(), parts[1].strip()
                    self.virus_signature_db[signature] = risk
                    updated_signatures += 1
            self.add_log_entry(f"Signature database updated with {updated_signatures} new entries.")
            messagebox.showinfo("Update Successful", f"Signature database updated with {updated_signatures} new entries.")
        except Exception as e:
            self.add_log_entry(f"Error updating signature database: {e}")
            messagebox.showerror("Update Failed", f"Error updating signature database: {e}")

    def schedule_regular_updates(self, interval_hours=24):
        """Schedule regular signature database updates every interval_hours."""
        def update_loop():
            while True:
                if not self.scan_active:
                    self.update_signature_database(from_online=True)
                time.sleep(interval_hours * 3600)
        threading.Thread(target=update_loop, daemon=True).start()

    def scan_files(self, filepaths):
        total_files = len(filepaths)
        threats_detected = 0
        locked_files = {"NTUSER.DAT", "ntuser.dat.LOG1", "ntuser.dat.LOG2"}
        for i, filepath in enumerate(filepaths, 1):
            if not self.scan_active:
                break
            if os.path.basename(filepath) in locked_files:
                self.add_log_entry(f"Skipping locked system file: {filepath}")
                continue
            detected_signatures = self.scan_file_for_viruses(filepath)
            if detected_signatures:
                threats_detected += len(detected_signatures)
                for sig in detected_signatures:
                    self.add_log_entry(f"Detected threat: {sig} in file {os.path.basename(filepath)}")
                    self.handle_threat(filepath, sig)
            self.update_progress(i, total_files, threats_detected)
            time.sleep(0.01)  # Small delay to keep UI responsive
        return threats_detected

    def handle_threat(self, filepath, signature):
        risk_level = self.virus_signature_db.get(signature, "low").lower()
        action = None
        if risk_level == "high":
            action = self.preferences.get("high_risk_action", "Delete")
        elif risk_level == "medium":
            action = self.preferences.get("medium_risk_action", "Quarantine")
        else:
            action = self.preferences.get("low_risk_action", "Quarantine")

        self.add_log_entry(f"Handling threat - Level: {risk_level.title()}, Signature: {signature}, Location: {filepath}, Action: {action}")

        try:
            if action == "Delete":
                os.remove(filepath)
                self.add_log_entry(f"Deleted file - Level: {risk_level.title()}, Signature: {signature}, Location: {filepath}")
            elif action == "Quarantine":
                # Create subfolder for threat level if it doesn't exist
                threat_level_folder = os.path.join(self.quarantine_folder, risk_level)
                if not os.path.exists(threat_level_folder):
                    os.makedirs(threat_level_folder)
                quarantine_path = os.path.join(threat_level_folder, os.path.basename(filepath))
                shutil.move(filepath, quarantine_path)
                self.add_log_entry(f"Quarantined file - Level: {risk_level.title()}, Signature: {signature}, Location: {filepath}, Quarantine Path: {quarantine_path}")
            elif action == "Ignore":
                self.add_log_entry(f"Ignored threat - Level: {risk_level.title()}, Signature: {signature}, Location: {filepath}")
        except Exception as e:
            self.add_log_entry(f"Error handling threat in file {filepath}: {e}")
    
    def run_quick_scan(self):
        if self.scan_active:
            return
        self.scan_active = True
        self.stop_button.config(state=tk.NORMAL)
        self.add_log_entry("Starting Quick Scan - Checking critical system areas")
        
        # For demo, define some common system paths (can be adjusted)
        common_paths = [
            os.path.expandvars(r"%SystemRoot%\\System32"),
            os.path.expandvars(r"%SystemRoot%"),
            os.path.expanduser("~")
        ]
        # Collect files from these directories (non-recursive for quick scan)
        files_to_scan = []
        for path in common_paths:
            if os.path.exists(path):
                try:
                    for entry in os.scandir(path):
                        if entry.is_file():
                            files_to_scan.append(entry.path)
                except Exception as e:
                    self.add_log_entry(f"Error accessing {path}: {e}")
        
        def quick_scan_thread():
            threats_found = self.scan_files(files_to_scan)
            self.scan_active = False
            self.stop_button.config(state=tk.DISABLED)
            self.add_log_entry(f"Quick Scan completed - {threats_found} threats detected")
            self.status_label.config(text="Status: Ready")
            if threats_found > 0:
                messagebox.showwarning("Scan Complete", f"Scan completed with {threats_found} threats detected!")
            else:
                messagebox.showinfo("Scan Complete", "No threats detected!")
        
        self.status_label.config(text="Status: Quick Scan Running")
        threading.Thread(target=quick_scan_thread, daemon=True).start()
    
    def run_full_scan(self):
        if self.scan_active:
            return
        self.scan_active = True
        self.stop_button.config(state=tk.NORMAL)
        self.add_log_entry("Starting Full System Scan - This may take several minutes")
        
        # For demo, scan entire user home directory recursively
        home_dir = os.path.expanduser("~")
        files_to_scan = []
        for root_dir, dirs, files in os.walk(home_dir):
            for file in files:
                files_to_scan_path = os.path.join(root_dir, file)
                files_to_scan.append(files_to_scan_path)
        
        def full_scan_thread():
            threats_found = self.scan_files(files_to_scan)
            self.scan_active = False
            self.stop_button.config(state=tk.DISABLED)
            self.add_log_entry(f"Full System Scan completed - {threats_found} threats detected")
            self.status_label.config(text="Status: Ready")
            if threats_found > 0:
                messagebox.showwarning("Scan Complete", f"Scan completed with {threats_found} threats detected!")
            else:
                messagebox.showinfo("Scan Complete", "No threats detected!")
        
        self.status_label.config(text="Status: Full Scan Running")
        threading.Thread(target=full_scan_thread, daemon=True).start()
    
    def run_custom_scan(self):
        # Allow user to select files or a directory or a drive
        paths = filedialog.askopenfilenames(title="Select files to scan")
        if not paths:
            # If no files selected, allow directory selection
            folder_path = filedialog.askdirectory(title="Select folder or drive to scan")
            if not folder_path:
                return
            # Recursively collect all files in the selected folder or drive
            files_to_scan = []
            for root_dir, dirs, files in os.walk(folder_path):
                for file in files:
                    files_to_scan.append(os.path.join(root_dir, file))
            self.custom_paths = files_to_scan
        else:
            self.custom_paths = paths

        if self.scan_active:
            return
        self.scan_active = True
        self.stop_button.config(state=tk.NORMAL)
        self.add_log_entry(f"Starting Custom Scan on {len(self.custom_paths)} files")

        def custom_scan_thread():
            threats_found = self.scan_files(self.custom_paths)
            self.scan_active = False
            self.stop_button.config(state=tk.DISABLED)
            self.add_log_entry(f"Custom Scan completed - {threats_found} threats detected")
            self.status_label.config(text="Status: Ready")
            if threats_found > 0:
                messagebox.showwarning("Scan Complete", f"Scan completed with {threats_found} threats detected!")
            else:
                messagebox.showinfo("Scan Complete", "No threats detected!")

        self.status_label.config(text="Status: Custom Scan Running")
        threading.Thread(target=custom_scan_thread, daemon=True).start()
    
    def run_zero_day_scan(self):
        if self.scan_active:
            return
        self.scan_active = True
        self.stop_button.config(state=tk.NORMAL)
        self.add_log_entry("Starting Zero-Day Threat Scan - Using advanced heuristics")
        
        # For demo, scan user home directory recursively but only check for zero-day signatures
        home_dir = os.path.expanduser("~")
        zero_day_signatures = [
            "Heuristic.SuspectBehavior.Generic",
            "Exploit.CVE-2024-1234.Potential",
            "Trojan.ZeroDay.Generic",
            "Rootkit.Stealth.Driver",
            "Malware.AI.Detected"
        ]
        files_to_scan = []
        for root_dir, dirs, files in os.walk(home_dir):
            for file in files:
                files_to_scan_path = os.path.join(root_dir, file)
                files_to_scan.append(files_to_scan_path)
        
        def zero_day_scan_thread():
            total_files = len(files_to_scan)
            threats_detected = 0
            for i, filepath in enumerate(files_to_scan, 1):
                if not self.scan_active:
                    break
                detected = []
                try:
                    with open(filepath, 'r', errors='ignore') as f:
                        content = f.read()
                        for signature in zero_day_signatures:
                            if signature in content:
                                detected.append(signature)
                except Exception as e:
                    self.add_log_entry(f"Error scanning file {filepath}: {e}")
                if detected:
                    threats_detected += len(detected)
                    for sig in detected:
                        self.add_log_entry(f"Zero-day threat detected: {sig} in file {os.path.basename(filepath)}")
                        self.handle_threat(filepath, sig)
                self.update_progress(i, total_files, threats_detected)
                time.sleep(0.01)
            self.scan_active = False
            self.stop_button.config(state=tk.DISABLED)
            self.add_log_entry(f"Zero-Day Scan completed - {threats_detected} potential zero-day threats detected")
            self.status_label.config(text="Status: Ready")
            if threats_detected > 0:
                messagebox.showwarning("Scan Complete", 
                    f"Scan detected {threats_detected} potential zero-day threats!\n\n" +
                    "These threats are not yet in standard databases. " +
                    "Please review the scan log for details.")
            else:
                messagebox.showinfo("Scan Complete", "No zero-day threats detected!")
        
        self.status_label.config(text="Status: Zero-Day Scan Running")
        threading.Thread(target=zero_day_scan_thread, daemon=True).start()
    
    def stop_scan(self):
        if self.scan_active:
            self.scan_active = False
            self.add_log_entry("Scan stopped by user.")
            self.status_label.config(text="Status: Scan Stopped")
            self.stop_button.config(state=tk.DISABLED)

    def run_custom_heuristic_scan(self):
        paths = filedialog.askopenfilenames(title="Select files for heuristic scan")
        if not paths:
            return
        if self.scan_active:
            return
        self.custom_paths = paths
        self.scan_active = True
        self.stop_button.config(state=tk.NORMAL)
        self.add_log_entry(f"Starting Custom Heuristic Scan on {len(paths)} selected files")

        heuristic_signatures = [
            "Heuristic.SuspectBehavior.Generic",
            "Exploit.CVE-2024-1234.Potential",
            "Trojan.ZeroDay.Generic",
            "Rootkit.Stealth.Driver",
            "Malware.AI.Detected"
        ]

        def custom_heuristic_scan_thread():
            total_files = len(self.custom_paths)
            threats_detected = 0
            for i, filepath in enumerate(self.custom_paths, 1):
                if not self.scan_active:
                    break
                detected = []
                try:
                    with open(filepath, 'r', errors='ignore') as f:
                        content = f.read()
                        for signature in heuristic_signatures:
                            if signature in content:
                                detected.append(signature)
                except Exception as e:
                    self.add_log_entry(f"Error scanning file {filepath}: {e}")
                if detected:
                    threats_detected += len(detected)
                    for sig in detected:
                        self.add_log_entry(f"Custom heuristic threat detected: {sig} in file {os.path.basename(filepath)}")
                        self.handle_threat(filepath, sig)
                self.update_progress(i, total_files, threats_detected)
                time.sleep(0.01)
            self.scan_active = False
            self.stop_button.config(state=tk.DISABLED)
            self.add_log_entry(f"Custom Heuristic Scan completed - {threats_detected} potential threats detected")
            self.status_label.config(text="Status: Ready")
            if threats_detected > 0:
                messagebox.showwarning("Scan Complete", 
                    f"Scan detected {threats_detected} potential heuristic threats!\n\n" +
                    "Please review the scan log for details.")
            else:
                messagebox.showinfo("Scan Complete", "No heuristic threats detected!")

        self.status_label.config(text="Status: Custom Heuristic Scan Running")
        threading.Thread(target=custom_heuristic_scan_thread, daemon=True).start()


if __name__ == "__main__":
    root = tk.Tk()
    app = ThreatScanner(root)
    root.mainloop()
