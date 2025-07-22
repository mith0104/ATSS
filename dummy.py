import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import shutil

class ThreatFileDownloaderUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Threat Level and File Type Downloader")
        self.root.geometry("400x400")
        self.root.resizable(False, False)

        # Threat level selection
        threat_frame = ttk.LabelFrame(root, text="Select Threat Levels")
        threat_frame.pack(fill=tk.X, padx=10, pady=10)

        self.high_var = tk.BooleanVar(value=True)
        self.medium_var = tk.BooleanVar(value=True)
        self.low_var = tk.BooleanVar(value=True)

        ttk.Checkbutton(threat_frame, text="High", variable=self.high_var).pack(anchor=tk.W, padx=10, pady=2)
        ttk.Checkbutton(threat_frame, text="Medium", variable=self.medium_var).pack(anchor=tk.W, padx=10, pady=2)
        ttk.Checkbutton(threat_frame, text="Low", variable=self.low_var).pack(anchor=tk.W, padx=10, pady=2)

        # File types selection (single choice)
        filetype_frame = ttk.LabelFrame(root, text="Select File Type to Download")
        filetype_frame.pack(fill=tk.X, padx=10, pady=10)

        self.filetype_var = tk.StringVar(value=".exe")

        file_types = [".exe", ".zip", ".bat", ".dll"]
        for ft in file_types:
            ttk.Radiobutton(filetype_frame, text=ft, variable=self.filetype_var, value=ft).pack(anchor=tk.W, padx=10, pady=2)

        # Download button
        download_button = ttk.Button(root, text="Download File", command=self.download_file)
        download_button.pack(pady=10)

    def download_file(self):
        selected_levels = []
        if self.high_var.get():
            selected_levels.append("high")
        if self.medium_var.get():
            selected_levels.append("medium")
        if self.low_var.get():
            selected_levels.append("low")

        selected_filetype = self.filetype_var.get()

        # For demonstration, simulate download by copying a file from a source folder on F: drive
        # Assuming files are organized in F:/threat_files/<level>/ with files of various types
        source_base = "F:/threat_files"
        destination_folder = "F:/downloaded_files"
        if not os.path.exists(destination_folder):
            os.makedirs(destination_folder)

        found_file = None
        for level in selected_levels:
            level_folder = os.path.join(source_base, level)
            if os.path.exists(level_folder):
                for filename in os.listdir(level_folder):
                    if filename.lower().endswith(selected_filetype.lower()):
                        found_file = os.path.join(level_folder, filename)
                        break
            if found_file:
                break

        if found_file:
            try:
                dest_path = os.path.join(destination_folder, os.path.basename(found_file))
                shutil.copy2(found_file, dest_path)
                messagebox.showinfo("Download Successful", f"File downloaded to: {dest_path}")
            except Exception as e:
                messagebox.showerror("Download Failed", f"Error copying file: {e}")
        else:
            messagebox.showwarning("File Not Found", "No file matching the selected criteria was found in the source folders.")

if __name__ == "__main__":
    root = tk.Tk()
    app = ThreatFileDownloaderUI(root)
    root.mainloop()
