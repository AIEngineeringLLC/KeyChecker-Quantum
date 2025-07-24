import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import os
from datetime import datetime

import threading
import time


# --- Configuration ---
OPENSSL_PATH = r"openssl.exe" # This path is correct based on your output
OUTPUT_FOLDER = os.path.abspath("output")
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# Corrected and Expanded ALGORITHMS list
ALGORITHMS = [
    # Classical RSA
    'RSA:2048',
    'RSA:3072',
    'RSA:4096',

    # Classical Elliptic Curve Cryptography (ECC)
    'EC:prime256v1',
    'EC:secp384r1',
    'EC:secp521r1',
    'ED25519',
    'ED448',

    # Post-Quantum Cryptography (PQC) - Hybrid Combinations
    'rsa3072_falcon512', 'rsa3072_falconpadded512',
    'rsa3072_sphincsha2128fsimple', 'rsa3072_sphincsha2128ssimple',
    'rsa3072_sphincsshake128fsimple',
    'rsa3072_mldsa44', 'rsa3072_mldsa65',

    'p256_falcon512', 'p256_falconpadded512',
    'p256_sphincssha2128fsimple', 'p256_sphincssha2128ssimple',
    'p256_sphincsshake128fsimple',
    'p256_mayo1', 'p256_mayo2',
    'p256_OV_Is_pkc', 'p256_OV_Ip_pkc', 'p256_OV_Is_pkc_skc', 'p256_OV_Ip_pkc_skc',
    'p256_frodo640aes', 'p256_frodo640shake',
    'p256_mlkem512', 'p256_mldsa44', 'p256_mldsa65',

    'p384_mayo3', 'p384_sphincssha2192fsimple',
    'p384_frodo976aes', 'p384_frodo976shake',
    'p384_mlkem768', 'p384_mldsa65', 'p384_mldsa87',

    'p521_falcon1024', 'p521_falconpadded1024',
    'p521_mayo5',
    'p521_frodo1344aes', 'p521_frodo1344shake',
    'p521_mlkem1024', 'p521_mldsa87',

    'mldsa44_ed25519', 'mldsa65_ed25519', 'mldsa87_ed448',

    # Pure PQC Algorithms
    'mlkem512', 'mlkem768', 'mlkem1024',
    'frodo640aes', 'frodo640shake', 'frodo976aes', 'frodo976shake',
    'frodo1344aes', 'frodo1344shake',
    'x25519_mlkem512', 'x448_mlkem768', 'X25519MLKEM768',
    'SecP256r1MLKEM768', 'SecP384r1MLKEM1024',

    'falcon512', 'falconpadded512', 'falcon1024', 'falconpadded1024',
    'sphincssha2128fsimple', 'sphincssha2128ssimple',
    'sphincssha2192fsimple', 'sphincsshake128fsimple',
    'mayo1', 'mayo2', 'mayo3', 'mayo5',
    'OV_Is_pkc', 'OV_Ip_pkc', 'OV_Is_pkc_skc', 'OV_Ip_pkc_skc',
    'mldsa44', 'mldsa65', 'mldsa87',
    'CROSSrsdp128balanced',
]

# Mapping of algorithms to their approximate security strength in bits (or NIST PQC level)
ALGORITHM_STRENGTHS = {
    'RSA:2048': {'type': 'classical', 'classical_bits': 112, 'notes': 'NIST SP 800-57 Part 1 Rev. 5 equivalent'},
    'RSA:3072': {'type': 'classical', 'classical_bits': 128, 'notes': 'NIST SP 800-57 Part 1 Rev. 5 equivalent'},
    'RSA:4096': {'type': 'classical', 'classical_bits': 140, 'notes': 'NIST SP 800-57 Part 1 Rev. 5 equivalent'},
    'EC:prime256v1': {'type': 'classical', 'classical_bits': 128, 'notes': 'NIST SP 800-57 Part 1 Rev. 5 equivalent (P-256)'},
    'EC:secp384r1': {'type': 'classical', 'classical_bits': 192, 'notes': 'NIST SP 800-57 Part 1 Rev. 5 equivalent (P-384)'},
    'EC:secp521r1': {'type': 'classical', 'classical_bits': 256, 'notes': 'NIST SP 800-57 Part 1 Rev. 5 equivalent (P-521)'},
    'ED25519': {'type': 'classical', 'classical_bits': 128, 'notes': 'Generally considered 128-bit security'},
    'ED448': {'type': 'classical', 'classical_bits': 224, 'notes': 'Generally considered 224-bit security'},
    'rsa3072_falcon512': {'type': 'hybrid', 'classical_bits': 128, 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'rsa3072_falconpadded512': {'type': 'hybrid', 'classical_bits': 128, 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'rsa3072_sphincsha2128fsimple': {'type': 'hybrid', 'classical_bits': 128, 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'rsa3072_sphincsha2128ssimple': {'type': 'hybrid', 'classical_bits': 128, 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'rsa3072_sphincsshake128fsimple': {'type': 'hybrid', 'classical_bits': 128, 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'rsa3072_mldsa44': {'type': 'hybrid', 'classical_bits': 128, 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'rsa3072_mldsa65': {'type': 'hybrid', 'classical_bits': 128, 'pqc_level': 'NIST L3 (AES-192 eq.)'},
    'p256_falcon512': {'type': 'hybrid', 'classical_bits': 128, 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'p256_falconpadded512': {'type': 'hybrid', 'classical_bits': 128, 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'p256_sphincssha2128fsimple': {'type': 'hybrid', 'classical_bits': 128, 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'p256_sphincssha2128ssimple': {'type': 'hybrid', 'classical_bits': 128, 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'p256_sphincsshake128fsimple': {'type': 'hybrid', 'classical_bits': 128, 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'p256_mayo1': {'type': 'hybrid', 'classical_bits': 128, 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'p256_mayo2': {'type': 'hybrid', 'classical_bits': 128, 'pqc_level': 'NIST L3 (AES-192 eq.)'},
    'p256_OV_Is_pkc': {'type': 'hybrid', 'classical_bits': 128, 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'p256_OV_Ip_pkc': {'type': 'hybrid', 'classical_bits': 128, 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'p256_OV_Is_pkc_skc': {'type': 'hybrid', 'classical_bits': 128, 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'p256_OV_Ip_pkc_skc': {'type': 'hybrid', 'classical_bits': 128, 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'p256_frodo640aes': {'type': 'hybrid', 'classical_bits': 128, 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'p256_frodo640shake': {'type': 'hybrid', 'classical_bits': 128, 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'p256_mlkem512': {'type': 'hybrid', 'classical_bits': 128, 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'p256_mldsa44': {'type': 'hybrid', 'classical_bits': 128, 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'p256_mldsa65': {'type': 'hybrid', 'classical_bits': 128, 'pqc_level': 'NIST L3 (AES-192 eq.)'},
    'p384_mayo3': {'type': 'hybrid', 'classical_bits': 192, 'pqc_level': 'NIST L3 (AES-192 eq.)'},
    'p384_sphincssha2192fsimple': {'type': 'hybrid', 'classical_bits': 192, 'pqc_level': 'NIST L3 (AES-192 eq.)'},
    'p384_frodo976aes': {'type': 'hybrid', 'classical_bits': 192, 'pqc_level': 'NIST L3 (AES-192 eq.)'},
    'p384_frodo976shake': {'type': 'hybrid', 'classical_bits': 192, 'pqc_level': 'NIST L3 (AES-192 eq.)'},
    'p384_mlkem768': {'type': 'hybrid', 'classical_bits': 192, 'pqc_level': 'NIST L3 (AES-192 eq.)'},
    'p384_mldsa65': {'type': 'hybrid', 'classical_bits': 192, 'pqc_level': 'NIST L3 (AES-192 eq.)'},
    'p384_mldsa87': {'type': 'hybrid', 'classical_bits': 192, 'pqc_level': 'NIST L5 (AES-256 eq.)'},
    'p521_falcon1024': {'type': 'hybrid', 'classical_bits': 256, 'pqc_level': 'NIST L5 (AES-256 eq.)'},
    'p521_falconpadded1024': {'type': 'hybrid', 'classical_bits': 256, 'pqc_level': 'NIST L5 (AES-256 eq.)'},
    'p521_mayo5': {'type': 'hybrid', 'classical_bits': 256, 'pqc_level': 'NIST L5 (AES-256 eq.)'},
    'p521_frodo1344aes': {'type': 'hybrid', 'classical_bits': 256, 'pqc_level': 'NIST L5 (AES-256 eq.)'},
    'p521_frodo1344shake': {'type': 'hybrid', 'classical_bits': 256, 'pqc_level': 'NIST L5 (AES-256 eq.)'},
    'p521_mlkem1024': {'type': 'hybrid', 'classical_bits': 256, 'pqc_level': 'NIST L5 (AES-256 eq.)'},
    'p521_mldsa87': {'type': 'hybrid', 'classical_bits': 256, 'pqc_level': 'NIST L5 (AES-256 eq.)'},
    'mldsa44_ed25519': {'type': 'hybrid', 'classical_bits': 128, 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'mldsa65_ed25519': {'type': 'hybrid', 'classical_bits': 128, 'pqc_level': 'NIST L3 (AES-192 eq.)'},
    'mldsa87_ed448': {'type': 'hybrid', 'classical_bits': 224, 'pqc_level': 'NIST L5 (AES-256 eq.)'},
    'mlkem512': {'type': 'pqc', 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'mlkem768': {'type': 'pqc', 'pqc_level': 'NIST L3 (AES-192 eq.)'},
    'mlkem1024': {'type': 'pqc', 'pqc_level': 'NIST L5 (AES-256 eq.)'},
    'frodo640aes': {'type': 'pqc', 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'frodo640shake': {'type': 'pqc', 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'frodo976aes': {'type': 'pqc', 'pqc_level': 'NIST L3 (AES-192 eq.)'},
    'frodo976shake': {'type': 'pqc', 'pqc_level': 'NIST L3 (AES-192 eq.)'},
    'frodo1344aes': {'type': 'pqc', 'pqc_level': 'NIST L5 (AES-256 eq.)'},
    'frodo1344shake': {'type': 'pqc', 'pqc_level': 'NIST L5 (AES-256 eq.)'},
    'x25519_mlkem512': {'type': 'hybrid_kem', 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'x448_mlkem768': {'type': 'hybrid_kem', 'pqc_level': 'NIST L3 (AES-192 eq.)'},
    'X25519MLKEM768': {'type': 'hybrid_kem', 'pqc_level': 'NIST L3 (AES-192 eq.)'},
    'SecP256r1MLKEM768': {'type': 'hybrid_kem', 'pqc_level': 'NIST L3 (AES-192 eq.)'},
    'SecP384r1MLKEM1024': {'type': 'hybrid_kem', 'pqc_level': 'NIST L5 (AES-256 eq.)'},
    'falcon512': {'type': 'pqc', 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'falconpadded512': {'type': 'pqc', 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'falcon1024': {'type': 'pqc', 'pqc_level': 'NIST L5 (AES-256 eq.)'},
    'falconpadded1024': {'type': 'pqc', 'pqc_level': 'NIST L5 (AES-256 eq.)'},
    'sphincssha2128fsimple': {'type': 'pqc', 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'sphincssha2128ssimple': {'type': 'pqc', 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'sphincssha2192fsimple': {'type': 'pqc', 'pqc_level': 'NIST L3 (AES-192 eq.)'},
    'sphincsshake128fsimple': {'type': 'pqc', 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'mayo1': {'type': 'pqc', 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'mayo2': {'type': 'pqc', 'pqc_level': 'NIST L3 (AES-192 eq.)'},
    'mayo3': {'type': 'pqc', 'pqc_level': 'NIST L3 (AES-192 eq.)'},
    'mayo5': {'type': 'pqc', 'pqc_level': 'NIST L5 (AES-256 eq.)'},
    'OV_Is_pkc': {'type': 'pqc', 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'OV_Ip_pkc': {'type': 'pqc', 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'OV_Is_pkc_skc': {'type': 'pqc', 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'OV_Ip_pkc_skc': {'type': 'pqc', 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'mldsa44': {'type': 'pqc', 'pqc_level': 'NIST L1 (AES-128 eq.)'},
    'mldsa65': {'type': 'pqc', 'pqc_level': 'NIST L3 (AES-192 eq.)'},
    'mldsa87': {'type': 'pqc', 'pqc_level': 'NIST L5 (AES-256 eq.)'},
    'CROSSrsdp128balanced': {'type': 'pqc', 'pqc_level': 'NIST L1 (AES-128 eq.)'},
}


class ModernQuantKeyApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("QuantKey - OpenSSL Cert & Key Generator")
        self.geometry("900x700")
        self.configure(bg="#1e1e2f")

        # --- Initial check for OpenSSL Path ---
        if not os.path.exists(OPENSSL_PATH):
            messagebox.showerror("Configuration Error",
                                 f"OpenSSL executable not found at:\n{OPENSSL_PATH}\n"
                                 "Please update OPENSSL_PATH in the script to your OpenSSL-Win64\\bin\\openssl.exe location.")
            self.destroy() # Close the application if OpenSSL is not found
            return

        style = ttk.Style(self)
        style.theme_use('clam')

        # --- Style Configurations ---
        style.configure("TButton",
                        padding=8,
                        relief="raised",
                        background="#45475a",
                        foreground="#e0def4",
                        font=("Segoe UI", 10, "bold"))
        style.map("TButton",
                  background=[('active', '#585b70')],
                  relief=[('pressed', 'sunken')])

        style.configure("TLabel",
                        background="#1e1e2f",
                        foreground="#e0def4",
                        font=("Segoe UI", 11))

        style.configure("TCombobox",
                        fieldbackground="#313244",
                        background="#45475a",
                        foreground="#e0def4",
                        padding=5)
        style.map('TCombobox',
                  selectbackground=[('readonly', '#585b70')],
                  selectforeground=[('readonly', '#e0def4')],
                  fieldbackground=[('readonly', '#313244')],
                  background=[('readonly', '#45475a')])

        style.configure("TEntry",
                        fieldbackground="#313244",
                        foreground="#e0def4",
                        padding=5)

        style.configure("TProgressbar",
                        background="#e0def4",
                        troughcolor="#313244",
                        bordercolor="#45475a",
                        lightcolor="#585b70",
                        darkcolor="#2a2d3e")

        # Main frame for all content, which will expand with the window
        main_frame = ttk.Frame(self, padding=15, style="Card.TFrame")
        main_frame.pack(fill=tk.BOTH, expand=True)

        style.configure("Card.TFrame",
                        background="#313244",
                        borderwidth=2,
                        relief="ridge")

        # Title
        title = ttk.Label(main_frame, text="QuantKey - OpenSSL Cert & Key Generator",
                          font=("Segoe UI", 18, "bold"))
        title.pack(pady=(0,15))

        # Inputs frame
        inputs_frame = ttk.Frame(main_frame, style="Card.TFrame")
        inputs_frame.pack(fill=tk.X, pady=5)

        ttk.Label(inputs_frame, text="Algorithm:").grid(row=0, column=0, sticky="w", padx=5, pady=8)
        self.algo_cb = ttk.Combobox(inputs_frame, values=ALGORITHMS, state="readonly", width=55)
        self.algo_cb.set("RSA:2048")
        self.algo_cb.grid(row=0, column=1, sticky="ew", padx=5, pady=8)

        ttk.Label(inputs_frame, text="Common Name (CN):").grid(row=1, column=0, sticky="w", padx=5, pady=8)
        self.cn_entry = ttk.Entry(inputs_frame)
        self.cn_entry.insert(0, "TestCert")
        self.cn_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=8)

        ttk.Label(inputs_frame, text="Days Valid:").grid(row=2, column=0, sticky="w", padx=5, pady=8)
        self.days_entry = ttk.Entry(inputs_frame, width=12)
        self.days_entry.insert(0, "365")
        self.days_entry.grid(row=2, column=1, sticky="w", padx=5, pady=8)

        # OpenSSL Provider selection
        ttk.Label(inputs_frame, text="OpenSSL Provider:").grid(row=3, column=0, sticky="w", padx=5, pady=8)
        self.provider_var = tk.StringVar(value="Auto (Default behavior)")
        self.provider_cb = ttk.Combobox(inputs_frame, textvariable=self.provider_var,
                                         values=["Auto (Default behavior)", "Explicit OQS Provider"],
                                         state="readonly", width=55)
        self.provider_cb.grid(row=3, column=1, sticky="ew", padx=5, pady=8)

        inputs_frame.columnconfigure(1, weight=1)

        # Buttons for generation
        gen_buttons_frame = ttk.Frame(main_frame, style="Card.TFrame")
        gen_buttons_frame.pack(pady=(10, 20))

        self.gen_button = ttk.Button(gen_buttons_frame, text="Generate Single Cert", command=self.generate_single_cert)
        self.gen_button.pack(side="left", padx=5)

        self.run_all_button = ttk.Button(gen_buttons_frame, text="Run All Algorithms", command=self.start_run_all_thread)
        self.run_all_button.pack(side="left", padx=5)

        # Progress bar for "Run All"
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, orient="horizontal", length=200, mode="determinate",
                                            variable=self.progress_var, style="TProgressbar")
        self.progress_bar.pack(fill=tk.X, padx=5, pady=5)
        self.progress_label = ttk.Label(main_frame, text="Progress: 0/0", background="#1e1e2f", foreground="#e0def4")
        self.progress_label.pack(pady=(0,10))


        # Separator
        sep = ttk.Separator(main_frame, orient="horizontal")
        sep.pack(fill="x", pady=10)

        # Files List Label
        ttk.Label(main_frame, text="Generated Files:").pack(anchor="w", padx=5)

        # File listbox with scrollbar
        files_frame = ttk.Frame(main_frame, style="Card.TFrame")
        files_frame.pack(fill=tk.BOTH, expand=True, padx=5)

        self.file_listbox = tk.Listbox(files_frame, height=10, bg="#2a2d3e", fg="#cdd6f4",
                                       selectbackground="#585b70", selectforeground="#f5e0dc",
                                       relief="flat", font=("Consolas", 10))
        self.file_listbox.pack(side="left", fill="both", expand=True)
        self.file_listbox.bind('<Double-Button-1>', self.open_selected_file)

        scrollbar = ttk.Scrollbar(files_frame, orient="vertical", command=self.file_listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.file_listbox.config(yscrollcommand=scrollbar.set)

        # Buttons under list
        btn_frame = ttk.Frame(main_frame, style="Card.TFrame")
        btn_frame.pack(fill="x", pady=8)

        refresh_btn = ttk.Button(btn_frame, text="Refresh List", command=self.refresh_file_list)
        refresh_btn.pack(side="left", padx=10)

        open_folder_btn = ttk.Button(btn_frame, text="Open Folder", command=self.open_output_folder)
        open_folder_btn.pack(side="left")

        # Output console label
        ttk.Label(main_frame, text="Output:", padding=(5,0)).pack(anchor="w", padx=5)

        # Output console - scrolled text
        self.output_text = scrolledtext.ScrolledText(main_frame, height=10, bg="#121212", fg="#e0def4",
                                                     insertbackground="#e0def4", font=("Consolas", 10))
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0,10))

        self.refresh_file_list()

    def refresh_file_list(self):
        """Refreshes the list of generated files in the GUI."""
        self.file_listbox.delete(0, tk.END)
        try:
            files = os.listdir(OUTPUT_FOLDER)
            for f in sorted(files):
                self.file_listbox.insert(tk.END, f)
        except Exception as e:
            self.append_output(f"Error listing files: {e}")

    def open_output_folder(self):
        """Opens the output folder in the system's file explorer."""
        try:
            os.startfile(OUTPUT_FOLDER)
        except Exception as e:
            self.append_output(f"Error opening folder: {e}")

    def open_selected_file(self, event=None):
        """Opens the selected file from the listbox using the default system application."""
        try:
            sel = self.file_listbox.curselection()
            if not sel:
                return
            filename = self.file_listbox.get(sel[0])
            filepath = os.path.join(OUTPUT_FOLDER, filename)
            os.startfile(filepath)
        except Exception as e:
            self.append_output(f"Error opening file: {e}")

    def append_output(self, text):
        """Appends text to the main output console and scrolls to the end."""
        self.output_text.insert(tk.END, text + "\n")
        self.output_text.see(tk.END)

    def _get_strength_message(self, algo_name):
        """
        Constructs a formatted string for the algorithm's security strength.
        Handles cases where 'classical_bits' or 'pqc_level' might not be present.
        """
        strength_info = ALGORITHM_STRENGTHS.get(algo_name, {"type": "unknown", "notes": "Strength not defined in app."})
        strength_msg = ""

        if strength_info['type'] == 'classical':
            strength_msg += f"Security Strength (Classical): {strength_info.get('classical_bits', 'N/A')} bits\n"
            strength_msg += f"Notes: {strength_info.get('notes', 'Based on general cryptographic consensus and NIST guidance.')}\n"
        elif strength_info['type'] == 'pqc':
            strength_msg += f"Security Strength (Post-Quantum): {strength_info.get('pqc_level', 'N/A')}\n"
            strength_msg += f"Notes: {strength_info.get('notes', 'Based on NIST PQC standardization levels (equivalent to AES strength against quantum attacks).')}\n"
        elif strength_info['type'] == 'hybrid' or strength_info['type'] == 'hybrid_kem':
            strength_msg += f"Security Strength (Hybrid Classical/PQC):\n"
            strength_msg += f"  Classical Component: {strength_info.get('classical_bits', 'N/A')} bits\n"
            strength_msg += f"  Post-Quantum Component: {strength_info.get('pqc_level', 'N/A')}\n"
            strength_msg += f"Notes: {strength_info.get('notes', 'Hybrid schemes aim for security against both classical and quantum attacks.')}\n"
        else:
            strength_msg += f"Security Strength: Not available for this algorithm in this tool.\n"
        return strength_msg

    def _execute_openssl_command(self, algo, cn, days, provider_choice):
        """
        Executes the OpenSSL command for a given algorithm and returns detailed results.
        This is a helper function used by both single and "Run All" generation.
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Generate unique filenames based on algo, CN, and timestamp
        safe_algo_name = algo.replace(':', '_').replace('/', '_')
        key_file_name = f"quantkey_{safe_algo_name}_key_{cn}_{timestamp}.pem"
        cert_file_name = f"quantkey_{safe_algo_name}_cert_{cn}_{timestamp}.pem"
        info_file_name = f"{cn}_{safe_algo_name}_{timestamp}_info.txt"

        key_file_path = os.path.join(OUTPUT_FOLDER, key_file_name)
        cert_file_path = os.path.join(OUTPUT_FOLDER, cert_file_name)
        info_file_path = os.path.join(OUTPUT_FOLDER, info_file_name)

        # Base OpenSSL command for certificate generation
        cmd = [
            OPENSSL_PATH,
            'req', # subcommand is at index 1
            '-x509',
            '-newkey', # This will be followed by algo or algorithm type like 'ec'
            # ... other req options ...
        ]

        # Handle specific algorithm types for -newkey and -pkeyopt
        pkeyopt_args = []
        if algo.startswith('EC:'):
            # For EC curves, use 'ec' as the algorithm type and specify the curve with -pkeyopt
            curve_name = algo.split(':')[1]
            cmd.append('ec') # The type of algorithm
            pkeyopt_args.extend(['-pkeyopt', f'ec_paramgen_curve:{curve_name}'])
            pkeyopt_args.extend(['-pkeyopt', 'ec_param_enc:named_curve']) # Ensure named curve encoding
        else:
            # For RSA, ED, and PQC algorithms, the algo string is directly used with -newkey
            cmd.append(algo)

        # Add remaining common options
        cmd.extend([
            '-keyout', key_file_path,
            '-out', cert_file_path,
            '-days', days,
            '-nodes', # No passphrase for the key
            '-subj', f"/CN={cn}"
        ])
        cmd.extend(pkeyopt_args) # Add pkeyopt arguments if any


        # Enhanced OpenSSL Provider Handling
        provider_args_to_insert = []
        if provider_choice == "Explicit OQS Provider":
            # Explicitly load default first, then oqsprovider with its path.
            # Base provider is implicitly loaded by default or via config, but can be added explicitly if needed.
            provider_args_to_insert.extend(['-provider', 'default'])
            provider_args_to_insert.extend(['-provider', 'oqsprovider'])
            # Assuming ossl-modules is next to openssl.exe; adjust if your setup is different.
            provider_args_to_insert.extend(['-provider-path', os.path.join(os.path.dirname(OPENSSL_PATH), 'ossl-modules')])

        # CRUCIAL FIX: Insert provider arguments *after* the subcommand ('req'),
        # but before its specific options like '-x509'.
        # The subcommand ('req') is at index 1. So, insert at index 2.
        if provider_args_to_insert:
            cmd[2:2] = provider_args_to_insert


        result = {
            'success': False,
            'algo': algo,
            'cn': cn,
            'key_file': key_file_name,
            'cert_file': cert_file_name,
            'info_file': info_file_name,
            'command': ' '.join(cmd),
            'stdout': '',
            'stderr': '',
            'returncode': -1,
            'error_message': None,
            'strength_message': self._get_strength_message(algo),
            'provider_choice': provider_choice
        }

        # Add a timeout to prevent indefinite hangs for problematic algorithms
        timeout_seconds = 180 # Increased timeout for potentially long PQC algos

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False, shell=False, timeout=timeout_seconds)
            result['stdout'] = proc.stdout
            result['stderr'] = proc.stderr
            result['returncode'] = proc.returncode

            if proc.returncode != 0:
                result['error_message'] = f"OpenSSL command failed with return code {proc.returncode}"
            else:
                result['success'] = True
                # Write strength info to a separate file
                with open(info_file_path, 'w') as f:
                    f.write(f"--- Cryptographic Certificate/Key Generation Details ---\n\n")
                    f.write(f"Algorithm: {result['algo']}\n")
                    f.write(f"Common Name: {result['cn']}\n")
                    f.write(f"Days Valid: {days}\n")
                    f.write(f"OpenSSL Provider Selected: {result['provider_choice']}\n")
                    f.write(f"Generation Timestamp: {timestamp}\n")
                    f.write(f"Output Folder: {OUTPUT_FOLDER}\n\n")
                    f.write(result['strength_message'])
                    f.write(f"\n--- Full OpenSSL Command Used ---\n")
                    f.write(result['command'] + "\n")
                    f.write(f"\n--- Raw OpenSSL STDOUT ---\n")
                    f.write(result['stdout'])
                    if result['stderr']:
                        f.write(f"\n--- Raw OpenSSL STDERR ---\n")
                        f.write(result['stderr'])

        except FileNotFoundError:
            result['error_message'] = f"Error: OpenSSL executable not found at {OPENSSL_PATH}. Please verify the path."
        except subprocess.TimeoutExpired as e: # Catch the exception object
            result['stdout'] = e.stdout if e.stdout else ""
            result['stderr'] = e.stderr if e.stderr else ""
            result['returncode'] = e.returncode if hasattr(e, 'returncode') else -1
            result['error_message'] = f"OpenSSL command timed out after {timeout_seconds} seconds." \
                                      f" This often indicates a hang or extremely long computation. " \
                                      f"Please check your OpenSSL setup, especially for the '{algo}' algorithm. " \
                                      f"Manual run of the command below is recommended to debug." \
                                      f"\nCommand: {result['command']}"
        except Exception as e:
            result['error_message'] = f"An unexpected error occurred: {e}"

        return result

    def generate_single_cert(self):
        """Handles the generation of a single certificate based on GUI inputs."""
        algo = self.algo_cb.get()
        cn = self.cn_entry.get().strip()
        days = self.days_entry.get().strip()
        provider_choice = self.provider_var.get()

        if not cn:
            messagebox.showwarning("Input Error", "Common Name (CN) cannot be empty.")
            return
        if not days.isdigit():
            messagebox.showwarning("Input Error", "Days Valid must be a number.")
            return

        self.append_output(f"\n--- Generating Single Cert for {algo} (CN: {cn}) ---")
        self.append_output("Please wait...")
        self.update_idletasks() # Update GUI to show "Please wait..."

        result = self._execute_openssl_command(algo, cn, days, provider_choice)

        self.append_output(f"Command: {result['command']}")
        self.append_output(f"STDOUT:\n{result['stdout']}")
        if result['stderr']:
            self.append_output(f"STDERR:\n{result['stderr']}")

        if result['success']:
            self.append_output(f"SUCCESS: Generated key: {result['key_file']}")
            self.append_output(f"SUCCESS: Generated cert: {result['cert_file']}")
            self.append_output(f"SUCCESS: Generated info file: {result['info_file']}")
            self.append_output("\n--- Security Strength Information (Based on 2026 Projections) ---")
            self.append_output(result['strength_message'])
            self.append_output("-----------------------------------------------------------\n")
            messagebox.showinfo("Success", "Self-signed certificate, key, and strength info generated successfully!")
        else:
            self.append_output(f"FAILURE: {result['error_message']}")
            messagebox.showerror("OpenSSL Error", f"Generation failed for {algo}. See output for details.")

        self.refresh_file_list()

    def start_run_all_thread(self):
        """Starts the 'Run All' process in a separate thread to keep the UI responsive."""
        # Disable input and buttons
        self.gen_button.config(state=tk.DISABLED)
        self.run_all_button.config(state=tk.DISABLED)
        self.algo_cb.config(state=tk.DISABLED)
        self.cn_entry.config(state=tk.DISABLED)
        self.days_entry.config(state=tk.DISABLED)
        self.provider_cb.config(state=tk.DISABLED)

        self.output_text.delete('1.0', tk.END) # Clear main output for new run
        self.append_output("Starting 'Run All Algorithms' process...")
        self.progress_bar.config(maximum=len(ALGORITHMS))
        self.progress_var.set(0)
        self.progress_label.config(text=f"Progress: 0/{len(ALGORITHMS)}")

        # Start the intensive task in a new thread
        self.run_all_thread = threading.Thread(target=self._run_all_algorithms_task)
        self.run_all_thread.start()
    
    def _run_all_algorithms_task(self):
        full_log_entries = []
        failed_algos = []  # Track failed algorithms here
        total_algorithms = len(ALGORITHMS)
        successful_generations = 0

        for i, algo in enumerate(ALGORITHMS):
            current_progress = i + 1
            self.after(0, self.append_output, f"\n--- Running: {algo} (Index {i}) ({current_progress}/{total_algorithms}) ---")
            self.after(0, self.progress_var.set, current_progress)
            self.after(0, self.progress_label.config, {'text': f"Progress: {current_progress}/{total_algorithms}"})
            self.after(0, self.update_idletasks)

            cn_for_batch = f"BatchTest_{algo.replace(':', '_').replace('/', '_')}"
            days_for_batch = "7"
            provider_choice_for_batch = "Explicit OQS Provider"

            result = self._execute_openssl_command(algo, cn_for_batch, days_for_batch, provider_choice_for_batch)
            full_log_entries.append(result)

            if result['success']:
                self.after(0, self.append_output, f"STATUS: SUCCESS for {algo}")
                successful_generations += 1
            else:
                self.after(0, self.append_output, f"STATUS: FAILED for {algo} - {result['error_message']}")
                # Append failure with all info needed for the report
                failed_algos.append({
                    'algorithm': algo,
                    'error_message': result.get('error_message', 'No error message'),
                    'returncode': result.get('returncode', 'N/A'),
                    'stderr': result.get('stderr', ''),
                    'command': result.get('command', '')
                })

            time.sleep(0.1)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_filename = f"quantkey_runall_report_{timestamp}.txt"
        report_path = os.path.join(OUTPUT_FOLDER, report_filename)

        with open(report_path, "w") as f:
            f.write("QuantKey Run-All Report\n")
            f.write("========================\n\n")
            f.write(f"Timestamp: {timestamp}\n")
            f.write(f"Total Algorithms Attempted: {total_algorithms}\n")
            f.write(f"Total Failures: {len(failed_algos)}\n\n")

            f.write("List of Failed Algorithms:\n")
            f.write("---------------------------\n")
            for idx, fail in enumerate(failed_algos, 1):
                f.write(f"{idx}. {fail['algorithm']}\n")
                f.write(f"   Return Code: {fail['returncode']}\n")
                f.write(f"   Error: {fail['stderr'].strip() or fail['error_message']}\n")
                f.write(f"   Command: {fail['command']}\n\n")

        final_report_path = report_path
        self.after(0, self.append_output, f"Run-All complete. Failure report saved to: {final_report_path}")
        self.after(0, self.append_output, f"Successfully generated {successful_generations} out of {total_algorithms} algorithms.")
        self.after(0, self.refresh_file_list)
        self.after(0, self.progress_label.config, {'text': f"Completed: {successful_generations}/{total_algorithms}"})

        # Re-enable buttons and inputs from the main thread
        self.after(0, self.gen_button.config, {'state': tk.NORMAL})
        self.after(0, self.run_all_button.config, {'state': tk.NORMAL})
        self.after(0, self.algo_cb.config, {'state': "readonly"})
        self.after(0, self.cn_entry.config, {'state': tk.NORMAL})
        self.after(0, self.days_entry.config, {'state': tk.NORMAL})
        self.after(0, self.provider_cb.config, {'state': "readonly"})

        # Show full log window
        self.after(0, self._show_full_log_window, full_log_entries)


    def _show_full_log_window(self, log_entries):
            """Opens a new Toplevel window to display the aggregated log."""
            log_window = tk.Toplevel(self)
            log_window.title("Full Run Log")
            log_window.geometry("800x600")
            log_window.transient(self) # Make it appear on top of the main window
            log_window.grab_set() # Make it modal

            log_text_widget = scrolledtext.ScrolledText(log_window, bg="#121212", fg="#e0def4",
                                                        insertbackground="#e0def4", font=("Consolas", 10), wrap=tk.WORD)
            log_text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            full_log_content = []
            for entry in log_entries:
                status = "SUCCESS" if entry['success'] else "FAILED"
                log_block = f"===== ALGORITHM: {entry['algo']} (CN: {entry['cn']}) - STATUS: {status} ====="
                log_block += f"\nProvider Choice: {entry['provider_choice']}"
                log_block += f"\nCommand: {entry['command']}"
                log_block += f"\nReturn Code: {entry['returncode']}"
                if entry['error_message']:
                    log_block += f"\nError Message: {entry['error_message']}"
                log_block += f"\n\n--- Security Strength (2026 Level Assessment) ---\n{entry['strength_message']}"
                log_block += f"\n--- OpenSSL STDOUT ---\n{entry['stdout']}"
                if entry['stderr']:
                    log_block += f"\n--- OpenSSL STDERR ---\n{entry['stderr']}"
                log_block += "\n" + "="*80 + "\n\n"
                full_log_content.append(log_block)

            log_text_widget.insert(tk.END, "".join(full_log_content))
            log_text_widget.config(state=tk.DISABLED) # Make read-only

            # Copy to clipboard button
            copy_button = ttk.Button(log_window, text="Copy Log to Clipboard",
                                    command=lambda: self._copy_log_to_clipboard(log_text_widget))
            copy_button.pack(pady=5)

            log_window.protocol("WM_DELETE_WINDOW", lambda: self._on_log_window_close(log_window))
            self.wait_window(log_window) # Wait for the log window to close

    def _copy_log_to_clipboard(self, text_widget):
            """Copies the content of the provided text widget to the clipboard."""
            try:
                content = text_widget.get('1.0', tk.END)
                self.clipboard_clear()
                self.clipboard_append(content)
                messagebox.showinfo("Copy Success", "Log copied to clipboard!", parent=text_widget.winfo_toplevel())
            except Exception as e:
                messagebox.showerror("Copy Error", f"Failed to copy log: {e}", parent=text_widget.winfo_toplevel())

    def _on_log_window_close(self, window):
            """Handles cleanup when the log window is closed."""
            window.destroy()
            self.grab_release() # Release grab on main window




if __name__ == "__main__":
    app = ModernQuantKeyApp()
    if app.winfo_exists(): # Check if app was not destroyed by initial OpenSSL path check
        app.mainloop()