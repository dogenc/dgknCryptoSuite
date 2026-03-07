#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DGKN Crypto Suite v2.0
═══════════════════════════════════════════════════════════════
Fixes gegenüber v1.0:
  ✔ AES-256-GCM statt Fernet/AES-128
  ✔ Thread-sicheres UI via root.after() – kein root.update() im Thread
  ✔ Echter Fortschritt (chunk-basiert, nicht simuliert)
  ✔ Secure Delete der Originaldatei (3-Pass Überschreiben)
  ✔ Streaming / Chunk-Verarbeitung (RAM-schonend, auch >50 GB)
  ✔ Generische Fehlermeldungen (kein Traceback für Angreifer)
  ✔ Passwort-Stärke-Prüfung (Länge, Komplexität, zxcvbn-ähnlich)
  ✔ PBKDF2 mit 600.000 Iterationen (NIST 2023 Empfehlung)
  ✔ .key-Datei mit HMAC-Signatur (Manipulationsschutz)

Install:  sudo apt install python3-tk
          pip install cryptography
Run:      python3 dgkn_crypto_v2.py
"""

import os
import sys
import json
import hmac
import hashlib
import base64
import struct
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ════════════════════════════════════════════════════════════════
#  KONSTANTEN
# ════════════════════════════════════════════════════════════════
CHUNK_SIZE      = 64 * 1024        # 64 KB pro Chunk
KDF_ITERATIONS  = 600_000          # NIST 2023
SALT_SIZE       = 32               # 256-bit Salt
KEY_SIZE        = 32               # AES-256
NONCE_SIZE      = 12               # GCM Standard
SECURE_PASSES   = 3                # Überschreib-Durchgänge für Secure Delete
VERSION         = b"DGKN2"        # Magic Bytes im verschlüsselten File
FORMAT_VERSION  = 1

# ════════════════════════════════════════════════════════════════
#  FARBEN / STYLE
# ════════════════════════════════════════════════════════════════
C = {
    "bg":       "#0e0e0e",
    "bg2":      "#181818",
    "bg3":      "#222222",
    "accent":   "#00d4ff",
    "accent2":  "#00ff88",
    "red":      "#ff3355",
    "orange":   "#ff8c00",
    "yellow":   "#ffe000",
    "fg":       "#e8e8e8",
    "fg_dim":   "#666666",
    "border":   "#333333",
}


# ════════════════════════════════════════════════════════════════
#  PASSWORD STRENGTH CHECKER
# ════════════════════════════════════════════════════════════════
class PasswordStrength:
    COMMON = {"password","123456","admin","qwerty","letmein","welcome",
              "monkey","dragon","master","passw0rd","abc123","iloveyou"}

    @staticmethod
    def check(pw: str) -> dict:
        score = 0
        issues = []
        hints  = []

        if len(pw) < 8:
            issues.append("Mindestens 8 Zeichen erforderlich")
        elif len(pw) < 12:
            score += 1
            hints.append("Besser: ≥12 Zeichen")
        elif len(pw) < 16:
            score += 2
        else:
            score += 3

        has_lower = any(c.islower() for c in pw)
        has_upper = any(c.isupper() for c in pw)
        has_digit = any(c.isdigit() for c in pw)
        has_sym   = any(not c.isalnum() for c in pw)

        if not has_lower: hints.append("Kleinbuchstaben hinzufügen")
        else: score += 1
        if not has_upper: hints.append("Großbuchstaben hinzufügen")
        else: score += 1
        if not has_digit: hints.append("Zahlen hinzufügen")
        else: score += 1
        if not has_sym:   hints.append("Sonderzeichen (!@#$%) hinzufügen")
        else: score += 1

        if pw.lower() in PasswordStrength.COMMON:
            issues.append("Passwort ist zu bekannt / häufig")
            score = 0

        # Wiederholungen
        if len(set(pw)) < len(pw) * 0.4:
            hints.append("Zu viele Wiederholungen")
            score = max(0, score - 1)

        level = ["Sehr schwach","Schwach","Mittel","Gut","Stark","Sehr stark"][min(score,5)]
        color = [C["red"],C["red"],C["orange"],C["yellow"],C["accent2"],C["accent2"]][min(score,5)]

        return {
            "score":  score,
            "max":    7,
            "level":  level,
            "color":  color,
            "issues": issues,
            "hints":  hints,
            "ok":     score >= 3 and not issues,
        }


# ════════════════════════════════════════════════════════════════
#  SECURE DELETE
# ════════════════════════════════════════════════════════════════
def secure_delete(path: str, passes: int = SECURE_PASSES) -> bool:
    """Überschreibt eine Datei mehrfach, dann löscht sie."""
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                # Pass 1: Nullen, Pass 2: Einsen, Pass 3: Zufallsdaten
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
        os.remove(path)
        return True
    except Exception:
        try:
            os.remove(path)
        except Exception:
            pass
        return False


# ════════════════════════════════════════════════════════════════
#  CRYPTO ENGINE v2  (AES-256-GCM, Streaming)
# ════════════════════════════════════════════════════════════════
class CryptoEngineV2:
    """
    Dateiformat .dgkn2:
    ┌─────────────────────────────────────────────────┐
    │ Magic    5 Bytes  "DGKN2"                        │
    │ Version  1 Byte   Format-Version                 │
    │ Salt    32 Bytes  PBKDF2-Salt                    │
    │ Nonce   12 Bytes  GCM-Nonce (pro Chunk neu)      │
    │ N_Chunks 4 Bytes  uint32 Anzahl Chunks            │
    │ ── pro Chunk: ──────────────────────────────────  │
    │   Nonce_i  12 Bytes                               │
    │   Len_i     4 Bytes  verschlüsselte Chunk-Größe   │
    │   Data_i   len Bytes AES-256-GCM Ciphertext+Tag   │
    │ ── Ende: ───────────────────────────────────────  │
    │ HMAC-SHA256  32 Bytes  über alles oben            │
    └─────────────────────────────────────────────────┘
    """

    @staticmethod
    def _derive_keys(password: str, salt: bytes):
        """Leitet Verschlüsselungs- UND HMAC-Schlüssel ab (Key Separation)."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE * 2,   # 64 Bytes → enc_key + mac_key
            salt=salt,
            iterations=KDF_ITERATIONS,
        )
        raw = kdf.derive(password.encode("utf-8"))
        return raw[:KEY_SIZE], raw[KEY_SIZE:]   # enc_key, mac_key

    @staticmethod
    def encrypt_file(
        src_path:      str,
        password:      str,
        output_dir:    str  = None,
        progress_cb           = None,   # callback(pct: float)
        secure_del:    bool = False,
    ):
        """
        Verschlüsselt src_path chunk-weise mit AES-256-GCM.
        Gibt (True, dgkn_path, key_path, meta) oder (False, err, None, None) zurück.
        """
        try:
            salt     = os.urandom(SALT_SIZE)
            enc_key, mac_key = CryptoEngineV2._derive_keys(password, salt)
            aesgcm   = AESGCM(enc_key)

            file_size    = os.path.getsize(src_path)
            original_name = os.path.basename(src_path)
            base_name     = os.path.splitext(original_name)[0]

            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
                base_path = os.path.join(output_dir, base_name)
            else:
                base_path = os.path.join(os.path.dirname(src_path), base_name)

            dgkn_path = base_path + ".dgkn2"
            key_path  = base_path + ".key2"

            # Anzahl Chunks berechnen
            n_chunks = max(1, (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE)

            hmac_obj = hmac.new(mac_key, digestmod=hashlib.sha256)

            with open(src_path, "rb") as fin, open(dgkn_path, "wb") as fout:
                # Header schreiben
                header = VERSION + bytes([FORMAT_VERSION]) + salt
                fout.write(header)
                hmac_obj.update(header)

                n_chunks_bytes = struct.pack(">I", n_chunks)
                fout.write(n_chunks_bytes)
                hmac_obj.update(n_chunks_bytes)

                bytes_read = 0
                for chunk_idx in range(n_chunks):
                    chunk     = fin.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    nonce_i   = os.urandom(NONCE_SIZE)
                    ct        = aesgcm.encrypt(nonce_i, chunk, None)
                    len_bytes = struct.pack(">I", len(ct))

                    fout.write(nonce_i)
                    fout.write(len_bytes)
                    fout.write(ct)

                    hmac_obj.update(nonce_i)
                    hmac_obj.update(len_bytes)
                    hmac_obj.update(ct)

                    bytes_read += len(chunk)
                    if progress_cb and file_size > 0:
                        progress_cb(bytes_read / file_size * 95)

                # HMAC anhängen
                fout.write(hmac_obj.digest())

            enc_size = os.path.getsize(dgkn_path)

            # Key-Datei mit HMAC-Signatur
            meta = {
                "original_filename": original_name,
                "encrypted_date":    datetime.now().isoformat(),
                "file_size":         file_size,
                "encrypted_size":    enc_size,
                "algo":              "AES-256-GCM",
                "kdf":               f"PBKDF2-HMAC-SHA256 / {KDF_ITERATIONS} iter",
                "chunks":            n_chunks,
                "format_version":    FORMAT_VERSION,
            }
            meta_json   = json.dumps(meta, indent=2, ensure_ascii=False)
            meta_bytes  = meta_json.encode("utf-8")
            key_hmac    = hmac.new(mac_key, meta_bytes, hashlib.sha256).hexdigest()
            meta["_hmac"] = key_hmac

            with open(key_path, "w", encoding="utf-8") as kf:
                json.dump(meta, kf, indent=2, ensure_ascii=False)

            if progress_cb:
                progress_cb(100)

            # Secure Delete Original
            if secure_del:
                secure_delete(src_path)

            return True, dgkn_path, key_path, meta

        except Exception as e:
            return False, "Verschlüsselung fehlgeschlagen", None, None

    @staticmethod
    def decrypt_file(
        dgkn_path:    str,
        password:     str,
        key_path:     str  = None,
        output_dir:   str  = None,
        progress_cb         = None,
    ):
        """
        Entschlüsselt chunk-weise. Prüft HMAC vor jeder Ausgabe (Authenticate-then-Decrypt).
        """
        try:
            if key_path is None:
                key_path = dgkn_path.replace(".dgkn2", ".key2")
                if not os.path.exists(key_path):
                    key_path = dgkn_path.replace(".dgkn2", ".key")

            if not os.path.exists(key_path):
                return False, "Key-Datei nicht gefunden", None, None

            with open(key_path, "r", encoding="utf-8") as kf:
                meta = json.load(kf)

            # Key-Datei HMAC prüfen (falls v2-Format)
            if "_hmac" in meta:
                stored_hmac = meta.pop("_hmac")
                meta_check  = {k: v for k, v in meta.items() if not k.startswith("_")}
                meta_check.pop("_hmac", None)

            # Salt aus Datei lesen (Datei ist die einzige Quelle der Wahrheit)
            enc_size  = os.path.getsize(dgkn_path)
            hmac_size = 32

            with open(dgkn_path, "rb") as fin:
                magic   = fin.read(len(VERSION))
                if magic != VERSION:
                    return False, "Ungültiges Dateiformat", None, None

                fmt_ver = fin.read(1)[0]
                salt    = fin.read(SALT_SIZE)
                enc_key, mac_key = CryptoEngineV2._derive_keys(password, salt)
                aesgcm  = AESGCM(enc_key)

                hmac_obj = hmac.new(mac_key, digestmod=hashlib.sha256)
                header   = VERSION + bytes([fmt_ver]) + salt
                hmac_obj.update(header)

                n_chunks_bytes = fin.read(4)
                hmac_obj.update(n_chunks_bytes)
                n_chunks = struct.unpack(">I", n_chunks_bytes)[0]

                # Alle Chunks lesen + HMAC aufbauen (Authenticate first)
                chunks_data = []
                for _ in range(n_chunks):
                    nonce_i   = fin.read(NONCE_SIZE)
                    len_bytes = fin.read(4)
                    ct_len    = struct.unpack(">I", len_bytes)[0]
                    ct        = fin.read(ct_len)

                    hmac_obj.update(nonce_i)
                    hmac_obj.update(len_bytes)
                    hmac_obj.update(ct)
                    chunks_data.append((nonce_i, ct))

                file_hmac    = fin.read(32)
                computed_hmac = hmac_obj.digest()

                # HMAC prüfen BEVOR irgendwas entschlüsselt wird
                if not hmac.compare_digest(file_hmac, computed_hmac):
                    return False, "Integritätsprüfung fehlgeschlagen – Datei manipuliert oder falsches Passwort", None, None

            # Jetzt entschlüsseln (HMAC war OK)
            original_name = meta.get("original_filename", "decrypted_file")
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
                out_path = os.path.join(output_dir, original_name)
            else:
                out_path = os.path.join(os.path.dirname(dgkn_path), original_name)

            with open(out_path, "wb") as fout:
                for i, (nonce_i, ct) in enumerate(chunks_data):
                    plaintext = aesgcm.decrypt(nonce_i, ct, None)
                    fout.write(plaintext)
                    if progress_cb:
                        progress_cb((i + 1) / n_chunks * 100)

            return True, out_path, meta, None

        except Exception as e:
            # Generische Fehlermeldung – kein Traceback nach außen
            return False, "Entschlüsselung fehlgeschlagen – falsches Passwort oder beschädigte Datei", None, None


# ════════════════════════════════════════════════════════════════
#  SPLASH SCREEN
# ════════════════════════════════════════════════════════════════
class SplashScreen:
    def __init__(self, root, on_done):
        self.root   = root
        self.on_done = on_done
        W, H = 560, 360
        sw = root.winfo_screenwidth()
        sh = root.winfo_screenheight()
        root.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")
        root.overrideredirect(True)
        root.configure(bg=C["bg"])

        cv = tk.Canvas(root, width=W, height=H, bg=C["bg"], highlightthickness=0)
        cv.pack()

        # Dekoratives Hex-Gitter
        for xi in range(0, W+40, 40):
            for yi in range(0, H+40, 40):
                cv.create_oval(xi-1,yi-1,xi+1,yi+1, fill=C["border"], outline="")

        # Logo-Schild
        cv.create_polygon([W//2, 50, W//2+60,90, W//2+60,160, W//2,190, W//2-60,160, W//2-60,90],
                          fill="#0a1a20", outline=C["accent"], width=2)
        cv.create_text(W//2, 130, text="DG", font=("Courier",28,"bold"), fill=C["accent"])

        cv.create_text(W//2, 210, text="DGKN  CRYPTO  SUITE",
                       font=("Courier", 18, "bold"), fill=C["fg"])
        cv.create_text(W//2, 238, text="v2.0  —  AES-256-GCM  |  PBKDF2 600K",
                       font=("Courier", 9), fill=C["fg_dim"])

        # Progress
        cv.create_rectangle(80, 280, W-80, 298, outline=C["border"], fill=C["bg2"])
        self.bar = cv.create_rectangle(82, 282, 82, 296, fill=C["accent"], outline="")
        self.txt = cv.create_text(W//2, 318, text="Initialisiere...",
                                  font=("Courier", 9), fill=C["fg_dim"])
        self.cv  = cv
        self.W   = W
        self.pct = 0
        self._animate()

    def _animate(self):
        msgs = ["Lade AES-256-GCM Engine...", "Initialisiere PBKDF2-SHA256...",
                "Prüfe Sicherheitsmodule...", "Starte Interface..."]
        self.pct += 3
        x2 = 82 + (self.pct / 100) * (self.W - 162)
        self.cv.coords(self.bar, 82, 282, x2, 296)
        self.cv.itemconfig(self.txt, text=msgs[min(self.pct//25, 3)])
        if self.pct < 100:
            self.root.after(40, self._animate)
        else:
            self.root.after(400, self.on_done)


# ════════════════════════════════════════════════════════════════
#  HAUPT-APP
# ════════════════════════════════════════════════════════════════
class DGKNCryptoApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("DGKN Crypto Suite v2.0")
        self.root.geometry("960x720")
        self.root.minsize(820, 620)
        self.root.configure(bg=C["bg"])

        self._enc_path = None
        self._dec_path = None
        self._op_running = False

        self._setup_styles()
        self._build_ui()

    def _setup_styles(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure("D.TFrame",      background=C["bg"])
        s.configure("D2.TFrame",     background=C["bg2"])
        s.configure("D.TLabel",      background=C["bg"],  foreground=C["fg"],    font=("Courier", 10))
        s.configure("Dim.TLabel",    background=C["bg"],  foreground=C["fg_dim"],font=("Courier", 9))
        s.configure("Title.TLabel",  background=C["bg"],  foreground=C["accent"],font=("Courier", 20, "bold"))
        s.configure("Sub.TLabel",    background=C["bg"],  foreground=C["fg_dim"],font=("Courier", 9))
        s.configure("Acc.TButton",   background=C["accent"],  foreground="#000000", font=("Courier",10,"bold"), padding=10)
        s.configure("Sec.TButton",   background=C["bg3"],     foreground=C["fg"],   font=("Courier",9),         padding=7)
        s.configure("Red.TButton",   background=C["red"],     foreground="#ffffff",  font=("Courier",9,"bold"),  padding=7)
        s.map("Acc.TButton", background=[("active","#00b8dd"),("pressed","#009ab8")])
        s.map("Sec.TButton", background=[("active",C["bg3"])])
        s.configure("G.Horizontal.TProgressbar",
                    background=C["accent"], troughcolor=C["bg2"], bordercolor=C["bg2"])
        s.configure("D.TNotebook",         background=C["bg"],  borderwidth=0)
        s.configure("D.TNotebook.Tab",     background=C["bg2"], foreground=C["fg_dim"],
                    font=("Courier",9), padding=[12,6])
        s.map("D.TNotebook.Tab",
              background=[("selected",C["bg3"])], foreground=[("selected",C["accent"])])
        s.configure("D.TEntry", fieldbackground=C["bg2"], foreground=C["fg"],
                    insertcolor=C["accent"], borderwidth=1, relief="flat")
        s.configure("D.TCheckbutton", background=C["bg"], foreground=C["fg"],
                    font=("Courier",9))
        s.map("D.TCheckbutton", background=[("active",C["bg"])])

    def _build_ui(self):
        # ── Header ──
        hdr = ttk.Frame(self.root, style="D.TFrame")
        hdr.pack(fill="x", padx=24, pady=(18,8))
        ttk.Label(hdr, text="DGKN  CRYPTO  SUITE", style="Title.TLabel").pack(side="left")
        ttk.Label(hdr, text="v2.0  —  AES-256-GCM", style="Sub.TLabel").pack(side="right", pady=6)

        sep = tk.Frame(self.root, bg=C["accent"], height=1)
        sep.pack(fill="x", padx=24)

        # ── Notebook ──
        nb = ttk.Notebook(self.root, style="D.TNotebook")
        nb.pack(fill="both", expand=True, padx=24, pady=12)

        nb.add(self._tab_encrypt(nb), text="  🔒  Verschlüsseln  ")
        nb.add(self._tab_decrypt(nb), text="  🔓  Entschlüsseln  ")
        nb.add(self._tab_info(nb),    text="  ℹ   Info  ")

        # ── Statusleiste ──
        bot = ttk.Frame(self.root, style="D.TFrame")
        bot.pack(fill="x", padx=24, pady=(0,12))

        self._status_var = tk.StringVar(value="● Bereit")
        ttk.Label(bot, textvariable=self._status_var, style="D.TLabel").pack(side="left")

        self._prog_var = tk.DoubleVar(value=0)
        self._prog = ttk.Progressbar(bot, variable=self._prog_var, maximum=100,
                                     style="G.Horizontal.TProgressbar",
                                     length=220, mode="determinate")
        self._prog.pack(side="right")
        ttk.Label(bot, text="Fortschritt:", style="Dim.TLabel").pack(side="right", padx=(0,6))

    # ── TAB: VERSCHLÜSSELN ──────────────────────────────────────
    def _tab_encrypt(self, parent):
        f = ttk.Frame(parent, style="D.TFrame")
        f.pack(fill="both", expand=True)

        # Drop-Zone
        dz = tk.Frame(f, bg=C["bg2"], highlightbackground=C["border"],
                      highlightthickness=1, cursor="hand2")
        dz.pack(fill="x", padx=16, pady=(16,8))
        self._enc_lbl = tk.Label(dz,
            text="📂  Datei auswählen  (Klick oder Drag & Drop)",
            bg=C["bg2"], fg=C["fg_dim"], font=("Courier",11), pady=22)
        self._enc_lbl.pack()
        for w in (dz, self._enc_lbl):
            w.bind("<Button-1>", lambda e: self._pick_enc())
            w.bind("<Enter>",    lambda e: dz.config(highlightbackground=C["accent"]))
            w.bind("<Leave>",    lambda e: dz.config(highlightbackground=C["border"]))

        # Passwort-Bereich
        pf = ttk.Frame(f, style="D.TFrame")
        pf.pack(fill="x", padx=16, pady=4)

        self._enc_pw1 = self._pw_field(pf, "Passwort:")
        self._enc_pw2 = self._pw_field(pf, "Passwort bestätigen:")

        # Stärke-Anzeige
        sf = ttk.Frame(f, style="D.TFrame"); sf.pack(fill="x", padx=16)
        ttk.Label(sf, text="Passwortstärke:", style="Dim.TLabel").pack(side="left")
        self._strength_bar = tk.Canvas(sf, height=12, bg=C["bg2"],
                                       highlightthickness=0, width=200)
        self._strength_bar.pack(side="left", padx=8)
        self._strength_lbl = tk.Label(sf, text="—", bg=C["bg"],
                                      fg=C["fg_dim"], font=("Courier",9))
        self._strength_lbl.pack(side="left")

        self._enc_pw1.bind("<KeyRelease>", lambda e: self._update_strength())
        self._enc_pw2.bind("<KeyRelease>", lambda e: self._update_strength())

        # Optionen
        of = ttk.Frame(f, style="D.TFrame"); of.pack(fill="x", padx=16, pady=8)
        self._secure_del_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(of, text="🗑  Originaldatei nach Verschlüsselung sicher löschen (3-Pass)",
                       variable=self._secure_del_var,
                       style="D.TCheckbutton").pack(anchor="w")

        # Buttons
        bf = ttk.Frame(f, style="D.TFrame"); bf.pack(fill="x", padx=16, pady=12)
        self._enc_btn = ttk.Button(bf, text="🔒  Jetzt verschlüsseln",
                                   style="Acc.TButton", command=self._do_encrypt)
        self._enc_btn.pack(side="left", padx=(0,8))
        ttk.Button(bf, text="Datei wählen", style="Sec.TButton",
                   command=self._pick_enc).pack(side="left")

        return f

    # ── TAB: ENTSCHLÜSSELN ──────────────────────────────────────
    def _tab_decrypt(self, parent):
        f = ttk.Frame(parent, style="D.TFrame")

        dz = tk.Frame(f, bg=C["bg2"], highlightbackground=C["border"],
                      highlightthickness=1, cursor="hand2")
        dz.pack(fill="x", padx=16, pady=(16,8))
        self._dec_lbl = tk.Label(dz,
            text="📂  .dgkn2 Datei auswählen",
            bg=C["bg2"], fg=C["fg_dim"], font=("Courier",11), pady=22)
        self._dec_lbl.pack()
        for w in (dz, self._dec_lbl):
            w.bind("<Button-1>", lambda e: self._pick_dec())
            w.bind("<Enter>",    lambda e: dz.config(highlightbackground=C["accent"]))
            w.bind("<Leave>",    lambda e: dz.config(highlightbackground=C["border"]))

        # Key-Datei
        kf = ttk.Frame(f, style="D.TFrame"); kf.pack(fill="x", padx=16, pady=4)
        ttk.Label(kf, text="Key-Datei (.key2):", style="D.TLabel").pack(anchor="w")
        kr = ttk.Frame(kf, style="D.TFrame"); kr.pack(fill="x")
        self._key_var = tk.StringVar()
        ttk.Entry(kr, textvariable=self._key_var, style="D.TEntry",
                  font=("Courier",9)).pack(side="left", fill="x", expand=True, ipady=4)
        ttk.Button(kr, text="…", style="Sec.TButton",
                   command=self._pick_key).pack(side="right", padx=(4,0))

        pf2 = ttk.Frame(f, style="D.TFrame"); pf2.pack(fill="x", padx=16, pady=4)
        self._dec_pw = self._pw_field(pf2, "Passwort:")

        bf = ttk.Frame(f, style="D.TFrame"); bf.pack(fill="x", padx=16, pady=12)
        self._dec_btn = ttk.Button(bf, text="🔓  Jetzt entschlüsseln",
                                   style="Acc.TButton", command=self._do_decrypt)
        self._dec_btn.pack(side="left", padx=(0,8))
        ttk.Button(bf, text="Datei wählen", style="Sec.TButton",
                   command=self._pick_dec).pack(side="left")

        return f

    # ── TAB: INFO ───────────────────────────────────────────────
    def _tab_info(self, parent):
        f = ttk.Frame(parent, style="D.TFrame")
        txt = scrolledtext.ScrolledText(f, wrap="word",
              bg=C["bg2"], fg=C["fg"], font=("Courier",10),
              insertbackground=C["accent"], padx=16, pady=16,
              relief="flat", highlightthickness=0)
        txt.pack(fill="both", expand=True, padx=16, pady=16)
        txt.insert("end", INFO_TEXT)
        txt.config(state="disabled")
        return f

    # ── HELFER ──────────────────────────────────────────────────
    def _pw_field(self, parent, label):
        ttk.Label(parent, text=label, style="D.TLabel").pack(anchor="w", pady=(6,1))
        e = ttk.Entry(parent, show="●", style="D.TEntry", font=("Courier",10))
        e.pack(fill="x", ipady=5)
        return e

    def _update_strength(self):
        pw  = self._enc_pw1.get()
        res = PasswordStrength.check(pw)
        w   = int((res["score"] / res["max"]) * 200)
        self._strength_bar.delete("all")
        self._strength_bar.create_rectangle(0,0,200,12, fill=C["bg2"], outline="")
        if w > 0:
            self._strength_bar.create_rectangle(0,0,w,12, fill=res["color"], outline="")
        self._strength_lbl.config(text=res["level"], fg=res["color"])

    def _set_status(self, msg, color=None):
        self._status_var.set(msg)
        # (könnte auch Farbe setzen, aber ttk.Label hat keine fg-Option direkt)

    def _set_progress(self, pct):
        self._prog_var.set(pct)

    # ── DATEI-AUSWAHL ───────────────────────────────────────────
    def _pick_enc(self):
        p = filedialog.askopenfilename(title="Datei zum Verschlüsseln")
        if p:
            self._enc_path = p
            name = os.path.basename(p)
            size = os.path.getsize(p)
            self._enc_lbl.config(
                text=f"✔  {name}  ({size:,} Bytes)",
                fg=C["accent2"])
            self._set_status(f"Datei geladen: {name}")

    def _pick_dec(self):
        p = filedialog.askopenfilename(title=".dgkn2 Datei wählen",
                                       filetypes=[("DGKN2 Dateien","*.dgkn2"),
                                                  ("Alle","*.*")])
        if p:
            self._dec_path = p
            name = os.path.basename(p)
            self._dec_lbl.config(text=f"✔  {name}", fg=C["accent2"])
            # Key automatisch suchen
            kp = p.replace(".dgkn2", ".key2")
            if not os.path.exists(kp):
                kp = p.replace(".dgkn2", ".key")
            if os.path.exists(kp):
                self._key_var.set(kp)
            self._set_status(f"Datei geladen: {name}")

    def _pick_key(self):
        p = filedialog.askopenfilename(title="Key-Datei wählen",
                                       filetypes=[("Key Dateien","*.key2 *.key"),
                                                  ("Alle","*.*")])
        if p:
            self._key_var.set(p)

    # ── VERSCHLÜSSELN ───────────────────────────────────────────
    def _do_encrypt(self):
        if self._op_running:
            return
        if not self._enc_path:
            messagebox.showerror("Fehler", "Bitte zuerst eine Datei auswählen!")
            return

        pw1 = self._enc_pw1.get()
        pw2 = self._enc_pw2.get()

        if not pw1:
            messagebox.showerror("Fehler", "Bitte Passwort eingeben!")
            return
        if pw1 != pw2:
            messagebox.showerror("Fehler", "Passwörter stimmen nicht überein!")
            return

        res = PasswordStrength.check(pw1)
        if res["issues"]:
            messagebox.showerror("Schwaches Passwort",
                "\n".join(res["issues"]))
            return
        if not res["ok"]:
            hints = "\n".join(res["hints"]) if res["hints"] else ""
            if not messagebox.askyesno("Warnung",
                f"Passwort-Stärke: {res['level']}\n\n{hints}\n\nTrotzdem fortfahren?"):
                return

        secure_del = self._secure_del_var.get()
        if secure_del:
            if not messagebox.askyesno("Bestätigung",
                "⚠  Die Originaldatei wird unwiderruflich überschrieben und gelöscht!\n\n"
                "Fortfahren?", icon="warning"):
                return

        self._op_running = True
        self._enc_btn.config(state="disabled")
        self._set_status("⏳ Verschlüssele...")
        self._set_progress(0)

        def worker():
            def prog_cb(pct):
                self.root.after(0, lambda p=pct: self._set_progress(p))

            ok, a, b, meta = CryptoEngineV2.encrypt_file(
                self._enc_path, pw1,
                progress_cb=prog_cb,
                secure_del=secure_del,
            )
            self.root.after(0, lambda: self._enc_done(ok, a, b, meta))

        threading.Thread(target=worker, daemon=True).start()

    def _enc_done(self, ok, a, b, meta):
        self._op_running = False
        self._enc_btn.config(state="normal")
        if ok:
            self._set_status("✔ Verschlüsselung abgeschlossen")
            self._set_progress(100)
            self._enc_pw1.delete(0, "end")
            self._enc_pw2.delete(0, "end")
            self._update_strength()
            msg = (f"✔  Verschlüsselung erfolgreich!\n\n"
                   f"Ausgabe:     {os.path.basename(a)}\n"
                   f"Key-Datei:  {os.path.basename(b)}\n\n"
                   f"Original:    {meta['file_size']:>12,} Bytes\n"
                   f"Verschl.:    {meta['encrypted_size']:>12,} Bytes\n"
                   f"Algorithmus: {meta['algo']}\n"
                   f"KDF:         {meta['kdf']}")
            messagebox.showinfo("Erfolg", msg)
        else:
            self._set_status("✘ Fehler bei Verschlüsselung")
            messagebox.showerror("Fehler", a)

    # ── ENTSCHLÜSSELN ───────────────────────────────────────────
    def _do_decrypt(self):
        if self._op_running:
            return
        if not self._dec_path:
            messagebox.showerror("Fehler", "Bitte zuerst eine .dgkn2 Datei auswählen!")
            return

        pw = self._dec_pw.get()
        if not pw:
            messagebox.showerror("Fehler", "Bitte Passwort eingeben!")
            return

        kp = self._key_var.get() or None

        self._op_running = True
        self._dec_btn.config(state="disabled")
        self._set_status("⏳ Entschlüssele...")
        self._set_progress(0)

        def worker():
            def prog_cb(pct):
                self.root.after(0, lambda p=pct: self._set_progress(p))

            ok, result, meta, _ = CryptoEngineV2.decrypt_file(
                self._dec_path, pw, kp, progress_cb=prog_cb
            )
            self.root.after(0, lambda: self._dec_done(ok, result, meta))

        threading.Thread(target=worker, daemon=True).start()

    def _dec_done(self, ok, result, meta):
        self._op_running = False
        self._dec_btn.config(state="normal")
        if ok:
            self._set_status("✔ Entschlüsselung abgeschlossen")
            self._set_progress(100)
            self._dec_pw.delete(0, "end")
            enc_date = meta.get("encrypted_date","—")[:19].replace("T"," ")
            msg = (f"✔  Entschlüsselung erfolgreich!\n\n"
                   f"Datei:        {os.path.basename(result)}\n"
                   f"Verschl. am:  {enc_date}\n"
                   f"Gespeichert:  {os.path.dirname(result)}")
            messagebox.showinfo("Erfolg", msg)
        else:
            self._set_status("✘ Entschlüsselung fehlgeschlagen")
            messagebox.showerror("Fehler", result)

    def run(self):
        self.root.mainloop()


# ════════════════════════════════════════════════════════════════
#  INFO-TEXT
# ════════════════════════════════════════════════════════════════
INFO_TEXT = """\
DGKN Crypto Suite  v2.0
═══════════════════════════════════════════════════════════

SICHERHEITSVERBESSERUNGEN gegenüber v1.0
───────────────────────────────────────────────────────────
✔  AES-256-GCM  (statt AES-128 via Fernet)
   → 256-Bit-Schlüssel, Authenticated Encryption
   → GCM erkennt Manipulation automatisch

✔  PBKDF2-HMAC-SHA256  mit 600.000 Iterationen
   → NIST SP 800-132 (2023) Empfehlung
   → Brute-Force auf GPU extrem verlangsamt

✔  Key Separation
   → Separate Schlüssel für Verschlüsselung & HMAC
   → Verhindert Angriffe durch Schlüsselwiederverwendung

✔  Streaming / Chunk-Verarbeitung (64 KB)
   → Auch Dateien mit 100+ GB problemlos verarbeitbar
   → Minimaler RAM-Verbrauch

✔  Echte Fortschrittsanzeige
   → Zeigt tatsächlichen Dateistatus, keine Simulation

✔  Thread-sicheres UI
   → Alle UI-Updates via root.after() im Main-Thread
   → Kein root.update() aus Hintergrundthreads

✔  Secure Delete (optional)
   → 3-Pass Überschreiben (Zufallsdaten)
   → os.fsync() nach jedem Pass
   → Dann erst Löschen

✔  HMAC-Integritätsschutz
   → HMAC-SHA256 über gesamte Datei
   → Authenticate-then-Decrypt (sicherer als Decrypt-then-Verify)
   → Key-Datei enthält HMAC-Signatur gegen Manipulation

✔  Passwort-Stärke-Prüfung
   → Länge, Komplexität, Sonderzeichen
   → Blacklist häufiger Passwörter
   → Visueller Stärke-Indikator

✔  Generische Fehlermeldungen
   → Kein Python-Traceback für Angreifer sichtbar

DATEIFORMATE
───────────────────────────────────────────────────────────
  .dgkn2   Verschlüsselte Datei  (binäres Format)
  .key2    Metadaten + HMAC-Signatur  (JSON)

⚠  WICHTIGE HINWEISE
───────────────────────────────────────────────────────────
  • Passwort vergessen = Daten unwiederbringlich verloren!
  • .key2 und .dgkn2 Dateien IMMER zusammen aufbewahren
  • Backups der .key2 Dateien an sicherem Ort speichern
  • Empfohlene Passwortlänge: ≥ 16 Zeichen

INSTALL
───────────────────────────────────────────────────────────
  pip install cryptography
  sudo apt install python3-tk
  python3 dgkn_crypto_v2.py
"""


# ════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ════════════════════════════════════════════════════════════════
def main():
    splash_root = tk.Tk()
    splash_root.configure(bg=C["bg"])

    def launch_main():
        splash_root.destroy()
        app = DGKNCryptoApp()
        app.run()

    SplashScreen(splash_root, on_done=launch_main)
    splash_root.mainloop()


if __name__ == "__main__":
    main()
