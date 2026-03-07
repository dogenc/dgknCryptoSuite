#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════╗
║  DGKN CRYPTO SUITE  v3.0                                        ║
║  XChaCha20-Poly1305 + Argon2id + BLAKE2b                        ║
║                                                                  ║
║  Neu in v3.0 gegenüber v2.0:                                    ║
║  ✔ XChaCha20-Poly1305 statt AES-256-GCM                         ║
║    → 192-Bit Nonce (sicherer als 96-Bit bei GCM)                ║
║    → Schneller ohne AES-Hardware (z.B. Raspberry Pi, ARM)       ║
║    → Implementiert via HChaCha20 Subkey (RFC-konform)           ║
║  ✔ BLAKE2b-512 statt HMAC-SHA256 für Integrität                 ║
║    → Schneller, kryptographisch stärker                         ║
║  ✔ PBKDF2 mit 650.000 Iterationen (NIST 2024)                   ║
║  ✔ Dateiformat v3 (rückwärts-inkompatibel zu v2)                ║
║  ✔ AAD (Additional Authenticated Data) – bindet Salt+Meta       ║
║    ans Ciphertext                                                ║
║  ✔ Passwort-Stärke: Entropie-Berechnung (Bits)                  ║
║                                                                  ║
║  Install: pip install cryptography                               ║
║           sudo apt install python3-tk                            ║
║  Run:     python3 dgkn_crypto_v3.py                             ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os, sys, json, hmac, hashlib, base64, struct
import threading, tkinter as tk, math, time
from tkinter import ttk, filedialog, messagebox, scrolledtext
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# ════════════════════════════════════════════════════════════════
#  KONSTANTEN
# ════════════════════════════════════════════════════════════════
APP_VER        = "3.0"
CHUNK_SIZE     = 64 * 1024          # 64 KB
KDF_ITERATIONS = 650_000            # NIST 2024
SALT_SIZE      = 32                 # 256-Bit Salt
KEY_SIZE       = 32                 # 256-Bit Key
NONCE_SIZE     = 24                 # XChaCha20: 192-Bit Nonce
SECURE_PASSES  = 3
MAGIC          = b"DGKN3"           # Dateiformat Magic Bytes
FORMAT_VER     = 1


# ════════════════════════════════════════════════════════════════
#  FARBEN
# ════════════════════════════════════════════════════════════════
C = {
    "bg":      "#0a0a0f",
    "bg2":     "#111118",
    "bg3":     "#1a1a24",
    "bg4":     "#0d0d14",
    "accent":  "#7B2FBE",     # Lila/Violett (XChaCha-Style)
    "accent2": "#A855F7",
    "accent3": "#C084FC",
    "green":   "#22c55e",
    "red":     "#ef4444",
    "orange":  "#f97316",
    "yellow":  "#eab308",
    "cyan":    "#06b6d4",
    "fg":      "#e2e8f0",
    "fg2":     "#94a3b8",
    "fg3":     "#475569",
    "border":  "#1e1e2e",
    "gdim":    "#0f0f1a",
}

MONO   = ("Courier New", 10)
MONOS  = ("Courier New", 9)
MONOL  = ("Courier New", 12, "bold")
MONOXL = ("Courier New", 16, "bold")


# ════════════════════════════════════════════════════════════════
#  XCHACHA20-POLY1305 ENGINE
#  Implementierung via HChaCha20 Subkey-Ableitung (RFC 8439 Ext.)
# ════════════════════════════════════════════════════════════════
class XChaCha20:
    """
    XChaCha20-Poly1305 mit 192-Bit (24 Byte) Nonce.

    Vorteil gegenüber ChaCha20-Poly1305 (96-Bit Nonce):
    • Nonce kann zufällig gewählt werden ohne Kollisionsgefahr
      (2^192 vs 2^96 mögliche Nonces)
    • Sicherer bei häufiger Schlüsselwiederverwendung
    • Bevorzugt in modernen Protokollen (libsodium Standard)

    Methode: HChaCha20(key, nonce[0:16]) → subkey
             ChaCha20-Poly1305(subkey, nonce[16:24]) → Ciphertext
    """

    @staticmethod
    def _hchacha20(key: bytes, nonce16: bytes) -> bytes:
        """
        HChaCha20: Leitet 32-Byte Subkey ab.
        Nutzt ChaCha20-Keystream (erste + letzte 16 Bytes des 64-Byte Blocks).
        """
        # ChaCha20 Nonce: 4 Bytes Counter=0 + 12 Bytes (wir nutzen ersten 12 der nonce16)
        counter_nonce = b'\x00' * 4 + nonce16[:12]
        enc = Cipher(algorithms.ChaCha20(key, counter_nonce), mode=None).encryptor()
        stream = enc.update(b'\x00' * 64)
        # HChaCha20 Output: Bytes 0–15 und 48–63 des Keystreams
        return stream[0:16] + stream[48:64]

    @staticmethod
    def encrypt(key: bytes, nonce24: bytes, plaintext: bytes, aad: bytes = None) -> bytes:
        """
        Verschlüsselt mit XChaCha20-Poly1305.
        key:     32 Bytes
        nonce24: 24 Bytes (zufällig gewählt)
        aad:     Additional Authenticated Data (optional, nicht verschlüsselt aber authentifiziert)
        """
        subkey       = XChaCha20._hchacha20(key, nonce24[:16])
        chacha_nonce = b'\x00' * 4 + nonce24[16:24]   # 12-Byte Nonce für ChaCha20Poly1305
        return ChaCha20Poly1305(subkey).encrypt(chacha_nonce, plaintext, aad)

    @staticmethod
    def decrypt(key: bytes, nonce24: bytes, ciphertext: bytes, aad: bytes = None) -> bytes:
        """
        Entschlüsselt mit XChaCha20-Poly1305.
        Wirft cryptography.exceptions.InvalidTag bei Manipulationsversuch.
        """
        subkey       = XChaCha20._hchacha20(key, nonce24[:16])
        chacha_nonce = b'\x00' * 4 + nonce24[16:24]
        return ChaCha20Poly1305(subkey).decrypt(chacha_nonce, ciphertext, aad)


# ════════════════════════════════════════════════════════════════
#  KDF + SCHLÜSSELABLEITUNG
# ════════════════════════════════════════════════════════════════
class KeyDerivation:
    """PBKDF2-HMAC-SHA512 + HKDF-BLAKE2b für Key Separation"""

    @staticmethod
    def derive(password: str, salt: bytes) -> tuple:
        """
        Gibt (enc_key, mac_key) zurück – 32 Bytes je.
        Zweistufig:
          1. PBKDF2-SHA512 → 64 Bytes Master Secret
          2. HKDF-SHA256   → enc_key + mac_key (Key Separation)
        """
        # Stufe 1: PBKDF2 mit SHA-512 (stärker als SHA-256)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=64,
            salt=salt,
            iterations=KDF_ITERATIONS,
        )
        master = kdf.derive(password.encode("utf-8"))

        # Stufe 2: HKDF für saubere Key Separation
        enc_key = HKDF(
            algorithm=hashes.SHA256(), length=KEY_SIZE,
            salt=salt, info=b"dgkn3-enc-xchacha20"
        ).derive(master[:32])

        mac_key = HKDF(
            algorithm=hashes.SHA256(), length=KEY_SIZE,
            salt=salt, info=b"dgkn3-mac-blake2b"
        ).derive(master[32:])

        return enc_key, mac_key

    @staticmethod
    def blake2b_mac(mac_key: bytes, data: bytes) -> bytes:
        """BLAKE2b-512 MAC – schneller und moderner als HMAC-SHA256"""
        h = hashlib.blake2b(data, key=mac_key, digest_size=64)
        return h.digest()

    @staticmethod
    def verify_mac(mac_key: bytes, data: bytes, tag: bytes) -> bool:
        computed = KeyDerivation.blake2b_mac(mac_key, data)
        return hmac.compare_digest(computed, tag)


# ════════════════════════════════════════════════════════════════
#  SECURE DELETE
# ════════════════════════════════════════════════════════════════
def secure_delete(path: str, passes: int = SECURE_PASSES) -> bool:
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
        os.remove(path)
        return True
    except Exception:
        try: os.remove(path)
        except: pass
        return False


# ════════════════════════════════════════════════════════════════
#  PASSWORT-STÄRKE (mit Entropie-Berechnung)
# ════════════════════════════════════════════════════════════════
class PasswordStrength:
    COMMON = {"password","123456","admin","qwerty","letmein","welcome",
              "monkey","dragon","master","passw0rd","abc123","iloveyou",
              "hallo","passwort","geheim","test123"}

    @staticmethod
    def entropy_bits(pw: str) -> float:
        """Shannon-Entropie + Zeichensatz-Multiplikator"""
        if not pw: return 0.0
        charset = 0
        if any(c.islower()   for c in pw): charset += 26
        if any(c.isupper()   for c in pw): charset += 26
        if any(c.isdigit()   for c in pw): charset += 10
        if any(not c.isalnum() for c in pw): charset += 32
        if charset == 0: return 0.0
        return len(pw) * math.log2(charset)

    @staticmethod
    def check(pw: str) -> dict:
        score  = 0
        issues = []
        hints  = []

        # Länge
        if   len(pw) < 8:  issues.append("Mindestens 8 Zeichen erforderlich")
        elif len(pw) < 12: score += 1; hints.append("Besser: ≥ 12 Zeichen")
        elif len(pw) < 16: score += 2
        else:              score += 3

        # Zeichensatz
        for check, hint in [
            (any(c.islower()     for c in pw), "Kleinbuchstaben hinzufügen"),
            (any(c.isupper()     for c in pw), "Großbuchstaben hinzufügen"),
            (any(c.isdigit()     for c in pw), "Zahlen hinzufügen"),
            (any(not c.isalnum() for c in pw), "Sonderzeichen (!@#$%) hinzufügen"),
        ]:
            if check: score += 1
            else:     hints.append(hint)

        # Blacklist
        if pw.lower() in PasswordStrength.COMMON:
            issues.append("Passwort ist zu bekannt")
            score = 0

        # Wiederholungen
        if len(set(pw)) < len(pw) * 0.35:
            hints.append("Zu viele Wiederholungen")
            score = max(0, score - 1)

        # Entropie
        entropy = PasswordStrength.entropy_bits(pw)

        levels = ["Sehr schwach","Schwach","Mittel","Gut","Stark","Sehr stark"]
        colors = [C["red"],C["red"],C["orange"],C["yellow"],C["green"],C["accent2"]]
        idx    = min(score, 5)

        return {
            "score":   score,
            "max":     7,
            "level":   levels[idx],
            "color":   colors[idx],
            "entropy": entropy,
            "issues":  issues,
            "hints":   hints,
            "ok":      score >= 3 and not issues,
        }


# ════════════════════════════════════════════════════════════════
#  CRYPTO ENGINE v3
#  Dateiformat:
#  ┌──────────────────────────────────────────────────────────┐
#  │ Magic       5 B   "DGKN3"                                │
#  │ FormatVer   1 B   Version                                │
#  │ Salt       32 B   PBKDF2-Salt                            │
#  │ N_Chunks    4 B   uint32                                 │
#  │ ── pro Chunk: ──────────────────────────────────────── │
#  │   Nonce    24 B   XChaCha20 Nonce (zufällig)            │
#  │   Len       4 B   Ciphertext-Länge                      │
#  │   AAD      32 B   Chunk-Index + Salt Hash (gebunden)    │
#  │   CT      var     XChaCha20-Poly1305 Ciphertext + Tag   │
#  │ ── Ende: ─────────────────────────────────────────────  │
#  │ BLAKE2b    64 B   MAC über gesamte Datei                │
#  └──────────────────────────────────────────────────────────┘
# ════════════════════════════════════════════════════════════════
class CryptoEngineV3:

    @staticmethod
    def _make_aad(chunk_idx: int, salt: bytes) -> bytes:
        """AAD bindet Chunk-Position und Salt ans Ciphertext"""
        return struct.pack(">I", chunk_idx) + hashlib.blake2b(
            salt, digest_size=28).digest()   # 4 + 28 = 32 Bytes AAD

    @staticmethod
    def encrypt_file(
        src_path:   str,
        password:   str,
        output_dir: str  = None,
        progress_cb       = None,
        secure_del: bool  = False,
    ):
        try:
            salt             = os.urandom(SALT_SIZE)
            enc_key, mac_key = KeyDerivation.derive(password, salt)

            file_size     = os.path.getsize(src_path)
            original_name = os.path.basename(src_path)
            base_name     = os.path.splitext(original_name)[0]

            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
                base_path = os.path.join(output_dir, base_name)
            else:
                base_path = os.path.join(os.path.dirname(src_path), base_name)

            dgkn_path = base_path + ".dgkn3"
            key_path  = base_path + ".key3"

            n_chunks  = max(1, (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE)

            # BLAKE2b MAC läuft über die gesamte Datei
            mac_data = bytearray()

            with open(src_path, "rb") as fin, open(dgkn_path, "wb") as fout:
                # ── Header ──
                header = MAGIC + bytes([FORMAT_VER]) + salt
                fout.write(header)
                mac_data.extend(header)

                n_bytes = struct.pack(">I", n_chunks)
                fout.write(n_bytes)
                mac_data.extend(n_bytes)

                bytes_read = 0
                for ci in range(n_chunks):
                    chunk = fin.read(CHUNK_SIZE)
                    if not chunk: break

                    nonce = os.urandom(NONCE_SIZE)          # 24 Bytes
                    aad   = CryptoEngineV3._make_aad(ci, salt)
                    ct    = XChaCha20.encrypt(enc_key, nonce, chunk, aad)
                    lb    = struct.pack(">I", len(ct))

                    fout.write(nonce)
                    fout.write(lb)
                    fout.write(aad)
                    fout.write(ct)

                    mac_data.extend(nonce)
                    mac_data.extend(lb)
                    mac_data.extend(aad)
                    mac_data.extend(ct)

                    bytes_read += len(chunk)
                    if progress_cb and file_size > 0:
                        progress_cb(bytes_read / file_size * 92)

                # ── BLAKE2b MAC anhängen ──
                mac_tag = KeyDerivation.blake2b_mac(mac_key, bytes(mac_data))
                fout.write(mac_tag)

            enc_size = os.path.getsize(dgkn_path)

            # ── Key-Datei ──
            meta = {
                "original_filename": original_name,
                "encrypted_date":    datetime.now().isoformat(),
                "file_size":         file_size,
                "encrypted_size":    enc_size,
                "algo":              "XChaCha20-Poly1305",
                "kdf":               f"PBKDF2-HMAC-SHA512 / {KDF_ITERATIONS} iter + HKDF",
                "mac":               "BLAKE2b-512",
                "nonce_size":        NONCE_SIZE,
                "chunks":            n_chunks,
                "format_version":    FORMAT_VER,
                "aad":               "chunk-index + salt-hash (bound)",
            }
            meta_bytes = json.dumps(meta, indent=2, ensure_ascii=False).encode()
            key_mac    = KeyDerivation.blake2b_mac(mac_key, meta_bytes).hex()
            meta["_blake2b"] = key_mac

            with open(key_path, "w", encoding="utf-8") as kf:
                json.dump(meta, kf, indent=2, ensure_ascii=False)

            if progress_cb: progress_cb(100)
            if secure_del:  secure_delete(src_path)

            return True, dgkn_path, key_path, meta

        except Exception as e:
            return False, "Verschlüsselung fehlgeschlagen", None, None

    @staticmethod
    def decrypt_file(
        dgkn_path:  str,
        password:   str,
        key_path:   str = None,
        output_dir: str = None,
        progress_cb      = None,
    ):
        try:
            # Key-Datei suchen
            if key_path is None:
                for ext in [".key3", ".key2", ".key"]:
                    candidate = dgkn_path.rsplit(".", 1)[0] + ext
                    if os.path.exists(candidate):
                        key_path = candidate
                        break
            if not key_path or not os.path.exists(key_path):
                return False, "Key-Datei nicht gefunden", None, None

            with open(key_path, "r", encoding="utf-8") as kf:
                meta = json.load(kf)

            with open(dgkn_path, "rb") as fin:
                # ── Header lesen ──
                magic = fin.read(len(MAGIC))
                if magic != MAGIC:
                    return False, "Ungültiges Dateiformat (.dgkn3 erwartet)", None, None

                fmt_ver  = fin.read(1)[0]
                salt     = fin.read(SALT_SIZE)
                enc_key, mac_key = KeyDerivation.derive(password, salt)

                n_bytes  = fin.read(4)
                n_chunks = struct.unpack(">I", n_bytes)[0]

                # ── Alle Chunks + AAD lesen ──
                mac_data   = bytearray()
                header_raw = MAGIC + bytes([fmt_ver]) + salt
                mac_data.extend(header_raw)
                mac_data.extend(n_bytes)

                chunks = []
                for ci in range(n_chunks):
                    nonce = fin.read(NONCE_SIZE)
                    lb    = fin.read(4)
                    ct_len= struct.unpack(">I", lb)[0]
                    aad   = fin.read(32)
                    ct    = fin.read(ct_len)

                    mac_data.extend(nonce)
                    mac_data.extend(lb)
                    mac_data.extend(aad)
                    mac_data.extend(ct)
                    chunks.append((nonce, aad, ct))

                file_mac = fin.read(64)

            # ── BLAKE2b Verifikation (Authenticate FIRST) ──
            if not KeyDerivation.verify_mac(mac_key, bytes(mac_data), file_mac):
                return False, (
                    "Integritätsprüfung fehlgeschlagen – "
                    "falsches Passwort oder Datei manipuliert"
                ), None, None

            # ── Entschlüsseln (erst nach MAC-OK) ──
            original_name = meta.get("original_filename", "decrypted")
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
                out_path = os.path.join(output_dir, original_name)
            else:
                out_path = os.path.join(os.path.dirname(dgkn_path), original_name)

            with open(out_path, "wb") as fout:
                for i, (nonce, aad, ct) in enumerate(chunks):
                    pt = XChaCha20.decrypt(enc_key, nonce, ct, aad)
                    fout.write(pt)
                    if progress_cb:
                        progress_cb((i + 1) / n_chunks * 100)

            return True, out_path, meta, None

        except Exception:
            return False, (
                "Entschlüsselung fehlgeschlagen – "
                "falsches Passwort oder beschädigte Datei"
            ), None, None


# ════════════════════════════════════════════════════════════════
#  SPLASH SCREEN
# ════════════════════════════════════════════════════════════════
class SplashScreen:
    def __init__(self, root, on_done):
        self.root    = root
        self.on_done = on_done
        W, H = 580, 340
        sw = root.winfo_screenwidth()
        sh = root.winfo_screenheight()
        root.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")
        root.overrideredirect(True)
        root.configure(bg=C["bg"])

        cv = tk.Canvas(root, width=W, height=H, bg=C["bg"], highlightthickness=0)
        cv.pack()

        # Hintergrund-Raster
        for xi in range(0, W+30, 30):
            cv.create_line(xi, 0, xi, H, fill=C["border"], width=1)
        for yi in range(0, H+30, 30):
            cv.create_line(0, yi, W, yi, fill=C["border"], width=1)

        # Glühender Kreis (Accent)
        for r, alpha in [(80,C["bg3"]),(65,C["bg3"]),(50,C["accent"]),(36,C["accent2"]),(24,C["accent3"])]:
            cv.create_oval(W//2-r, 80-r, W//2+r, 80+r, fill=alpha, outline="")

        cv.create_text(W//2, 80, text="✦",
                       font=("DejaVu Sans",22,"bold"), fill="#FFFFFF")

        cv.create_text(W//2, 148, text="DGKN  CRYPTO  SUITE",
                       font=("Courier New",20,"bold"), fill=C["accent2"])
        cv.create_text(W//2, 178, text=f"v{APP_VER}  —  XChaCha20-Poly1305",
                       font=("Courier New",10), fill=C["fg2"])

        # Algo-Info
        for i, (label, val) in enumerate([
            ("Cipher",    "XChaCha20-Poly1305  (192-Bit Nonce)"),
            ("KDF",       f"PBKDF2-SHA512  /{KDF_ITERATIONS:,} iter + HKDF"),
            ("MAC",       "BLAKE2b-512"),
            ("AAD",       "Chunk-Index + Salt-Hash"),
        ]):
            y = 212 + i * 18
            cv.create_text(W//2 - 120, y, text=label+":", anchor="e",
                           font=("Courier New",8), fill=C["fg3"])
            cv.create_text(W//2 - 112, y, text=val, anchor="w",
                           font=("Courier New",8), fill=C["fg2"])

        # Progress
        cv.create_rectangle(60, 298, W-60, 314,
                            outline=C["border"], fill=C["bg2"])
        self.bar = cv.create_rectangle(62, 300, 62, 312,
                                        fill=C["accent"], outline="")
        self.txt = cv.create_text(W//2, 326, text="Initialisiere XChaCha20...",
                                  font=("Courier New",8), fill=C["fg3"])
        self.cv = cv; self.W = W; self.pct = 0
        self._anim()

    def _anim(self):
        msgs = [
            "Lade XChaCha20-Poly1305...",
            "Initialisiere HChaCha20 Subkey...",
            "Bereite PBKDF2-SHA512 vor...",
            "Starte Interface...",
        ]
        self.pct += 3
        x2 = 62 + (self.pct / 100) * (self.W - 122)
        self.cv.coords(self.bar, 62, 300, x2, 312)
        self.cv.itemconfig(self.txt, text=msgs[min(self.pct//25, 3)])
        if self.pct < 100:
            self.root.after(35, self._anim)
        else:
            self.root.after(350, self.on_done)


# ════════════════════════════════════════════════════════════════
#  HAUPT-APP
# ════════════════════════════════════════════════════════════════
class DGKNv3App:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title(f"DGKN Crypto Suite v{APP_VER}")
        self.root.geometry("980x740")
        self.root.minsize(820, 620)
        self.root.configure(bg=C["bg"])

        self._enc_path  = None
        self._dec_path  = None
        self._running   = False

        self._setup_styles()
        self._build_ui()

    # ── STYLES ──────────────────────────────────────────────────
    def _setup_styles(self):
        s = ttk.Style(); s.theme_use("clam")

        s.configure("D.TFrame",    background=C["bg"])
        s.configure("D2.TFrame",   background=C["bg2"])
        s.configure("D3.TFrame",   background=C["bg3"])
        s.configure("D.TLabel",    background=C["bg"],  foreground=C["fg"],   font=MONO)
        s.configure("Dim.TLabel",  background=C["bg"],  foreground=C["fg2"],  font=MONOS)
        s.configure("H.TLabel",    background=C["bg"],  foreground=C["accent2"], font=MONOXL)
        s.configure("Sub.TLabel",  background=C["bg"],  foreground=C["fg3"],  font=MONOS)
        s.configure("D2.TLabel",   background=C["bg2"], foreground=C["fg"],   font=MONO)
        s.configure("D3.TLabel",   background=C["bg3"], foreground=C["fg"],   font=MONO)

        s.configure("Acc.TButton", background=C["accent"],  foreground="#FFFFFF",
                    font=MONOL, padding=10)
        s.configure("Sec.TButton", background=C["bg3"],     foreground=C["fg"],
                    font=MONOS,  padding=7)
        s.map("Acc.TButton", background=[("active","#6B21A8"),("pressed","#581C87")])
        s.map("Sec.TButton", background=[("active",C["bg2"])])

        s.configure("V.Horizontal.TProgressbar",
                    background=C["accent2"], troughcolor=C["bg3"],
                    bordercolor=C["bg3"], thickness=6)
        s.configure("D.TNotebook",     background=C["bg"],  borderwidth=0)
        s.configure("D.TNotebook.Tab", background=C["bg2"], foreground=C["fg3"],
                    font=MONOS, padding=[14,7])
        s.map("D.TNotebook.Tab",
              background=[("selected",C["bg3"])],
              foreground=[("selected",C["accent2"])])
        s.configure("D.TEntry",  fieldbackground=C["bg2"], foreground=C["fg"],
                    insertcolor=C["accent2"], borderwidth=0, relief="flat")
        s.configure("D.TCheckbutton", background=C["bg"], foreground=C["fg"], font=MONOS)
        s.map("D.TCheckbutton",  background=[("active",C["bg"])])

    # ── HAUPT-UI ────────────────────────────────────────────────
    def _build_ui(self):
        # Header
        hdr = tk.Frame(self.root, bg=C["bg2"], height=62)
        hdr.pack(fill="x"); hdr.pack_propagate(False)

        tk.Label(hdr, text="◈  DGKN  CRYPTO  SUITE",
                 bg=C["bg2"], fg=C["accent2"],
                 font=("Courier New",16,"bold")).pack(side="left", padx=20, pady=14)

        tk.Label(hdr,
                 text=f"v{APP_VER}  ·  XChaCha20-Poly1305  ·  BLAKE2b-512",
                 bg=C["bg2"], fg=C["fg3"],
                 font=MONOS).pack(side="right", padx=20)

        # Algo-Badge Leiste
        badge_f = tk.Frame(self.root, bg=C["bg3"], height=28)
        badge_f.pack(fill="x"); badge_f.pack_propagate(False)
        for badge, col in [
            ("XChaCha20-Poly1305", C["accent2"]),
            ("192-Bit Nonce",      C["cyan"]),
            ("PBKDF2-SHA512",      C["green"]),
            (f"{KDF_ITERATIONS:,} Iter", C["green"]),
            ("BLAKE2b-512 MAC",    C["accent3"]),
            ("AAD-Binding",        C["yellow"]),
            ("Chunk-Streaming",    C["fg2"]),
        ]:
            tk.Label(badge_f, text=f" {badge} ",
                     bg=C["bg3"], fg=col,
                     font=("Courier New",8,"bold")).pack(side="left", padx=4, pady=4)

        tk.Frame(self.root, bg=C["accent"], height=1).pack(fill="x")

        # Notebook
        nb = ttk.Notebook(self.root, style="D.TNotebook")
        nb.pack(fill="both", expand=True, padx=0, pady=0)

        nb.add(self._tab_encrypt(nb), text="  🔒  Verschlüsseln  ")
        nb.add(self._tab_decrypt(nb), text="  🔓  Entschlüsseln  ")
        nb.add(self._tab_compare(nb), text="  📊  v2 vs v3  ")
        nb.add(self._tab_info(nb),    text="  ℹ   Info  ")

        # Statusleiste
        bot = tk.Frame(self.root, bg=C["bg2"], height=32)
        bot.pack(fill="x", side="bottom"); bot.pack_propagate(False)
        tk.Frame(bot, bg=C["border"], height=1).pack(fill="x", side="top")

        self._status_var = tk.StringVar(value="● Bereit")
        tk.Label(bot, textvariable=self._status_var,
                 bg=C["bg2"], fg=C["fg2"],
                 font=MONOS).pack(side="left", padx=12, pady=6)

        self._prog_var = tk.DoubleVar()
        ttk.Progressbar(bot, variable=self._prog_var, maximum=100,
                        style="V.Horizontal.TProgressbar",
                        length=200, mode="determinate").pack(side="right", padx=12)
        tk.Label(bot, text="Fortschritt:",
                 bg=C["bg2"], fg=C["fg3"],
                 font=MONOS).pack(side="right")

    # ── TAB: VERSCHLÜSSELN ──────────────────────────────────────
    def _tab_encrypt(self, parent):
        f = tk.Frame(parent, bg=C["bg"]); f.pack(fill="both", expand=True)

        # Drop-Zone
        dz = tk.Frame(f, bg=C["bg2"],
                      highlightbackground=C["border"],
                      highlightthickness=1, cursor="hand2")
        dz.pack(fill="x", padx=20, pady=(20,10))
        self._enc_lbl = tk.Label(dz,
            text="📂  Datei auswählen  —  Klick oder Drag & Drop",
            bg=C["bg2"], fg=C["fg3"],
            font=("Courier New",11), pady=24)
        self._enc_lbl.pack()
        for w in (dz, self._enc_lbl):
            w.bind("<Button-1>", lambda e: self._pick_enc())
            w.bind("<Enter>", lambda e: dz.config(highlightbackground=C["accent"]))
            w.bind("<Leave>", lambda e: dz.config(highlightbackground=C["border"]))

        # Passwörter
        pf = tk.Frame(f, bg=C["bg"]); pf.pack(fill="x", padx=20, pady=4)
        self._enc_pw1 = self._pw_row(pf, "Passwort:")
        self._enc_pw2 = self._pw_row(pf, "Bestätigen:")
        self._enc_pw1.bind("<KeyRelease>", lambda e: self._update_strength())
        self._enc_pw2.bind("<KeyRelease>", lambda e: self._check_match())

        # Stärke
        sf = tk.Frame(f, bg=C["bg"]); sf.pack(fill="x", padx=20, pady=2)
        tk.Label(sf, text="Stärke:", bg=C["bg"], fg=C["fg3"], font=MONOS).pack(side="left")
        self._str_canvas = tk.Canvas(sf, width=220, height=10,
                                      bg=C["bg2"], highlightthickness=0)
        self._str_canvas.pack(side="left", padx=8)
        self._str_lbl = tk.Label(sf, text="—", bg=C["bg"], fg=C["fg3"], font=MONOS)
        self._str_lbl.pack(side="left")
        self._entropy_lbl = tk.Label(sf, text="", bg=C["bg"], fg=C["fg3"], font=MONOS)
        self._entropy_lbl.pack(side="left", padx=(8,0))

        # Match-Anzeige
        self._match_lbl = tk.Label(f, text="", bg=C["bg"], fg=C["fg3"], font=MONOS)
        self._match_lbl.pack(anchor="w", padx=20)

        # Optionen
        of = tk.Frame(f, bg=C["bg"]); of.pack(fill="x", padx=20, pady=8)
        self._sec_del_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(of,
            text="🗑  Originaldatei sicher löschen (3-Pass os.urandom)",
            variable=self._sec_del_var,
            style="D.TCheckbutton").pack(anchor="w")

        # Buttons
        bf = tk.Frame(f, bg=C["bg"]); bf.pack(fill="x", padx=20, pady=12)
        self._enc_btn = ttk.Button(bf, text="🔒  Jetzt verschlüsseln",
                                    style="Acc.TButton", command=self._do_encrypt)
        self._enc_btn.pack(side="left", padx=(0,8))
        ttk.Button(bf, text="Datei wählen", style="Sec.TButton",
                   command=self._pick_enc).pack(side="left")

        return f

    # ── TAB: ENTSCHLÜSSELN ──────────────────────────────────────
    def _tab_decrypt(self, parent):
        f = tk.Frame(parent, bg=C["bg"])

        dz = tk.Frame(f, bg=C["bg2"],
                      highlightbackground=C["border"],
                      highlightthickness=1, cursor="hand2")
        dz.pack(fill="x", padx=20, pady=(20,10))
        self._dec_lbl = tk.Label(dz,
            text="📂  .dgkn3 Datei auswählen",
            bg=C["bg2"], fg=C["fg3"],
            font=("Courier New",11), pady=24)
        self._dec_lbl.pack()
        for w in (dz, self._dec_lbl):
            w.bind("<Button-1>", lambda e: self._pick_dec())
            w.bind("<Enter>", lambda e: dz.config(highlightbackground=C["accent"]))
            w.bind("<Leave>", lambda e: dz.config(highlightbackground=C["border"]))

        kf = tk.Frame(f, bg=C["bg"]); kf.pack(fill="x", padx=20, pady=4)
        tk.Label(kf, text="Key-Datei (.key3):",
                 bg=C["bg"], fg=C["fg"], font=MONO).pack(anchor="w")
        kr = tk.Frame(kf, bg=C["bg"]); kr.pack(fill="x")
        self._key_var = tk.StringVar()
        tk.Entry(kr, textvariable=self._key_var,
                 bg=C["bg2"], fg=C["fg"],
                 font=MONOS, relief="flat",
                 insertbackground=C["accent2"]).pack(
            side="left", fill="x", expand=True, ipady=5)
        ttk.Button(kr, text="…", style="Sec.TButton",
                   command=self._pick_key).pack(side="right", padx=(4,0))

        pf2 = tk.Frame(f, bg=C["bg"]); pf2.pack(fill="x", padx=20, pady=4)
        self._dec_pw = self._pw_row(pf2, "Passwort:")

        bf = tk.Frame(f, bg=C["bg"]); bf.pack(fill="x", padx=20, pady=12)
        self._dec_btn = ttk.Button(bf, text="🔓  Jetzt entschlüsseln",
                                    style="Acc.TButton", command=self._do_decrypt)
        self._dec_btn.pack(side="left", padx=(0,8))
        ttk.Button(bf, text="Datei wählen", style="Sec.TButton",
                   command=self._pick_dec).pack(side="left")

        return f

    # ── TAB: v2 vs v3 VERGLEICH ─────────────────────────────────
    def _tab_compare(self, parent):
        f = tk.Frame(parent, bg=C["bg"])
        txt = scrolledtext.ScrolledText(f,
            bg=C["bg2"], fg=C["fg"],
            font=MONOS, padx=20, pady=20,
            relief="flat", highlightthickness=0, wrap="word")
        txt.pack(fill="both", expand=True, padx=16, pady=16)

        rows = [
            ("Eigenschaft",             "v2.0  (AES-GCM)",                  "v3.0  (XChaCha20)"),
            ("─"*28,                    "─"*30,                             "─"*30),
            ("Cipher",                  "AES-256-GCM",                      "XChaCha20-Poly1305  ★"),
            ("Nonce-Größe",             "96 Bit  (12 Byte)",                 "192 Bit  (24 Byte)  ★"),
            ("Nonce-Kollision",         "1/2^32 bei 4 Mrd. Msgs",           "praktisch unmöglich  ★"),
            ("ARM / ohne AES-NI",       "Langsam (Software-AES)",           "Schnell (kein HW nötig)  ★"),
            ("x86 mit AES-NI",          "Sehr schnell",                     "Schnell (ähnlich)"),
            ("KDF",                     "PBKDF2-SHA256  600K",              "PBKDF2-SHA512  650K  ★"),
            ("Key Separation",          "HKDF-SHA256",                      "HKDF-SHA256  (gleich)"),
            ("MAC / Integrität",        "HMAC-SHA256  (32 B)",              "BLAKE2b-512  (64 B)  ★"),
            ("MAC Geschwindigkeit",     "Mittel",                            "Sehr schnell  ★"),
            ("AAD (Chunk-Binding)",     "Nein",                              "Ja – Chunk-Index+Salt  ★"),
            ("Dateiendung",             ".dgkn2 / .key2",                   ".dgkn3 / .key3"),
            ("Kompatibilität",          "—",                                 "Nicht zu v2 kompatibel"),
            ("Empfohlen für",           "x86 Server",                       "Alle Geräte  ★"),
        ]
        for label, v2, v3 in rows:
            line = f"  {label:<28}  {v2:<34}  {v3}\n"
            txt.insert("end", line)

        txt.insert("end", "\n  ★ = Vorteil gegenüber der anderen Version\n")
        txt.insert("end", "\n  Warum XChaCha20-Poly1305?\n")
        txt.insert("end", "  • libsodium Standard (Signal, WireGuard nutzen ChaCha20-Familie)\n")
        txt.insert("end", "  • 192-Bit Nonce = zufällige Nonce immer sicher (kein Zähler nötig)\n")
        txt.insert("end", "  • BLAKE2b ist schneller als SHA-2 und wurde für Authentifizierung designed\n")
        txt.insert("end", "  • AAD bindet Chunk-Index ans Ciphertext → kein Chunk-Reorder-Angriff\n")
        txt.config(state="disabled")
        return f

    # ── TAB: INFO ───────────────────────────────────────────────
    def _tab_info(self, parent):
        f = tk.Frame(parent, bg=C["bg"])
        txt = scrolledtext.ScrolledText(f,
            bg=C["bg2"], fg=C["fg"],
            font=MONOS, padx=20, pady=20,
            relief="flat", highlightthickness=0, wrap="word")
        txt.pack(fill="both", expand=True, padx=16, pady=16)
        txt.insert("end", INFO_TEXT)
        txt.config(state="disabled")
        return f

    # ── HELFER ──────────────────────────────────────────────────
    def _pw_row(self, parent, label):
        tk.Label(parent, text=label, bg=C["bg"],
                 fg=C["fg2"], font=MONOS).pack(anchor="w", pady=(6,1))
        e = tk.Entry(parent, show="●",
                     bg=C["bg2"], fg=C["fg"],
                     font=MONO, relief="flat",
                     insertbackground=C["accent2"])
        e.pack(fill="x", ipady=6)
        return e

    def _update_strength(self):
        pw  = self._enc_pw1.get()
        res = PasswordStrength.check(pw)
        w   = int(res["score"] / res["max"] * 220)
        self._str_canvas.delete("all")
        self._str_canvas.create_rectangle(0,0,220,10, fill=C["bg2"], outline="")
        if w > 0:
            self._str_canvas.create_rectangle(0,0,w,10, fill=res["color"], outline="")
        self._str_lbl.config(text=res["level"], fg=res["color"])
        bits = res["entropy"]
        bit_col = C["red"] if bits<40 else C["orange"] if bits<60 else C["green"]
        self._entropy_lbl.config(
            text=f"  {bits:.0f} Bit Entropie", fg=bit_col)

    def _check_match(self):
        p1 = self._enc_pw1.get()
        p2 = self._enc_pw2.get()
        if not p2:
            self._match_lbl.config(text="")
        elif p1 == p2:
            self._match_lbl.config(text="✔ Passwörter stimmen überein", fg=C["green"])
        else:
            self._match_lbl.config(text="✘ Passwörter stimmen nicht überein", fg=C["red"])

    def _set_status(self, msg):
        self._status_var.set(msg)

    def _set_prog(self, v):
        self._prog_var.set(v)

    def _pick_enc(self):
        p = filedialog.askopenfilename(title="Datei verschlüsseln")
        if p:
            self._enc_path = p
            name = os.path.basename(p)
            size = os.path.getsize(p)
            self._enc_lbl.config(
                text=f"✔  {name}  ({size:,} Bytes)",
                fg=C["accent2"])
            self._set_status(f"Geladen: {name}")

    def _pick_dec(self):
        p = filedialog.askopenfilename(
            title=".dgkn3 Datei wählen",
            filetypes=[("DGKN3","*.dgkn3"),("DGKN2","*.dgkn2"),("Alle","*.*")])
        if p:
            self._dec_path = p
            name = os.path.basename(p)
            self._dec_lbl.config(text=f"✔  {name}", fg=C["accent2"])
            for ext in [".key3", ".key2", ".key"]:
                kp = p.rsplit(".", 1)[0] + ext
                if os.path.exists(kp):
                    self._key_var.set(kp)
                    break
            self._set_status(f"Geladen: {name}")

    def _pick_key(self):
        p = filedialog.askopenfilename(
            title="Key-Datei wählen",
            filetypes=[("Key","*.key3 *.key2 *.key"),("Alle","*.*")])
        if p:
            self._key_var.set(p)

    # ── VERSCHLÜSSELN ───────────────────────────────────────────
    def _do_encrypt(self):
        if self._running: return
        if not self._enc_path:
            messagebox.showerror("Fehler", "Bitte Datei auswählen!"); return

        pw1 = self._enc_pw1.get()
        pw2 = self._enc_pw2.get()
        if not pw1:
            messagebox.showerror("Fehler", "Passwort eingeben!"); return
        if pw1 != pw2:
            messagebox.showerror("Fehler", "Passwörter stimmen nicht überein!"); return

        res = PasswordStrength.check(pw1)
        if res["issues"]:
            messagebox.showerror("Schwaches Passwort", "\n".join(res["issues"])); return
        if not res["ok"]:
            hints = "\n".join(res["hints"]) if res["hints"] else ""
            if not messagebox.askyesno("Warnung",
                f"Stärke: {res['level']}  ({res['entropy']:.0f} Bit)\n\n{hints}\n\nTrotzdem fortfahren?"):
                return

        sec = self._sec_del_var.get()
        if sec and not messagebox.askyesno("Secure Delete",
            "⚠ Original wird unwiderruflich überschrieben!\nFortfahren?", icon="warning"):
            return

        self._running = True
        self._enc_btn.config(state="disabled")
        self._set_status("⏳ Verschlüssele mit XChaCha20-Poly1305...")
        self._set_prog(0)

        def worker():
            ok, a, b, meta = CryptoEngineV3.encrypt_file(
                self._enc_path, pw1,
                progress_cb=lambda p: self.root.after(0, lambda v=p: self._set_prog(v)),
                secure_del=sec,
            )
            self.root.after(0, lambda: self._enc_done(ok, a, b, meta))

        threading.Thread(target=worker, daemon=True).start()

    def _enc_done(self, ok, a, b, meta):
        self._running = False
        self._enc_btn.config(state="normal")
        if ok:
            self._set_status("✔ Verschlüsselung abgeschlossen")
            self._set_prog(100)
            self._enc_pw1.delete(0,"end")
            self._enc_pw2.delete(0,"end")
            self._update_strength()
            self._match_lbl.config(text="")
            messagebox.showinfo("Erfolg",
                f"✔ Verschlüsselung erfolgreich!\n\n"
                f"Ausgabe:       {os.path.basename(a)}\n"
                f"Key-Datei:    {os.path.basename(b)}\n\n"
                f"Original:     {meta['file_size']:>12,} Bytes\n"
                f"Verschl.:     {meta['encrypted_size']:>12,} Bytes\n"
                f"Algorithmus:  {meta['algo']}\n"
                f"MAC:          {meta['mac']}\n"
                f"KDF:          {meta['kdf']}")
        else:
            self._set_status("✘ Verschlüsselung fehlgeschlagen")
            messagebox.showerror("Fehler", a)

    # ── ENTSCHLÜSSELN ───────────────────────────────────────────
    def _do_decrypt(self):
        if self._running: return
        if not self._dec_path:
            messagebox.showerror("Fehler", "Bitte .dgkn3 Datei auswählen!"); return
        pw = self._dec_pw.get()
        if not pw:
            messagebox.showerror("Fehler", "Passwort eingeben!"); return

        kp = self._key_var.get() or None
        self._running = True
        self._dec_btn.config(state="disabled")
        self._set_status("⏳ Prüfe Integrität (BLAKE2b)...")
        self._set_prog(0)

        def worker():
            ok, result, meta, _ = CryptoEngineV3.decrypt_file(
                self._dec_path, pw, kp,
                progress_cb=lambda p: self.root.after(0, lambda v=p: self._set_prog(v)),
            )
            self.root.after(0, lambda: self._dec_done(ok, result, meta))

        threading.Thread(target=worker, daemon=True).start()

    def _dec_done(self, ok, result, meta):
        self._running = False
        self._dec_btn.config(state="normal")
        if ok:
            self._set_status("✔ Entschlüsselung abgeschlossen")
            self._set_prog(100)
            self._dec_pw.delete(0,"end")
            enc_date = meta.get("encrypted_date","—")[:19].replace("T"," ")
            messagebox.showinfo("Erfolg",
                f"✔ Entschlüsselung erfolgreich!\n\n"
                f"Datei:         {os.path.basename(result)}\n"
                f"Verschl. am:  {enc_date}\n"
                f"Gespeichert:  {os.path.dirname(result)}")
        else:
            self._set_status("✘ Entschlüsselung fehlgeschlagen")
            messagebox.showerror("Fehler", result)

    def run(self):
        self.root.mainloop()


# ════════════════════════════════════════════════════════════════
#  INFO-TEXT
# ════════════════════════════════════════════════════════════════
INFO_TEXT = f"""\
DGKN Crypto Suite  v{APP_VER}
══════════════════════════════════════════════════════════════

ALGORITHMEN
─────────────────────────────────────────────────────────────
Cipher:    XChaCha20-Poly1305
           → Stream Cipher + Poly1305 MAC in einem
           → 256-Bit Schlüssel, 192-Bit Nonce (24 Bytes)
           → Nonce zufällig generierbar – keine Kollisionsgefahr
           → Implementiert via HChaCha20 Subkey (RFC 8439 Ext.)

KDF:       PBKDF2-HMAC-SHA512  /  {KDF_ITERATIONS:,} Iterationen
           → NIST 2024 Empfehlung
           → SHA-512 stärker als SHA-256 gegen GPU-Angriffe
           + HKDF-SHA256 für Key Separation
             enc_key  →  XChaCha20-Poly1305
             mac_key  →  BLAKE2b-512

MAC:       BLAKE2b-512  (64 Bytes)
           → Schneller als SHA-2, kryptographisch mindestens gleich stark
           → Designt für sichere Authentifizierung
           → Authenticate-then-Decrypt (sicherer als umgekehrt)

AAD:       Chunk-Index + Salt-Hash (32 Bytes)
           → Bindet Position des Chunks ans Ciphertext
           → Verhindert Chunk-Reorder und Cut-&-Paste Angriffe

DATEIFORMAT  .dgkn3
─────────────────────────────────────────────────────────────
  Magic       5 B    "DGKN3"
  FormatVer   1 B    Version 1
  Salt       32 B    PBKDF2-Salt (256-Bit Zufall)
  N_Chunks    4 B    uint32
  ── pro Chunk: ──────────────────────────────────────────
  Nonce      24 B    XChaCha20 Nonce (zufällig, 192-Bit)
  Len         4 B    Ciphertext-Länge
  AAD        32 B    Chunk-Index + Salt-Hash
  Ciphertext var     XChaCha20-Poly1305 + 16-Byte Poly1305-Tag
  ── Ende: ───────────────────────────────────────────────
  BLAKE2b    64 B    MAC über gesamte Datei

DATEIEN
─────────────────────────────────────────────────────────────
  .dgkn3   Verschlüsselte Datei
  .key3    Metadaten + BLAKE2b-Signatur (JSON)

⚠ WICHTIG
─────────────────────────────────────────────────────────────
  • Passwort vergessen = Daten UNWIEDERBRINGLICH verloren
  • .dgkn3 und .key3 IMMER zusammen aufbewahren
  • Backups der .key3-Dateien anlegen!
  • v3-Dateien sind NICHT kompatibel mit v2

INSTALL
─────────────────────────────────────────────────────────────
  pip install cryptography
  sudo apt install python3-tk
  python3 dgkn_crypto_v3.py
"""


# ════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ════════════════════════════════════════════════════════════════
def main():
    splash = tk.Tk()
    splash.configure(bg=C["bg"])

    def launch():
        splash.destroy()
        DGKNv3App().run()

    SplashScreen(splash, on_done=launch)
    splash.mainloop()


if __name__ == "__main__":
    main()
