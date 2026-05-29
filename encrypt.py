#!/usr/bin/env python3
"""
Encrypt src/index.html into a self-contained, password-gated index.html.

The committed index.html is AES-256-GCM ciphertext + a WebCrypto decryptor +
a public share card (title / description / og:image / favicon). The readable
content and the password are NOT in the repo — only the encrypted blob and a
random salt/IV. Decryption happens entirely in the visitor's browser.

Usage:
    TMB_SITE_PASSWORD='your-password' python3 encrypt.py
    python3 encrypt.py                 # prompts for the password (hidden)
    python3 encrypt.py src/index.html index.html

Crypto: PBKDF2-HMAC-SHA256 (200k iters) -> 256-bit key -> AES-GCM (96-bit IV,
128-bit tag). Matches WebCrypto's deriveKey + AES-GCM decrypt exactly.
"""
import base64
import getpass
import os
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITERATIONS = 200_000

# Public share metadata — safe to expose; this is the teaser, not the content.
CANONICAL_URL = "https://tmb2027.com/"
OG_IMAGE = "https://tmb2027.com/img/mont-blanc-massif-golden-hour.jpg"
SHARE_TITLE = "Tour du Mont Blanc · September 2027"
SHARE_DESC = "161 km around Mont Blanc. 11 days hut to hut. 6–16 September 2027."


def derive_and_encrypt(plaintext: str, password: str):
    salt = os.urandom(16)
    iv = os.urandom(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
    key = kdf.derive(password.encode("utf-8"))
    ct = AESGCM(key).encrypt(iv, plaintext.encode("utf-8"), None)  # ciphertext||tag
    b64 = lambda b: base64.b64encode(b).decode("ascii")
    return b64(salt), b64(iv), b64(ct)


GATE_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
<title>__TITLE__</title>
<meta name="description" content="__DESC__" />
<meta name="robots" content="noindex, nofollow" />

<meta property="og:type" content="website" />
<meta property="og:url" content="__URL__" />
<meta property="og:title" content="__TITLE__" />
<meta property="og:description" content="__DESC__" />
<meta property="og:image" content="__IMAGE__" />
<meta name="twitter:card" content="summary_large_image" />
<meta name="twitter:title" content="__TITLE__" />
<meta name="twitter:description" content="__DESC__" />
<meta name="twitter:image" content="__IMAGE__" />

<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' fill='%230E0E10'/%3E%3Cpath d='M16 6 L27 26 H5 Z' fill='none' stroke='%23C8A45C' stroke-width='2' stroke-linejoin='round'/%3E%3C/svg%3E" />

<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@300;400&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  *,*::before,*::after{ box-sizing:border-box; }
  html,body{ margin:0; height:100%; }
  body{
    background:
      radial-gradient(ellipse at 50% 28%, rgba(60,60,68,.35), transparent 60%),
      linear-gradient(180deg, #131318 0%, #0E0E10 55%, #0A0A0C 100%), #0E0E10;
    color:#F5F1E8;
    font-family:"Inter", system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
    min-height:100dvh; display:flex; align-items:center; justify-content:center;
    padding:24px; -webkit-font-smoothing:antialiased;
  }
  .gate{ width:100%; max-width:420px; text-align:center; }
  .eyebrow{ font-size:11px; font-weight:500; letter-spacing:.28em; text-transform:uppercase; color:#7A7975; }
  h1{ font-family:"Cormorant Garamond", Georgia, serif; font-weight:300; font-size:clamp(30px,7vw,44px);
      line-height:1.08; margin:18px 0 6px; letter-spacing:-.01em; }
  h1 .sep{ color:#C8A45C; padding:0 .12em; }
  .sub{ color:#7A7975; font-size:13px; letter-spacing:.04em; margin:0 0 36px; }
  .rule{ width:56px; height:1px; background:#C8A45C; opacity:.7; margin:26px auto; }
  form{ display:flex; flex-direction:column; gap:14px; }
  label{ font-size:10px; letter-spacing:.28em; text-transform:uppercase; color:#7A7975; text-align:left; }
  input[type=password]{
    width:100%; background:transparent; border:0; border-bottom:1px solid rgba(245,241,232,.18);
    color:#F5F1E8; font-family:inherit; font-size:16px; padding:12px 2px; outline:none;
    transition:border-color .2s ease; text-align:center; letter-spacing:.12em;
  }
  input[type=password]:focus{ border-color:#C8A45C; }
  button{
    margin-top:10px; background:transparent; color:#F5F1E8; border:1px solid #C8A45C;
    font-family:inherit; font-weight:500; font-size:12px; letter-spacing:.32em; text-transform:uppercase;
    padding:16px; cursor:pointer; transition:background .25s ease, color .25s ease;
  }
  button:hover{ background:#C8A45C; color:#0E0E10; }
  button[disabled]{ opacity:.5; cursor:wait; }
  .err{ min-height:18px; margin-top:6px; color:#E2A06B; font-size:12px; letter-spacing:.02em; opacity:0; transition:opacity .2s ease; }
  .err.show{ opacity:1; }
  .remember{ display:flex; align-items:center; justify-content:center; gap:9px; color:#7A7975; font-size:12px; letter-spacing:.02em; cursor:pointer; margin-top:2px; }
  .remember input{ accent-color:#C8A45C; }
  noscript{ display:block; margin-top:24px; color:#7A7975; font-size:13px; }
</style>
</head>
<body>
  <main class="gate">
    <div class="eyebrow">By invitation</div>
    <h1>Tour du Mont Blanc<span class="sep">·</span>2027</h1>
    <p class="sub">This page is locked. Enter the password from the group.</p>
    <div class="rule"></div>
    <form id="gate-form">
      <label for="pw">Password</label>
      <input id="pw" type="password" autocomplete="current-password" autofocus />
      <label class="remember"><input id="remember" type="checkbox" checked /> Keep me unlocked on this device</label>
      <button id="go" type="submit">Enter</button>
      <div class="err" id="err"></div>
    </form>
    <noscript>This site needs JavaScript to unlock.</noscript>
  </main>

<script>
  var CFG = { salt: "__SALT__", iv: "__IV__", ct: "__CT__", iter: __ITER__ };

  // IIFE — do NOT remove. Keeps this wrapper's top-level vars (form, errBox, btn…)
  // out of global scope. The decrypted page declares its own top-level `const form`
  // / `const errBox`; a global `var` of the same name makes that a SyntaxError that
  // silently aborts the entire site script (dead buttons/tabs). Stay scoped.
  (function(){
  function b64ToBytes(s){
    var bin = atob(s), u = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    return u;
  }
  async function deriveKey(pw){
    var km = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name:"PBKDF2", salt:b64ToBytes(CFG.salt), iterations:CFG.iter, hash:"SHA-256" },
      km, { name:"AES-GCM", length:256 }, false, ["decrypt"]);
  }
  async function decryptWith(pw){
    var key = await deriveKey(pw);
    var buf = await crypto.subtle.decrypt({ name:"AES-GCM", iv:b64ToBytes(CFG.iv) }, key, b64ToBytes(CFG.ct));
    return new TextDecoder().decode(buf);
  }
  function reveal(html){
    // Full re-parse via document.write. Button/tabs work (the gate script is IIFE-scoped,
    // so no global var/const collision). Desktop window-resize won't dynamically reflow,
    // but mobile loads at device-width and renders the correct responsive layout — the
    // accepted trade-off, since the audience answers from phones. (A blob-URL reveal was
    // fully responsive on desktop but failed on mobile Safari, so it was reverted.)
    document.open();
    document.write(html);
    document.close();
  }
  var form = document.getElementById("gate-form");
  var pwInput = document.getElementById("pw");
  var errBox = document.getElementById("err");
  var btn = document.getElementById("go");

  async function attempt(pw, remember, silent){
    try {
      var html = await decryptWith(pw);
      if (remember){ try { localStorage.setItem("tmb_pw", pw); } catch(e){} }
      reveal(html);
    } catch (e){
      try { localStorage.removeItem("tmb_pw"); } catch(_){}
      if (!silent){
        errBox.textContent = "Wrong password.";
        errBox.classList.add("show");
        pwInput.value = ""; pwInput.focus();
        btn.disabled = false; btn.textContent = "Enter";
      }
    }
  }
  form.addEventListener("submit", function(e){
    e.preventDefault();
    errBox.classList.remove("show");
    btn.disabled = true; btn.textContent = "Unlocking…";
    attempt(pwInput.value, document.getElementById("remember").checked, false);
  });
  // Auto-unlock if this browser already holds the password.
  (function(){
    var saved = null;
    try { saved = localStorage.getItem("tmb_pw"); } catch(e){}
    if (saved) attempt(saved, false, true);
  })();
  })();
</script>
</body>
</html>
"""


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "src/index.html"
    out = sys.argv[2] if len(sys.argv) > 2 else "index.html"

    if not os.path.exists(src):
        sys.exit(f"error: source not found: {src}")

    password = os.environ.get("TMB_SITE_PASSWORD") or getpass.getpass("Site password: ")
    if not password:
        sys.exit("error: empty password")

    with open(src, "r", encoding="utf-8") as f:
        plaintext = f.read()

    salt_b64, iv_b64, ct_b64 = derive_and_encrypt(plaintext, password)

    html = (
        GATE_TEMPLATE
        .replace("__TITLE__", SHARE_TITLE)
        .replace("__DESC__", SHARE_DESC)
        .replace("__URL__", CANONICAL_URL)
        .replace("__IMAGE__", OG_IMAGE)
        .replace("__SALT__", salt_b64)
        .replace("__IV__", iv_b64)
        .replace("__ITER__", str(ITERATIONS))
        .replace("__CT__", ct_b64)
    )

    with open(out, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"Encrypted {src} ({len(plaintext):,} chars) -> {out} ({len(html):,} chars)")
    print("The committed file is ciphertext + a share card. Plaintext stays in src/ (git-ignored).")


if __name__ == "__main__":
    main()
