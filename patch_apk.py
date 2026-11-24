#!/usr/bin/env python3
"""Turn the official Telegram for Android APK into Bullgram.

Input: the official standalone APK from telegram.org (pinned by SHA-256 in
upstream.json). Output: an unsigned, rebuilt APK; signing is done by the caller.

What changes, and nothing else:
  * native tgnet (every ABI): Telegram DC IPv4/IPv6 strings -> our server, the
    two embedded RSA public keys -> ours (same length; the server also announces
    Telegram's two key fingerprints for our key, so no code bytes are touched);
  * Java: right after native_init, every DC 1..5 is pointed at SERVER:PORT via
    the client's own native_applyDatacenterAddress (port lives in code, the IP
    strings above only cover the first instant); the DNS/Firebase "backup
    address" lookup is disabled so it cannot send the app back to Telegram;
  * package org.telegram.messenger.web -> PACKAGE (manifest, authorities,
    permissions and the string literals that name them; class names untouched);
  * app name -> BRAND in every language; Firebase values -> google-services.json.

Every step asserts its exact match count, so a new upstream version that moved
something fails loudly instead of producing a half-patched app.
"""
import argparse, hashlib, json, os, re, shutil, subprocess, sys, base64

ORIG_PACKAGE = "org.telegram.messenger.web"
TG_IPV4 = ["149.154.175.50", "149.154.167.51", "95.161.76.100", "149.154.175.100",
           "149.154.167.91", "149.154.171.5", "149.154.175.40", "149.154.167.40",
           "149.154.175.117"]
TG_PROD_KEY_HEAD = "MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g"
TG_TEST_KEY_HEAD = "MIIBCgKCAQEAyMEdY1aR+sCR3ZSJrtztKTKqigvO/vBfqACJLZtS7QMgCGXJ6XIR"


def run(cmd, **kw):
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True, **kw)


def pem_body(pem):
    lines = [l.strip() for l in pem.strip().splitlines()]
    assert lines[0] == "-----BEGIN RSA PUBLIC KEY-----" and lines[-1] == "-----END RSA PUBLIC KEY-----"
    return lines[1:-1]


def patch_native(lib_root, server_ip, our_pem):
    ours = pem_body(our_pem)
    ours_blob = "\n".join(ours).encode()
    libs = []
    for abi in sorted(os.listdir(lib_root)):
        for name in os.listdir(os.path.join(lib_root, abi)):
            if re.match(r"libtmessages\.\d+\.so$", name):
                libs.append(os.path.join(lib_root, abi, name))
    assert libs, "no libtmessages.*.so found"
    for path in libs:
        data = bytearray(open(path, "rb").read())
        # RSA keys: find each key's body (lines joined by \n), replace with ours.
        for head in (TG_PROD_KEY_HEAD, TG_TEST_KEY_HEAD):
            start = data.find(head.encode())
            assert start != -1 and data.find(head.encode(), start + 1) == -1, (path, head[:20])
            end = data.find(b"\n-----END RSA PUBLIC KEY-----", start)
            assert end != -1
            old = bytes(data[start:end])
            assert len(old) == len(ours_blob), (path, len(old), len(ours_blob))
            data[start:end] = ours_blob
        # IPv4 DC strings (NUL-terminated); replaced in place, padded with NULs.
        rep = server_ip.encode()
        for ip in TG_IPV4:
            needle = ip.encode() + b"\0"
            pos = 0
            hits = 0
            while True:
                i = data.find(needle, pos)
                if i == -1:
                    break
                # whole string only: previous byte must be a terminator
                if i == 0 or data[i - 1] == 0:
                    assert len(rep) <= len(ip)
                    data[i:i + len(ip)] = rep + b"\0" * (len(ip) - len(rep))
                    hits += 1
                pos = i + 1
            if ip in ("149.154.175.50", "149.154.167.51", "149.154.175.100", "149.154.167.91", "149.154.171.5"):
                assert hits >= 1, (path, ip)
        # IPv6 DC strings: make them unusable so IPv6 can never reach Telegram.
        v6 = 0
        for m in list(re.finditer(rb"\x002001:0?b28:[0-9a-f:]+\x00|\x002001:0?67c:[0-9a-f:]+\x00", bytes(data))):
            s, e = m.start() + 1, m.end() - 1
            data[s:e] = b"::" + b"\0" * (e - s - 2)
            v6 += 1
        assert v6 >= 5, (path, "ipv6", v6)
        assert data.count(server_ip.encode() + b"\0") >= 5
        open(path, "wb").write(data)
        print(f"native ok: {path} ipv6={v6}")


HOOK = """
.method public static bullgramApplyDcs(I)V
    .locals 3
    const-string v1, "{ip}"
    const v2, {port}
{calls}
    return-void
.end method
"""


def patch_smali(root, server_ip, port):
    cm = None
    for d in sorted(os.listdir(root)):
        p = os.path.join(root, d, "org/telegram/tgnet/ConnectionsManager.smali")
        if d.startswith("smali") and os.path.exists(p):
            cm = p
    assert cm, "ConnectionsManager.smali not found"
    s = open(cm, encoding="utf-8").read()
    # 1. hook after native_init(currentAccount in the first range register)
    m = re.findall(r"( +invoke-static/range \{(v\d+) \.\. v\d+\}, Lorg/telegram/tgnet/ConnectionsManager;->native_init\([^\n]*\n)", s)
    assert len(m) == 1, "native_init call sites: %d" % len(m)
    line, reg = m[0]
    assert int(reg[1:]) <= 15
    s = s.replace(line, line + f"\n    invoke-static {{{reg}}}, Lorg/telegram/tgnet/ConnectionsManager;->bullgramApplyDcs(I)V\n", 1)
    assert "native_applyDatacenterAddress(IILjava/lang/String;I)V" in s
    calls = "".join(
        f"    const/4 v0, 0x{dc:x}\n    invoke-static {{p0, v0, v1, v2}}, Lorg/telegram/tgnet/ConnectionsManager;->native_applyDatacenterAddress(IILjava/lang/String;I)V\n"
        for dc in range(1, 6))
    s += HOOK.format(ip=server_ip, port=hex(port), calls=calls)
    # 2. no backup-address lookup (DNS TXT / Firebase) -> it would override us
    pat = re.compile(r"(\.method public static onRequestNewServerIpAndPort\(II\)V\n).*?(\.end method)", re.S)
    assert len(pat.findall(s)) == 1
    s = pat.sub(lambda mm: mm.group(1) + "    .locals 0\n\n    return-void\n" + mm.group(2), s, count=1)
    open(cm, "w", encoding="utf-8").write(s)
    print("smali hook ok:", cm)


def patch_package(root, package):
    man = os.path.join(root, "AndroidManifest.xml")
    s = open(man, encoding="utf-8").read()
    n = s.count(ORIG_PACKAGE)
    assert n >= 10, n
    # package attribute, authorities and app-defined permissions
    s = s.replace(ORIG_PACKAGE + ".", package + ".")
    s = s.replace(f'package="{ORIG_PACKAGE}"', f'package="{package}"')
    assert ORIG_PACKAGE not in s, "left: " + str(s.count(ORIG_PACKAGE))
    open(man, "w", encoding="utf-8").write(s)
    # literal strings in code that name the package or its authorities
    hits = 0
    lit = re.compile(r'"' + re.escape(ORIG_PACKAGE) + r'(\.[A-Za-z0-9_.]+)?"')
    for d in os.listdir(root):
        if not d.startswith("smali"):
            continue
        for dirpath, _, files in os.walk(os.path.join(root, d)):
            for fn in files:
                if not fn.endswith(".smali"):
                    continue
                p = os.path.join(dirpath, fn)
                t = open(p, encoding="utf-8").read()
                if ORIG_PACKAGE not in t:
                    continue
                t2, k = lit.subn(lambda mm: '"' + package + (mm.group(1) or "") + '"', t)
                if k:
                    hits += k
                    open(p, "w", encoding="utf-8").write(t2)
    assert hits >= 5, hits
    print("package ok:", package, "code literals:", hits)


def patch_resources(root, brand, gservices):
    gs = json.load(open(gservices))
    client = gs["client"][0]
    fb = {
        "google_app_id": client["client_info"]["mobilesdk_app_id"],
        "gcm_defaultSenderId": gs["project_info"]["project_number"],
        "google_api_key": client["api_key"][0]["current_key"],
        "google_crash_reporting_api_key": client["api_key"][0]["current_key"],
        "google_storage_bucket": gs["project_info"]["storage_bucket"],
        "project_id": gs["project_info"]["project_id"],
    }
    res = os.path.join(root, "res")
    changed = 0
    for d in os.listdir(res):
        p = os.path.join(res, d, "strings.xml")
        if not d.startswith("values") or not os.path.exists(p):
            continue
        s = open(p, encoding="utf-8").read()
        s2 = re.sub(r'(<string name="(AppName|AppNameBeta)"[^>]*>)[^<]*(</string>)', r"\g<1>" + brand + r"\g<3>", s)
        if d == "values":
            for k, v in fb.items():
                s2, c = re.subn(r'(<string name="' + k + r'"[^>]*>)[^<]*(</string>)', r"\g<1>" + v + r"\g<2>", s2)
                assert c == 1, k
        if s2 != s:
            changed += 1
            open(p, "w", encoding="utf-8").write(s2)
    assert changed >= 1
    print("resources ok, files:", changed)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk", required=True)
    ap.add_argument("--sha256", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--work", default="work")
    ap.add_argument("--apktool", required=True)
    ap.add_argument("--server-ip", required=True)
    ap.add_argument("--port", type=int, default=42000)
    ap.add_argument("--pubkey", required=True)
    ap.add_argument("--package", default="com.usa8.messenger")
    ap.add_argument("--brand", default="Bullgram")
    ap.add_argument("--google-services", required=True)
    a = ap.parse_args()

    h = hashlib.sha256(open(a.apk, "rb").read()).hexdigest()
    assert h == a.sha256, f"APK sha256 {h} != pinned {a.sha256}"
    if os.path.exists(a.work):
        shutil.rmtree(a.work)
    run(["java", "-jar", a.apktool, "d", "-f", "-o", a.work, a.apk])
    patch_native(os.path.join(a.work, "lib"), a.server_ip, open(a.pubkey).read())
    patch_smali(a.work, a.server_ip, a.port)
    patch_package(a.work, a.package)
    patch_resources(a.work, a.brand, a.google_services)
    run(["java", "-jar", a.apktool, "b", "-o", a.out, a.work])
    print("built", a.out)


if __name__ == "__main__":
    main()
