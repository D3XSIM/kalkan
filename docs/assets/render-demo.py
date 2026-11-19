"""Renders docs/assets/demo.svg, the animated terminal at the top of the README.

The lines come from a real boot log of a test kernel:

    cargo xtask test --quick
    python docs/assets/render-demo.py target/kalkan-test.log docs/assets/demo.svg

Only the Python standard library is used. Lines are picked by the patterns
below (first match each), coloured, and revealed one after another in a loop.
Viewers that do not animate SVG show the final state.
"""

import html
import re
import sys

# (pattern, seconds before the line appears)
PICK = [
    ("Kalkan v", 0.4),
    ("[boot] bootloader:", 0.25),
    ("Security posture:", 0.35),
    ("] NX (", 0.15),
    ("] SMEP (", 0.15),
    ("] SMAP (", 0.15),
    ("] UMIP (", 0.15),
    ("] W^X kernel image", 0.15),
    ("] KASLR (kernel image)", 0.15),
    ("Boot module integrity", 0.3),
    ("  [PASS] init ", 0.15),
    ("  [PASS] sandbox ", 0.15),
    ("[mm] kernel page tables active", 0.35),
    ("[kernel] root task 'init' ready", 0.45),
    ("[BLOCKED] forge a different badge", 0.6),
    ("[BLOCKED] smuggle a capability over IPC (its console", 0.45),
    ("[BLOCKED] kill the root task", 0.45),
    ("sandbox escape attempts all refused", 0.6),
    ("[PASS] read kernel code", 0.6),
    ("[PASS] overwrite the kernel stack", 0.45),
    ("[PASS] read the kernel through the direct map", 0.45),
    ("[PASS] redirect the system call entry", 0.45),
    ("[PASS] iretq into ring 0", 0.45),
    ("fuzzer: 24000 system calls", 0.7),
    ("[PASS] a server that dies holding a call", 0.6),
    ("[PASS] kill a process blocked in IPC", 0.45),
    ("KALKAN-TEST: PASS", 0.8),
    ("[kernel] audit: object graph consistent", 0.6),
    ("[kernel] system shut down cleanly", 0.4),
]
HOLD = 5.0  # seconds the complete log stays on screen
MAX_CHARS = 128
FONT = 12.5
CHAR_W = FONT * 0.602
LINE_H = 17
PAD = 18
TOP = 38


def shorten(line):
    """Drops detail that does not help a reader (marked with an ellipsis)."""
    line = re.sub(r"errors by code \[[^\]]*\]", "errors by code […]", line)
    line = re.sub(r"consistent \([^)]*\)", "consistent (…)", line)
    if len(line) > MAX_CHARS:
        line = line[: MAX_CHARS - 1] + "…"
    return line


PREFIX = re.compile(r"^(\[(?:init|sandbox|probe\d+|kernel|boot|mm|cpu)\])")
TOKENS = re.compile(r"(\[PASS\]|\[BLOCKED\]|KALKAN-TEST: PASS)")


def spans(line):
    """Splits a line into (css class, text) pieces."""
    out = []
    m = PREFIX.match(line)
    if m:
        tag = m.group(1)
        cls = {
            "[init]": "init",
            "[sandbox]": "sb",
        }.get(tag, "pr" if tag.startswith("[probe") else "dim")
        out.append((cls, tag))
        line = line[len(tag):]
    for part in TOKENS.split(line):
        if not part:
            continue
        if TOKENS.fullmatch(part):
            out.append(("ok", part))
        elif line.startswith("Kalkan v") or part.strip() in ("Security posture:",):
            out.append(("hi", part))
        else:
            out.append(("", part))
    return out


def main(log_path, svg_path):
    raw = open(log_path, encoding="utf-8", errors="replace").read()
    lines = [re.sub(r"\x1b\[[0-9;]*m", "", l).rstrip() for l in raw.splitlines()]
    picked, at, t = [], [], 0.0
    for pattern, delay in PICK:
        line = next((l for l in lines if pattern in l), None)
        if line is None:
            sys.exit(f"no log line matches {pattern!r}")
        t += delay
        picked.append(shorten(line))
        at.append(t)
    total = t + HOLD

    width = int(PAD * 2 + CHAR_W * max(len(l) for l in picked)) + 1
    height = TOP + PAD + LINE_H * len(picked)
    css = [
        ".t{font:%gpx ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace;"
        "white-space:pre;fill:#c9d1d9}" % FONT,
        ".dim{fill:#8b949e}.ok{fill:#3fb950;font-weight:600}.init{fill:#58a6ff}"
        ".sb{fill:#39c5cf}.pr{fill:#bc8cff}.hi{fill:#f0f6fc;font-weight:600}",
        ".l{animation-duration:%.1fs;animation-iteration-count:infinite;"
        "animation-timing-function:linear}" % total,
    ]
    for i, start in enumerate(at):
        p = 100 * start / total
        css.append(
            "@keyframes k%d{0%%,%.2f%%{opacity:0}%.2f%%,97%%{opacity:1}100%%{opacity:0}}"
            ".l%d{animation-name:k%d}" % (i, max(p - 0.01, 0), p, i, i)
        )
    css.append("@media (prefers-reduced-motion:reduce){.l{animation:none}}")

    out = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" '
        'viewBox="0 0 %d %d" role="img" aria-labelledby="title desc">' % (width, height, width, height),
        "<title id=\"title\">Kalkan boots and runs its adversarial security suite</title>",
        "<desc id=\"desc\">A test kernel checks its hardware protections and boot "
        "modules, then untrusted processes attack it: every attack is blocked and "
        "all 143 security tests pass.</desc>",
        "<style>%s</style>" % "".join(css),
        '<rect x="0.5" y="0.5" width="%d" height="%d" rx="9" fill="#0d1117" stroke="#30363d"/>'
        % (width - 1, height - 1),
        '<path d="M1 %d H%d" stroke="#30363d"/>' % (TOP - 10, width - 1),
        '<circle cx="18" cy="14" r="5.5" fill="#ff5f57"/>'
        '<circle cx="36" cy="14" r="5.5" fill="#febc2e"/>'
        '<circle cx="54" cy="14" r="5.5" fill="#28c840"/>',
        '<text class="t dim" x="%d" y="18.5" text-anchor="middle">'
        "qemu-system-x86_64 — Kalkan (test kernel)</text>" % (width // 2),
    ]
    for i, line in enumerate(picked):
        y = TOP + PAD - 4 + i * LINE_H
        body = "".join(
            '<tspan class="%s">%s</tspan>' % (cls, html.escape(text)) if cls else html.escape(text)
            for cls, text in spans(line)
        )
        out.append('<text class="t l l%d" x="%d" y="%d">%s</text>' % (i, PAD, y, body))
    out.append("</svg>")
    with open(svg_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out) + "\n")
    print(f"{svg_path}: {len(picked)} lines, {width}x{height}, {total:.1f}s loop")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
