# Red Team Projects

Offensive-security projects from [failclosed.com](https://failclosed.com), documented
for defenders.

> **These are stub entries.** Each project has a description, screenshots and
> detection guidance. **No source code is published here.** See
> [Why there's no source](#why-theres-no-source).

---

## Projects

| Project | What it demonstrates | Write-up |
|---|---|---|
| [Morse Code Packet Transceiver](morse-code-packet-transceiver/) | Data smuggled one symbol per packet through ICMP, TCP or UDP payloads | [Post](https://failclosed.com/2026-08-16-morse-code-packet-transceiver/) |
| [RC4 Encryptor and Base64 Encoder](rc4-encryptor-base64-encoder/) | Why the canonical loader shape gets caught, and why obfuscation is not encryption | [Post](https://failclosed.com/2026-08-16-rc4-encryptor-base64-encoder/) |
| [EICAR Control Validation Suite](eicar-control-validation-suite/) | An IDS reporting a 100% block rate while passing every encrypted payload | [Post](https://failclosed.com/2026-08-16-eicar-control-validation-suite/) |

---

## The through-line

These were built separately and ended up making the same argument three times, which
is the reason they are collected rather than scattered.

**Detections pinned to a tool's constants are cheap to write and cheap to evade.
Detections built on what a technique structurally has to do are harder to write and
much harder to get around.**

Each project has a version of that same pair:

| Project | The brittle detection | The durable one |
|---|---|---|
| Morse transceiver | Content match on the sentinel bytes and ICMP identifier — all of them configurable | Single-byte ICMP echo payloads, arriving in volume, at regular intervals, with contents that vary |
| RC4 encoder | Defender's `Cobacis` signature on the specific script | AMSI and script block logging, which see the deobfuscated body regardless of the wrapper |
| EICAR suite | A signature for the EICAR string itself — which nothing that is actually trying will ever send you | The ratio of *not-inspected* to inspected traffic per egress path |

The pattern in the right-hand column is that the attacker cannot remove the thing
being detected without giving up the thing they were trying to do. The Morse tool
cannot stop sending one small unit per packet. The loader cannot stop reconstructing
its body in memory. And no attacker can stop your sensor from admitting, in its own
logs, that it could not see inside TLS.

That last one is the odd one out and the most useful: it is a detection built on your
own infrastructure's telemetry rather than on the adversary's artifacts, which means
there is nothing for them to change.

---

## What these are not

Two of the three carry a Red Team label and are deliberately *not* offensive tools.

The Morse transceiver is **not a covert channel** — it emits fixed sentinels, uses a
hardcoded identifier, sends one packet per symbol on a metronome, and burns fifty
packets on a short sentence. Every one of those choices was made for visibility. It
is a generator for traffic a detection *should* catch, so you can find out whether
yours does.

The RC4 encoder provides **no meaningful confidentiality**. Hardcoded key, no IV, and
a retired cipher — it is documented as a cautionary example, not a recommendation.

The EICAR suite uses a payload that **cannot do anything**. Sixty-eight printable
ASCII characters with no execution and no persistence. It measures whether your
controls are looking, not whether they are good.

Nothing here is intended to help anyone evade a control. The consistent goal is the
opposite: make the technique loud enough to see clearly, then work out what actually
catches it.

---

## Why there's no source

The detection material is the part with public value, and it is complete in each
project's README — signature rules where they help, behavioural indicators where they
matter more, and an honest account of which is which.

The implementations add little a defender needs. A working per-symbol exfiltration
harness, a ready-to-run RC4 loader, and a suite that pushes malware test files across
networks are all things that are safe when run deliberately by someone who scoped the
work, and considerably less safe as one-click downloads.

Where a project's analysis depends on an implementation detail that is easy to get
wrong, that detail is written out in the project README rather than left implicit.

If a project's source is later published, its entry here will link to it.

---

## Authorized use only

These projects are documented for lawful and authorized purposes only. Apply the
techniques and detections described here only on systems you own or for which you
have explicit written authorization from the owner. They are intended for security
research and education, academic use, authorized penetration testing and security
assessment.

Unauthorized access to, use of, or interception of traffic from systems you do not
own may be a criminal offence. Determining whether a given use is lawful is the
responsibility of the user.

## License

Documentation and screenshots are released under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). No source code is included
or licensed.

Detection content — signature rules, hunt logic and behavioural indicators — may be
freely adapted into your own detection pipeline without attribution if you prefer.
