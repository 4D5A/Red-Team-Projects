# DNS Tunneling Transceiver

Moves a file out of a network one DNS label at a time, loudly, so you can confirm
your resolver notices.

DNS is the channel that is allowed to leave when everything else is closed or
inspected, because resolution has to work or the network stops. This tool chunks a
file, encodes each chunk into a subdomain under a zone it controls, and sends one
query per chunk; a receiver on the authoritative side logs, decodes and reassembles.

> **Stub repository.** This repo documents the project. The source is not
> published - see [Why the source isn't here](#why-the-source-isnt-here).
**Full write-up:** <https://failclosed.com/2026-08-17-dns-tunneling-transceiver/>

---

## What it does

Every transfer is framed by handshake queries under an attacker-controlled zone:

```
<seq>.<base32-chunk>.exfil.lab.example   ->   A / TXT
```

A `SOT` query announces the filename and size, numbered data queries carry the body
one chunk per query, and an `EOT` query closes it with a CRC32 of the reassembled
file. The receiver ignores everything until it sees a start-of-transmission label, so
unrelated lookups for the same zone do not corrupt a session. A `TXT` return channel
carries command output back, base32-encoded in the answer section.

Four transport profiles change what actually goes on the wire:

| Profile | Wire form | Relative volume |
|---|---|---|
| A-record, metronome | one base32 chunk per `A` query, fixed interval | baseline |
| TXT request/response | larger return capacity on a rare record type | higher back |
| Base16 labels | hex encoding instead of base32 | about 2x |
| Jittered timing | the only profile that tries to blend in at all | baseline |

At roughly 30 usable bytes per label, a one-megabyte file is on the order of
thirty-five thousand queries to a single zone. That number is the point, not a flaw.

---

## What this is not

**This is not a covert channel**, and it is worth saying plainly rather than letting
the Red Team label imply otherwise.

A tool built to evade detection would pack far more data per query, rotate across many
zones, hide its labels inside normal-looking names, and pace itself against the host's
real DNS behaviour. This does the opposite of all four: a fixed prefix, a hardcoded
handshake, one small chunk per query, and a default metronome.

Every one of those choices was made for **visibility**. It is a generator for traffic
a detection *should* catch, so you can find out whether yours does.

---

## Detection

Two levels, and the gap between them is the reason this project exists.

**The easy level is content matching.** The default prefix and handshake tokens are
fixed strings in the query name:

| Artifact | Value |
|---|---|
| Zone | `exfil.lab.example` |
| Start / end tokens | `sot`, `eot` |
| Return record type | `TXT` |
| Default query interval | 0.3 s |

```
alert dns any any -> any any (msg:"DNS Tunneling Transceiver handshake label"; \
  dns.query; content:"exfil"; nocase; pcre:"/\b(sot|eot)\b/i"; \
  classtype:policy-violation; sid:1000020; rev:1;)
```

That rule works and is close to worthless as a general detection, because every one
of those values is configurable. A signature keyed to the defaults catches only the
person who did not change them.

**The durable level is behavioural.** To move a byte out over DNS you have to ask a
question the resolver has never seen, because a cache answers repeated questions and
exfil never repeats one. Every chunk is a fresh cache miss and a recursive lookup your
own resolver writes into its query log:

- **Unique-label cardinality per registered domain.** A benign zone is served from
  cache after the first few lookups; an exfil zone shows a continuously climbing count
  of never-before-seen subdomains. Jitter, re-encoding and record-type swaps do
  nothing to this.
- **Query volume and rate to one low-reputation second-level domain.**
- **Label length and character distribution** - base32/base16 labels sit near maximum
  length with near-uniform, high-entropy characters, unlike human or CDN names.
- **NXDOMAIN ratio per zone** and unusual `TXT`/`NULL` answer volume on the return
  path.

```
-- per registered domain over a rolling window (Pi-hole FTL, Unbound, Zeek dns.log)
SELECT   registered_domain,
         COUNT(*)                  AS queries,
         COUNT(DISTINCT subdomain) AS unique_labels,
         AVG(LENGTH(subdomain))    AS avg_label_len
FROM     dns_queries
WHERE    ts > now() - INTERVAL '5 minutes'
GROUP BY registered_domain
HAVING   unique_labels > 100 AND avg_label_len > 30
ORDER BY unique_labels DESC;
```

That query does not care about this tool or about DNS tunneling by any particular
name. It fires on anything that has to keep asking new questions to move data, which
is every exfiltration-over-DNS technique there is. Like the EICAR suite in this
collection, the durable detection is built on telemetry your own infrastructure is
forced to produce - there is nothing in it for the adversary to change.

---

## Why the source isn't here

This repository is a stub: description and detection guidance, with no implementation.

The detection material is the part with public value and it is complete above - the
cardinality query works against anything built along these lines, not just this tool.
A working DNS exfiltration harness adds nothing a defender needs and is not something
worth handing out ready to run. Anyone who needs it can rebuild it from the
methodology in the write-up.

---

## Authorized use only

This project is made available for lawful and authorized purposes only. Use it only
on zones and systems you own or for which you have explicit written authorization from
the owner. It is intended for security research and education, academic use, authorized
penetration testing and security assessment.

Unauthorized exfiltration of data or interception of traffic from systems you do not
own may be a criminal offence. Determining whether a given use is lawful is the
responsibility of the user.

## License

Documentation in this repository is released under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). No source code is included
or licensed.
