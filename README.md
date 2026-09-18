# Hackfest 2k24 — pwn write-ups

Binary exploitation solutions from Hackfest 2k24.

| Challenge | |
|---|---|
| `fileplay` | File-handling bug exploited through `sol.py` |
| `static/attachment` | Statically linked binary — no dynamic symbols to leak, so the gadget chain is built from the binary itself |

A statically linked target rules out the usual libc leak: there is no GOT entry to resolve and no loader to lean on, so the ROP chain has to come from gadgets already present in the binary.

## Reproducing

```bash
cd fileplay && python3 sol.py
```

Built with `pwntools`.

> Flags are left in place — archived competition.