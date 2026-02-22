# Bitcoin Balance Parser (GUI)

A Tkinter (Python) GUI app that generates random `bitcoinco.org` IDs (30 chars), derives the corresponding BTC address, and checks balance / transaction presence via Esplora-compatible APIs (e.g. Blockstream, mempool.space).

Russian version: `README.ru.md`.

## Features

- Multi-threaded checking of random IDs (configurable count and thread number).
- API provider selection: `Blockstream`, `mempool.space`, or `Custom (Esplora)`.
- Request throttling (RPS) and configurable pause on `HTTP 429`.
- Manual check: paste a `bitcoinco` URL/ID or a BTC address.
- Right-side results panel:
  - **With balance** - addresses with positive balance (`sats > 0`);
  - **With transactions** - addresses with transactions (`tx_count > 0`);
  - right-click to copy line/address, double-click copies the address.
- Saves found results to `results.txt`.

## Requirements

- Python 3.10+

## Install

```bash
pip install -r requirements.txt
```

## Run

```bash
python btc_parser.py
```

## API Notes

- The app calls the Esplora endpoint:
  - `GET /api/address/<address>`
- It computes:
  - balance as `funded_txo_sum - spent_txo_sum` (chain + mempool),
  - `tx_count` as `chain_stats.tx_count + mempool_stats.tx_count`.
- Public providers have rate limits - use reasonable threads/RPS.

## Proxies (Auto-Rotation)

Enable **"Use proxies (rotate on 429)"**:

- On `HTTP 429` the app automatically switches to another proxy and retries.
- You can also paste **your own proxies** (one per line) and click **"Apply my proxies"** - they participate in auto-rotation together with the public lists.

Public proxy lists are loaded from:

```text
https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt
https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt
```

Supported formats for "My proxies":

- `http://ip:port`
- `socks5://ip:port` (recommended for HTTPS APIs)
- `ip:port` (treated as `http://ip:port`)

## Responsible Use

This tool is intended for testing/learning and for checking **your own** addresses/identifiers. Use it legally and ethically, and respect API providers' rules and any applicable terms of service.

## Repository Layout

- `btc_parser.py` - main application.
- `_bitcoinjs.min.js` - helper JS (reference for logic parity).
- `SPEC.md` - specification.
- `requirements.txt` - dependencies.

