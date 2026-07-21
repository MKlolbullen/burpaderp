# Payload corpus

Raw payload libraries used as an external corpus by Recon Hound.

The extension indexes `.txt` files from the first available directory:

1. `$RECON_HOUND_PAYLOADS`
2. `./payloads`
3. `~/.recon-hound/payloads`
4. `~/payloads`

These payloads are **not automatically fired** by passive scanning or crawling. The active discovery loop performs GET requests only. This separation is intentional: the corpus includes time-based and potentially destructive payloads and should only be used deliberately against authorized targets.

Current categories are described in `manifest.json`.
