# Public Bootstrap Release Trust

Recommended public repository:

```text
LoudSkyMedia/server-bootstrap
```

The source directory can remain named `server-bootstrap`.

## Channels

Convenience channel:

```bash
curl -fsSL https://raw.githubusercontent.com/LoudSkyMedia/server-bootstrap/stable/bootstrap.sh \
  -o /tmp/lsm-vps-bootstrap.sh \
  && sudo bash /tmp/lsm-vps-bootstrap.sh
```

The `stable` branch or immutable redirect mechanism should advance only after a
reviewed release is promoted. It must not track day-to-day `main` work.

Reproducible channel:

```bash
curl -fsSL https://raw.githubusercontent.com/LoudSkyMedia/server-bootstrap/v0.1.0/bootstrap.sh \
  -o /tmp/lsm-vps-bootstrap.sh \
  && sudo LSM_VPS_INIT_REF=v0.1.0 \
    LSM_VPS_INIT_SHA256=<release-archive-sha256> \
    bash /tmp/lsm-vps-bootstrap.sh
```

## Release Artifacts

Each production release should include:

- immutable Git tag, for example `v0.1.0`
- source archive checksum, at minimum SHA-256
- generated checksum manifest for the release archive and `bootstrap.sh`
- release notes with supported OS, Node.js pin, pinned Node release-key
  fingerprint review, and known residuals
- optional signed attestation once the public repo policy is finalized

The bootstrap supports `LSM_VPS_INIT_REF`, `LSM_VPS_INIT_ARCHIVE_URL`, and
`LSM_VPS_INIT_SHA256` so the public URL can be stable while production runs can
pin a specific release and checksum.
