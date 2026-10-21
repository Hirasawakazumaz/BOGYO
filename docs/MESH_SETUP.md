# Mesh setup — two of your own servers / 自分のサーバー2台でメッシュを動かす

Run the distributed parallel-patch mesh between **two servers you own** (A and B),
each specializing in a different patch domain, sharing patches over the rolling-key
channel and a signed patch chain. Use only your own servers (consent requires it).
自分が所有する2台(A・B)で、担当領域を分け、ローリング鍵通信＋署名チェーンでパッチを
共有します。接続は自分のサーバー同士のみ（同意条項）。

> Prereqs on each server: install Sentinel-Guard, run `sentinel init` → edit
> `config/scope.yaml` (that server's own assets) → `keygen` → `sign-scope` →
> `consent` (accept the "own servers only" clause). Put the two servers on a
> private network (e.g. WireGuard) and only expose the mesh port there.

Assume A = `10.8.0.1`, B = `10.8.0.2`, mesh port `8787`.

## 1. Create a node key on EACH server / 各サーバーでノード鍵を作成
```bash
# on A
sentinel mesh keygen --name serverA          # prompts for a passphrase
# on B
sentinel mesh keygen --name serverB
```
Each prints its **public** keys (`ed25519_pub`, `x25519_pub`). The key file
(`config/node.key.enc`) is machine-bound + passphrase-encrypted — do not copy it.

## 2. Exchange PUBLIC keys and fill `mesh:` in settings.yaml / 公開鍵を交換し設定
Copy the `mesh:` block from [../config/mesh.example.yaml](../config/mesh.example.yaml)
into each server's `config/settings.yaml`. On A, list B as a peer; on B, list A.
`time_window_seconds` must match on both.

```yaml
# A's settings.yaml                      # B's settings.yaml
mesh:                                    mesh:
  enabled: true                            enabled: true
  node_name: serverA                       node_name: serverB
  domain: sshd                             domain: nginx
  peers:                                   peers:
    - name: serverB                          - name: serverA
      domain: nginx                            domain: sshd
      endpoint: "http://10.8.0.2:8787"         endpoint: "http://10.8.0.1:8787"
      ed25519_pub: "<B ed25519 pub>"           ed25519_pub: "<A ed25519 pub>"
      x25519_pub:  "<B x25519 pub>"            x25519_pub:  "<A x25519 pub>"
```
You can also set these over the control API, e.g.
`sentinel config set mesh.enabled true`.

## 3. Start each node's endpoint / 各ノードのエンドポイントを起動
```bash
# on A (listens for B)                   # on B (listens for A)
sentinel mesh serve --host 10.8.0.1 --port 8787
sentinel mesh serve --host 10.8.0.2 --port 8787
```
(Leave these running. Each is blocking; use tmux/systemd for production.)

## 4. Propose a patch on one node and share it / パッチを作って共有
```bash
# on A: create a signed patch block for A's domain
sentinel mesh propose --service sshd --finding CVE-2024-6387 --path /etc/ssh/sshd_config

# on A: push it to B over the rolling-key channel
sentinel mesh push --to serverB
```
B receives it, verifies the signature, runs its conflict check, and (if clean)
records it as applied on its chain. You'll see `peer ack: applied ref=…`.

## 5. Verify the shared chain / 共有チェーンを確認
```bash
sentinel mesh status          # on either node: height / pending / applied / valid
```

## How the security works (summary) / 仕組み（要約）
- **Auth** is a machine-bound encrypted node key, not a copyable API key.
- The **session key changes every message**, derived from the previously exchanged
  ciphertext + the time window; a peer is accepted only if its key matches, and
  both sides ratchet forward. Messages are doubly AEAD-encrypted and signed.
- Patches live on a **signed, hash-linked chain**; a peer's patch is applied only
  after the local **conflict check** passes.

See [WHITEPAPER.md](WHITEPAPER.md) §4 for diagrams, and [SAFE_USE.md](SAFE_USE.md).

## Troubleshooting / トラブルシュート
- `peer '…' not in mesh.peers` → the `--to` name must match a `peers[].name`.
- `no endpoint` → set `peers[].endpoint` or pass `--endpoint http://host:port`.
- 400 / key errors → check both sides share the same `time_window_seconds`, the
  pasted public keys are correct, and clocks are within ~1 window of each other.
- Connection refused → the peer's `sentinel mesh serve` isn't running / firewalled.
