# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## プロジェクト概要

**gsnet** は **VXLAN on WireGuard** で実装された分散型 L2 VPN。WireGuard が UDP トンネルと暗号化を担い、VXLAN がイーサネットフレームをカプセル化、独自のゴシップ制御プレーンがピア・サブネット・トポロジ情報を Ed25519 署名付きで配布する。

## 設計の柱

### データプレーン: VXLAN on WireGuard
- **WireGuard** がトンネル鍵交換と認証付き暗号化を担う。独自プロトコルは無い。
- **VXLAN** が L2 フレームをカプセル化する。ブロードキャスト/マルチキャスト/ARP 含む完全な L2 接続。
- Linux カーネルの WireGuard + VXLAN ドライバを使用 (ユーザースペース実装は無し)。
- VXLAN は **unicast head-end replication** + **決定論的 MAC** で動作。reconciler が broadcast MAC とピア MAC の両方の FDB エントリを pre-install するので、kernel 動的 MAC 学習に依存せず初手から確実にユニキャストできる。マルチキャスト IP は前提としない。
- **オーバーレイ ( `InnerAddress`) と WG アンダーレイ (`UnderlayAddress`) は別アドレス空間**。WG インターフェースが UnderlayAddress を持ち、VXLAN encap はそれをソースに使う。VXLAN デバイスは InnerAddress を持つ。同一空間にすると kernel の `vxlan_get_route` が ELOOP で全フレームを drop する。

### コントロールプレーン: Ed25519 署名ゴシップ
- TCP 接続でピア間に JSON envelope をフラッディング。
- 各 envelope は origin の Ed25519 鍵で署名され、受信側が検証。
- 安定 ID (`<origin>/<kind>/<key>`) + TS による dedup でメモリ有界。
- heartbeat (30 秒) で outbox を再放送し、新規接続ピアを catch-up。

### 招待プロトコル: ECDH 暗号化
- URL `host:port/<keyhash><cookie>` でブートストラップ。
- 接続時に X25519 を交換、ChaCha20-Poly1305 で本体暗号化。
- inviter は長期 Ed25519 鍵でエフェメラル公開鍵に署名し、URL の keyhash と一致を確認することで MITM 防止。

## 機能網羅マトリクス (実装済み)

| カテゴリ | 機能 | 状態 |
|---|---|---|
| **トポロジ** | メッシュ + ConnectTo + 自動再接続 (exponential backoff) | ✅ |
| **転送モード** | switch (MAC 学習) / hub / router | ✅ |
| **ピア発見** | invitation URL + ECDH 暗号化交換 / export-import | ✅ |
| **暗号** | Ed25519 (ノード ID) + WireGuard (X25519) + ChaCha20-Poly1305 | ✅ |
| **NAT 越え** | STUN + UPnP-IGD で reflexive アドレス取得、gossip 公開 | ✅ |
| **PMTU** | WG の組み込み path MTU 探索を利用 (MTU 設定可) | ✅ |
| **NIC** | VXLAN デバイス自動作成・破棄 | ✅ |
| **スクリプト** | gsnet-up / gsnet-down / hosts/<NAME>-up/-down 等 | フックランナ完成、未配線フック有 |
| **CLI** | init/get/set/add/del/invite/join/dump/export/import/fsck/pcap/top/stop/reload/retry/purge/pid | ✅ |
| **制御ソケット** | UNIX socket + cookie 認証、REQ_* 一式 | ✅ |
| **デーモン運用** | フラグ + SIGHUP reload + SIGALRM retry | ✅ |
| **設定ファイル** | gsnet.conf + conf.d/ + hosts/<NAME>、case-insensitive | ✅ |
| **圧縮** | zlib + lz4 ライブラリ実装済み (データプレーン未統合: kernel VXLAN のため) | 部分 |
| **Sandbox** | setuid + chdir + Landlock (Linux 5.13+) | ✅ |

## アーキテクチャの「大きな絵」

実装は以下のレイヤに分離されている:

1. **設定 / 状態ストア** — ノード ID、公開鍵、宣言サブネット、エンドポイント候補、招待のローカル DB (`gsnet.conf` + `hosts/` + `invitations/`)
2. **コントロールプレーン** — ピア間でゴシップ (ADD_EDGE/SUBNET 等の伝搬、グラフ同期、招待引き換え)
3. **データプレーン reconciler** — 1/2 の望ましい状態から、WG インターフェース・ピア、VXLAN デバイス、FDB エントリ、ルーティングテーブルを netlink で宣言的に整合させる
4. **CLI / 制御ソケット** — `gsnet` コマンドと UNIX socket API
5. **スクリプトランナ** — `gsnet-up` 等のフック実行と環境変数注入

データプレーンは **観測 → 望ましい状態と差分計算 → 適用** の reconcile ループ。手続き的な再接続ロジックよりも理解しやすい。

## パッケージ構成

| パッケージ | 役割 |
|---|---|
| `internal/subnet` | サブネットパース (IPv4/v6/MAC + weight) |
| `internal/nodename` | ノード名バリデーションと `$ENV` 展開 |
| `internal/keys` | Ed25519 / WireGuard 鍵、PEM / base64、sign/verify、Hash() |
| `internal/config` | `gsnet.conf` / `hosts/<NAME>` パーサ (conf.d 対応) |
| `internal/invite` | 招待 URL (`host:port/keyhash+cookie`)、invitation file、X25519 ECDH crypto |
| `internal/control` | UNIX socket プロトコル、PID ファイル、サーバ／クライアント |
| `internal/graph` | ノード／エッジ／サブネットの in-memory トポロジ |
| `internal/gossip` | Envelope (JSON + Ed25519 署名)、安定 ID、TS dedup、outbox |
| `internal/transport` | TCP (GOSSIP + INVITE2 多重化)、Dial 重複検出 |
| `internal/dataplane` | reconciler interface + TrafficStats reporter |
| `internal/dataplane/fake` | テスト用 in-memory 実装 |
| `internal/dataplane/linux` | netlink + wgctrl の本番実装 (WG / VXLAN / FDB) |
| `internal/script` | フックランナと環境変数注入 |
| `internal/stun` | RFC 5389 Binding クライアント |
| `internal/upnp` | SSDP + IGD クライアント (AddPortMapping / DeletePortMapping / GetExternalIPAddress) |
| `internal/sandbox` | setuid + chdir + Landlock (Sandbox=high) |
| `internal/pcap` | libpcap savefile writer + AF_PACKET キャプチャ |
| `internal/compression` | zlib + lz4 codec |
| `internal/daemon` | `Init()`、Daemon ループ、reload / シグナル、orchestration、NAT discovery |
| `cmd/gsnetd` | デーモン本体 (`--fake` で root 不要のドライラン) |
| `cmd/gsnet` | CLI (init/get/set/add/del/invite/dump/...) |

## 開発メモ

- 実装言語: **Go** (`wgctrl-go` + `vishvananda/netlink`)
- TDD は t-wada 流。Red → Green → Refactor を細かく回す。テストリストは `TODO.md`。
- 検証は netns で複数ノードを模擬可能 (`go test -tags netns`、root 必須)。
- 単体テストはすべて非特権で実行可能。fake reconciler で daemon 全体の挙動も検証できる。

## ビルド・実行

```sh
# テスト
go test ./...
go test -race ./...                                 # レース検出
sudo -E go test -tags netns ./internal/dataplane/linux/  # kernel 統合 (root)

# ビルド (バイナリは $GOBIN へ)
go install ./cmd/gsnet ./cmd/gsnetd

# ドライラン (root 不要、fake reconciler)
mkdir -p /tmp/gsnet-test/run
gsnet -n vpn -c /tmp/gsnet-test init alice
gsnet -n vpn -c /tmp/gsnet-test add Subnet 10.42.0.0/16
gsnetd -n vpn -c /tmp/gsnet-test -r /tmp/gsnet-test/run --fake &
gsnet -n vpn -c /tmp/gsnet-test -r /tmp/gsnet-test/run dump subnets
gsnet -n vpn -c /tmp/gsnet-test -r /tmp/gsnet-test/run stop

# 本番 (root 必要、Linux のみ)
sudo gsnetd -n vpn
```

## 重要な実装メモ

- **gossip envelope は安定 ID**: 同じ事実は同じ ID。`<origin>/<kind>/<key>`。dedup は TS 比較で、新しい TS が古いものを上書き。heartbeat は outbox を再放送するだけなのでメモリは事実数で有界。
- **gossip.Hello が overlay/underlay を運ぶ**: `InnerAddr` / `UnderlayAddr` フィールドを持ち、各ノードが自分のアドレスを Hello で fan-out する。受信側は Plane の `InnerAddrOf` / `UnderlayAddrOf` で参照、`buildState` は gossip-learned > `hosts/<peer>` のフォールバック順。`KindDelNode` でこれらと `endpoints` / `pubKeys` も purge。
- **invitation は ECDH 暗号化**: `INVITE2 GET/JOIN` プロトコル。X25519 鍵共有、ChaCha20-Poly1305 で本体暗号化、Ed25519 で inviter 認証。URL の keyhash が MITM 検出キー。
- **VXLAN MAC は決定論的**: `vxlanMACFromKey(WGPublicKey)` = SHA-256(pubkey)[:6] に local-admin ビット ON / multicast ビット OFF。両ピアが相手の MAC を独立に計算できるので、unicast FDB エントリを pre-install できる ( `reconcileFDB` がブロードキャスト MAC とピア MAC の 2 種を管理)。switch モードは `Learning=true` のまま、hub は `Learning=false`。
- **WG ピア管理は idempotent**: `ConfigureDevice` に `ReplacePeers=true` を渡すと kernel が毎 reconcile でセッション (handshake / replay counter) を壊すため、`configureWGPeers` は existing-peers を列挙して消えたものだけ `Remove=true` を立てる差分適用。
- **VXLAN SrcAddr は creation-only**: kernel の VXLAN driver は SrcAddr 変更 API を持たないので、`ensureVXLAN` は既存 link の `vx.SrcAddr` を `LocalUnderlayAddr` と比較して drift があれば `LinkDel` → 再作成する。
- **NAT 越え**: 各ノードが STUN/UPnP で reflexive アドレスを発見 → gossip Hello で公開 → 全ピアの WG ピア設定が更新 → PersistentKeepalive (25 秒) が両側の NAT pinhole を開く。symmetric NAT 用のリレーは未実装。
- **Plane の競合修正**: `Receive` は verify → claim (CAS) → apply → Broadcast の順。`claim` は TS 比較を 1 つの critical section で行うため、並行受信での二重 apply が起きない。
- **Transport.Dial は冪等**: 既存接続が同じ outbound アドレスを持つなら no-op。`maintainPeer` の周期再 Dial で接続数が無限増加することを防ぐ。

## 未実装

`TODO.md` 参照。主要機能は揃っており、残るのは:
- **Symmetric NAT 用リレー** (TURN-like)
- **seccomp-bpf** によるシステムコールフィルタ
- **IPv6 STUN XOR-MAPPED-ADDRESS** デコード
