# gsnet

**VXLAN on WireGuard で実装された分散型 L2 VPN.**

gsnet は WireGuard（暗号化された UDP トンネル）と VXLAN（L2 カプセル化）を組み合わせた分散型 VPN です。独自のクリプトプロトコルは持たず、ピア間トポロジ情報の交換に集中したシンプルなコントロールプレーンと、kernel が処理する高速なデータプレーンを兼ね備えます。

```
┌─────────┐ gossip (TCP, signed JSON)        ┌─────────┐
│  alice  │ ◄───────────────────────────────► │   bob   │
│         │ VXLAN(overlay) over WireGuard UDP │         │
│ overlay 10.42.0.1   ◄────────────────►   10.42.0.2    │
│ underlay 172.16.0.1 ◄── WG tunnel ───► 172.16.0.2     │
└─────────┘                                   └─────────┘
```

オーバーレイ (VXLAN 上の L2) と WG アンダーレイ (UDP-4789 を運ぶ IP 層) は別のアドレス空間。これによりカーネルの `vxlan_get_route` が経路ループを起こさず、純粋な L2 接続を提供できる。

## 特徴

| 機能 | 実装 |
|---|---|
| **データプレーン** | Linux kernel の WireGuard + VXLAN (BUM ↔ FDB head-end replication) |
| **コントロールプレーン** | Ed25519 署名付き JSON envelope のフラッディング (TCP) |
| **anti-entropy** | 安定 ID + outbox 再送。dedup テーブルは事実数で有界 |
| **PKI** | Ed25519 (ノード ID + 署名) + Curve25519 (WireGuard) |
| **招待制度** | URL `host:port/keyhash+cookie` + ECDH 暗号化 (X25519 + ChaCha20-Poly1305) |
| **NAT 越え** | STUN / UPnP-IGD で reflexive アドレス取得 → gossip で公開 → WG keepalive |
| **forwarding mode** | switch (L2 + MAC 学習) / hub (L2 ブロードキャスト) / router (L3 のみ) |
| **フック** | `gsnet-up` / `gsnet-down` / `hosts/<NAME>-up` / `subnet-up` etc. |
| **sandbox** | setuid + chdir + Landlock (Linux 5.13+) |
| **デバッグ** | `gsnet fsck` (設定検査), `gsnet top` (トラフィック統計), `gsnet pcap` (パケットキャプチャ) |

## 制約

- **Linux 専用** (kernel WireGuard と netlink を使用)
- **Symmetric NAT** にはリレー (TURN-like) が必要 — 未実装
- データプレーンは kernel が担当するため、ユーザースペース圧縮は無効

## インストール

```sh
# 必要: Go 1.21+
git clone <this repo>
cd gsnet
go install ./cmd/gsnet ./cmd/gsnetd
```

実行には WireGuard と VXLAN を作る権限が必要です (`CAP_NET_ADMIN` または root)。

## クイックスタート (2 ノード)

### alice (招待側)

```sh
# 設定ツリーを作る (鍵ペア生成 + gsnet.conf + hosts/alice)
gsnet -n vpn init alice
gsnet -n vpn set Address vpn.example.com
gsnet -n vpn set Port 51820
gsnet -n vpn set InnerAddress    10.42.0.1/16    # VXLAN オーバーレイ上のアドレス
gsnet -n vpn set UnderlayAddress 172.16.0.1/24   # WG 内の自分の IP (VXLAN encap source)
gsnet -n vpn add Subnet 10.42.0.0/16

# デーモン起動 (root 必要 — WG + VXLAN 作成のため)
sudo gsnetd -n vpn

# 別ターミナルで招待を作成
gsnet -n vpn invite bob
# → vpn.example.com:51820/kJ4M9...XVw（このURLを bob に渡す）
```

### bob (招待される側)

```sh
# URL から自動セットアップ (鍵生成 + 設定 + hosts/* の書き出し)
gsnet -c /etc/gsnet join 'vpn.example.com:51820/kJ4M9...XVw'

# 自分側のアドレスとサブネットを追加
gsnet -n vpn set InnerAddress    10.42.0.2/16
gsnet -n vpn set UnderlayAddress 172.16.0.2/24
gsnet -n vpn add Subnet 10.42.1.0/24

sudo gsnetd -n vpn
```

これで `alice` と `bob` の VXLAN インターフェース経由で L2 接続が成立します。アドレスは gossip Hello で自動配布されるので、ピアの `hosts/<peer>` を手動で同期する必要はありません。

> **switch/hub モードでは `UnderlayAddress` が必須**です。これを設定しないと `gsnetd` が `LocalUnderlayAddr is required for switch/hub mode` で起動を拒否します。`router` モードでは不要。

## 設定リファレンス

`<conf-root>/<netname>/gsnet.conf` の主要キー (`Key = Value` 書式、`=` 省略可、case-insensitive):

| キー | 既定 | 説明 |
|---|---|---|
| `Name` | — | ノード名 (英数字 + `_`、必須) |
| `Address` | — | 外部からの WG エンドポイント (host または IP) |
| `Port` | 51820 | WG UDP リスニングポート |
| `InnerAddress` | — | VXLAN オーバーレイ上の自ノード IP (CIDR 推奨、例 `10.42.0.1/16`) |
| `UnderlayAddress` | — | WG インターフェースに割り振る IP (CIDR、switch/hub モードで必須) |
| `Subnet` | (複数可) | このノードがオーナーシップを持つサブネット |
| `ConnectTo` | (複数可) | 起動時に接続を試みるピア名 |
| `Mode` | switch | `switch` / `hub` / `router` |
| `VXLANID` | 42 | VXLAN VNI |
| `VXLANPort` | 4789 | VXLAN UDP ポート |
| `MTU` | 1420 | WG インターフェース MTU (VXLAN は内部で `-50`) |
| `STUN` | — | STUN サーバ (host:port、複数可) |
| `UPnP` | no | `yes` / `udponly` / `no` |
| `UPnPRefreshPeriod` | 60 | UPnP ポートマッピング再設置間隔 (秒) |
| `Sandbox` | off | `off` / `normal` / `high` (Landlock) |
| `User` | — | setuid 先のユーザー名 |

ホスト設定 (`hosts/<name>`) は招待で自動配布されます。手動配布は `gsnet export` / `gsnet import`。

## フックスクリプト

ConfDir に置いた以下の実行可能ファイルが、対応するイベントで同期実行されます。すべてのフックは省略可能（存在しないファイルは no-op）。

| ファイル名 | 起動タイミング |
|---|---|
| `gsnet-up` | デーモン起動直後（VXLAN/WG インターフェースが上がった後） |
| `gsnet-down` | デーモン停止直前 |
| `hosts/<name>-up` | 特定ノードが到達可能になったとき |
| `hosts/<name>-down` | 特定ノードが到達不能になったとき |
| `host-up` / `host-down` | 任意ノードの到達性変化 |
| `subnet-up` / `subnet-down` | サブネットの到達性変化 |
| `invitation-created` | 招待ファイル生成直後 |
| `invitation-accepted` | 招待が使われた直後 |

環境変数: `NETNAME`, `NAME`, `DEVICE`, `INTERFACE`, `NODE`, `REMOTEADDRESS`, `REMOTEPORT`, `SUBNET`, `WEIGHT`, `INVITATION_FILE`, `INVITATION_URL`。

アドレス割り当てと link up はデータプレーン reconciler が自動で行うので、フックでやる必要はありません。フックは「上がった後」にやりたいこと (firewall ルール、ブリッジ作成、隣接ノードへの通知など) に使います。

例 (`/etc/gsnet/vpn/gsnet-up` — VXLAN をローカルブリッジに接続する):

```sh
#!/bin/sh
ip link add br-vpn type bridge
ip link set $INTERFACE master br-vpn
ip link set br-vpn up
```

## CLI コマンド

```
init <name>             設定ツリー + 鍵ペア生成
get <key>               設定値を表示
set <key> <value>       設定値を上書き
add <key> <value>       同名キーを追加 (ConnectTo 等)
del <key> [value]       設定値を削除
invite <name>           招待 URL を生成
join <url>              招待 URL から参加
export                  自ノードの host config を stdout
import                  host config を stdin から読み込み
dump nodes|edges|subnets|connections|graph|invitations
                        ランニング状態をダンプ
top [-i interval]       per-peer トラフィック統計をライブ表示
pcap [-i iface] [-s N]  パケットを pcap 形式で stdout (Linux)
fsck                    設定整合性チェック
stop / reload / retry / purge / pid
                        デーモン制御
```

## アーキテクチャ

```
┌──────────────────── gsnetd (per-node daemon) ──────────────────────┐
│                                                                    │
│   ┌──────────┐    ┌─────────┐    ┌──────────────┐    ┌──────────┐ │
│   │ Control  │ ── │  Plane  │ ─► │  Reconciler  │ ─► │  kernel  │ │
│   │  socket  │    │ (gossip)│    │ (netlink+wg) │    │  WG+VXLAN│ │
│   └────┬─────┘    └────┬────┘    └──────┬───────┘    └──────────┘ │
│        │               │                                          │
│        │               ▼                                          │
│        │         ┌─────────┐    Hello / Edge / Subnet             │
│        │         │  Graph  │    Add+Del envelopes (signed)        │
│        │         └─────────┘                                      │
│        ▼                                                          │
│   ┌──────────┐    TCP gossip                                      │
│   │ Discovery│    + INVITE2 (ECDH)                                │
│   │ STUN/UPnP│ ◄────────────────────────►  other gsnetd peers     │
│   └──────────┘                                                    │
└────────────────────────────────────────────────────────────────────┘
```

主要パッケージ:

| パッケージ | 役割 |
|---|---|
| `internal/subnet` | サブネットパース (IPv4/v6/MAC + weight) |
| `internal/keys` | Ed25519 + WireGuard 鍵管理、署名・検証、keyhash |
| `internal/config` | gsnet.conf パーサ (conf.d 対応、case-insensitive) |
| `internal/invite` | 招待 URL / file / ECDH 暗号化 (X25519 + ChaCha20-Poly1305) |
| `internal/control` | UNIX socket コントロールプロトコル |
| `internal/graph` | ノード／エッジ／サブネット in-memory トポロジ |
| `internal/gossip` | 安定 ID Envelope、outbox、Ed25519 署名 |
| `internal/transport` | TCP (GOSSIP / INVITE2 多重化) |
| `internal/dataplane` | reconciler interface + Linux 実装 (netlink/wgctrl) |
| `internal/script` | フックスクリプトランナ |
| `internal/daemon` | デーモン本体、orchestration |
| `internal/stun` | RFC 5389 Binding クライアント |
| `internal/upnp` | SSDP + IGD AddPortMapping クライアント |
| `internal/sandbox` | setuid / chdir / Landlock |
| `internal/pcap` | libpcap savefile writer + AF_PACKET キャプチャ |
| `internal/compression` | zlib + lz4 |

## 開発

```sh
# 全テスト
go test ./...

# レース検出付き
go test -race ./...

# kernel 統合テスト (要 root)
sudo -E go test -tags netns ./internal/dataplane/linux/

# 単一パッケージ
go test -v ./internal/gossip/
```

実装は t-wada 流 TDD に準拠 — `TODO.md` がテストリスト兼ロードマップ。

## ライセンス

[MIT License](LICENSE) (c) 2026 chun37

## 関連

- [WireGuard](https://www.wireguard.com/) — データプレーン暗号化
- [Linux VXLAN documentation](https://www.kernel.org/doc/Documentation/networking/vxlan.txt)
