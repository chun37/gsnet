# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## プロジェクト概要

**gsnet** は tinc の全機能を網羅することを目標とした L2 VPN 実装。データプレーンは **VXLAN on WireGuard**（WG トンネル上で VXLAN によりイーサネットフレームをカプセル化）で構成する。

現状はグリーンフィールド（コードは未配置）。tinc のリファレンス実装は `/tmp/tinc/`（gsliepen/tinc を clone 済）。仕様の出典として参照すること。

## 設計指針

### データプレーン：VXLAN on WireGuard
- **WireGuard** が認証付き暗号化と鍵交換を担う。tinc独自プロトコル（SPTPS / legacy）は使わない。
- **VXLAN** が L2 フレームをカプセル化し、ブロードキャスト/マルチキャスト/ARP を含む完全な L2 接続を提供する（tinc の switch / hub モード相当）。
- Linux カーネルの WireGuard + VXLAN デバイスを基本とする。
- VXLAN は **unicast head-end replication**（FDB ベース）で動作させる。マルチキャスト IP は前提としない。

### コントロールプレーン
tinc が独自プロトコル（meta-protocol over TCP）で担っていた機能を、別途設計する必要がある。鍵交換は WG に任せ、ピア・サブネット・トポロジ情報のゴシップに専念できるので、tinc よりは単純になる。

## tinc 機能網羅リスト（実装スコープ）

`/tmp/tinc/doc/` 全文と `tinc.conf.5.in` / `tinc.8.in` / `tincd.8.in` から抽出。MUST = 必須、SHOULD = 標準で実装、MAY = オプション、SKIP = WG/VXLAN で代替されるか不要。

### 1. トポロジ・接続
- **MUST** メッシュトポロジ、中央サーバなし
- **MUST** AutoConnect（明示的 ConnectTo なしで自動的にメタ接続を張る）
- **MUST** ConnectTo（明示的アウトバウンド接続先指定。複数可）
- **MUST** ノードの自動再接続（バックオフ付き）。tinc は最大 15 分間隔。
- **SHOULD** Address 複数指定（順次試行）
- **SHOULD** LocalDiscovery（同一 LAN 内ピアの自動発見）
- **SHOULD** IndirectData（直接通信を避け、メタ接続経由でリレー）
- **SHOULD** DirectOnly（リレー禁止。直接届かないパケットは drop）
- **MAY** TunnelServer（forwarding 抑制。ローカル host config に書かれたピア以外を許可しない）
- **MAY** StrictSubnets（ローカル host config の Subnet のみ受け入れる）
- **MAY** MaxConnectionBurst（短時間の接続数制限）
- **MAY** MaxTimeout（再接続最大待ち）
- **SKIP** TCPOnly（WG は UDP のみ。TCP fallback が必要なら別途検討）

### 2. ルーティング・転送モード
- **MUST** switch モード（MAC 学習による L2 スイッチング）— gsnet の主目的
- **MUST** ADD_EDGE / DEL_EDGE 相当のグラフ同期
- **MUST** ADD_SUBNET / DEL_SUBNET 相当のサブネット所有権伝搬
- **MUST** Subnet 宣言（IPv4 / IPv6 / MAC、prefix 長、weight による優先度）
- **MUST** BroadcastSubnet（サブネットブロードキャストアドレスの宣言）
- **MUST** Broadcast モード（no / mst / direct）— L2 では mst 相当が必須
- **SHOULD** hub モード（全パケットを全ピアへブロードキャスト）
- **SHOULD** router モード（IPv4/IPv6 のみ、Subnet による L3 ルーティング）
- **MAY** DecrementTTL（中継時の TTL 減算）
- **MAY** Forwarding = off | internal | kernel（中継方式の切替）
- **MAY** PriorityInheritance（内部 IPv4 ToS を外側 UDP にコピー）
- **MAY** ClampMSS（TCP MSS クランプ。PMTU ブラックホール対策）

### 3. ピア発見・参加
- **MUST** invitation 機構（`tinc invite` / `tinc join`）。短い URL（`host:port/keyhash+cookie`）でブートストラップ。
- **MUST** invitation URL の検証（keyhash で MITM 防止）
- **MUST** invitation file 形式（Name / Netname / ConnectTo + host config ブロック）
- **MUST** Ifconfig ヒント（招待ファイル内に IP / netmask / dhcp / dhcp6 / slaac / MAC を埋め込み、`tinc-up` を自動生成）
- **MUST** Route ヒント（招待ファイル内に IPv4/IPv6 ルートを埋め込み）
- **MUST** InvitationExpire（既定 604800 秒）
- **MUST** export / export-all / import / exchange / exchange-all（host config の手動配布）
- **MUST** invitation-created / invitation-accepted フック

### 4. 暗号・認証
- **MUST** ノード PKI（公開鍵で identity を表現、相互認証）
- **MUST** 鍵生成（gsnet では WG キーペア + 制御プレーン用 Ed25519 が妥当）
- **MUST** sign / verify（任意ファイルをノード鍵で署名・検証）
- **MUST** ReplayWindow（リプレイ防止ウィンドウ）— WG が担う
- **MUST** KeyExpire / 鍵ローテーション — WG の rekey が担う
- **SKIP** Cipher / Digest / MACLength 選択（WG の単一スイートで固定）
- **SKIP** PrivateKeyFile / Ed25519PrivateKeyFile / ExperimentalProtocol / SPTPS（独自プロトコル不要）

### 5. NAT 越え・トランスポート
- **MUST** UDP hole punching（WG の `Endpoint` 動的更新で実現）
- **MUST** UDPDiscovery 相当の到達性チェック（WG handshake / keepalive で代替可）
- **MUST** UDPDiscoveryKeepaliveInterval / UDPDiscoveryInterval / UDPDiscoveryTimeout（WG の PersistentKeepalive と独自プローブで代替）
- **MUST** UDPInfoInterval（外側エンドポイント情報の伝搬）
- **SHOULD** UPnP / UPnP-IGD（NAT ルーターでのポートマッピング）
- **SHOULD** STUN 等の外部 reflexive アドレス取得（tinc は持たないが NAT 越えを真面目にやるなら必要）
- **MAY** Proxy（socks4 / socks5 / http / exec）— WG では使えないため SKIP の候補
- **MAY** FWMark（Linux: ソケットの fwmark）

### 6. MTU / PMTU
- **MUST** PMTU Discovery（ピアごと）
- **MUST** PMTU の VPN 内強制（path MTU 以下に制限）
- **MUST** MTUInfoInterval（リレー path MTU の更新）
- **MUST** PMTU 既定値（tinc は 1514）

### 7. ネットワークインターフェース
- **MUST** tap デバイス相当の L2 NIC を作成・破棄（VXLAN デバイスがその役割）
- **MUST** Interface 名指定
- **MUST** DeviceStandby（到達可能ピアがある時のみ if up）
- **SHOULD** Device / DeviceType の抽象化（dummy / fd / etc.）

### 8. スクリプト・フック
スクリプト名 / 引数 / 環境変数は tinc と互換にする（既存ユーザのスクリプト流用を可能に）。
- **MUST** `tinc-up` / `tinc-down`
- **MUST** `hosts/<HOST>-up` / `hosts/<HOST>-down`（特定ノードの到達性変化）
- **MUST** `host-up` / `host-down`（任意ノードの到達性変化）
- **MUST** `subnet-up` / `subnet-down`（サブネット到達性変化）
- **MUST** `invitation-created` / `invitation-accepted`
- **MUST** 環境変数: `NETNAME`, `NAME`, `DEVICE`, `INTERFACE`, `NODE`, `REMOTEADDRESS`, `REMOTEPORT`, `SUBNET`, `WEIGHT`, `INVITATION_FILE`, `INVITATION_URL`
- **SHOULD** ScriptsExtension / ScriptsInterpreter

### 9. CLI / 制御
`tincctl` 互換コマンドを CLI として提供する。
- **MUST** `init [name]` — 設定とキーペア生成
- **MUST** `start` / `stop` / `restart` / `reload` — デーモン操作
- **MUST** `get` / `set` / `add` / `del` / `edit` — 設定変数操作（`host.variable` 表記対応）
- **MUST** `invite <name>` / `join [URL]`
- **MUST** `export` / `export-all` / `import` / `exchange` / `exchange-all`
- **MUST** `generate-keys` / `generate-ed25519-keys` / `generate-rsa-keys`（互換のため空打ち可とするか要検討）
- **MUST** `dump nodes` / `dump reachable nodes` / `dump edges` / `dump subnets` / `dump connections` / `dump graph|digraph` / `dump invitations`
- **MUST** `info <node|subnet|address>`
- **MUST** `purge`（unreachable ノードの情報破棄）
- **MUST** `retry` — 即時再接続試行
- **MUST** `disconnect <node>`
- **MUST** `debug <N>` / `log [N]`
- **MUST** `pid`
- **MUST** `pcap` — VPN トラフィックを pcap 形式で標準出力へ
- **MUST** `top` — curses 風ライブ統計（s/c/n/i/I/o/O/t/T/b/k/M/G/q キーバインド）
- **MUST** `fsck` — 設定検査と自動修正提案
- **MUST** `sign` / `verify`
- **MUST** `network [netname]` — netname 切替・一覧
- **MUST** インタラクティブシェル（readline、`#` コメント、パイプ入力対応）
- **MUST** `-n NETNAME` で複数 VPN 同居（設定ディレクトリ分離）
- **MAY** `-b/--batch` / `--force` / `--pidfile` / `--config`

### 10. 制御ソケットプロトコル
- **MUST** UNIX socket リスナ（PID ファイル内のクッキーで認証）
- **MUST** REQ_STOP / DUMP_NODES / DUMP_EDGES / DUMP_SUBNETS / DUMP_CONNECTIONS / DUMP_TRAFFIC / DUMP_INVITATIONS
- **MUST** REQ_PURGE / SET_DEBUG / RETRY / RELOAD / DISCONNECT / PCAP / LOG
- 詳細フォーマットは `/tmp/tinc/doc/CONTROL` 参照（互換性を保つ場合）

### 11. デーモン運用
- **MUST** `-D/--no-detach`, `-d/--debug[=N]`, `-s/--syslog`, `--logfile[=FILE]`
- **MUST** SIGHUP で reload、SIGALRM で `retry` 相当
- **MUST** デバッグレベル 0–5（接続 / プロトコル / メタソケット / VPN トラフィック）
- **SHOULD** `-L/--mlock`（鍵を swap に書かない）
- **SHOULD** `-R/--chroot` / `-U/--user`（権限分離）
- **SHOULD** Sandbox（off / normal / high）— Linux なら seccomp / Landlock 相当
- **MAY** AddressFamily（ipv4 / ipv6 / any）
- **MAY** BindToAddress / BindToInterface / ListenAddress / Port（複数 Listen）
- **MAY** UDPRcvBuf / UDPSndBuf / IffOneQueue
- **MAY** ProcessPriority（low / normal / high）
- **MAY** Hostnames（DNS 逆引き）
- **MAY** PingInterval / PingTimeout
- **SKIP** `--bypass-security`

### 12. 設定ファイル
- **MUST** netname ごとの設定ディレクトリ（`<confdir>/<NETNAME>/`）
- **MUST** `tinc.conf`、`hosts/<NAME>`
- **MUST** `conf.d/` 配下の追加ファイル読み込み
- **MUST** 設定変数の case-insensitive
- **MUST** `Name` 環境変数置換（`$HOST` 等）
- **MUST** `invitations/`, `invitation-data` の管理

### 13. 圧縮
- **MAY** Compression レベル（0=off, 1–9=zlib, 10–11=lzo, 12=lz4）。WG / VXLAN は標準で持たないため、データプレーンに追加処理を入れることになる。既定は無効。

## アーキテクチャの「大きな絵」

実装は以下のレイヤに分離する：

1. **設定 / 状態ストア** — ノード ID、公開鍵、宣言サブネット、エンドポイント候補、招待のローカル DB（tinc の `tinc.conf` + `hosts/` + `invitations/` 相当）
2. **コントロールプレーン** — ピア間でゴシップ（ADD_EDGE/SUBNET 相当の伝搬、グラフ同期、招待引き換え）
3. **データプレーン reconciler** — 1/2 の望ましい状態から、WG インターフェース・ピア、VXLAN デバイス、FDB エントリ、ルーティングテーブルを netlink で宣言的に整合させる
4. **CLI / 制御ソケット** — `tincctl` 互換コマンドと UNIX socket API
5. **スクリプトランナ** — `tinc-up` 等のフック実行と環境変数注入

データプレーンは **観測 → 望ましい状態と差分計算 → 適用** の reconcile ループにする。tinc の手続き的再接続ロジックよりも理解しやすい。

## 開発メモ

- 実装言語: **Go** (`wgctrl-go` + `vishvananda/netlink`)
- TDD は t-wada 流。Red → Green → Refactor を細かく回す。テストリストは `TODO.md`。
- 検証は netns で複数ノードを模擬予定。物理ホスト不要。
- tinc 互換性のテストは、`tinc invite` ↔ `gsnet join` のような相互運用ではなく、CLI / 設定ファイル / フック契約レベルの互換に絞る（プロトコルは別物）。

## 現状（実装済み）

| パッケージ | 役割 |
|---|---|
| `internal/subnet` | tinc 形式サブネット（IPv4/v6/MAC + weight）パース |
| `internal/nodename` | ノード名バリデーションと `$ENV` 展開 |
| `internal/keys` | Ed25519 / WireGuard 鍵、PEM / base64、sign/verify、Hash() |
| `internal/config` | `gsnet.conf` / `hosts/<NAME>` パーサ（conf.d 対応） |
| `internal/invite` | 招待 URL（`host:port/keyhash+cookie`）と invitation file |
| `internal/control` | UNIX socket プロトコル、PID ファイル、サーバ／クライアント |
| `internal/graph` | ノード／エッジ／サブネットの in-memory トポロジ |
| `internal/gossip` | Envelope（JSON + Ed25519 署名）、loop 抑止、Plane（Announce/Receive） |
| `internal/transport` | TCP gossip + invite を多重化したノード間トランスポート |
| `internal/dataplane` | reconciler interface |
| `internal/dataplane/fake` | テスト用 in-memory 実装 |
| `internal/dataplane/linux` | netlink + wgctrl の本番実装（WG / VXLAN / FDB） |
| `internal/script` | tinc-up 等のフックランナと環境変数注入 |
| `internal/daemon` | `Init()`、Daemon ループ、reload/シグナル、コントロールハンドラ |
| `cmd/gsnetd` | デーモン本体（`--fake` で root 不要のドライラン） |
| `cmd/gsnet` | tincctl 互換 CLI（init/get/set/add/del/invite/dump/...） |

## ビルド・実行

```sh
# テスト
go test ./...

# ビルド（バイナリは $GOBIN へ）
go install ./cmd/gsnet ./cmd/gsnetd

# ドライラン（root 不要、fake reconciler）
mkdir -p /tmp/gsnet-test/run
gsnet -n vpn -c /tmp/gsnet-test init alice
gsnet -n vpn -c /tmp/gsnet-test add Subnet 10.42.0.0/16
gsnetd -n vpn -c /tmp/gsnet-test -r /tmp/gsnet-test/run --fake &
gsnet -n vpn -c /tmp/gsnet-test -r /tmp/gsnet-test/run dump subnets
gsnet -n vpn -c /tmp/gsnet-test -r /tmp/gsnet-test/run stop

# 本番（root 必要、Linux のみ）
sudo gsnetd -n vpn
```

## 未実装（次に着手すべき領域）

`TODO.md` の Phase 11 残課題セクション参照。主な機能は揃っており、残るのは:
- **netns 統合テスト**: 実 kernel での WG+VXLAN+FDB 動作確認（root 必須）
- **STUN / hole punching**: NAT 越え

## 重要な実装メモ

- **gossip envelope は安定 ID**: 同じ事実は同じ ID を持つ。`<origin>/<kind>/<key>`。dedup は TS 比較で、新しい TS が古いものを上書き。heartbeat は outbox を再放送するだけなのでメモリは有界。
- **invitation は ECDH 暗号化**: `INVITE2 GET/JOIN` プロトコル。X25519 で鍵共有、ChaCha20-Poly1305 で本体暗号化、Ed25519 で inviter 認証。URL の keyhash が MITM 検出キー。
- **VXLAN は Learning=true**: 動的 MAC 学習は kernel が担当。reconciler は broadcast MAC エントリ（head-end replication）のみ管理する。
