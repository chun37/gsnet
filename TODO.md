# TODO list (t-wada 流 TDD のテストリスト)

このファイルは「次に書きたいテスト」のリスト。実装の地図でもある。

進行原則:
1. テストリストから1件選ぶ（簡単で具体的なものから）
2. 失敗するテストを書く（コンパイルすら通らない）
3. コンパイルだけ通す最小スタブ
4. テストを通す最小の実装（仮実装でもよい）
5. 三角測量で一般化を強制
6. リファクタリング
7. 次の1件を選ぶ

---

## Phase 1: Subnet ✅ DONE

- [x] IPv4 プレフィックス / 単一ホスト / IPv6 プレフィックス / 単一ホスト
- [x] MAC アドレス（厳格形と 1 桁省略形）
- [x] weight サフィックス / 既定値 10
- [x] String() ラウンドトリップ
- [x] ContainsIP / ContainsMAC
- [x] 不正入力の拒否

## Phase 2: Node identity + PKI ✅ DONE

- [x] ノード名バリデーション（英数字 + アンダースコア）
- [x] `$HOST` 等の環境変数展開（無効文字は `_` に正規化）
- [x] Ed25519 鍵ペア生成 / PEM ラウンドトリップ
- [x] WireGuard 鍵ペア生成 / 文字列ラウンドトリップ
- [x] 公開鍵 SHA-256 ハッシュ（invitation URL 用 keyhash）
- [x] sign / verify

## Phase 3: gsnet.conf パーサ ✅ DONE

- [x] `Variable = Value` 形式（`=` 省略可、case-insensitive、コメント）
- [x] 複数同名変数（ConnectTo 等）の保持
- [x] conf.d/ の追加読み込み
- [x] Render でラウンドトリップ
- [x] 不正な行の拒否

## Phase 4: Invitation URL / file ✅ DONE

- [x] URL のパース: `host:port/keyhash+cookie`
- [x] URL の生成 / ラウンドトリップ
- [x] 招待ファイル（複数 host config ブロックの連結）
- [x] Ifconfig / Route ヒントの抽出
- [x] cookie 生成

## Phase 5: Control socket protocol ✅ DONE

- [x] メッセージのエンコード / デコード（class 18 ベース）
- [x] Greeting（class 0）のラウンドトリップ
- [x] PID ファイル形式
- [x] UNIX socket での認証（PID 内 cookie で `^cookie` を検証）
- [x] サーバ／クライアントの round-trip
- [x] 認証失敗で接続拒否

## Phase 6: Gossip + graph ✅ DONE

- [x] グラフのノード／エッジ／サブネット操作
- [x] BFS による reachability
- [x] サブネット所有権の検索
- [x] Envelope のエンコード／デコード（JSON）
- [x] 重複メッセージの抑止（unique ID）
- [x] OnMessage オブザーバ

## Phase 7: Data plane reconciler ✅ DONE

- [x] dataplane.Reconciler インターフェース
- [x] fake 実装（テスト・dry-run 用）
- [x] Linux 実装: netlink + wgctrl で WG / VXLAN / FDB を reconcile
- [x] FDB は unicast head-end replication（ピアごとに ff:ff:ff:ff:ff:ff エントリ）

## Phase 8: CLI (gsnet) ✅ DONE

- [x] `init <name>` / `get` / `set` / `add` / `del`
- [x] `invite <name>` / URL とファイル生成
- [x] `dump nodes|edges|subnets|connections|graph|invitations`（コントロールソケット経由）
- [x] `stop` / `reload` / `retry` / `purge` / `pid`
- [x] `export` / `import`（host config の手動配布）

## Phase 9: Daemon (gsnetd) ✅ DONE

- [x] フラグパース（`-n`, `-c`, `-r`, `--fake`）
- [x] 設定ロード（Name, Subnets, WG/VXLAN パラメータ）
- [x] gossip plane の起動と AnnounceLocal
- [x] dataplane reconcile（OnMessage で再 reconcile）
- [x] コントロールソケットでのハンドラ
- [x] SIGHUP で reload、SIGALRM で retry、SIGINT/SIGTERM で停止
- [x] gsnet-up / gsnet-down フックの実行
- [x] PID ファイル + control socket のライフサイクル

## Phase 10: Cross-node transport ✅ DONE

- [x] Envelope の Ed25519 署名と verify（不正署名は drop）
- [x] TCP transport（gossip + invite を同一ポートで多重化）
- [x] ConnectTo 経由のアウトバウンド + exponential backoff
- [x] daemon に gossip plane を組み込み、heartbeat で anti-entropy
- [x] `gsnet join <url>` でネットワーク経由ファイル取得 + 自動設定
- [x] 2 ノード統合テスト（gossip 伝搬 + invite/join 完全フロー）

## Phase 11: 仕上げ ✅ DONE

- [x] **outbox + 安定 ID + TS ベース dedup**: 同じ事実は同じ ID を持ち、新しい TS が古いものを上書き。dedup テーブルはネットワーク内の facts 数で有界化。heartbeat は 30 秒に延長し、outbox 再ブロードキャストのみ。
- [x] **ECDH 暗号化 invite (INVITE2)**: X25519 鍵交換 + ChaCha20-Poly1305 で invitation 本体を暗号化。inviter の長期 Ed25519 鍵でエフェメラル公開鍵に署名し、URL の keyhash に対して検証することで MITM を防ぐ。
- [x] **VXLAN MAC 学習**: `Learning=true` で kernel に動的 MAC 学習を任せる。reconciler は broadcast MAC エントリのみ管理するので、kernel-learned エントリと衝突しない。

## Phase 12: 残課題消化 ✅ DONE

- [x] **fsck コマンド**: 設定・鍵・hosts/ の整合性チェック (`gsnet fsck`)
- [x] **pcap ダンプ**: pcap savefile writer + AF_PACKET ベースの `gsnet pcap` (Linux のみ)
- [x] **hub モード**: VXLAN `Learning=false` で実装。`Mode = hub` で有効化
- [x] **router モード**: VXLAN を作らず、各ピアの宣言サブネットを WG `AllowedIPs` に展開。`Mode = router`
- [x] **top コマンド (テキスト版)**: `REQ_DUMP_TRAFFIC` 経由で per-peer の WG カウンタを表示。`gsnet top -i 1`
- [x] **Compression API**: zlib (level 1-9) + lz4 (level 12) を `internal/compression` で実装
- [x] **STUN クライアント**: RFC 5389 Binding Request で reflexive アドレス取得 (`internal/stun`)
- [x] **UPnP-IGD**: SSDP M-SEARCH + AddPortMapping/DeletePortMapping (`internal/upnp`)
- [x] **Sandbox (Linux)**: `Sandbox` / `User` 設定で setuid + chdir。Landlock は API 不安定のため省略
- [x] **netns 統合テスト**: `-tags netns` で root 環境にて kernel WG+VXLAN を検証

## Phase 13: NAT 越え + 強化 sandbox ✅ DONE

- [x] **STUN/UPnP の daemon 統合**: 設定 `STUN = host:port` / `UPnP = yes|udponly|no` / `UPnPRefreshPeriod` を読み、起動時+定期的に reflexive アドレスを発見し `gossip.Hello.Endpoint` で公開。
- [x] **NAT 越え (cone NAT)**: gossip で endpoint を伝搬 → 各ピアの WG が当該 endpoint に PersistentKeepalive (25s) を送る → 双方の NAT に pinhole が開く。
- [x] **Landlock filesystem confinement**: `Sandbox = high` で有効。`landlock_create_ruleset` / `_add_rule` / `_restrict_self` を直接 syscall。ConfDir read-only、RunDir/InvitationsDir read-write、その他全 deny。Linux 5.13+ で動作、それ以前は明示的なエラー。

## Phase 14: データプレーン安定化 (PR #2) ✅ DONE

二ノード実機での導通検証で発覚したバグ群と、それに伴う設計修正。

- [x] **オーバーレイ/アンダーレイ分離**: 旧実装は `InnerAddress` を VXLAN デバイスと FDB 宛先の両方に使い、kernel の `vxlan_get_route()` が circular route を検出して `-ELOOP` で全 encap を drop していた。`UnderlayAddress` を導入し、WG インターフェース + VXLAN encap source + FDB 宛先を別アドレス空間に。switch/hub モードでは `UnderlayAddress` 必須 (起動時に reconciler が拒否)。
- [x] **FDB family 修正**: `reconcileFDB` の `netlink.Neigh` を `FAMILY_ALL` (=`AF_UNSPEC`) から `syscall.AF_BRIDGE` に。前者では L3 neighbor table に積まれて bridge FDB に登録されず、`bridge fdb show` が空という silent bug。
- [x] **WG セッション維持**: `ConfigureDevice` の `ReplacePeers=true` を撤廃し、existing-peers との差分から `Remove=true` を立てる方式に。30 秒 heartbeat 毎にハンドシェイクをやり直す問題を解消。
- [x] **決定論的 VXLAN MAC + ピア MAC FDB**: `vxlanMACFromKey(pub)` = `sha256(pub)[:6]` (local-admin ON / multicast OFF)。`reconcileFDB` がブロードキャスト MAC とピア MAC の 2 種を pre-install するので kernel 動的 MAC 学習に依存しない。
- [x] **MTU を毎 reconcile 反映**: `LinkSetMTU` を WG / VXLAN 両方に。`gsnet.conf` の `MTU` 変更が SIGHUP で効くように。既定は 1420 (旧 1450 は 1500-byte underlay LAN でオーバーフロー)。
- [x] **VXLAN SrcAddr drift の再作成**: `UnderlayAddress` を変えて reload した場合、kernel が SrcAddr 変更 API を持たないので `LinkDel` → 再作成。reconciler が再 install するので副作用なし。
- [x] **gossip Hello に Inner/UnderlayAddr 追加**: 招待・export/import 経路だけでは invitee 側が inviter の overlay/underlay を知れなかったため、`Hello` 経由で fan-out。`Plane` に `InnerAddrOf` / `UnderlayAddrOf` (`netip.Addr`)、`KindDelNode` で per-origin state を purge。`buildState` は gossip-learned > `hosts/<peer>` の順で解決。

## 残課題（さらに先 — もう仕様の範囲外）

- [ ] Symmetric NAT への対処（リレー TURN-like サーバが必要）
- [ ] seccomp-bpf によるシステムコールフィルタ
- [ ] IPv6 用の STUN XOR-MAPPED-ADDRESS デコード
