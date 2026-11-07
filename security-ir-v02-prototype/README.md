# Security Design IR v0.2 — 独立適合性検証プロトタイプ

更新: 2026-11-07 / 実装位置: このディレクトリ

## 最新の検証と凍結判断（2026-11-07）

**v0.2全面凍結不可。RC版は確定していません。** 開発スナップショットは `0.2.0-dev.20261107`。全69件成功（CT-001〜026を含む）、合成3ケースの要求経路4/4、注入欠陥42/42、証拠再評価12/12、正常ケースのフラグ0/3です。CLIも12回のプロセス往復で判定と終了コードを確認しました。実API・実CIの真正性は未検証です。

```sh
.venv/bin/python verify_freeze.py
```

[今回の実測・変更・未実装一覧](EVALUATION-2026-11-07.md)と[機械可読監査報告](reports/freeze-audit-2026-11-07.json)を参照してください。監査コマンドの終了0は再現成功であり、凍結承認ではありません。以下の2026-11-03時点の記録は履歴として保持しています。

> **重要**: これは会話中の独自仕様を検証する独立プロトタイプです。追加されたソースフォルダーを直接確認して拡張しました。別作業領域のv0.1/v0.2試作とのモデル統合や、全要件への適合認定はしていません。

## 実行

Python 3.11+ と `jsonschema` が必要です。
以下はこのディレクトリで実行します。`uv venv` は仮想環境を作成しますが、シェルの `python` コマンドは自動では切り替わりません。

```bash
uv venv --python 3.14.2
uv pip install --python .venv/bin/python 'jsonschema>=4.18'
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python cli.py validate fixtures/order_cancel_valid.json \
  --profile review --catalogs fixtures/catalogs.json \
  --output conformance-valid.json
.venv/bin/python cli.py release-gate fixtures/release_candidate_valid.json \
  --candidate RC-001 --catalogs fixtures/catalogs.json \
  --output release-gate-valid.json
```

短い `python` コマンドを使う場合は、先に `source .venv/bin/activate` を実行してください。以後の新しいターミナルでも有効化が必要です。

`validate` の終了コードは `0` = 構造適合、`1` = 不適合、`2` = 未解決。`release-gate` は `0` = ready、`1` = blocked、`2` = review-required / unknown。**`ready`は人間によるReleaseDecisionや安全性認定ではありません。**

## 作成物

| ファイル | 内容 |
|---|---|
| `schema.json` | JSON Schema Draft 2020-12; ノード種別ごとの最小必須属性を検査 |
| `engine.py` | グラフ検証、外部参照、Claim循環、四値論理、証拠適用性、保証評価の一部、Release Gate集約と候補IRからの判定導出 |
| `cli.py` | JSON IRの検査と独立したValidation Report出力 |
| `fixtures/order_cancel_valid.json` | 注文キャンセルAPIの縮小IR例 |
| `fixtures/catalogs.json` | 外部カタログ参照の模擬解決 |
| `tests/test_conformance.py` | CT-001〜CT-026と性質テスト7件 |
| `tests/test_release_candidate.py` | Release GateのIR統合回帰テスト12件 |
| `fixtures/release_candidate_valid.json` / `release-gate-valid.json` | 候補、版付きポリシー、保証・リスク記録を含む正常例と判定結果 |
| `conformance-valid.json` | CLIでの縮小IR構造検証結果 |
| `conformance-unresolved.json` | カタログ未指定時の判定不能結果 |
| `test-results.txt` | テスト実行ログ |
| `CONFORMANCE.md` | 実装の対応状況、ギャップ、凍結判断 |

## 実測結果（2026-11-03）

- 変更前: 33件成功。2026-11-03: **54件実行、54件成功**（既存51件と今回追加3件）。
- `cli.py validate ... --catalogs fixtures/catalogs.json`: `structurally-conformant`（findings=0、終了コード0）。
- カタログ未指定: `indeterminate`（外部参照未解決2件、終了コード2）。
- テストは人工的な小規模フィクスチャと評価器の単体テストで、実システムのセキュリティ検証ではありません。

## 重要なスコープ制限

1. `evaluate_release_candidate` はReleaseCandidateと版付きReleasePolicy、必須Claim、EvidenceValidityAssessment、AssuranceAssessment、Finding、ResidualRiskから5チェックを導出します。従来の `evaluate_release_gate` は低水準の集約関数として維持します。
2. IR統合はEvidenceを直接Premiseに持つClaimに限定します。子Claim、Assumption、Defeaterを含む完全なAssurance Caseの統合評価は未実装です。
3. Evidenceの来歴は必須フィールドの存在を検査するのみで、署名・ハッシュなどの完全性、実在のCI証拠の真偽を確認していません。
4. Evidenceの独立性は同一IDの重複除外まで。異なるEvidence IDでも同一テスト実行・共通原因で相関する場合の検出は未実装です。
5. Gateの変更依存は`changedDependencies`を**利用者が与える前提**。2026-11-07からIR影響伝播をGateに接続しました。実コード差分や変更集合の完全性は検証しません。
6. L3のScope Coverageは文字列集合の包含関係のみです。テナント×ロール×操作などの組合せ、信頼できるEvidence-to-Claim推論、脅威網羅性の評価は未実装です。
7. Draft/Review/Releaseは一部のグラフ制約に対して適用しました。v0.2の全30件のプロファイル別規則が完全実装されたわけではありません。

## Release GateのIR契約と結果

`ReleaseCandidate.policyRef` は `ReleasePolicy ID@version`。`usesReleasePolicy` も同じポリシーノードを指す必要があります。ポリシーは5つの必須チェックと阻害Findingの重大度を保持します。候補は `requiresClaim`、`tracksFinding`、`tracksRisk` で判定材料を結び、`claimsComplete` / `changedDependenciesComplete` / `findingsComplete` / `risksComplete` で一覧の完全性を申告します。Claimは `supportedByArgument` → `hasPremise` → Evidenceで論証し、EvidenceValidityAssessmentとAssuranceAssessmentを現在の候補revisionと照合します。各チェック値と根拠IDはレポートに残します。ポリシー未解決・必須チェック欠落・必要な評価記録欠落・外部カタログ未解決は`unknown`です。

正常フィクスチャで `ready`、旧Evidenceで `review-required`、反証Evidenceと重大open Findingで `blocked`、リスク未承認で `review-required` を確認しました。モデル上の`ready`は入力記録からの候補判定にすぎません。Evidence真正性、評価者の権限、変更集合の完全性、Claim/Finding/Risk一覧の網羅性は検証できません。詳細は[CONFORMANCE.md](CONFORMANCE.md)。

## 次の改訂順序

1. ReleasePolicyとReleaseCandidateのモデルを正式仕様としてレビューし、完全な適合性テストに落とす。
2. 子Claim・Assumption・Defeater、独立証拠、Claim集合の網羅性を統合評価する。
3. Reference resolverを実カタログへ接続し、参照先不在と到達不能を監査可能な形で区別する。
4. 脅威モデルとDomain Model IRを参照するスコープの意味論を設計し、カバレッジの単なる集合包含を超える。
5. 仕様と実装を分離した適合性スイートとプロファイル別レポートを固定する。

## 関連文書

2026-11-07の試行契約では、同一Evidence IDへの重複リンクは票を増やしません。IR変更を依存証拠へ伝播し、未知変更IDも成功にしません。要求経路を評価対象候補へ結び付け、廃止・未承認Evidenceと未承認リスク記録は保留します。台帳は環境・scope・依存も照合します。

Policyに任意の `maxEvidenceAgeSeconds` を指定すると、候補の `evaluatedAt` とEvidenceの `observedAt` を比較します。タイムゾーン付き日時が必要です。上限ちょうどは有効、超過・未来観測は保留、必要な日時欠落は成功にしません。台帳必須時は観測日時も照合します。このオプションがないPolicyでは時間期限を検査しません。評価記録自体の時間期限と信頼された時計・台帳・承認者権限は未実装です。

[設計文書目次](../api-security-design/README.md)、[v0.1メタモデル](../api-security-design/04_Security_Design_IR.md)、[v0.2保証・適合性・Release Gate](../api-security-design/05_Security_Design_IR_v0.2.md)、[適合性記録](CONFORMANCE.md)を参照。v0.1案と本プロトタイプは独立しており、同一スキーマとして統合されていません。

## 変更履歴

- 2026-11-02: 候補IRからのRelease Gate導出を追加し、45件の試作テストを確認。設計文書との相互リンクを整備。

## 2026-11-03 実証と測定

[実測・適合性評価](EVALUATION-2026-11-03.md)に3つの合成APIケース、変更影響、欠陥注入、測定値、凍結判断を記録。`fixtures/build_pilots.py`でフィクスチャを再生成し、`run_pilots.py`で`pilot-results.json`を再計算します。54件成功、要求経路4/4、欠陥検出27/27、クリーン誤検出0/3、申告済み証拠失効6/6。実APIコードと証拠実体は未検証です。

試験用Policyが要求する `evidenceRegistryRequired` と `completeTraceRequired` は、台帳照合と要求経路欠落のGate保留を有効にします。CLIでは `--evidence-registry fixtures/evidence_registry.json` を渡してください。台帳は合成フィクスチャから作った別ファイルであり、真正なCI記録ではありません。詳細と限界は[実測評価](EVALUATION-2026-11-03.md)を参照。
