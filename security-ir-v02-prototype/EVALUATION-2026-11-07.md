# v0.2凍結監査とRelease Gate回帰検証

検証日: 2026-11-07。**v0.2全面凍結不可。リリース候補版は確定しない。** 実装の識別子 `0.2.0-dev.20261107` は今回の開発スナップショットであり、適合認定やリリース承認ではない。

## 確認した正本と作業開始時の状態

参照ChatGPTチャット `6ae18d1e-f010-83ec-916a-e67def77869d` と前回Workチャット `01a19ff9-75f0-77b0-9fa7-96617144fec8` を取得した。前者の直近内容はWorkへの引き継ぎで、後者の54件成功・欠陥27/27検出という報告をローカルの実装・ログと照合した。アップロード済みの別添規範仕様は確認できていない。

作業対象は `/Users/behike56/01_product/api-builder/security-ir-v02-prototype`。Gitの履歴は `ab775a1 Initial commit` の1件のみで、開始時点ですでにルートREADMEが変更済み、設計文書とプロトタイプ全体が未追跡だった。そのためGit差分だけで前回からの変更を確定できない。既存変更を保持し、実ファイル、前回Work記録、README、CONFORMANCE、2026-11-03評価報告を比較した。対象内と親ディレクトリに適用されるAGENTS.mdは見つからなかった。

`/Users/behike56/Documents/ChatGPT/build-api` はGitリポジトリではない。同所の `security_design_ir` は別のモデルと評価器で、今回も42件成功した。両試作の件数を足してv0.2適合性の分母にはしない。再実行ログは同所の `security_design_ir/reports/test-results-2026-11-07.txt`。

## 再現手順と実測

プロトタイプのディレクトリで次を実行する。同梱 `.venv` のPythonとjsonschemaを利用した。

```sh
.venv/bin/python verify_freeze.py
```

このコマンドはスキーマ検査、全テスト、3つのパイロット測定を実行し、[テストログ](test-results.txt)、[パイロット結果](pilot-results.json)、[機械可読監査報告](reports/freeze-audit-2026-11-07.json)を保存する。監査報告は入力ソース・フィクスチャのSHA-256も保持する。終了0は実験の再現成功であり、凍結可能という意味ではない。JSON内の `freezeDecision` は `not-eligible`。

| 項目 | 変更前 | 変更後 | 測定の範囲 |
| --- | ---: | ---: | --- |
| 全回帰テスト | 54/54成功 | 69/69成功 | unittestのテストメソッド数。失敗0、エラー0、skip 0 |
| CT-001〜026 | 26/26成功 | 26/26成功 | 既存の限定的契約。26 IDの収集も自動検査 |
| 3ケースの要求経路 | 4/4 | 4/4 | 全アクティブ要求を対象候補に結ぶ構造監査 |
| 注入欠陥の検出 | 27/27 | 42/42 | 14変異×3ケース。Gateの期待判定とも42/42一致 |
| 証拠再評価の検出 | 6/6 | 12/12 | revision、直接依存、IR要求、IR実行境界の変更×3ケース |
| 正常ケースのフラグ | 0/3 | 0/3 | 合成IRに限る。運用上の誤検出率ではない |
| CLIプロセス往復 | 今回は未計測 | 12/12 | 3ケース×ready / blocked / review-required / unknown |

注文キャンセル、機密情報参照、二段階承認は**合成IRのE2EとCLI入出力**を試した。APIサーバーのHTTP要求、実認可、DB状態遷移や承認者分離を実行した結果ではない。二段階承認のIR変更では、第2段階のみの要求・制御・境界・検証条件から `EVD-002` に影響が届き、第1段階の `EVD-001` へは届かないことを確認した。

## 再現した欠陥と修正

追加安全性テスト14メソッドを修正前の実装へ適用すると、subTestを含む25件のアサーション失敗が発生した。[修正前ログ](reports/gate-safety-before.txt)を保存した。これは既存54件の失敗数ではなく、今回追加した期待動作との差である。

| 問題 | 修正した振る舞い | 主な回帰テスト |
| --- | --- | --- |
| 同じEvidenceへの2リンクで `atLeast(2)` が成功 | PremiseをIDで重複排除してから閾値を計算。1根拠で閾値2ならunknown | `test_duplicate_evidence_cannot_satisfy_at_least_two` |
| IRの要求・境界変更がGateへ伝わらない | 宣言変更を型付きIRで伝播し、証拠を再評価。未知変更はunknown | `test_declared_ir_changes_invalidate_only_affected_stage` |
| 別候補が要求経路を補ってreadyになる | 全アクティブ要求の経路を、今回評価するcandidate IDで制限 | `test_other_candidate_cannot_cover_missing_required_claim` |
| 台帳が環境・scope・依存を拘束しない | 既存5属性に加えて環境・scope・依存を照合 | `test_registry_binds_environment_scope_and_dependencies` |
| 廃止証拠と未承認リスク記録が通る | EvidenceとResidualRiskのノード承認状態も照合 | `test_unapproved_or_retired_evidence_requires_review` |
| 時間が経過しても同じrevisionなら証拠を再利用 | 任意の版付きPolicyによる証拠最大経過秒数と明示評価日時を導入 | `test_expired_or_future_evidence_requires_review` |

`fail > review > unknown > pass` の集約は保持する。有効なIRにおいて未知変更と重大open Findingが共存すればblocked、リスク未承認ならreview-required。構造・Policy自体が無効な入力は、導出前にunknownを返す。

## 今回追加した試行契約と制限

以下は既存の完全な規範要件を復元したものではなく、今回実装して回帰確認した試行契約である。

- `ReleasePolicy.attributes.maxEvidenceAgeSeconds`: 任意の0以上の整数。指定時には候補の `evaluatedAt` とEvidenceの `observedAt` が必要。
- 日時はタイムゾーン付きISO 8601。欠落なら成功にせず、不正形式ならschema-invalid。経過秒数が上限と等しい場合は有効、1秒超過または未来観測はreview-required。時間鮮度を検査しない既存Policyとの互換性を維持する。
- 時間鮮度を要求する台帳照合では `observedAt` も比較する。評価時計も台帳も入力値であり、信頼された時刻証明ではない。AssuranceAssessment自身の時間期限・期限付きリスク承認は未実装。
- `changedDependencies` は利用者が申告する。今回、IRの依存伝播をGateに接続したが、実コード差分の抽出や変更一覧の真の完全性は検証しない。制御変更から対象要求へも伝播し、要求に対する検証条件を再評価する。意味上無関係な変更の除外は人のレビューが必要。
- `completeTraceRequired` は全アクティブ要求を当該候補で追跡する保守的な契約。複数候補に要求を分割する正式なスコープ宣言は未定義。経路存在は制御・論証の意味的妥当性を証明しない。
- 別IDのEvidenceの独立性は依然として未検証。同じ実行物から作った複数IDの票を独立根拠とは認定できない。
- 台帳は合成データの固定ファイル。署名、CI実行物の取得、成果物内容のハッシュ検証、承認者権限の検証はない。

## C1〜C4と凍結判定

規範30要件の番号別本文が利用可能なソースにない。両ソースフォルダーのMarkdown/JSONで番号を検索し、旧 `api-security-design-system-complete.zip` も確認したが、ZIPは2026-10-30の設計体系・パターン・注文キャンセル文書の3ファイルのみだった。既存報告の番号範囲はC1が8、C2〜C4が各7で合計29にしかならず、30件目も未特定。今回の安全性テストを、その欠けた規範本文や独立適合性試験の代替とはしない。

| 区分 | 今回実測した部分 | 全面凍結を妨げる項目 | 判定 |
| --- | --- | --- | --- |
| C1 Structural | スキーマ・日時形式・型付き関係・参照・循環、CT-001〜007 | 全属性・多重度・状態遷移の規範、実カタログ | partial |
| C2 Argumentation | 四値論理・閾値・同一ID票の排除、CT-008〜016 | 子Claim・Assumption・Defeaterの候補IR統合、独立性・意味論 | partial |
| C3 Assurance | revision/環境/scope、IR変更伝播、任意期限、CT-017〜021 | 証拠真正性、実差分の完全性、組合せscope、評価記録自体の時間期限 | partial |
| C4 Release | 候補ごとの経路、5条件導出、重大Finding・リスク保留、CT-022〜026 | 真のClaim/Finding/Risk網羅性、権限、ReleaseDecision発行 | partial |

凍結ブロッカーは、(1)番号付き規範本文と独立オラクルの欠落、(2)構造・ライフサイクル契約の不完全性、(3)完全な保証論証の未統合、(4)証拠真正性・独立性・承認権限の未検証、(5)実差分・一覧完全性の未検証、(6)ReleaseDecisionと実API/CIの未接続。したがって**RC確定は行わない**。CLIの `decision` は候補評価値で、人間のリリース承認を発行しない。

## 次の優先作業

まずv0.2の規範本文を回収し、要件ごとに実装箇所、独立した期待値、試験、未達理由を固定する。要件不足を埋めるために番号や合格基準を捏造しない。

v0.3候補の順序は、(1)正本のOpenAPI operationId・Domain Model IR要素・BDDシナリオを版付きで参照し、参照消失・重複・版不一致で保留する接続、(2)その参照と実差分から変更集合を導出する機構、(3)実CIの実行ID・revision・環境・成果物ハッシュに結び付く証拠台帳、(4)承認権限とReleaseDecision契約。この順序は計画であり、実装・受け入れテスト完了とは主張しない。今回は未達時の分岐に従い、v0.2の欠陥修正を優先した。

## 今回変更したファイル

- 実装: `engine.py`、`application_audit.py`、`schema.json`、`run_pilots.py`、`verify_freeze.py`。
- フィクスチャ: `fixtures/evidence_registry.json`。既存パイロットIRは変更していない。
- 回帰テスト: `tests/test_gate_safety.py`、`tests/test_cli_e2e.py`。
- 実測成果物: `test-results.txt`、`pilot-results.json`、`release-gate-valid.json`、`reports/freeze-audit-2026-11-07.json`、修正前後の `reports/gate-safety-before.txt` / `gate-safety-after.txt`。後者の68件成功はCLIテスト追加前の中間結果。
- 文書: 本書、`README.md`、`CONFORMANCE.md`、上位 `README.md`、`api-security-design/05_Security_Design_IR_v0.2.md`。別ルートの `security_design_ir/README.md` と再実行ログも更新。
