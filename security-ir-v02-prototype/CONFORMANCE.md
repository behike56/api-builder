# v0.2 適合性評価（実装状況と未解決点）

最新検証日: 2026-11-07。**結論：v0.2全面凍結不可／C1〜C4全体への適合未確認。RC確定なし。**

## 最新判定（2026-11-07）

開発スナップショット `0.2.0-dev.20261107` で全69件成功、CT-001〜026は26/26成功。3つの合成IRで要求経路4/4、欠陥注入42/42、Gate期待判定42/42、証拠再評価12/12、正常ケースのフラグ0/3。CLIプロセス往復12/12も確認しました。別ルートの独立試作42件とは区別します。

同一Evidenceの重複票、IR変更のGateへの未伝播、別候補による経路補完、台帳の環境・scope・依存未照合、廃止証拠・未承認リスクの通過を修正しました。任意Policyで証拠の時間期限を検査します。C1〜C4は全てpartialです。規範本文の欠落、完全な論証の未統合、証拠真正性・独立性・権限・一覧完全性・実API/CI・ReleaseDecisionは引き続きブロッカーです。

再現は `.venv/bin/python verify_freeze.py`。[最新の実測・契約・凍結ブロッカー](EVALUATION-2026-11-07.md)と[監査JSON](reports/freeze-audit-2026-11-07.json)を現在の判定根拠とします。以下は2026-11-03以前の検証履歴で、54件などの値は当時の測定です。歴史的な `rc1` 表記やschema IDは全面適合したRCの発行を意味しません。

[設計文書](../api-security-design/05_Security_Design_IR_v0.2.md) · [実行手順](README.md) · [テスト](tests/test_conformance.py)

## 目次

- [モジュール別の判定](#モジュール別の判定)
- [CT-001〜CT-026の結果](#ct-001ct-026の結果)
- [規範30要件に対するギャップ](#規範30要件に対するギャップ)
- [明示的な仕様上の未決事項](#明示的な仕様上の未決事項)
- [今回の実装と実測（2026-11-02）](#今回の実装と実測2026-11-02)
- [凍結判定と変更履歴](#凍結判定と変更履歴)

## モジュール別の判定

| モジュール | 実装・テストできた部分 | 未完成の部分 | 判定 |
|---|---|---|---|
| C1 Structural | JSON Schema、ID重複、ローカル参照、型付きRelation、外部参照の未解決/不存在、Claim依存循環 | 全ノード詳細の制約、完全な多重度・状態モデル、実カタログ | partial |
| C2 Argumentation | 四値論理`allOf/anyOf/atLeast`、異常閾値、順序非依存性、Evidence-ID重複 | グラフからのPremise状態の導出、独立根拠の意味評価、全Claim論証の実行 | partial |
| C3 Assurance | revision/環境/単純Scope比較、依存変更による再評価、Assumption/Defeater保留、保証評価との分離 | 実証拠来歴/完全性、Claim全域カバレッジ、変更影響グラフ、保証十分性レビュー | partial |
| C4 Release | 必須5条件のFail>Review>Unknown>Ready集約、欠落チェックのUnknown化 | 候補・版付きPolicy・Claim/Evidence/Finding/Riskからのチェック導出を追加。Claim集合の網羅性、真正性、権限照合、ReleaseDecision発行は未完成 | partial |

## CT-001〜CT-026の結果

すべてのテストケースは、**この試作器の限定的な期待動作**を検証して成功しました（26件/26件）。追加の性質テスト7件も成功しました。今回のIR統合回帰テスト12件も成功し、2026-11-03には実証回帰9件を加え、合計54件です。これは全30件の規範要件を実装・立証したことを意味しません。

| ケース | 概要 | 試作器の結果 |
|---|---|---|
| CT-001〜007 | 構造・ID・参照・関係・循環・外部カタログ・スキーマ | 7/7 pass |
| CT-008〜016 | 四値論理・閾値・同一Evidence ID重複 | 9/9 pass |
| CT-017〜021 | Scope・変更・Assumption・Defeater | 5/5 pass |
| CT-022〜026 | Release Gateの結果集約 | 5/5 pass |

## 規範30要件に対するギャップ

- **C1:** C1-01〜06、C1-08の中心機能を試作。C1-07の細部（エンティティ別制約）にギャップ。`status`等のライフサイクル完全性は未評価。
- **C2:** C2-01〜04、C2-07の計算部分を試作。C2-05（必須Premiseのグラフ結合）とC2-06（独立性）は部分対応。
- **C3:** C3-01、C3-04〜05、C3-07の区別を関数で試作。C3-02〜03、C3-06は対象と被覆の意味論・変更追跡が部分対応。
- **C4:** C4-03〜05、C4-07のチェック値集約に加え、版付きReleasePolicyとReleaseCandidateの関係を導入し、候補に結び付く記録から5条件を導出。C4-01〜02とC4-06の一部を試作したが、ReleaseDecision発行・署名・権限検証と一覧の完全性は未実装。

## 明示的な仕様上の未決事項

1. **外部参照未解決:** 参照先が欠落しているのか、リゾルバーが取得できないのか。後者は`indeterminate`（CLI終了2）とし、成功とみなさない。
2. **論証の十分性:** 四値演算子の演算結果は論証の妥当性を証明しない。`supported`を最終AssuranceAssessmentに転記する際はレビューが必要。
3. **同一Evidenceの独立性:** ID重複排除は独立性の証明ではない。証拠の生成源・共通原因と証拠の使用目的をモデル化する必要がある。
4. **証拠の有効性:** 旧revisionというだけで`not-applicable`と断定せず`needs-review`とした。変更内容が意味に影響しない可能性を残す。
5. **検証結果の信頼境界:** `evaluate_release_candidate` はIRからチェックを導出するが、IR内の証拠・評価・承認・一覧完全性の申告を認証しない。これはReleaseConformanceの主要ギャップ。
6. **四値論理の反証伝播:** allOf/anyOfの負の伝播は、Premiseが親Claimの必要十分な分解であると正当に説明できる場合に限り意味を持つ。
7. **プロファイル:** `release`の全必須条件を単なるgraph validationの`approved`に同一視しない。保証判定は別評価器が担当。

## 再現用コマンド

```bash
python -m unittest discover -s tests -v
python cli.py validate fixtures/order_cancel_valid.json --catalogs fixtures/catalogs.json
python cli.py validate fixtures/order_cancel_valid.json
```

後者は期待どおり外部参照未解決で**終了コード2**となります。

## 今回の実装と実測（2026-11-02）

追加された `security-ir-v02-prototype` を直接調査。変更前に既存33件が成功。`schema.json` に ReleasePolicy と候補・評価記録の属性制約を追加し、`engine.py` に候補IRからの判定導出、`cli.py` に `release-gate` コマンドを追加した。`fixtures/release_candidate_valid.json` と回帰テスト12件を追加。JSON Schema Draft 2020-12としてスキーマを検査し、45件を実行して45件成功（0.098秒）。正常候補のCLI結果は `ready`（終了0）、旧revision候補は `review-required`、反証Evidenceと重大open Findingは `blocked`、未承認リスクは `review-required`、ポリシー版不一致・必須チェック欠落・外部カタログ未解決は `unknown`。

| 領域 | 現在の到達点 | 残る制約 |
|---|---|---|
| C1 | 型付き関係、スキーマ、版付きPolicy参照を検査 | v0.2全ノードの厳密な属性・多重度・状態遷移は未規定 |
| C2 | 単純なEvidence Premiseの論証をIRから計算 | 子Claim、Assumption、Defeater、独立根拠の統合は未実装 |
| C3 | Evidence適用性を候補revision・環境・スコープ・変更依存で再計算し、記録された評価と照合 | Evidenceの真正性、変更差分の網羅性、評価者権限、時間ベースの期限は未検査 |
| C4 | 候補→ポリシー→5チェックを導出し、Fail > Review > Unknown > Readyの優先順位で集約 | 必須Claim/Finding/Risk一覧の真の完全性、ReleaseDecision発行・承認は未実装 |

`claimsComplete` / `changedDependenciesComplete` / `findingsComplete` / `risksComplete` は入力側の自己申告であり、実際の網羅性を証明しない。現行のRelease Gateは直接EvidenceをPremiseに持つClaimのみを評価し、それ以外の論証形は`unknown`にする。評価記録の `assessedAt` は必須だが、有効期間はまだ検査していない。`ready` はリリース許可ではない。これらの未実装があるため、**v0.2の全面凍結は引き続き不可**。今回の候補IR契約は実験用の試行仕様としてのみ固定できる。

## 凍結判定と変更履歴

全面凍結の前提は、C1〜C4全必須要件の仕様・独立した適合性テスト、完全な論証と証拠の評価、真正性・権限・列挙完全性、実案件での評価が揃うこと。現行54件は試作の限定的回帰テストであり、この前提を満たさない。

- 2026-11-02: 候補IRと版付きポリシーからの5条件導出、追加12テストを記録。
- 2026-11-02: 設計文書への相互リンクと凍結前提を明記。

## 2026-11-03の再評価

[実測と個別ギャップ](EVALUATION-2026-11-03.md)を参照。C1〜C4の30要件は番号ごとの規範本文がこのソースに収録されていないため、個別の適合認定はできない。CT-001〜026は26/26成功したが、限定的試作動作の確認である。GateはClaim・変更依存の一覧完全性申告がfalseならunknown、未承認の証拠有効性評価ならreview-requiredにした。54件の回帰テスト成功と3つの合成ケースでの実証結果からも、全面凍結不可という判断は変わらない。

- 2026-11-03: 試験用Policyに台帳照合と要求経路必須を追加。CT-001〜026は26/26、全54件が成功。合成3ケースの欠陥検出は27/27、要求経路は4/4、申告済み失効は6/6。台帳の真正性、ReleaseDecision発行、規範30要件の個別適合は未確認。
