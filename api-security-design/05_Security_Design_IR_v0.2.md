# Security Design IR v0.2 — 保証論証とリリース判定

更新日: 2026-11-07 / 状態: **独自仕様の試行案。全面凍結前。RC未確定**

2026-11-07の[凍結監査](../security-ir-v02-prototype/EVALUATION-2026-11-07.md)では、全69件、CT-001〜026が成功。合成3ケースで欠陥42/42、証拠再評価12/12を確認した。C1〜C4は部分対応のままで、全面凍結不可と判定した。以下の2026-11-03の数値は検証履歴である。

[文書目次](README.md) · [v0.1メタモデル](04_Security_Design_IR.md) · [試作README](../security-ir-v02-prototype/README.md) · [適合性記録](../security-ir-v02-prototype/CONFORMANCE.md)

## 目次

- [位置づけと3層](#位置づけと3層)
- [型付きグラフと契約](#型付きグラフと契約)
- [保証論証と証拠](#保証論証と証拠)
- [適合性と受け入れテスト](#適合性と受け入れテスト)
- [Release Gate](#release-gate)
- [凍結基準と未決事項](#凍結基準と未決事項)
- [参照と変更履歴](#参照と変更履歴)

## 位置づけと3層

本書は[基本体系](01_基本体系.md)の8軸・原則・制御4分類軸/9領域、[7群21候補](02_設計パターン.md)の同定・合成・選択、[注文キャンセルAPI](03_ケーススタディ_注文キャンセルAPI.md)を、追跡可能なモデルへ接続するための**本検討独自の提案**である。21件は候補であり、全件がパターンとして検証済みではない。

| 層 | 主な概念 | 正本と現行実装 |
| --- | --- | --- |
| Knowledge | Principle、ControlDefinition、PatternDefinition、ThreatType | 版付き外部カタログを想定。試作は入力されたID一覧との照合のみ |
| Design | Asset、Requirement、Threat、Decision、ControlApplication、PatternApplication、Component等 | システム固有の判断。試作は一部のノード・関係のみ検査 |
| Assurance | Verification、Evidence、Claim、Argument、Assumption、Defeater、Assessment、Finding、Risk、ReleaseCandidate/Policy | 試作は単純な直接Evidence論証と候補判定を実装 |

IRの構造適合、エンジンの仕様適合、個別リリース候補の可否は別の判断である。設計が承認済みでも、証拠が有効または十分とは限らない。

## 型付きグラフと契約

正規意味モデルは Typed Property Graph。ノードは `id/kind/status/attributes`、関係は `id/kind/source/target` を持つ。ローカル関係を属性の参照配列と二重に正本化しない。v0.1案の多重度（例: `protects` 1..*、`enforcedAt` 1..*、`applies` 1）は[旧メタモデル](04_Security_Design_IR.md#5-関係型多重度)を参照。現行試作が全多重度を検査するという意味ではない。

識別子はモデル内で一意にし、モデル間は Qualified ID、外部知識はカタログ名・版・IDで参照する。`schemaVersion`、カタログ版、`design.revision`、証拠の対象revision、ReleasePolicyの版は独立して管理する。試作の[JSON Schema Draft 2020-12](../security-ir-v02-prototype/schema.json)は `schemaVersion: 0.2.0`、一部の必須属性と列挙値を検査する。外部カタログが取得不能なら未解決、取得した一覧にIDがなければ不存在として扱う。ただし一覧は入力側の申告で、実カタログの真正性を検査しない。

Draft/Review/Releaseは設計グラフの検証プロファイル。Draftでは基本構造、Review/Releaseでは一部の関係下限と採用論証の下限を追加する。**Releaseプロファイルの構造検査とRelease Gateの判定は別**であり、全状態遷移やリリース要件の網羅は未実装。

## 保証論証と証拠

提案モデルでは `AssuranceClaim → supportedByArgument → AssuranceArgument → hasPremise → Claim/Evidence/Assumption` とし、Defeaterは主張を弱める要因として扱う。Argumentは `allOf`、`anyOf`、`atLeast(k)` を持つ。四値論理は肯定・否定の2ビットから `supported / refuted / conflicted / undetermined` を導出する。論理演算の結果は保証の十分性を証明しない。同一Evidence IDの重複を除外しても、別ID間の独立性は立証できない。

Evidenceには対象、revision、環境、scope、生成者、成果物参照、結果を記録する。評価結果は元の観測から分離する。証拠適用性は `applicable / needs-review / not-applicable / unknown`、AssuranceAssessmentは `supported / unsupported / indeterminate / review-required` とする。旧revision、環境差、変更依存は再評価を促し、旧Evidenceの観測値自体を書き換えない。現行試作のscope比較は文字列集合の包含のみで、役割×テナント×操作の意味は評価しない。変更依存集合は入力側が与え、差分の完全性を追跡しない。

Assumption未検証、重大Defeater未解決、論証レビュー未承認は保証評価を保留する関数がある。ただし[候補IRからの統合評価](../security-ir-v02-prototype/engine.py)は直接EvidenceだけをPremiseに持つClaimに限定され、子Claim/Assumption/Defeaterを含む完全な保証ケースは未実装である。`AssuranceAssessment` の承認は入力値で、承認者の権限は検証しない。

## 適合性と受け入れテスト

C1〜C4は成熟度の順位ではなく、機能別の適合区分。`conformant / non-conformant / not-tested / not-implemented` を区別する。全体適合の主張には、各モジュールの必須要件と独立した適合性試験が必要である。

| 区分 | 対象 | 現行の確認範囲 | 主な残課題 |
| --- | --- | --- | --- |
| C1 構造 | ID、型、参照、多重度、循環、版 | JSON Schemaと一部のグラフ検査 | 全属性・多重度・遷移、実カタログ |
| C2 論証 | Claim、Argument、四値、Premise | 演算関数と単純な直接Evidence | 子Claim、独立根拠、論証の意味的妥当性 |
| C3 保証 | 証拠有効性、変更影響、十分性 | revision/環境/scope/申告された変更依存を照合 | 真正性、変更差分、カバレッジ、期限 |
| C4 Release | 候補、版付きPolicy、5条件、阻害事項 | 候補IRのリンク記録からチェックを導出・集約 | 列挙完全性、署名・権限、ReleaseDecision発行 |

[CT-001〜026](../security-ir-v02-prototype/tests/test_conformance.py)は構造7、論証9、保証5、Gate集約5件。[追加12件](../security-ir-v02-prototype/tests/test_release_candidate.py)は候補IRからの判定を検査する。2026-11-03に54件を実行し成功した。ただしCT成功は30件の規範要件全体への適合を示さず、実システムの安全性も検証しない。規範要件ごとのギャップは[CONFORMANCE](../security-ir-v02-prototype/CONFORMANCE.md)を参照。

## Release Gate

ReleaseCandidateは `policyRef = ReleasePolicy ID@version` と `usesReleasePolicy` で版を固定し、`requiresClaim`、`tracksFinding`、`tracksRisk` で判定材料を結ぶ。ポリシーの必須チェックは Required Claims、Evidence Validity、Open Findings、Residual Risk、Assessment Freshness の5つ。エンジンはリンク先の記録からチェック値と理由IDを導出し、優先順位 `fail > review > unknown > pass` で `blocked / review-required / unknown / ready` に集約する。既知の阻害事項を情報不足で隠さない。

`claimsComplete` / `changedDependenciesComplete` / `findingsComplete` / `risksComplete` は自己申告。Policy未解決、必須チェック欠落、必要な評価記録欠落、外部カタログ未解決は `unknown` にする。旧Evidenceは `review-required`、重大open Findingは `blocked`、残留リスク未承認は `review-required` という試作テストがある。`ready` は候補判定であり、人間のReleaseDecision、運用上のリリース許可、安全性認定ではない。

試験用Policyでは `evidenceRegistryRequired` と `completeTraceRequired` を有効にした。前者は別ファイルの証拠台帳とIRの主要属性を照合し、後者は要求から候補・Policyまでの構造経路欠落を保留する。台帳もPolicy自体も実運用の信頼された正本ではない。

## 凍結基準と未決事項

2026-11-07の実装では、同一Evidence IDの重複票を排除し、宣言変更をIRから依存証拠とGateへ伝播する。未知変更は成功にしない。全アクティブ要求の経路を対象候補に結び付け、Evidence・リスクの承認状態を照合する。任意の `ReleasePolicy.maxEvidenceAgeSeconds` と候補の `evaluatedAt`、Evidenceの `observedAt` によって時間鮮度を検査する。上限ちょうどは有効、超過・未来は再評価、日時欠落は成功にしない。これらは今回の試行契約であり、欠落している規範30要件の復元ではない。時間・台帳・変更集合は依然として入力側の申告で、詳細とテスト対応は[今回の報告](../security-ir-v02-prototype/EVALUATION-2026-11-07.md)を参照する。

v0.2全面凍結は見送る。試行契約として扱える範囲は、現行スキーマと試作テストが覆う部分に限る。凍結前に、(1)全エンティティ・関係・多重度・状態遷移の規範化、(2)C1〜C4全必須要件の独立試験、(3)証拠の真正性・独立性・鮮度・変更影響の根拠、(4)必須Claim/Finding/Riskの網羅性、(5)承認権限とReleaseDecisionの契約、(6)実案件での適用・例外処理を確認する。実装済みの部分と未実装/未検証の詳細は[適合性記録](../security-ir-v02-prototype/CONFORMANCE.md)を正本とする。

## 参照と変更履歴

- 外部文献の検証済み範囲: [OWASP API Security Top 10 2023](https://api-security.owasp.org/editions/2023/en/0x11-t10/)のBOLA/BOPLA/BFLA等、[NIST SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final)のゼロトラスト概念、[JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12)のスキーマ形式。
- 書籍の参考一覧は[文書目次](README.md#参照文献)にある。個別の章・頁と本書の各設計判断の対応は未確認。本書の8軸、9領域、7群21候補、IRメタモデル、C1〜C4、Release Gateはそれらの文献による公式分類ではなく本検討の提案。
- 2026-10-30: v0.1メタモデルと設計文書群を作成。
- 2026-11-02: 保証論証、適合性、候補IR由来のRelease Gate、実装差分、凍結基準を追記。45件の試作テストを再実行。
- 2026-11-03: [3ケースの実証と測定](../security-ir-v02-prototype/EVALUATION-2026-11-03.md)を追加。54件成功。30要件の番号ごとの規範本文がソース内にないため、全要件の個別適合は未確定。全面凍結不可。
- 2026-11-03: 試験用Policyで要求経路と別ファイル証拠台帳の照合を必須化。合成欠陥27/27を検出したが、台帳の真正性・権限は未検証。ReleaseDecision発行は未実装。
