# v0.2適合性・API適用・有効性の実測

検証日: 2026-11-03。対象はこのディレクトリの独立試作器と `../api-security-design/05_Security_Design_IR_v0.2.md`。別ルートの `build-api/security_design_ir` は独立した v0.1/v0.2 試作であり、同じスキーマ・判定器ではない。

## 再現手順と実行結果

```sh
security-ir-v02-prototype/.venv/bin/python security-ir-v02-prototype/fixtures/build_pilots.py
security-ir-v02-prototype/.venv/bin/python -m unittest discover -s security-ir-v02-prototype/tests -v
security-ir-v02-prototype/.venv/bin/python security-ir-v02-prototype/run_pilots.py
security-ir-v02-prototype/.venv/bin/python security-ir-v02-prototype/cli.py validate security-ir-v02-prototype/fixtures/pilot_multistage_approval.json --catalogs security-ir-v02-prototype/fixtures/catalogs.json --profile review
security-ir-v02-prototype/.venv/bin/python security-ir-v02-prototype/cli.py release-gate security-ir-v02-prototype/fixtures/pilot_multistage_approval.json --catalogs security-ir-v02-prototype/fixtures/catalogs.json --evidence-registry security-ir-v02-prototype/fixtures/evidence_registry.json --candidate RC-001
```

2026-11-03 の実行では54件成功（既存51件と追加3件）。独立試作器 `build-api/security_design_ir` は同日42件成功。`api-builder` のシステム Python 3.9 は `jsonschema` がなくテスト収集に失敗したため、同梱 `.venv` の Python 3.14.2 を使用した。3件の合成IRはReview構造検査で findings 0、試験用の別ファイル台帳を渡した候補判定は `ready`。出力は `test-results.txt` と `pilot-results.json`。Policy が要求する台帳は `fixtures/evidence_registry.json` に置いた試験用の値で、実CIから独立取得した記録ではない。

## C1〜C4とCTの到達点

30必須要件の**番号ごとの規範本文は追加ソースに存在しない**。既存 `CONFORMANCE.md` が言及する番号は C1-01〜08、C2-01〜07、C3-01〜07、C4-01〜07 の計29個までで、30件目の番号・内容も確認できない。以下はその概括と実装を照合した評価であり、30件の個別適合認定ではない。

| 区分 | 番号範囲（件数） | 検証した部分 | 未充足・未検証 |
|---|---:|---|---|
| C1 | 01〜08（8） | JSON Schema、ID、型付き関係、参照、Claim循環、外部カタログ、候補の追加必須属性 | 全ノード属性・多重度・状態遷移、実カタログ真正性 |
| C2 | 01〜07（7） | 四値演算、閾値、ID重複除外、直接Evidence premise | 子Claim・Assumption・DefeaterのIR統合、証拠独立性・論証意味論 |
| C3 | 01〜07（7） | revision・環境・scope・申告された変更依存、評価記録の照合 | 実証拠真正性、変更一覧完全性、時間期限、組合せscope |
| C4 | 01〜07（7）＋未特定1件 | 版付きPolicy、候補リンク、5チェック導出、fail優先、保留 | Claim/Finding/Risk真の網羅性、承認権限、ReleaseDecision発行 |

CT-001〜026はテスト名を全件確認し、同梱環境で26/26成功。C1の7件、C2の9件、C3の5件、C4の5件である。CT-008〜026の多くは演算・集約関数への直接入力であり、IR全経路の適合性試験ではない。追加12件は候補IRからのGate導出、今回の9件は実証ケース、保留動作、台帳照合を対象とする。独立した仕様オラクルや外部システム検証はない。

今回修正した点: `ReleaseCandidate` に `claimsComplete` と `changedDependenciesComplete` の明示申告を要求し、false なら `unknown`。EvidenceValidityAssessmentが未承認なら `review-required`。AssuranceAssessmentの日時はタイムゾーン付きISO形式として検査する。Evidence/Claim/候補の主要属性に型制約を加えた。これらは欠落・誤形式の入力による誤った `ready` を抑えるが、true の申告内容を独立検証しない。

## 3ケースの追跡と変更影響

合成フィクスチャは `fixtures/pilot_order_cancel.json`、`pilot_sensitive_read.json`、`pilot_multistage_approval.json`。実アプリケーションへのコード統合や実CI証拠の取得ではない。各ケースに Requirement→Asset/Threat→Control→Component→Criterion→VerificationActivity→Evidence→Claim→AssuranceAssessment→ReleaseCandidate→ReleasePolicy を置いた。二段階承認には2要求と2組の制御・証拠・主張を置いた。`application_audit.py` が経路の欠落を列挙する。

| ケース | 要求 | 完全経路 | 変更 `SR-003` からの影響例 |
|---|---:|---:|---|
| 注文キャンセル | 1 | 1 | `EVD-001`, `CLAIM-001`, `RC-001` |
| 機密情報参照 | 1 | 1 | `EVD-001`, `CLAIM-001`, `RC-001` |
| 二段階承認 | 2 | 2 | 第1段階の `EVD-001`, `CLAIM-001` と候補。第2段階の証拠は影響外 |

`affected_by_changes` は型付き関係を逆向きにたどる、宣言的な影響候補の抽出である。変更IDが不明なら `unknown` に残す。実コードの差分や全依存を自動発見するものではない。IRの経路が揃っていても制御の正しさ・証拠の真偽は保証されない。

## 測定値と限界

測定定義は `run_pilots.py` に固定した。分母は現実の全要求や全欠陥ではなく、上記3件の合成IRと意図的な変異である。

| 指標 | 実測 | 分母と意味 |
|---|---:|---|
| 要求追跡率 | 4/4 = 100% | 11段階の構造経路が全て存在した要求 |
| 注入欠陥の検出率 | 27/27 = 100% | 9変異×3ケース。経路欠落3種、旧revision、評価欠落、台帳と不一致の証拠参照、重大open Finding、未承認リスク、Policy版不一致を検出 |
| クリーンケースの誤検出 | 0/3 | 合成正常フィクスチャがフラグされた割合。一般的な誤検出率の推定ではない |
| 証拠失効の検出率 | 6/6 = 100% | 候補revision変更と**申告済み**依存変更、各3ケース |
| レビュー負荷 | 未測定 | 人間のレビュー時間、判断回数、認知負荷の実測なし |

`ready` はIRと試験用台帳に対する候補判定に限り、人間のリリース承認ではない。実際のAPIコード、OpenAPI、CI実行物、カタログ実体との照合は未実施。虚偽の `artifactRef` 3件は台帳照合で保留となった。台帳をIRと同時に改変できる場合や、台帳の内容自体が虚偽の場合は検出できない。欠陥検出率と誤検出の値を実運用へ一般化できない。

## 今回の修正とリリース判定

試験用Policyに `evidenceRegistryRequired` と `completeTraceRequired` を加えた。前者は候補に結び付くEvidenceの参照・生成者・結果・対象・revisionを別ファイル台帳と比較し、欠落なら `unknown`、不一致なら `review-required` にする。後者はアクティブな要求の構造経路が欠けた場合に `unknown` にする。3ケースの注入された経路欠落は、監査だけでなくGateも `ready` を返さなくなった。重大open Findingは `blocked`、未承認リスクは `review-required`、Policy版不一致は `unknown` を各ケースで確認した。`ReleaseDecision` ノードの発行や承認者署名は未実装であり、CLIの `decision` は候補評価値である。

## 凍結判断とv0.3候補

**v0.2全面凍結不可。** 30要件の個別規範本文、独立適合性スイート、真正な証拠と承認、変更集合・列挙の完全性、実APIへの接続がない。現行スキーマ・CLI・54件の試行契約だけを版付きで保持できる。

v0.3候補は、(1)30要件の規範本文と要件→テスト対応表、(2)OpenAPI `operationId` とコード境界の参照方式、(3)実CIからの証拠台帳取得、署名・ハッシュ・実行IDと独立性、(4)差分から依存変更を導出する機構、(5)Claim/Finding/Risk一覧の外部正本との照合、(6)子Claim・Assumption・Defeaterを含む保証評価、(7)承認者権限とReleaseDecision契約、(8)実案件でのレビュー時間・精度測定。
