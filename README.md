# APIセキュリティ設計とSecurity Design IR

APIセキュリティ設計の整理案、注文キャンセルAPIの仮想ケース、Security Design IR v0.2の独立試作を収録します。

- [設計文書の目次](api-security-design/README.md) — 8軸、原則、制御、7群21候補、ケーススタディ、IR v0.1/v0.2
- [試作の実行手順](security-ir-v02-prototype/README.md) — JSON Schema、評価器、フィクスチャ、テスト
- [適合性と凍結判断](security-ir-v02-prototype/CONFORMANCE.md) — C1〜C4の実装範囲と残課題

本リポジトリのIRは独自の試行仕様です。試作テストの成功は実システムの安全性やv0.2全面適合を意味しません。

2026-11-07の[凍結監査](security-ir-v02-prototype/EVALUATION-2026-11-07.md)では全69件、CT-001〜026が成功。合成3ケースの欠陥42/42と証拠再評価12/12を検出しました。規範本文・真正な証拠・承認権限・ReleaseDecisionなどが未完了のため、v0.2全面凍結とRC確定は見送っています。

## 変更履歴

- 2026-11-02: 設計文書、試作、適合性記録への案内を追加。
