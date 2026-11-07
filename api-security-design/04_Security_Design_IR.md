# Security Design IR v0.1 — メタモデルと検証仕様

[目次へ](README.md) · [基本体系](01_基本体系.md) · [パターン](02_設計パターン.md) · [ケーススタディ](03_ケーススタディ_注文キャンセルAPI.md)

更新日: 2026-11-02 / 状態: **v0.1の設計案**。別個の[v0.2試作と適合性評価](05_Security_Design_IR_v0.2.md)は存在するが、この文書の全項目が実装されたわけではない。

## 1. 目的と不変の設計方針

**Security Design IR** はセキュリティ要求、脅威、判断、制御、パターン、責務、検証・保証を、技術実装から独立した一貫した意味構造として表す中間モデル。

用途: 共有メンタルモデル、要求→制御→実装→検証の追跡、関係不整合の検出、OpenAPI/Domain Model IR/ADR/テストとの接続。

**区別するもの**: 設計された制御と実際の有効性、セキュリティ設計知識とシステム固有設計、検証条件と証拠、事実と推論。正しいIR構造は安全な実装を保証しない。

## 2. 3層モデル

| 層 | 内容 | 役割 |
|---|---|---|
| L1 Security Knowledge Model | Principle, ControlDefinition, PatternDefinition, PatternRelation, ThreatType | 再利用可能な知識 |
| L2 Security Design Model | Asset, SecurityRequirement, ThreatScenario, RiskAssessment, TrustBoundary, Component, SecurityPolicy, DesignDecision, ControlApplication, PatternApplication, PatternComposition, DataFlow | システム固有の設計主張 |
| L3 Security Assurance Model | VerificationCriterion, VerificationActivity, Evidence, Finding, ResidualRisk, AssuranceClaim | 評価・証拠・保証 |

**定義と適用を分離**: `PatternDefinition` と `PatternApplication`、`ControlDefinition` と `ControlApplication` は別概念。外部カタログのバージョンを固定して参照する。

## 3. 正規表現形式

- **正規意味モデル**: Typed Property Graph（型付きノードと型付き関係）。
- **シリアライズ**: 編集用YAML、ツール交換用JSON。どちらも同じ意味に変換する。
- **ノード**: `id`, `kind`, `attributes`。関係: `id`, `kind`, `source`, `target`, `attributes`。
- **関係の独立化**: 関係に根拠・適用条件・有効期間・レビュー状態が必要な場合は属性付きエッジとする。単純な分類はノード属性としてよい。

### 最小例

```yaml
schemaVersion: '0.1.0'
design:
  id: order-management-api
  revision: 3
catalogs:
  patterns: 'security-patterns@0.1.0'
  controls: 'security-controls@0.1.0'
nodes:
  - id: AST-001
    kind: Asset
    attributes:
      name: Order
      assetType: domain-resource
  - id: SR-003
    kind: SecurityRequirement
    attributes:
      name: Order Cancellation Authorization
      statement: 利用者は権限のある注文のみキャンセルできる
      criticality: high
  - id: CMP-001
    kind: Component
    attributes:
      name: CancelOrder Application Service
      componentType: application-service
  - id: CA-001
    kind: ControlApplication
    attributes:
      name: Order Authorization
      controlRef: 'security-controls@0.1.0:object-authz'
  - id: PA-001
    kind: PatternApplication
    attributes:
      name: Resource-Level Authorization for Orders
      patternRef: 'security-patterns@0.1.0:P1-03'
  - id: VC-001
    kind: VerificationCriterion
    attributes:
      name: Cross-tenant cancellation rejection
      expectedOutcome: denied-without-state-change
relations:
  - {id: REL-001, kind: protects, source: SR-003, target: AST-001}
  - {id: REL-002, kind: addresses, source: CA-001, target: SR-003}
  - {id: REL-003, kind: enforcedAt, source: CA-001, target: CMP-001}
  - {id: REL-004, kind: realizes, source: PA-001, target: CA-001}
  - {id: REL-005, kind: evaluates, source: VC-001, target: SR-003}
```

> 部分例。L1カタログ、ADR・脅威・実行結果等は未収録。この例を「完全なSecurity IR」とみなさない。

## 4. 主要エンティティ属性（案）

共通: `id`, `kind`, `name`, `description?`, `status`, `revision`, `sourceRefs?`。シリアライズ形式では共通属性を`attributes`に置くかトップレベルに置くかを**未確定**とし、スキーマ実装時に一方式へ統一する。

| エンティティ | 必須の固有属性例 |
|---|---|
| Asset | assetType, ownerRef |
| SecurityRequirement | statement, criticality |
| ThreatScenario | scenario, targetRefs |
| RiskAssessment | threatRef, impact, likelihood, assessmentStatus |
| DesignDecision | problem, decision, rationale, alternativeRefs |
| SecurityPolicy | subject, resource, action, effect |
| ControlApplication | controlRef, enforcementRefs |
| PatternApplication | patternRef, decisionRef |
| Component | componentType, responsibility |
| TrustBoundary | insideRefs, outsideRefs, crossingRefs |
| VerificationCriterion | statement, expectedOutcome |
| VerificationActivity | criterionRefs, method, executionStatus |
| Evidence | activityRef, result, artifactRef, observedAt |
| AssuranceClaim | claim, requirementRefs, evidenceRefs |

**モデル化上の注意**: 属性配列の`*Refs`と独立したRelationを二重に正本化しない。正式v0.1ではRelationを正本とし、属性内の参照は外部カタログ等の固定参照に限定する方向で検討する。

## 5. 関係型・多重度

多重度は始点ノード当たりの終点数。各関係の逆方向制約は別定義が必要。

| 関係 | 始点 → 終点 | 提案多重度 |
|---|---|---|
| protects | SecurityRequirement → Asset | 1..* |
| threatens | ThreatScenario → Asset | 1..* |
| addresses | ControlApplication → SecurityRequirement | 1..* |
| guidedBy | DesignDecision → Principle | 0..* |
| applies | PatternApplication → PatternDefinition | 1 |
| realizes | PatternApplication → ControlApplication | 1..* |
| enforcedAt | ControlApplication → Component | 1..* |
| crosses | DataFlow → TrustBoundary | 0..* |
| evaluates | VerificationCriterion → Requirement/ControlApplication | 1..* |
| produces | VerificationActivity → Evidence | 0..* |
| supports | Evidence → AssuranceClaim | 0..* |

`PatternDefinition`/`Principle`等はL1外部参照で解決してよい。全ての設計途中状態に多重度を強制せず、検証プロファイルにより警告・エラーを切り替える。

## 6. 状態・識別子・版

### 状態

一般設計エンティティ: `draft → reviewed → approved → retired`。変更時に再審査。`approved`は**設計承認**であり、検証合格ではない。VerificationActivityは別途`planned`, `running`, `completed`, `blocked`などを持ち、実行状態と結果を分離する。

### IDとバージョン

- Entity ID: `SR-003`（モデル内一意）
- Qualified ID: `order-api:SR-003`（モデル横断）
- Versioned Reference: `security-patterns@0.1.0:P1-03`
- 独立管理: `schemaVersion`、`knowledgeCatalogVersion`、`design.revision`。
- 外部参照: OpenAPI `operationId`、Domain Model IR ID、ADR ID、テストID。必要に応じて参照先の版/ハッシュを固定。

## 7. 3段階の検証

| レベル | 対象 | 方法 | 限界 |
|---|---|---|---|
| L1 構造 | 必須属性、型、列挙値、フォーマット | JSON Schema 2020-12 | 参照先存在・設計妥当性は判定しない |
| L2 意味・関係 | ID一意、参照整合、関係型、多重度、カバレッジ | グラフ検証・宣言的ルール | 脅威への実効性は保証しない |
| L3 セキュリティ妥当性 | 脅威適合、保証主張、実装・証拠・残留リスク | レビュー、テスト、監査、証拠評価 | 絶対安全の証明ではない |

### 検証プロファイル

- **Draft**: 型、参照、ID等の基礎構造。不完全な対応関係を許容・警告。
- **Review**: 要求・脅威・制御・責務・パターン・検証計画の対応を要求。
- **Release**: 必須検証の結果・証拠・残留リスクと未解決重大不備の扱いを確認。

### ルール初期案

| ID | ルール | Draft | Review | Release |
|---|---|---|---|---|
| R-001 | ノードIDは一意 | error | error | error |
| R-002 | Relation参照先が存在 | error | error | error |
| R-003 | Relation始点・終点型が正しい | error | error | error |
| R-004 | 必須要求に保護対象がある | warning | error | error |
| R-005 | 重要な脅威に対応方針がある | warning | error | error |
| R-006 | 採用制御の強制点が明示される | warning | error | error |
| R-007 | パターン依存・競合を評価 | info | warning | error |
| R-008 | 必須要求に検証条件がある | warning | error | error |
| R-009 | 必須検証に結果・証拠がある | info | warning | error |
| R-010 | 残留リスク判断を記録 | info | warning | error |

重要度未評価の脅威は勝手に高・低と推定せず、判定不能として扱う。ルール重要度（error/warning/info）と検証結果を混同しない。

### 検証結果

`pass`, `fail`, `unknown`, `not-applicable`。別属性として`severity: error|warning|info`を持つ。例: `R-006 fail/error`（強制点未定義）、`R-009 unknown/warning`（検証未実施）。これは**想定例であり実行結果ではない**。

## 8. 検証パイプライン

`YAML/JSON parse → JSON Schema validation → typed graph construction → ID/reference/type/cardinality validation → profile-based semantic rules → ValidationReport → review/CI`。

同じ入力・カタログ・ルール版に対する決定的な検証を目指す。AI提案はルールによる確定的違反と分離する。結果にモデルrevision、検証プロファイル、カタログ版、ルール版を記録。

JSON Schema例の型の枠組み（**部分例**）:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["id", "kind", "attributes"],
  "properties": {
    "id": {"type": "string", "pattern": "^[A-Za-z][A-Za-z0-9._-]*$"},
    "kind": {"enum": ["Asset", "SecurityRequirement", "ThreatScenario", "DesignDecision", "ControlApplication", "PatternApplication", "Component", "VerificationCriterion"]},
    "attributes": {"type": "object"}
  },
  "additionalProperties": false
}
```

この部分例自体は実行対象ではない。現行の[v0.2 JSON Schema](../security-ir-v02-prototype/schema.json)は一部のノード属性を検査するが、ここに挙げた全エンティティ・多重度・遷移を網羅しない。

## 9. Assurance・証拠

`AssuranceClaim ← supports ← Evidence ← producedBy ← VerificationActivity ← evaluates ← VerificationCriterion`。

Evidenceに少なくとも `artifactRef`, `subjectRevision`, `environmentRef`, `observedAt`, `result`, `scope`, `limitations` を持たせる。証拠は特定版の設計・実装と環境に対して有効。変更時に再評価する。テストケースの存在はテスト成功の証拠ではない。AssuranceClaimに適用範囲・前提・未検証領域・残留リスクを明示する。

## 10. 他の成果物との接続

| 外部成果物 | IRのリンク対象 | 正本の扱い |
|---|---|---|
| OpenAPI | operationId、入力制約、認証方式 | API契約はOpenAPI |
| Domain Model IR | 集約、操作、値型、状態遷移、不変条件 | 業務ルールはドメインモデル |
| ADR | 採用根拠・代替案 | ADRと設計決定を相互参照 |
| Threat Model | 攻撃経路、影響、リスク | 脅威評価の根拠を保持 |
| BDD/Tests | 受け入れ条件・テスト実行 | テスト定義・結果に参照 |
| Source/CI | 強制点と実装位置、コミット | 実装を正本とする |
| Logs/Telemetry | 監査・検知・実運用の証拠 | 有効期間・保護・秘匿に配慮 |

例: `AST-001 → domain:Order`、`PA-STATE-001 → domain:CancelOrder`、`CA-STATE-001 → domain:Order.canCancel`。`canCancel`は業務可否であり、主体の認可を代替しない。

## 11. 変更影響分析

例: 「注文所有者のみ取消可」→「所有者または同一企業の権限ある管理者が取消可」。参照グラフでSecurityPolicy、DesignDecision、ControlApplication、VerificationCriterion、TestCase、AssuranceClaimを再評価対象として列挙。**自動変更と自動承認はしない**。

## 12. IR自身の品質特性

完全性、一貫性、追跡可能性、明確性、進化容易性、相互運用性。`addresses`関係の存在は対策の十分性の保証ではない。

## 13. 未確定事項・次の検証

1. 正規ノード属性の共通フィールド配置とRelation/Refs二重管理を解消する。
2. エンティティと関係の完全なJSON Schema、外部カタログ参照スキームを定義する。
3. Draft/Review/Releaseのルールと例外承認を形式化する。
4. 注文キャンセルAPIの全要素をIRで表現する。
5. 正常・意図的に不正なIRでL1/L2の検出を実測する。
6. L3保証の限界、証拠失効、残留リスクとリリース判定を設計する。
7. Domain Model IR、OpenAPI、ADR、BDDとの往復参照を検証する。

### 現時点の状態

本書のv0.1メタモデルとR-001〜010は**設計案**。現行[v0.2試作](../security-ir-v02-prototype/README.md)には動作する部分スキーマと評価器があり、2026-11-02に45件の試作テスト成功を確認した。これは本書の全ルールの実装、実システムの安全性、v0.2全面適合を意味しない。差分と凍結基準は[v0.2文書](05_Security_Design_IR_v0.2.md)と[適合性記録](../security-ir-v02-prototype/CONFORMANCE.md)を参照。
