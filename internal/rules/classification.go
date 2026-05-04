package rules

import (
	"regexp"
	"strings"
)

// AdvisoryReason returns a human-readable explanation when the given rule_id is
// known to require manual review instead of AI auto-fix. Empty bool means the
// rule is auto-fixable by default (subject to other runtime signals).
//
// The catalog lists rules whose "fix" is fundamentally a human decision:
// identity migrations, engine upgrades, policy audits, or anything where a
// terraform-only patch would either fail validate (cross-resource refs) or
// cause an outage (data migration, breaking IAM changes). Keep this list
// conservative — false advisories cost a manual review; false auto-fixes
// cost a rollback and erode trust.
//
// The map only covers rules where the ID is the most reliable signal. For the
// long tail (Checkov has ~500 AWS rules, tfsec ~200, Terrascan ~150), pattern
// matching against message/remediation handles cross-scanner coverage —
// see advisoryPatterns and AdvisoryReasonForFinding.
var advisoryRules = map[string]string{
	// IAM identity changes — deletion or scope changes ripple to access keys,
	// KMS key policies, and resource-based grants that reference the user.
	"CKV_AWS_273": "removing IAM users requires migrating dependents to IAM roles",

	// Wildcard / admin-grade IAM policies — narrowing them needs a permission
	// audit specific to the workload; AI cannot infer the minimum scope.
	"CKV_AWS_61":  "wildcard IAM policy requires per-workload permission audit",
	"CKV_AWS_62":  "AssumeRole wildcard requires identifying the legitimate trust principals",
	"CKV_AWS_63":  "wildcard action in policy requires per-workload permission audit",
	"CKV_AWS_107": "credentials exposure rule requires manual rotation and policy audit",
	"CKV_AWS_108": "data exfiltration policy requires consumer-side permission review",
	"CKV_AWS_109": "permissions management actions require ownership review",
	"CKV_AWS_110": "privilege escalation policy requires identity hierarchy review",
	"CKV_AWS_111": "write-without-constraints policy requires resource-scope audit",
	"CKV_AWS_287": "wildcard NotAction requires explicit allow/deny policy redesign",
	"CKV_AWS_288": "admin policy attachment requires ownership review before scoping",
	"CKV_AWS_289": "permissions management actions require ownership review",
	"CKV_AWS_290": "policy with wildcard actions requires audit of consumer permissions",
	"CKV_AWS_355": "wildcard resource scope requires audit of dependent operations",
	"CKV2_AWS_40": "IAM policy attachment changes require role inventory review",
	"CKV2_AWS_41": "IAM role for EC2 needs application-level permission scoping",

	// RDS / database / engine upgrades — application driver compatibility and
	// data migration plans must be validated before bumping engine_version or
	// flipping availability flags on a live cluster.
	"CKV_AWS_157": "enabling RDS Multi-AZ triggers failover and brief client disruption",
	"CKV_AWS_293": "engine version change requires migration plan and downtime window",
	"CKV_AWS_133": "RDS backup retention change affects DR policy and storage cost",
	"CKV2_AWS_30": "RDS query logging change affects performance and storage budget",
	"CKV2_AWS_60": "RDS deletion protection toggle depends on environment policy",

	// ElastiCache / DynamoDB / Redshift — multi-AZ failover changes propagate
	// to clients and DNS, not safe to flip blindly on a live cluster.
	"CKV2_AWS_50": "enabling multi-AZ failover affects client reconnect behavior",
	"CKV_AWS_31":  "ElastiCache auth token rotation requires client coordination",

	// VPC / default security group / default network — locking them down can
	// sever existing access from resources that implicitly relied on them.
	"CKV2_AWS_12": "locking the default security group affects implicit access paths",
	"CKV2_AWS_11": "VPC flow logs change affects retention/storage budget decisions",

	// Public access toggles — flipping public_access on running services
	// breaks existing client connectivity outside the VPC.
	"CKV_AWS_56": "S3 block-public-access change requires audit of public consumers",
	"CKV_AWS_53": "S3 block-public-access change requires audit of public consumers",
	"CKV_AWS_54": "S3 block-public-access change requires audit of public consumers",
	"CKV_AWS_55": "S3 block-public-access change requires audit of public consumers",

	// Secrets / hard-coded credentials — removing them requires a migration to
	// a secrets manager plus consumer reconfiguration.
	"CKV_SECRET_2":  "hard-coded secret removal requires migration to a secrets manager",
	"CKV_SECRET_6":  "hard-coded secret removal requires migration to a secrets manager",
	"CKV_SECRET_19": "hard-coded secret removal requires migration to a secrets manager",
}

// advisoryPattern matches a finding by regex against a composite of its
// rule_id, message, and remediation. Patterns cover cross-scanner cases
// where rule IDs differ (Checkov vs tfsec vs Terrascan) but the underlying
// remediation is the same human decision.
type advisoryPattern struct {
	match  *regexp.Regexp
	reason string
}

var advisoryPatterns = []advisoryPattern{
	// IAM identity / policy redesign
	{
		match:  regexp.MustCompile(`(?i)(remove|delete|disable).{0,40}iam\s+(user|group)`),
		reason: "IAM identity changes require migration of dependent access keys and grants",
	},
	{
		match:  regexp.MustCompile(`(?i)(wildcard|"\*"|administrative|admin\s+priv).{0,40}(polic(y|ies)|action|permission)`),
		reason: "wildcard policy requires per-workload permission audit",
	},
	{
		match:  regexp.MustCompile(`(?i)(privilege\s+escalation|permissions\s+management)`),
		reason: "privilege/permissions-management policy requires identity hierarchy review",
	},
	{
		match:  regexp.MustCompile(`(?i)(assume[-_\s]?role|sts:assumerole).{0,40}(wildcard|"\*"|public)`),
		reason: "AssumeRole trust changes require identifying legitimate principals",
	},

	// Public exposure flips on stateful services
	{
		match:  regexp.MustCompile(`(?i)(rds|db|aurora|dms|redshift|elasticsearch|opensearch|elasticache|memcached|mq|neptune|documentdb).{0,80}(publicly\s+accessible|public\s+access|public\s+endpoint)`),
		reason: "public-access change on stateful service affects existing client connectivity",
	},
	{
		match:  regexp.MustCompile(`(?i)(s3|bucket).{0,40}(block\s+public|public[-\s]?access[-\s]?block)`),
		reason: "S3 block-public-access change requires audit of public consumers",
	},

	// Engine / runtime / version upgrades
	{
		match:  regexp.MustCompile(`(?i)(engine\s+version|deprecated.{0,20}runtime|outdated.{0,20}runtime|latest\s+(supported\s+)?(tls|version))`),
		reason: "engine/runtime version change requires application compatibility review",
	},
	{
		match:  regexp.MustCompile(`(?i)(lambda|elasticbeanstalk).{0,40}runtime`),
		reason: "runtime upgrade requires application/library compatibility review",
	},

	// Multi-region / cross-account / org-wide controls
	{
		match:  regexp.MustCompile(`(?i)(all\s+regions|multi[-\s]?region|cross[-\s]?region|cross[-\s]?account)`),
		reason: "multi-region/cross-account change requires org-level configuration review",
	},
	{
		match:  regexp.MustCompile(`(?i)(organi[sz]ation|aws\s+organizations|control\s+tower)`),
		reason: "AWS Organizations change affects all accounts — needs governance review",
	},

	// Deletion protection / termination protection / lifecycle
	{
		match:  regexp.MustCompile(`(?i)(deletion\s+protection|termination\s+protection|prevent[-_\s]destroy)`),
		reason: "deletion/termination protection toggle depends on environment policy",
	},
	{
		match:  regexp.MustCompile(`(?i)(skip[-_\s]final[-_\s]snapshot|final\s+snapshot)`),
		reason: "final-snapshot policy depends on data-recovery requirements",
	},

	// Default network resources
	{
		match:  regexp.MustCompile(`(?i)default\s+(vpc|security\s+group|network\s+acl|route\s+table)`),
		reason: "default network resource changes affect implicit dependencies",
	},

	// Hard-coded secrets / credentials
	{
		match:  regexp.MustCompile(`(?i)(hard[-_\s]?coded|plain[-_\s]?text|in[-_\s]?clear).{0,30}(secret|credential|password|token|key)`),
		reason: "secret removal requires migration to a secrets manager and consumer rotation",
	},
	{
		match:  regexp.MustCompile(`(?i)(secret|credential|password|api[-_\s]?key).{0,30}in\s+(env|environment|user\s+data|metadata)`),
		reason: "secret removal requires migration to a secrets manager and consumer rotation",
	},

	// KMS key policies / rotation
	{
		match:  regexp.MustCompile(`(?i)(kms).{0,40}(rotation|policy|grant)`),
		reason: "KMS key change affects all consumers granted via key policy",
	},

	// Backup / retention / DR
	{
		match:  regexp.MustCompile(`(?i)(backup\s+retention|retention\s+period|log\s+retention|lifecycle\s+rule)`),
		reason: "retention/backup change affects DR policy and storage cost",
	},

	// MFA / root account / break-glass
	{
		match:  regexp.MustCompile(`(?i)(\bmfa\b|root\s+account|break[-\s]glass)`),
		reason: "MFA/root-account change requires identity governance review",
	},
}

// AdvisoryReason returns (reason, true) if the ruleID is in the static
// advisory catalog. Returns ("", false) otherwise. ID-only check — for the
// full pattern-aware classifier, use AdvisoryReasonForFinding.
func AdvisoryReason(ruleID string) (string, bool) {
	r, ok := advisoryRules[ruleID]
	return r, ok
}

// AdvisoryReasonForFinding evaluates the static catalog first, then falls
// back to pattern matching against the finding's message + remediation. This
// catches cross-scanner cases (tfsec, Terrascan) where rule IDs differ but
// the underlying human decision is the same.
func AdvisoryReasonForFinding(f Finding) (string, bool) {
	if reason, ok := advisoryRules[f.RuleID]; ok {
		return reason, true
	}
	haystack := strings.Join([]string{f.RuleID, f.Message, f.Remediation}, "\n")
	for _, p := range advisoryPatterns {
		if p.match.MatchString(haystack) {
			return p.reason, true
		}
	}
	return "", false
}

// IsArchitecturalFinding returns true for findings whose category implies a
// design decision rather than a code-level patch. The combination is
// independent of source — both AI and scanner findings tagged "architecture"
// are treated as advisory because the remediation is structural, not textual.
func IsArchitecturalFinding(source, category string) bool {
	return category == "architecture"
}
