package builtin

import (
	"os"
	"path/filepath"
	"testing"
)

// ── Scan ──────────────────────────────────────────────────────────────

const minimalInsecurePlan = `{
  "format_version": "1.2",
  "resource_changes": [
    {
      "address": "aws_s3_bucket.bad",
      "type": "aws_s3_bucket",
      "name": "bad",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": { "actions": ["create"], "after": {} }
    },
    {
      "address": "aws_db_instance.bad",
      "type": "aws_db_instance",
      "name": "bad",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": { "actions": ["create"], "after": { "publicly_accessible": true } }
    },
    {
      "address": "aws_s3_bucket.noop",
      "type": "aws_s3_bucket",
      "name": "noop",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": { "actions": ["no-op"], "after": {} }
    }
  ]
}`

func TestScan_FileNotFound(t *testing.T) {
	_, err := Scan("/nonexistent/path/plan.json")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestScan_InvalidJSON(t *testing.T) {
	f := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(f, []byte("not json {{{"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Scan(f)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestScan_ValidPlan_FindsViolations(t *testing.T) {
	f := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(f, []byte(minimalInsecurePlan), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := Scan(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings for insecure S3 and RDS resources, got 0")
	}
	// S3 bucket triggers CKV_AWS_18, 19, 21 (missing logging, encryption, versioning)
	s3Count := 0
	for _, f := range findings {
		if f.Resource == "aws_s3_bucket.bad" {
			s3Count++
		}
	}
	if s3Count == 0 {
		t.Error("expected findings for aws_s3_bucket.bad")
	}
}

func TestScan_NoOpResourceSkipped(t *testing.T) {
	f := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(f, []byte(minimalInsecurePlan), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := Scan(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, finding := range findings {
		if finding.Resource == "aws_s3_bucket.noop" {
			t.Errorf("no-op resource must be skipped, but got finding: %s", finding.RuleID)
		}
	}
}

// ── strVal helper ─────────────────────────────────────────────────────

func TestStrVal_NilMap(t *testing.T) {
	if got := strVal(nil, "key"); got != "" {
		t.Errorf("nil map: want empty string, got %q", got)
	}
}

func TestStrVal_MissingKey(t *testing.T) {
	if got := strVal(map[string]interface{}{"other": "val"}, "key"); got != "" {
		t.Errorf("missing key: want empty string, got %q", got)
	}
}

func TestStrVal_WrongType(t *testing.T) {
	if got := strVal(map[string]interface{}{"key": 42}, "key"); got != "" {
		t.Errorf("wrong type (int): want empty string, got %q", got)
	}
}

// ── boolVal helper ────────────────────────────────────────────────────

func TestBoolVal_Float64True(t *testing.T) {
	if !boolVal(map[string]interface{}{"key": float64(1)}, "key") {
		t.Error("float64(1) should be truthy")
	}
}

func TestBoolVal_Float64Zero(t *testing.T) {
	if boolVal(map[string]interface{}{"key": float64(0)}, "key") {
		t.Error("float64(0) should be falsy")
	}
}

func TestBoolVal_NilMap(t *testing.T) {
	if boolVal(nil, "key") {
		t.Error("nil map: want false")
	}
}

// ── isList helper ─────────────────────────────────────────────────────

func TestIsList_NilMap(t *testing.T) {
	if isList(nil, "key") {
		t.Error("nil map: want false")
	}
}

func TestIsList_EmptySlice(t *testing.T) {
	if isList(map[string]interface{}{"key": []interface{}{}}, "key") {
		t.Error("empty slice: want false")
	}
}

// ── CKV_AWS_16 (RDS backup) ───────────────────────────────────────────

func TestCKV_AWS_16_MissingKey(t *testing.T) {
	r := resource("aws_db_instance", "aws_db_instance.db", map[string]interface{}{})
	checkFires(t, "CKV_AWS_16", r)
}

func TestCKV_AWS_16_RetentionZero(t *testing.T) {
	r := resource("aws_db_instance", "aws_db_instance.db", map[string]interface{}{
		"backup_retention_period": float64(0),
	})
	checkFires(t, "CKV_AWS_16", r)
}

func TestCKV_AWS_16_RetentionPositive(t *testing.T) {
	r := resource("aws_db_instance", "aws_db_instance.db", map[string]interface{}{
		"backup_retention_period": float64(7),
	})
	checkSilent(t, "CKV_AWS_16", r)
}

// ── Compliant (silent) cases for rules missing them ───────────────────

func TestCKV_AWS_18_S3WithLogging(t *testing.T) {
	r := resource("aws_s3_bucket", "aws_s3_bucket.data", map[string]interface{}{
		"logging": []interface{}{map[string]interface{}{"target_bucket": "logs-bucket"}},
	})
	checkSilent(t, "CKV_AWS_18", r)
}

func TestCKV_AWS_21_S3WithVersioning(t *testing.T) {
	r := resource("aws_s3_bucket", "aws_s3_bucket.state", map[string]interface{}{
		"versioning": []interface{}{map[string]interface{}{"enabled": true}},
	})
	checkSilent(t, "CKV_AWS_21", r)
}

func TestCKV_AWS_23_RDSEncrypted(t *testing.T) {
	r := resource("aws_db_instance", "aws_db_instance.main", map[string]interface{}{
		"storage_encrypted": true,
	})
	checkSilent(t, "CKV_AWS_23", r)
}

func TestCKV_AWS_24_RDSMultiAZ(t *testing.T) {
	r := resource("aws_db_instance", "aws_db_instance.main", map[string]interface{}{
		"multi_az": true,
	})
	checkSilent(t, "CKV_AWS_24", r)
}

func TestCKV_AWS_25_RDSPrivate(t *testing.T) {
	r := resource("aws_db_instance", "aws_db_instance.main", map[string]interface{}{
		"publicly_accessible": false,
	})
	checkSilent(t, "CKV_AWS_25", r)
}

func TestCKV_AWS_88_EC2NoPublicIP(t *testing.T) {
	r := resource("aws_instance", "aws_instance.web", map[string]interface{}{
		"associate_public_ip_address": false,
	})
	checkSilent(t, "CKV_AWS_88", r)
}

func TestCKV_AWS_64_RDPRestricted(t *testing.T) {
	r := resource("aws_security_group", "aws_security_group.win", map[string]interface{}{
		"ingress": []interface{}{
			map[string]interface{}{
				"from_port":   float64(3389),
				"to_port":     float64(3389),
				"cidr_blocks": []interface{}{"10.0.0.0/8"},
			},
		},
	})
	checkSilent(t, "CKV_AWS_64", r)
}

func TestCKV_AWS_92_LambdaWithDLQ(t *testing.T) {
	r := resource("aws_lambda_function", "aws_lambda_function.worker", map[string]interface{}{
		"dead_letter_config": []interface{}{map[string]interface{}{"target_arn": "arn:aws:sqs:..."}},
	})
	checkSilent(t, "CKV_AWS_92", r)
}

func TestCKV_AWS_117_LambdaWithVPC(t *testing.T) {
	r := resource("aws_lambda_function", "aws_lambda_function.api", map[string]interface{}{
		"vpc_config": []interface{}{map[string]interface{}{"subnet_ids": []interface{}{"subnet-abc"}}},
	})
	checkSilent(t, "CKV_AWS_117", r)
}

func TestCKV_AWS_28_ElastiCacheTransitEncrypted(t *testing.T) {
	r := resource("aws_elasticache_replication_group", "aws_elasticache_replication_group.redis", map[string]interface{}{
		"transit_encryption_enabled": true,
	})
	checkSilent(t, "CKV_AWS_28", r)
}

func TestCKV_AWS_31_ElastiCacheAtRestEncrypted(t *testing.T) {
	r := resource("aws_elasticache_replication_group", "aws_elasticache_replication_group.redis", map[string]interface{}{
		"at_rest_encryption_enabled": true,
	})
	checkSilent(t, "CKV_AWS_31", r)
}

// ── DynamoDB PITR disabled branch ─────────────────────────────────────

func TestCKV_AWS_119_DynamoDBPITRDisabled(t *testing.T) {
	r := resource("aws_dynamodb_table", "aws_dynamodb_table.users", map[string]interface{}{
		"point_in_time_recovery": []interface{}{map[string]interface{}{"enabled": false}},
	})
	checkFires(t, "CKV_AWS_119", r)
}

// ── CloudFront (CKV_AWS_91) ───────────────────────────────────────────

func TestCKV_AWS_91_CloudFrontDefaultCert(t *testing.T) {
	r := resource("aws_cloudfront_distribution", "aws_cloudfront_distribution.cdn", map[string]interface{}{
		"viewer_certificate": []interface{}{
			map[string]interface{}{"cloudfront_default_certificate": true},
		},
	})
	checkFires(t, "CKV_AWS_91", r)
}

func TestCKV_AWS_91_CloudFrontCustomCert(t *testing.T) {
	r := resource("aws_cloudfront_distribution", "aws_cloudfront_distribution.cdn", map[string]interface{}{
		"viewer_certificate": []interface{}{
			map[string]interface{}{
				"cloudfront_default_certificate": false,
				"acm_certificate_arn":            "arn:aws:acm:us-east-1:123:certificate/abc",
			},
		},
	})
	checkSilent(t, "CKV_AWS_91", r)
}

func TestCKV_AWS_91_CloudFrontNoCert(t *testing.T) {
	r := resource("aws_cloudfront_distribution", "aws_cloudfront_distribution.cdn", map[string]interface{}{})
	checkSilent(t, "CKV_AWS_91", r)
}

// ── checkOpenPort — aws_security_group_rule paths ─────────────────────

func TestCKV_AWS_63_SGRuleSSHOpenIPv4(t *testing.T) {
	r := resource("aws_security_group_rule", "aws_security_group_rule.ssh", map[string]interface{}{
		"type":        "ingress",
		"from_port":   float64(22),
		"to_port":     float64(22),
		"cidr_blocks": []interface{}{"0.0.0.0/0"},
	})
	checkFires(t, "CKV_AWS_63", r)
}

func TestCKV_AWS_63_SGRuleSSHOpenIPv6(t *testing.T) {
	r := resource("aws_security_group_rule", "aws_security_group_rule.ssh6", map[string]interface{}{
		"type":             "ingress",
		"from_port":        float64(22),
		"to_port":          float64(22),
		"ipv6_cidr_blocks": []interface{}{"::/0"},
	})
	checkFires(t, "CKV_AWS_63", r)
}

func TestCKV_AWS_63_SGRuleEgress(t *testing.T) {
	r := resource("aws_security_group_rule", "aws_security_group_rule.egress", map[string]interface{}{
		"type":        "egress",
		"from_port":   float64(22),
		"to_port":     float64(22),
		"cidr_blocks": []interface{}{"0.0.0.0/0"},
	})
	checkSilent(t, "CKV_AWS_63", r)
}

func TestCKV_AWS_63_SGNoIngress(t *testing.T) {
	r := resource("aws_security_group", "aws_security_group.empty", map[string]interface{}{})
	checkSilent(t, "CKV_AWS_63", r)
}

func TestCKV_AWS_63_SGIngressPortMismatch(t *testing.T) {
	r := resource("aws_security_group", "aws_security_group.http", map[string]interface{}{
		"ingress": []interface{}{
			map[string]interface{}{
				"from_port":   float64(80),
				"to_port":     float64(80),
				"cidr_blocks": []interface{}{"0.0.0.0/0"},
			},
		},
	})
	checkSilent(t, "CKV_AWS_63", r)
}

func TestCKV_AWS_64_SGRuleRDPOpenIPv6(t *testing.T) {
	r := resource("aws_security_group_rule", "aws_security_group_rule.rdp6", map[string]interface{}{
		"type":             "ingress",
		"from_port":        float64(3389),
		"to_port":          float64(3389),
		"ipv6_cidr_blocks": []interface{}{"::/0"},
	})
	checkFires(t, "CKV_AWS_64", r)
}
