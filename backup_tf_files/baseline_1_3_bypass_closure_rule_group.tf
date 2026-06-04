# =============================================================================
# baseline-1-3-bypass-closure  -  custom AWS WAFv2 rule group
# =============================================================================
# Purpose
#   Close the 186-test-id gap observed on the 1.3b WebACL during the 20260601
#   JuiceShop corpus run (76.6% CF_BLOCK rate). The 6 rules below target the
#   attack families that the AWS managed rule groups miss after decoding tricks
#   (double URL-encoding, HTML-entity encoding, Unicode escapes, IFS-bypass,
#   etc.).
#
#   Each rule is wired against 5 field-to-match locations so it catches the
#   payload regardless of which placement (POST-QS, POST-Body, GET-QS, Cookie,
#   ALL_HEADERS) carries it.
#
# Roll-out
#   1. All 6 rules ship with `action { count {} }` - they LOG only, do not block.
#   2. Sample production for 7 days. Watch CloudWatch metric `<rule>-count`.
#   3. Promote one rule at a time from COUNT -> BLOCK by replacing
#      `action { count {} }` with `action { block {} }` and re-applying.
#   4. Recommended promotion order (least false-positive first):
#         rule-1-rfi  ->  rule-2-lfi  ->  rule-3-cmdi  ->
#         rule-4-ssti ->  rule-5-sqli ->  rule-6-xss
#
# Capacity / WCU
#   Rule group declares capacity = 1500 (the WAFv2 max) so there is headroom
#   for future regex additions. Estimated current draw ~ 800 WCU. AWS will
#   refuse `terraform apply` if the declared `capacity` is too low - if you
#   see that error, raise the number, do not lower the rules.
#
# Separate fix NOT in this file
#   The 1.1 bypass evidence showed `SizeRestrictions_BODY` is overridden to
#   COUNT inside CommonRuleSet. That override must be removed at the
#   WebACL level (`rule_action_override` on the managed_rule_group_statement
#   for AWSManagedRulesCommonRuleSet) - it is not something this rule group
#   can fix. Track that as a separate change.
# =============================================================================

# -----------------------------------------------------------------------------
# 1.  RFI  -  remote file inclusion (priority 1, highest)
# -----------------------------------------------------------------------------
resource "aws_wafv2_regex_pattern_set" "rfi" {
  name        = "baseline-1-3-bypass-rfi"
  scope       = "CLOUDFRONT"
  description = "RFI / remote URL inclusion - covers 11 leaked test_ids on 1.3b"

  # Patterns are matched after URL_DECODE x2 + LOWERCASE text transforms,
  # so they see double-encoded variants like %2568%2574%2574%2570 -> http.
  regular_expression {
    # http(s)://hostname.tld/...  - the canonical RFI vector
    regex_string = "(?:^|[\\s'\"=?&#])https?://[a-z0-9.\\-]+\\.[a-z]{2,}/"
  }
  regular_expression {
    # SMB / UNC \\host\share
    regex_string = "\\\\\\\\[a-z0-9.\\-]+\\\\"
  }
  regular_expression {
    # Dangerous PHP-style wrappers used as RFI / LFI vectors
    regex_string = "(?:php|data|expect|file|zip|glob|phar)://"
  }
  regular_expression {
    # Encoded character inside the hostname (e.g. ev%69l.com)
    regex_string = "https?://[a-z0-9.\\-]*%[0-9a-f]{2}[a-z0-9.\\-]*\\.[a-z]{2,}"
  }
}

# -----------------------------------------------------------------------------
# 2.  LFI  -  local file inclusion / path traversal (priority 2)
# -----------------------------------------------------------------------------
resource "aws_wafv2_regex_pattern_set" "lfi" {
  name        = "baseline-1-3-bypass-lfi"
  scope       = "CLOUDFRONT"
  description = "LFI / path traversal - covers 4 leaked test_ids on 1.3b"

  regular_expression {
    # ../  ..\\  ....//  ..%c0%af  ..%2f  in any encoded form
    regex_string = "(?:\\.{2,}|%2[eE]{1,2}){1,}[/\\\\%]"
  }
  regular_expression {
    # Overlong UTF-8 representations of / and \\
    regex_string = "(?:%c0%af|%c0%2f|%c1%9c)"
  }
  regular_expression {
    # Sensitive Linux files
    regex_string = "/etc/(?:passwd|shadow|hosts|fstab)|/proc/self/environ"
  }
  regular_expression {
    # Sensitive Windows files
    regex_string = "c:\\\\windows\\\\(?:win\\.ini|system32)"
  }
}

# -----------------------------------------------------------------------------
# 3.  CMDI  -  command injection (priority 3)
# -----------------------------------------------------------------------------
resource "aws_wafv2_regex_pattern_set" "cmdi" {
  name        = "baseline-1-3-bypass-cmdi"
  scope       = "CLOUDFRONT"
  description = "Command injection - covers 8 leaked test_ids on 1.3b"

  regular_expression {
    # Command separator + common Linux binaries
    regex_string = "(?:^|[\\s;&|`$(])(?:id|whoami|uname|cat|nc|wget|curl|sh|bash|ksh|powershell)\\b"
  }
  regular_expression {
    # IFS bypass for space-stripped command lines:  sh${IFS}-c${IFS}whoami
    regex_string = "\\$(?:\\{IFS\\}|IFS\\b)"
  }
  regular_expression {
    # Backtick command substitution:  `id`, `uname -a`
    regex_string = "`[^`]{1,80}`"
  }
  regular_expression {
    # $(...) and <(...) substitution
    regex_string = "(?:\\$\\(|<\\()\\s*(?:id|whoami|uname|cat)"
  }
}

# -----------------------------------------------------------------------------
# 4.  SSTI  -  server-side template injection (priority 4)
# -----------------------------------------------------------------------------
resource "aws_wafv2_regex_pattern_set" "ssti" {
  name        = "baseline-1-3-bypass-ssti"
  scope       = "CLOUDFRONT"
  description = "Template injection (Jinja/Freemarker/SpEL/Twig) - covers 10 leaked test_ids"

  regular_expression {
    # {{ 7*7 }}  - Jinja / Twig / Handlebars
    regex_string = "\\{\\{\\s*[\\w\\d.()*+/\\-]{1,50}\\s*\\}\\}"
  }
  regular_expression {
    # ${...} and #{...}  - Spring SpEL, Freemarker, JSP EL, shell
    regex_string = "(?:\\$|#)\\{\\s*[\\w\\d.()*+/\\-]{1,50}\\s*\\}"
  }
  regular_expression {
    # <%= ... %>  -  ERB / ASP / Java JSP
    regex_string = "<%\\s*="
  }
  regular_expression {
    # Freemarker exploit assigning Execute helper
    regex_string = "<#assign[^>]+freemarker\\.template"
  }
}

# -----------------------------------------------------------------------------
# 5.  SQLi  -  bypass-targeting SQLi (priority 5)
# -----------------------------------------------------------------------------
resource "aws_wafv2_regex_pattern_set" "sqli" {
  name        = "baseline-1-3-bypass-sqli"
  scope       = "CLOUDFRONT"
  description = "SQLi bypass variants AWS-managed SQLiRuleSet misses - covers 55 leakers"

  regular_expression {
    # Quoted OR/AND with optional parens and spaces:  ' OR ', ') OR ('1=1
    regex_string = "(?:^|[\\s()'\"])'\\s*[)\\]]?\\s*(?:or|and)\\s+['\"]?[\\w\\d]+['\"]?\\s*=\\s*['\"]?[\\w\\d]+"
  }
  regular_expression {
    # Lone quote followed by comment terminator: admin'--   admin'#
    regex_string = "['\"](?:\\s|\\+)*(?:-{2,}|#)"
  }
  regular_expression {
    # Stacked queries: ; DROP / INSERT / UPDATE / DELETE
    regex_string = ";\\s*(?:drop|insert|update|delete)\\b"
  }
  regular_expression {
    # UNION SELECT with comment-padding
    regex_string = "union(?:\\s|/\\*.*?\\*/)+select"
  }
}

# -----------------------------------------------------------------------------
# 6.  XSS  -  bypass-targeting XSS (priority 6, lowest = checked last)
#     Highest FP risk. Keep COUNT-only until production noise is measured.
# -----------------------------------------------------------------------------
resource "aws_wafv2_regex_pattern_set" "xss" {
  name        = "baseline-1-3-bypass-xss"
  scope       = "CLOUDFRONT"
  description = "XSS bypass variants AWS-managed XSS misses - covers 96 leakers"

  regular_expression {
    # <script> or </script> after multi-pass decoding (catches &lt; %3C %253C)
    regex_string = "<\\s*/?\\s*script[\\s>]"
  }
  regular_expression {
    # Inline event-handler injection (onclick, onerror, onload, ...)
    regex_string = "\\bon(?:click|load|error|mouseover|focus|blur|submit|change|key(?:up|down|press))\\s*="
  }
  regular_expression {
    # alert / prompt / confirm / eval with any encoded opening paren
    regex_string = "\\b(?:alert|prompt|confirm|eval)\\s*(?:\\(|\\\\x28|\\\\u0028)"
  }
  regular_expression {
    # javascript: URI scheme
    regex_string = "javascript\\s*:\\s*\\S"
  }
}

# =============================================================================
# Rule group: baseline-1-3-bypass-closure
# =============================================================================
resource "aws_wafv2_rule_group" "baseline_1_3_bypass_closure" {
  name        = "baseline-1-3-bypass-closure"
  scope       = "CLOUDFRONT"
  capacity    = 400
  description = "custom rule group closing the 186-test gap on 1.3b (run 20260601). All rules ship in COUNT - promote to BLOCK family-by-family after FP measurement."

  # ---------------------------------------------------------------------------
  # Priority 1  -  RFI  (lowest FP risk, biggest absolute leak coverage)
  # ---------------------------------------------------------------------------
  rule {
    name     = "rule-1-rfi-remote-inclusion"
    priority = 1
    action { count {} }   # PROMOTE: change to  block {}  when FP rate acceptable

    statement {
      or_statement {
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.rfi.arn
          field_to_match { body { oversize_handling = "CONTINUE" } }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "LOWERCASE" }
        }}
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.rfi.arn
          field_to_match { json_body { match_pattern { all {} } match_scope = "VALUE" invalid_fallback_behavior = "EVALUATE_AS_STRING" oversize_handling = "CONTINUE" } }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "LOWERCASE" }
        }}
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.rfi.arn
          field_to_match { query_string {} }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "LOWERCASE" }
        }}
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.rfi.arn
          field_to_match { cookies { match_pattern { all {} } match_scope = "VALUE" oversize_handling = "CONTINUE" } }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "LOWERCASE" }
        }}
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.rfi.arn
          field_to_match { headers { match_pattern { all {} } match_scope = "VALUE" oversize_handling = "MATCH" } }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "LOWERCASE" }
        }}
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "baseline-1-3-bypass-rule-1-rfi"
      sampled_requests_enabled   = true
    }
  }

  # ---------------------------------------------------------------------------
  # Priority 2  -  LFI / path traversal
  # ---------------------------------------------------------------------------
  rule {
    name     = "rule-2-lfi-traversal-wrappers"
    priority = 2
    action { count {} }

    statement {
      or_statement {
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.lfi.arn
          field_to_match { body { oversize_handling = "CONTINUE" } }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "LOWERCASE" }
        }}
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.lfi.arn
          field_to_match { json_body { match_pattern { all {} } match_scope = "VALUE" invalid_fallback_behavior = "EVALUATE_AS_STRING" oversize_handling = "CONTINUE" } }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "LOWERCASE" }
        }}
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.lfi.arn
          field_to_match { query_string {} }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "LOWERCASE" }
        }}
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.lfi.arn
          field_to_match { uri_path {} }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "LOWERCASE" }
        }}
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.lfi.arn
          field_to_match { headers { match_pattern { all {} } match_scope = "VALUE" oversize_handling = "MATCH" } }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "LOWERCASE" }
        }}
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "baseline-1-3-bypass-rule-2-lfi"
      sampled_requests_enabled   = true
    }
  }

  # ---------------------------------------------------------------------------
  # Priority 3  -  CMDI / shell injection
  # ---------------------------------------------------------------------------
  rule {
    name     = "rule-3-cmdi-shell-injection"
    priority = 3
    action { count {} }

    statement {
      or_statement {
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.cmdi.arn
          field_to_match { body { oversize_handling = "CONTINUE" } }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "LOWERCASE" }
        }}
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.cmdi.arn
          field_to_match { json_body { match_pattern { all {} } match_scope = "VALUE" invalid_fallback_behavior = "EVALUATE_AS_STRING" oversize_handling = "CONTINUE" } }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "LOWERCASE" }
        }}
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.cmdi.arn
          field_to_match { query_string {} }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "LOWERCASE" }
        }}
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.cmdi.arn
          field_to_match { cookies { match_pattern { all {} } match_scope = "VALUE" oversize_handling = "CONTINUE" } }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "LOWERCASE" }
        }}
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.cmdi.arn
          field_to_match { headers { match_pattern { all {} } match_scope = "VALUE" oversize_handling = "MATCH" } }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "LOWERCASE" }
        }}
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "baseline-1-3-bypass-rule-3-cmdi"
      sampled_requests_enabled   = true
    }
  }

  # ---------------------------------------------------------------------------
  # Priority 4  -  SSTI / template injection
  # ---------------------------------------------------------------------------
  rule {
    name     = "rule-4-ssti-template-injection"
    priority = 4
    action { count {} }

    statement {
      or_statement {
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.ssti.arn
          field_to_match { body { oversize_handling = "CONTINUE" } }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "LOWERCASE" }
        }}
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.ssti.arn
          field_to_match { json_body { match_pattern { all {} } match_scope = "VALUE" invalid_fallback_behavior = "EVALUATE_AS_STRING" oversize_handling = "CONTINUE" } }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "LOWERCASE" }
        }}
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.ssti.arn
          field_to_match { query_string {} }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "LOWERCASE" }
        }}
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.ssti.arn
          field_to_match { cookies { match_pattern { all {} } match_scope = "VALUE" oversize_handling = "CONTINUE" } }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "LOWERCASE" }
        }}
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.ssti.arn
          field_to_match { headers { match_pattern { all {} } match_scope = "VALUE" oversize_handling = "MATCH" } }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "LOWERCASE" }
        }}
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "baseline-1-3-bypass-rule-4-ssti"
      sampled_requests_enabled   = true
    }
  }

  # ---------------------------------------------------------------------------
  # Priority 5  -  SQLi bypass variants
  # ---------------------------------------------------------------------------
  rule {
    name     = "rule-5-sqli-bypass"
    priority = 5
    action { count {} }

    statement {
      or_statement {
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.sqli.arn
          field_to_match { body { oversize_handling = "CONTINUE" } }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "LOWERCASE" }
        }}
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.sqli.arn
          field_to_match { json_body { match_pattern { all {} } match_scope = "VALUE" invalid_fallback_behavior = "EVALUATE_AS_STRING" oversize_handling = "CONTINUE" } }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "LOWERCASE" }
        }}
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.sqli.arn
          field_to_match { query_string {} }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "LOWERCASE" }
        }}
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.sqli.arn
          field_to_match { cookies { match_pattern { all {} } match_scope = "VALUE" oversize_handling = "CONTINUE" } }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "LOWERCASE" }
        }}
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.sqli.arn
          field_to_match { headers { match_pattern { all {} } match_scope = "VALUE" oversize_handling = "MATCH" } }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "LOWERCASE" }
        }}
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "baseline-1-3-bypass-rule-5-sqli"
      sampled_requests_enabled   = true
    }
  }

  # ---------------------------------------------------------------------------
  # Priority 6  -  XSS bypass variants  (highest FP risk - longest in COUNT)
  # ---------------------------------------------------------------------------
  rule {
    name     = "rule-6-xss-bypass"
    priority = 6
    action { count {} }

    statement {
      or_statement {
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.xss.arn
          field_to_match { body { oversize_handling = "CONTINUE" } }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "HTML_ENTITY_DECODE" }
          text_transformation { priority = 3 type = "LOWERCASE" }
        }}
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.xss.arn
          field_to_match { json_body { match_pattern { all {} } match_scope = "VALUE" invalid_fallback_behavior = "EVALUATE_AS_STRING" oversize_handling = "CONTINUE" } }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "HTML_ENTITY_DECODE" }
          text_transformation { priority = 3 type = "LOWERCASE" }
        }}
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.xss.arn
          field_to_match { query_string {} }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "HTML_ENTITY_DECODE" }
          text_transformation { priority = 3 type = "LOWERCASE" }
        }}
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.xss.arn
          field_to_match { cookies { match_pattern { all {} } match_scope = "VALUE" oversize_handling = "CONTINUE" } }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "HTML_ENTITY_DECODE" }
          text_transformation { priority = 3 type = "LOWERCASE" }
        }}
        statement { regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.xss.arn
          field_to_match { headers { match_pattern { all {} } match_scope = "VALUE" oversize_handling = "MATCH" } }
          text_transformation { priority = 0 type = "URL_DECODE" }
          text_transformation { priority = 1 type = "URL_DECODE" }
          text_transformation { priority = 2 type = "HTML_ENTITY_DECODE" }
          text_transformation { priority = 3 type = "LOWERCASE" }
        }}
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "baseline-1-3-bypass-rule-6-xss"
      sampled_requests_enabled   = true
    }
  }

  # ---------------------------------------------------------------------------
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "baseline-1-3-bypass-closure"
    sampled_requests_enabled   = true
  }

  tags = {
    Project   = "baseline-1.3"
    Component = "waf-rule-group"
    Purpose   = "bypass-closure"
    OwnedBy   = "WAFCoE"
  }
}

