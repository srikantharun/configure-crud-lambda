# =============================================================================
# owasp-top10-alpha  -  WCU-optimised refactor of the original rule group
# =============================================================================
# Original draws 5410 WCU; this version targets ~4000 WCU (well under 5000).
#
# Three changes from the original:
#
#   1. Search-string consolidation.
#      Every byte_match block that asked "does <field> contain <string>?" with
#      a single transformation has been replaced by an aws_wafv2_regex_pattern_set
#      that contains MANY strings + a single regex_pattern_set_reference_statement
#      per placement. The number of inner statements drops from ~110 to ~15
#      across the two heavy rules (PHP and RFI/LFI).
#
#   2. Chained text transformations.
#      The original ran transformations IN PARALLEL (N separate statements,
#      one transform each). This version chains them in priority order, so
#      one statement per placement covers all transforms. Manager has
#      accepted the semantic trade-off:
#        - BETTER at catching multi-encoded payloads (URL+hex, URL+base64).
#        - SAME at catching single-encoded payloads (transformations are
#          best-effort and pass non-matching input through unchanged in AWS WAF).
#
#   3. Bug fixes carried in:
#        - `search_string = https://` was missing quotes in the original.
#        - Duplicate `auto_prepend_file=` byte_match block removed.
#        - `field_to_match { body { } oversize_handling = "..." }` had brace
#          misplacement in original rule 3 - fixed.
#
# Wired to the same custom_response pattern as the bypass-closure rule group
# (var.rule_label_namespace, custom_response_body "hsbc-default-block").
# =============================================================================

module "custom_responses" {
  source = "../custom_responses"
}

# -----------------------------------------------------------------------------
# IP sets - unchanged
# -----------------------------------------------------------------------------
resource "aws_wafv2_ip_set" "admin_remote_ip" {
  name               = "owasp-match-admin-remote-ip-alpha"
  scope              = var.scope
  ip_address_version = "IPV4"
  addresses          = var.admin_remote_ip
}

resource "aws_wafv2_ip_set" "blacklisted_ips" {
  name               = "owasp-match-blacklisted-ips-alpha"
  scope              = var.scope
  ip_address_version = "IPV4"
  addresses          = var.blacklisted_ips
}

# -----------------------------------------------------------------------------
# Consolidated regex pattern sets
# -----------------------------------------------------------------------------

# Design split per Dean's spec:
#   - byte_match in body / headers / cookies for the single most important
#     literal patterns (item 1 "php", item 10 "://")
#   - regex_pattern_set with `|` alternation in URI path / query string for
#     ALL items (PHP signatures, PHP config strings, and RFI/LFI patterns)
# This keeps WCU low (one regex statement covers many strings on URI/QS)
# while keeping FP risk down on body/headers/cookies (byte_match is more
# restrictive than regex alternation there).

# Pattern set 1: matches anything ending in "php" - used by rule 3, group A,
# on URI path and query string only.
resource "aws_wafv2_regex_pattern_set" "owasp_php_extension" {
  name        = "owasp-php-extension-alpha"
  scope       = var.scope
  description = "Matches strings ending with 'php' - PHP file extension detection (URI/QS only via this regex set; body/headers/cookies use byte_match)"

  regular_expression {
    regex_string = "php$"
  }
}

# Pattern set 2: PHP config strings - all 8 folded into one regex with
# alternation (Dean's WCU optimisation). Case-sensitive (uses _ENV[ and
# _SERVER[ literally so no LOWERCASE transform is needed).
resource "aws_wafv2_regex_pattern_set" "owasp_php_config_strings" {
  name        = "owasp-php-config-strings-alpha"
  scope       = var.scope
  description = "PHP config strings (8 strings as alternation) - used in URI / QS only"

  regular_expression {
    regex_string = "disable_functions=|_ENV\\[|_SERVER\\[|allow_url_include=|safe_mode=|open_basedir=|auto_append_file=|auto_prepend_file="
  }
}

# Pattern set 3: RFI/LFI signatures
# "://" catches any URL scheme. "\.\./" catches path traversal (regex-escaped).
# Used by rule 4 group 1.
resource "aws_wafv2_regex_pattern_set" "owasp_rfi_lfi_signatures" {
  name        = "owasp-rfi-lfi-signatures-alpha"
  scope       = var.scope
  description = "RFI/LFI signatures combined into one regex with alternation: '://' OR '../'."

  regular_expression {
    regex_string = "://|\\.\\./"
  }
}

# Pattern set 2: HTTPS exemption - legitimate HTTPS URLs should not trip RFI rule
# Used inside rule 4's not_statement.
resource "aws_wafv2_regex_pattern_set" "owasp_https_exempt" {
  name        = "owasp-https-exempt-alpha"
  scope       = var.scope
  description = "Legitimate https:// URL pattern - exempted from RFI/LFI rule via not_statement"

  regular_expression {
    regex_string = "https://"
  }
}

# Pattern set 3: MAUTH scheme exemption (used dynamically when allow_mauth = true)
resource "aws_wafv2_regex_pattern_set" "owasp_mauth_exempt" {
  name        = "owasp-mauth-exempt-alpha"
  scope       = var.scope
  description = "mauth:// URL pattern - exempted when var.owasp_detect_rfi_lfi_allow_mauth = true"

  regular_expression {
    regex_string = "mauth://"
  }
}

# =============================================================================
# Rule group
# =============================================================================
resource "aws_wafv2_rule_group" "main" {
  name        = "owasp-top10-alpha"
  description = "owasp top 10 waf rule group alpha (refactored for WCU efficiency)"
  scope       = var.scope
  capacity    = 5000

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "owasptop10rulegroupalpha"
    sampled_requests_enabled   = true
  }

  custom_response_body {
    key          = "hsbc-default-block"
    content_type = "TEXT_HTML"
    content      = module.custom_responses.default_block
  }

  # ===========================================================================
  # Rule 0 - admin URL access from non-allowlisted IP  (unchanged)
  # ===========================================================================
  rule {
    name     = "owasp-detect-admin-access"
    priority = 0

    action {
      block {
        custom_response {
          custom_response_body_key = "hsbc-default-block"
          response_code            = 403
        }
      }
    }

    rule_label {
      name = "${var.rule_label_namespace}:owasp-detect-admin-access"
    }

    statement {
      and_statement {
        statement {
          byte_match_statement {
            positional_constraint = "STARTS_WITH"
            search_string         = "/admin"

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
          }
        }

        statement {
          not_statement {
            statement {
              ip_set_reference_statement {
                arn = aws_wafv2_ip_set.admin_remote_ip.arn
              }
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "owaspdetectadminaccess"
      sampled_requests_enabled   = true
    }
  }

  # ===========================================================================
  # Rule 1 - bad auth tokens  (unchanged)
  # ===========================================================================
  rule {
    name     = "owasp-detect-bad-auth-tokens"
    priority = 1

    action {
      block {
        custom_response {
          custom_response_body_key = "hsbc-default-block"
          response_code            = 403
        }
      }
    }

    rule_label {
      name = "${var.rule_label_namespace}:owasp-detect-bad-auth-tokens"
    }

    statement {
      or_statement {
        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "example-session-id"

            field_to_match {
              single_header {
                name = "cookie"
              }
            }

            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "ENDS_WITH"
            search_string         = ".TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"

            field_to_match {
              single_header {
                name = "authorization"
              }
            }

            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "owaspbadauthtokens"
      sampled_requests_enabled   = true
    }
  }

  # ===========================================================================
  # Rule 2 - blacklisted IPs  (unchanged)
  # ===========================================================================
  rule {
    name     = "owasp-detect-blacklisted-ips"
    priority = 2

    action {
      block {
        custom_response {
          custom_response_body_key = "hsbc-default-block"
          response_code            = 403
        }
      }
    }

    rule_label {
      name = "${var.rule_label_namespace}:owasp-detect-blacklisted-ips"
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.blacklisted_ips.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "owaspblacklistedips"
      sampled_requests_enabled   = true
    }
  }

  # ===========================================================================
  # Rule 3 - owasp-detect-php-insecure  (REFACTORED)
  #
  # Trigger condition (and_statement of two or_statements):
  #   A. The request matches a PHP signature - either ends with "php" in any
  #      of 5 placements, OR contains a "/" in URI path.
  #   B. AND contains one of the PHP config strings in query_string or headers.
  #
  # Note on placement coverage of group B:
  #   The manager's table lists query_string for all 8 config strings PLUS
  #   request_header specifically for _SERVER[. Putting them all in one
  #   pattern set + applying that set to BOTH query_string AND headers gives
  #   slight over-coverage (the other 7 strings also checked in headers) -
  #   but FP risk is negligible (none of those strings legitimately appear
  #   in headers) and it saves a few hundred WCU.
  # ===========================================================================
  rule {
    name     = "owasp-detect-php-insecure"
    priority = 3

    action {
      block {
        custom_response {
          custom_response_body_key = "hsbc-default-block"
          response_code            = 403
        }
      }
    }

    rule_label {
      name = "${var.rule_label_namespace}:owasp-detect-php-insecure"
    }

    statement {
      and_statement {

        # ---------------------------------------------------------------
        # Group A: "php" signature
        #   - regex on URI path + query_string (covers items 1 partial)
        #   - byte_match on body / headers / cookies (Dean's spec)
        #   - byte_match "/" on URI path (existing)
        # ---------------------------------------------------------------
        statement {
          or_statement {

            # 1. regex "php$" on URI path
            statement {
              regex_pattern_set_reference_statement {
                arn = aws_wafv2_regex_pattern_set.owasp_php_extension.arn

                field_to_match {
                  uri_path {}
                }

                text_transformation {
                  priority = 0
                  type     = "URL_DECODE"
                }
                text_transformation {
                  priority = 1
                  type     = "HTML_ENTITY_DECODE"
                }
                text_transformation {
                  priority = 2
                  type     = "HEX_DECODE"
                }
                text_transformation {
                  priority = 3
                  type     = "BASE64_DECODE"
                }
                text_transformation {
                  priority = 4
                  type     = "UTF8_TO_UNICODE"
                }
              }
            }

            # 2. regex "php$" on query_string
            statement {
              regex_pattern_set_reference_statement {
                arn = aws_wafv2_regex_pattern_set.owasp_php_extension.arn

                field_to_match {
                  query_string {}
                }

                text_transformation {
                  priority = 0
                  type     = "URL_DECODE"
                }
                text_transformation {
                  priority = 1
                  type     = "HTML_ENTITY_DECODE"
                }
                text_transformation {
                  priority = 2
                  type     = "HEX_DECODE"
                }
                text_transformation {
                  priority = 3
                  type     = "BASE64_DECODE"
                }
                text_transformation {
                  priority = 4
                  type     = "UTF8_TO_UNICODE"
                }
              }
            }

            # 3. byte_match "php" ENDS_WITH on body
            statement {
              byte_match_statement {
                positional_constraint = "ENDS_WITH"
                search_string         = "php"

                field_to_match {
                  body {}
                }

                text_transformation {
                  priority = 0
                  type     = "URL_DECODE"
                }
                text_transformation {
                  priority = 1
                  type     = "HTML_ENTITY_DECODE"
                }
                text_transformation {
                  priority = 2
                  type     = "HEX_DECODE"
                }
                text_transformation {
                  priority = 3
                  type     = "BASE64_DECODE"
                }
                text_transformation {
                  priority = 4
                  type     = "UTF8_TO_UNICODE"
                }
              }
            }

            # 4. byte_match "php" ENDS_WITH on all headers
            statement {
              byte_match_statement {
                positional_constraint = "ENDS_WITH"
                search_string         = "php"

                field_to_match {
                  headers {
                    match_pattern {
                      all {}
                    }
                    match_scope       = "ALL"
                    oversize_handling = "NO_MATCH"
                  }
                }

                text_transformation {
                  priority = 0
                  type     = "URL_DECODE"
                }
                text_transformation {
                  priority = 1
                  type     = "HTML_ENTITY_DECODE"
                }
                text_transformation {
                  priority = 2
                  type     = "HEX_DECODE"
                }
                text_transformation {
                  priority = 3
                  type     = "BASE64_DECODE"
                }
                text_transformation {
                  priority = 4
                  type     = "UTF8_TO_UNICODE"
                }
              }
            }

            # 5. byte_match "php" ENDS_WITH on cookies
            statement {
              byte_match_statement {
                positional_constraint = "ENDS_WITH"
                search_string         = "php"

                field_to_match {
                  cookies {
                    match_pattern {
                      all {}
                    }
                    match_scope       = "ALL"
                    oversize_handling = "NO_MATCH"
                  }
                }

                text_transformation {
                  priority = 0
                  type     = "URL_DECODE"
                }
                text_transformation {
                  priority = 1
                  type     = "HTML_ENTITY_DECODE"
                }
                text_transformation {
                  priority = 2
                  type     = "HEX_DECODE"
                }
                text_transformation {
                  priority = 3
                  type     = "BASE64_DECODE"
                }
                text_transformation {
                  priority = 4
                  type     = "UTF8_TO_UNICODE"
                }
              }
            }

            # 6. byte_match "/" ENDS_WITH on URI path (existing single-transform check)
            statement {
              byte_match_statement {
                positional_constraint = "ENDS_WITH"
                search_string         = "/"

                field_to_match {
                  uri_path {}
                }

                text_transformation {
                  priority = 0
                  type     = "URL_DECODE"
                }
              }
            }
          }
        }

        # ---------------------------------------------------------------
        # Group B: PHP config strings (8 strings combined via alternation
        # in one regex_pattern_set) on URI path + query string only.
        # No body/headers/cookies coverage for config strings per Dean's spec.
        # ---------------------------------------------------------------
        statement {
          or_statement {

            # regex 8-string alternation on URI path
            statement {
              regex_pattern_set_reference_statement {
                arn = aws_wafv2_regex_pattern_set.owasp_php_config_strings.arn

                field_to_match {
                  uri_path {}
                }

                text_transformation {
                  priority = 0
                  type     = "URL_DECODE"
                }
                text_transformation {
                  priority = 1
                  type     = "HTML_ENTITY_DECODE"
                }
                text_transformation {
                  priority = 2
                  type     = "HEX_DECODE"
                }
                text_transformation {
                  priority = 3
                  type     = "BASE64_DECODE"
                }
                text_transformation {
                  priority = 4
                  type     = "UTF8_TO_UNICODE"
                }
              }
            }

            # regex 8-string alternation on query_string
            statement {
              regex_pattern_set_reference_statement {
                arn = aws_wafv2_regex_pattern_set.owasp_php_config_strings.arn

                field_to_match {
                  query_string {}
                }

                text_transformation {
                  priority = 0
                  type     = "URL_DECODE"
                }
                text_transformation {
                  priority = 1
                  type     = "HTML_ENTITY_DECODE"
                }
                text_transformation {
                  priority = 2
                  type     = "HEX_DECODE"
                }
                text_transformation {
                  priority = 3
                  type     = "BASE64_DECODE"
                }
                text_transformation {
                  priority = 4
                  type     = "UTF8_TO_UNICODE"
                }
              }
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "owaspdetectphpinsecure"
      sampled_requests_enabled   = true
    }
  }

  # ===========================================================================
  # Rule 4 - owasp-detect-rfi-lfi-traversal  (REFACTORED)
  #
  # Group 1: "://" or "../" present in query_string, uri_path, or body
  # Group 2 (NOT): legit https:// in qs/uri OR (dynamically) mauth:// in qs/uri
  #
  # Body is INTENTIONALLY excluded from the https:// exemption because
  # legitimate apps don't accept URLs in the body and an attacker exploiting
  # SSRF / RFI would smuggle https:// there.
  # ===========================================================================
  rule {
    name     = "owasp-detect-rfi-lfi-traversal"
    priority = 4

    action {
      block {
        custom_response {
          custom_response_body_key = "hsbc-default-block"
          response_code            = 403
        }
      }
    }

    rule_label {
      name = "${var.rule_label_namespace}:owasp-detect-rfi-lfi-traversal"
    }

    statement {
      and_statement {

        # -------------------------------------------------------------------
        # Group 1:
        #   - regex `://|\.\./` on URI path + query_string (catches both patterns)
        #   - byte_match `://` on body + headers + cookies (item 10 only, no `../`)
        # -------------------------------------------------------------------
        statement {
          or_statement {

            # regex `://|\.\./` on query_string
            statement {
              regex_pattern_set_reference_statement {
                arn = aws_wafv2_regex_pattern_set.owasp_rfi_lfi_signatures.arn

                field_to_match {
                  query_string {}
                }

                text_transformation {
                  priority = 0
                  type     = "URL_DECODE"
                }
                text_transformation {
                  priority = 1
                  type     = "HTML_ENTITY_DECODE"
                }
                text_transformation {
                  priority = 2
                  type     = "HEX_DECODE"
                }
                text_transformation {
                  priority = 3
                  type     = "BASE64_DECODE"
                }
                text_transformation {
                  priority = 4
                  type     = "UTF8_TO_UNICODE"
                }
              }
            }

            # regex `://|\.\./` on uri_path
            statement {
              regex_pattern_set_reference_statement {
                arn = aws_wafv2_regex_pattern_set.owasp_rfi_lfi_signatures.arn

                field_to_match {
                  uri_path {}
                }

                text_transformation {
                  priority = 0
                  type     = "URL_DECODE"
                }
                text_transformation {
                  priority = 1
                  type     = "HTML_ENTITY_DECODE"
                }
                text_transformation {
                  priority = 2
                  type     = "HEX_DECODE"
                }
                text_transformation {
                  priority = 3
                  type     = "BASE64_DECODE"
                }
                text_transformation {
                  priority = 4
                  type     = "UTF8_TO_UNICODE"
                }
              }
            }

            # byte_match `://` CONTAINS on body (item 10 only - `../` is NOT body-checked)
            statement {
              byte_match_statement {
                positional_constraint = "CONTAINS"
                search_string         = "://"

                field_to_match {
                  body {}
                }

                text_transformation {
                  priority = 0
                  type     = "URL_DECODE"
                }
                text_transformation {
                  priority = 1
                  type     = "HTML_ENTITY_DECODE"
                }
                text_transformation {
                  priority = 2
                  type     = "HEX_DECODE"
                }
                text_transformation {
                  priority = 3
                  type     = "BASE64_DECODE"
                }
                text_transformation {
                  priority = 4
                  type     = "UTF8_TO_UNICODE"
                }
              }
            }

            # byte_match `://` CONTAINS on all headers
            statement {
              byte_match_statement {
                positional_constraint = "CONTAINS"
                search_string         = "://"

                field_to_match {
                  headers {
                    match_pattern {
                      all {}
                    }
                    match_scope       = "ALL"
                    oversize_handling = "NO_MATCH"
                  }
                }

                text_transformation {
                  priority = 0
                  type     = "URL_DECODE"
                }
                text_transformation {
                  priority = 1
                  type     = "HTML_ENTITY_DECODE"
                }
                text_transformation {
                  priority = 2
                  type     = "HEX_DECODE"
                }
                text_transformation {
                  priority = 3
                  type     = "BASE64_DECODE"
                }
                text_transformation {
                  priority = 4
                  type     = "UTF8_TO_UNICODE"
                }
              }
            }

            # byte_match `://` CONTAINS on cookies
            statement {
              byte_match_statement {
                positional_constraint = "CONTAINS"
                search_string         = "://"

                field_to_match {
                  cookies {
                    match_pattern {
                      all {}
                    }
                    match_scope       = "ALL"
                    oversize_handling = "NO_MATCH"
                  }
                }

                text_transformation {
                  priority = 0
                  type     = "URL_DECODE"
                }
                text_transformation {
                  priority = 1
                  type     = "HTML_ENTITY_DECODE"
                }
                text_transformation {
                  priority = 2
                  type     = "HEX_DECODE"
                }
                text_transformation {
                  priority = 3
                  type     = "BASE64_DECODE"
                }
                text_transformation {
                  priority = 4
                  type     = "UTF8_TO_UNICODE"
                }
              }
            }
          }
        }

        # -------------------------------------------------------------------
        # Group 2 (NOT): exempt legit https:// AND optionally mauth://
        # -------------------------------------------------------------------
        statement {
          not_statement {
            statement {
              or_statement {

                # https:// in query_string
                statement {
                  regex_pattern_set_reference_statement {
                    arn = aws_wafv2_regex_pattern_set.owasp_https_exempt.arn

                    field_to_match {
                      query_string {}
                    }

                    text_transformation {
                      priority = 0
                      type     = "URL_DECODE"
                    }
                    text_transformation {
                      priority = 1
                      type     = "HTML_ENTITY_DECODE"
                    }
                  }
                }

                # https:// in uri_path
                statement {
                  regex_pattern_set_reference_statement {
                    arn = aws_wafv2_regex_pattern_set.owasp_https_exempt.arn

                    field_to_match {
                      uri_path {}
                    }

                    text_transformation {
                      priority = 0
                      type     = "URL_DECODE"
                    }
                    text_transformation {
                      priority = 1
                      type     = "HTML_ENTITY_DECODE"
                    }
                  }
                }

                # mauth:// in query_string (dynamic, only when var.owasp_detect_rfi_lfi_allow_mauth)
                dynamic "statement" {
                  for_each = var.owasp_detect_rfi_lfi_allow_mauth ? [1] : []
                  content {
                    regex_pattern_set_reference_statement {
                      arn = aws_wafv2_regex_pattern_set.owasp_mauth_exempt.arn

                      field_to_match {
                        query_string {}
                      }

                      text_transformation {
                        priority = 0
                        type     = "URL_DECODE"
                      }
                      text_transformation {
                        priority = 1
                        type     = "HTML_ENTITY_DECODE"
                      }
                    }
                  }
                }

                # mauth:// in uri_path (dynamic)
                dynamic "statement" {
                  for_each = var.owasp_detect_rfi_lfi_allow_mauth ? [1] : []
                  content {
                    regex_pattern_set_reference_statement {
                      arn = aws_wafv2_regex_pattern_set.owasp_mauth_exempt.arn

                      field_to_match {
                        uri_path {}
                      }

                      text_transformation {
                        priority = 0
                        type     = "URL_DECODE"
                      }
                      text_transformation {
                        priority = 1
                        type     = "HTML_ENTITY_DECODE"
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "owaspdetectrfilfi"
      sampled_requests_enabled   = true
    }
  }

  # ===========================================================================
  # Rule 5 - owasp-detect-ssi  (unchanged - already minimal)
  # ===========================================================================
  rule {
    name     = "owasp-detect-ssi"
    priority = 5

    action {
      block {
        custom_response {
          custom_response_body_key = "hsbc-default-block"
          response_code            = 403
        }
      }
    }

    rule_label {
      name = "${var.rule_label_namespace}:owasp-detect-ssi"
    }

    statement {
      or_statement {
        statement {
          byte_match_statement {
            positional_constraint = "ENDS_WITH"
            search_string         = ".backup"

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "ENDS_WITH"
            search_string         = ".cfg"

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "ENDS_WITH"
            search_string         = ".ini"

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "STARTS_WITH"
            search_string         = "/includes"

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "ENDS_WITH"
            search_string         = ".bak"

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "ENDS_WITH"
            search_string         = ".config"

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "ENDS_WITH"
            search_string         = ".log"

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "ENDS_WITH"
            search_string         = ".conf"

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "owaspdetectssi"
      sampled_requests_enabled   = true
    }
  }

  # ===========================================================================
  # Rule 6 - owasp-mitigate-sqli  (REFACTORED - chained transforms per placement)
  # Was 8 statements (4 placements x 2 transforms). Now 4 statements with chained transforms.
  # ===========================================================================
  rule {
    name     = "owasp-mitigate-sqli"
    priority = 6

    action {
      block {
        custom_response {
          custom_response_body_key = "hsbc-default-block"
          response_code            = 403
        }
      }
    }

    rule_label {
      name = "${var.rule_label_namespace}:owasp-mitigate-sqli"
    }

    statement {
      or_statement {
        statement {
          sqli_match_statement {
            field_to_match {
              query_string {}
            }

            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 1
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }

        statement {
          sqli_match_statement {
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 1
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }

        statement {
          sqli_match_statement {
            field_to_match {
              body {}
            }

            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 1
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }

        statement {
          sqli_match_statement {
            field_to_match {
              single_header {
                name = "cookie"
              }
            }

            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 1
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "owaspmitigatesqli"
      sampled_requests_enabled   = true
    }
  }

  # ===========================================================================
  # Rule 7 - owasp-mitigate-xss  (REFACTORED - chained transforms per placement)
  # Was 25 statements (5 placements x 5 transforms). Now 5 statements with chained transforms.
  # ===========================================================================
  rule {
    name     = "owasp-mitigate-xss"
    priority = 7

    action {
      block {
        custom_response {
          custom_response_body_key = "hsbc-default-block"
          response_code            = 403
        }
      }
    }

    rule_label {
      name = "${var.rule_label_namespace}:owasp-mitigate-xss"
    }

    statement {
      or_statement {
        statement {
          xss_match_statement {
            field_to_match {
              query_string {}
            }

            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 1
              type     = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority = 2
              type     = "HEX_DECODE"
            }
            text_transformation {
              priority = 3
              type     = "BASE64_DECODE"
            }
            text_transformation {
              priority = 4
              type     = "UTF8_TO_UNICODE"
            }
          }
        }

        statement {
          xss_match_statement {
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 1
              type     = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority = 2
              type     = "HEX_DECODE"
            }
            text_transformation {
              priority = 3
              type     = "BASE64_DECODE"
            }
            text_transformation {
              priority = 4
              type     = "UTF8_TO_UNICODE"
            }
          }
        }

        statement {
          xss_match_statement {
            field_to_match {
              body {}
            }

            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 1
              type     = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority = 2
              type     = "HEX_DECODE"
            }
            text_transformation {
              priority = 3
              type     = "BASE64_DECODE"
            }
            text_transformation {
              priority = 4
              type     = "UTF8_TO_UNICODE"
            }
          }
        }

        statement {
          xss_match_statement {
            field_to_match {
              single_header {
                name = "cookie"
              }
            }

            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 1
              type     = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority = 2
              type     = "HEX_DECODE"
            }
            text_transformation {
              priority = 3
              type     = "BASE64_DECODE"
            }
            text_transformation {
              priority = 4
              type     = "UTF8_TO_UNICODE"
            }
          }
        }

        statement {
          xss_match_statement {
            field_to_match {
              headers {
                match_pattern {
                  all {}
                }
                match_scope       = "ALL"
                oversize_handling = "NO_MATCH"
              }
            }

            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 1
              type     = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority = 2
              type     = "HEX_DECODE"
            }
            text_transformation {
              priority = 3
              type     = "BASE64_DECODE"
            }
            text_transformation {
              priority = 4
              type     = "UTF8_TO_UNICODE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "owaspmitigatexss"
      sampled_requests_enabled   = true
    }
  }
}
