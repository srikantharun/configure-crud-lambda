# =============================================================================
# rulegroups.tf  -  bypass-closure resources
# =============================================================================
# Pairs with variables.tf.
#
# Structure (read top-to-bottom):
#   1.  Six regex pattern sets, one per attack family. Each one's regex list
#       is read from var.rule_families[<name>].patterns.
#   2.  One rule group with six rules, one per family. Each rule:
#         - always BLOCKs (the count/block toggle was removed for readability;
#           the `action` field is no longer on the rule_families variable)
#         - checks placements: body, json_body, query_string, cookies, and
#           (for rfi/lfi/cmdi/ssti only) headers. The LFI variant uses
#           uri_path instead of cookies. SQLi and XSS DO NOT check headers
#           (dropped to save ~145 WCU - real-world header-based SQLi/XSS
#           are rare).
#         - applies URL_DECODE + LOWERCASE before regex match (single decode
#           pass; the second URL_DECODE was dropped to save ~100 WCU - trade
#           off is missing 9 double-URL-encoded leakers from the 186 corpus)
#           (XSS family gets an extra HTML_ENTITY_DECODE step)
#   3.  Outputs.
#
# Migration: delete the old monolithic baseline_1_3_bypass_closure_rule_group.tf
# before applying - it declares the same resource addresses and Terraform
# will reject duplicate declarations otherwise. The 6 pattern set addresses
# and the rule group address are identical to the old file, so NO state
# moves are needed and `terraform plan` should show NO changes.
# =============================================================================

# -----------------------------------------------------------------------------
# 1.  Pattern sets (one per family)
# -----------------------------------------------------------------------------
module "custom_responses" {
  source = "../custom_responses"
}

# resource "aws_wafv2_regex_pattern_set" "rfi" {
#   name        = "${var.rule_group_name}-rfi"
#   scope       = var.scope
#   description = "RFI / remote URL inclusion"
#
#   dynamic "regular_expression" {
#     for_each = var.rule_families["rfi"].patterns
#     content {
#       regex_string = regular_expression.value
#     }
#   }
# }

# resource "aws_wafv2_regex_pattern_set" "lfi" {
#   name        = "${var.rule_group_name}-lfi"
#   scope       = var.scope
#   description = "LFI / path traversal + sensitive files"
#
#   dynamic "regular_expression" {
#     for_each = var.rule_families["lfi"].patterns
#     content {
#       regex_string = regular_expression.value
#     }
#   }
# }

# resource "aws_wafv2_regex_pattern_set" "cmdi" {
#   name        = "${var.rule_group_name}-cmdi"
#   scope       = var.scope
#   description = "Command injection"
#
#   dynamic "regular_expression" {
#     for_each = var.rule_families["cmdi"].patterns
#     content {
#       regex_string = regular_expression.value
#     }
#   }
# }

# resource "aws_wafv2_regex_pattern_set" "ssti" {
#   name        = "${var.rule_group_name}-ssti"
#   scope       = var.scope
#   description = "Template injection (Jinja / Freemarker / SpEL / Twig)"
#
#   dynamic "regular_expression" {
#     for_each = var.rule_families["ssti"].patterns
#     content {
#       regex_string = regular_expression.value
#     }
#   }
# }

resource "aws_wafv2_regex_pattern_set" "sqli" {
  name        = "${var.rule_group_name}-sqli"
  scope       = var.scope
  description = "SQLi bypass variants the managed SQLiRuleSet misses"

  dynamic "regular_expression" {
    for_each = var.rule_families["sqli"].patterns
    content {
      regex_string = regular_expression.value
    }
  }
}

resource "aws_wafv2_regex_pattern_set" "xss" {
  name        = "${var.rule_group_name}-xss"
  scope       = var.scope
  description = "XSS bypass variants the managed XSS rule misses"

  dynamic "regular_expression" {
    for_each = var.rule_families["xss"].patterns
    content {
      regex_string = regular_expression.value
    }
  }
}

# -----------------------------------------------------------------------------
# 2.  Rule group  -  six rules, one per family
# -----------------------------------------------------------------------------
resource "aws_wafv2_rule_group" "baseline_1_3_bypass_closure" {
  name        = var.rule_group_name
  scope       = var.scope
  capacity    = var.capacity
  description = var.description
  tags        = var.tags

  custom_response_body {
    key          = "hsbc-default-block"
    content_type = "TEXT_HTML"
    content      = module.custom_responses.default_block
  }

  # ===========================================================================
  # Rule 1  -  SQLi (priority 1 = checked first, lowest FP risk)
  # ===========================================================================
  rule {
    name     = "rule-1-sqli"
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
      name = "${var.rule_label_namespace}:owasp-custom-sqli-closure"
    }

    statement {
      or_statement {
        statement {
          regex_pattern_set_reference_statement {
            arn = aws_wafv2_regex_pattern_set.sqli.arn

            field_to_match {
              body {
                oversize_handling = "CONTINUE"
              }
            }

            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 1
              type     = "LOWERCASE"
            }
          }
        }

        statement {
          regex_pattern_set_reference_statement {
            arn = aws_wafv2_regex_pattern_set.sqli.arn

            field_to_match {
              json_body {
                match_pattern {
                  all {}
                }
                match_scope               = "VALUE"
                invalid_fallback_behavior = "EVALUATE_AS_STRING"
                oversize_handling         = "CONTINUE"
              }
            }

            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 1
              type     = "LOWERCASE"
            }
          }
        }

        statement {
          regex_pattern_set_reference_statement {
            arn = aws_wafv2_regex_pattern_set.sqli.arn

            field_to_match {
              query_string {}
            }

            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 1
              type     = "LOWERCASE"
            }
          }
        }

        statement {
          regex_pattern_set_reference_statement {
            arn = aws_wafv2_regex_pattern_set.sqli.arn

            field_to_match {
              cookies {
                match_pattern {
                  all {}
                }
                match_scope       = "VALUE"
                oversize_handling = "CONTINUE"
              }
            }

            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 1
              type     = "LOWERCASE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.rule_group_name}-sqli"
      sampled_requests_enabled   = true
    }
  }
  # ===========================================================================
  # Rule 2  -  XSS (priority 2)
  # XSS gets an extra HTML_ENTITY_DECODE step to defeat &lt;script&gt; etc.
  # ===========================================================================
  rule {
    name     = "rule-2-xss"
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
      name = "${var.rule_label_namespace}:owasp-custom-xss-closure"
    }

    statement {
      or_statement {
        statement {
          regex_pattern_set_reference_statement {
            arn = aws_wafv2_regex_pattern_set.xss.arn

            field_to_match {
              body {
                oversize_handling = "CONTINUE"
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
              type     = "LOWERCASE"
            }
          }
        }

        statement {
          regex_pattern_set_reference_statement {
            arn = aws_wafv2_regex_pattern_set.xss.arn

            field_to_match {
              json_body {
                match_pattern {
                  all {}
                }
                match_scope               = "VALUE"
                invalid_fallback_behavior = "EVALUATE_AS_STRING"
                oversize_handling         = "CONTINUE"
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
              type     = "LOWERCASE"
            }
          }
        }

        statement {
          regex_pattern_set_reference_statement {
            arn = aws_wafv2_regex_pattern_set.xss.arn

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
              type     = "LOWERCASE"
            }
          }
        }

        statement {
          regex_pattern_set_reference_statement {
            arn = aws_wafv2_regex_pattern_set.xss.arn

            field_to_match {
              cookies {
                match_pattern {
                  all {}
                }
                match_scope       = "VALUE"
                oversize_handling = "CONTINUE"
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
              type     = "LOWERCASE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.rule_group_name}-xss"
      sampled_requests_enabled   = true
    }
  }


  # -------------------------------------------------------------------------
  # The following 4 family rules are commented out for now (sqli + xss only
  # are active). Uncomment a family + uncomment its pattern set above to enable.
  # -------------------------------------------------------------------------

#   # ===========================================================================
#   # Rule 1  -  RFI  (priority 1 = checked first)
#   # ===========================================================================
#   rule {
#     name     = "rule-1-rfi"
#     priority = 1
#
#     # Action: count or block, taken from variables.tf
#     action {
#       block {}
#     }
#
#     statement {
#       or_statement {
#         # ---- check the request BODY ----
#         statement {
#           regex_pattern_set_reference_statement {
#             arn = aws_wafv2_regex_pattern_set.rfi.arn
#
#             field_to_match {
#               body {
#                 oversize_handling = "CONTINUE"
#               }
#             }
#
#             text_transformation {
#               priority = 0
#               type     = "URL_DECODE"
#             }
#             text_transformation {
#               priority = 1
#               type     = "LOWERCASE"
#             }
#           }
#         }
#
#         # ---- check JSON BODY values ----
#         statement {
#           regex_pattern_set_reference_statement {
#             arn = aws_wafv2_regex_pattern_set.rfi.arn
#
#             field_to_match {
#               json_body {
#                 match_pattern {
#                   all {}
#                 }
#                 match_scope               = "VALUE"
#                 invalid_fallback_behavior = "EVALUATE_AS_STRING"
#                 oversize_handling         = "CONTINUE"
#               }
#             }
#
#             text_transformation {
#               priority = 0
#               type     = "URL_DECODE"
#             }
#             text_transformation {
#               priority = 1
#               type     = "LOWERCASE"
#             }
#           }
#         }
#
#         # ---- check the query string ----
#         statement {
#           regex_pattern_set_reference_statement {
#             arn = aws_wafv2_regex_pattern_set.rfi.arn
#
#             field_to_match {
#               query_string {}
#             }
#
#             text_transformation {
#               priority = 0
#               type     = "URL_DECODE"
#             }
#             text_transformation {
#               priority = 1
#               type     = "LOWERCASE"
#             }
#           }
#         }
#
#         # ---- check cookies ----
#         statement {
#           regex_pattern_set_reference_statement {
#             arn = aws_wafv2_regex_pattern_set.rfi.arn
#
#             field_to_match {
#               cookies {
#                 match_pattern {
#                   all {}
#                 }
#                 match_scope       = "VALUE"
#                 oversize_handling = "CONTINUE"
#               }
#             }
#
#             text_transformation {
#               priority = 0
#               type     = "URL_DECODE"
#             }
#             text_transformation {
#               priority = 1
#               type     = "LOWERCASE"
#             }
#           }
#         }
#
#         # ---- check all request headers ----
#         statement {
#           regex_pattern_set_reference_statement {
#             arn = aws_wafv2_regex_pattern_set.rfi.arn
#
#             field_to_match {
#               headers {
#                 match_pattern {
#                   all {}
#                 }
#                 match_scope       = "VALUE"
#                 oversize_handling = "MATCH"
#               }
#             }
#
#             text_transformation {
#               priority = 0
#               type     = "URL_DECODE"
#             }
#             text_transformation {
#               priority = 1
#               type     = "LOWERCASE"
#             }
#           }
#         }
#       }
#     }
#
#     visibility_config {
#       cloudwatch_metrics_enabled = true
#       metric_name                = "${var.rule_group_name}-rfi"
#       sampled_requests_enabled   = true
#     }
#   }
#

#   # ===========================================================================
#   # Rule 2  -  LFI  (priority 2)
#   # LFI uses uri_path instead of cookies (path traversal is mostly URL-based)
#   # ===========================================================================
#   rule {
#     name     = "rule-2-lfi"
#     priority = 2
#
#     action {
#       block {}
#     }
#
#     statement {
#       or_statement {
#         statement {
#           regex_pattern_set_reference_statement {
#             arn = aws_wafv2_regex_pattern_set.lfi.arn
#
#             field_to_match {
#               body {
#                 oversize_handling = "CONTINUE"
#               }
#             }
#
#             text_transformation {
#               priority = 0
#               type     = "URL_DECODE"
#             }
#             text_transformation {
#               priority = 1
#               type     = "LOWERCASE"
#             }
#           }
#         }
#
#         statement {
#           regex_pattern_set_reference_statement {
#             arn = aws_wafv2_regex_pattern_set.lfi.arn
#
#             field_to_match {
#               json_body {
#                 match_pattern {
#                   all {}
#                 }
#                 match_scope               = "VALUE"
#                 invalid_fallback_behavior = "EVALUATE_AS_STRING"
#                 oversize_handling         = "CONTINUE"
#               }
#             }
#
#             text_transformation {
#               priority = 0
#               type     = "URL_DECODE"
#             }
#             text_transformation {
#               priority = 1
#               type     = "LOWERCASE"
#             }
#           }
#         }
#
#         statement {
#           regex_pattern_set_reference_statement {
#             arn = aws_wafv2_regex_pattern_set.lfi.arn
#
#             field_to_match {
#               query_string {}
#             }
#
#             text_transformation {
#               priority = 0
#               type     = "URL_DECODE"
#             }
#             text_transformation {
#               priority = 1
#               type     = "LOWERCASE"
#             }
#           }
#         }
#
#         # LFI checks URI path (instead of cookies)
#         statement {
#           regex_pattern_set_reference_statement {
#             arn = aws_wafv2_regex_pattern_set.lfi.arn
#
#             field_to_match {
#               uri_path {}
#             }
#
#             text_transformation {
#               priority = 0
#               type     = "URL_DECODE"
#             }
#             text_transformation {
#               priority = 1
#               type     = "LOWERCASE"
#             }
#           }
#         }
#
#         statement {
#           regex_pattern_set_reference_statement {
#             arn = aws_wafv2_regex_pattern_set.lfi.arn
#
#             field_to_match {
#               headers {
#                 match_pattern {
#                   all {}
#                 }
#                 match_scope       = "VALUE"
#                 oversize_handling = "MATCH"
#               }
#             }
#
#             text_transformation {
#               priority = 0
#               type     = "URL_DECODE"
#             }
#             text_transformation {
#               priority = 1
#               type     = "LOWERCASE"
#             }
#           }
#         }
#       }
#     }
#
#     visibility_config {
#       cloudwatch_metrics_enabled = true
#       metric_name                = "${var.rule_group_name}-lfi"
#       sampled_requests_enabled   = true
#     }
#   }
#

#   # ===========================================================================
#   # Rule 3  -  CMDI  (priority 3)
#   # ===========================================================================
#   rule {
#     name     = "rule-3-cmdi"
#     priority = 3
#
#     action {
#       block {}
#     }
#
#     statement {
#       or_statement {
#         statement {
#           regex_pattern_set_reference_statement {
#             arn = aws_wafv2_regex_pattern_set.cmdi.arn
#
#             field_to_match {
#               body {
#                 oversize_handling = "CONTINUE"
#               }
#             }
#
#             text_transformation {
#               priority = 0
#               type     = "URL_DECODE"
#             }
#             text_transformation {
#               priority = 1
#               type     = "LOWERCASE"
#             }
#           }
#         }
#
#         statement {
#           regex_pattern_set_reference_statement {
#             arn = aws_wafv2_regex_pattern_set.cmdi.arn
#
#             field_to_match {
#               json_body {
#                 match_pattern {
#                   all {}
#                 }
#                 match_scope               = "VALUE"
#                 invalid_fallback_behavior = "EVALUATE_AS_STRING"
#                 oversize_handling         = "CONTINUE"
#               }
#             }
#
#             text_transformation {
#               priority = 0
#               type     = "URL_DECODE"
#             }
#             text_transformation {
#               priority = 1
#               type     = "LOWERCASE"
#             }
#           }
#         }
#
#         statement {
#           regex_pattern_set_reference_statement {
#             arn = aws_wafv2_regex_pattern_set.cmdi.arn
#
#             field_to_match {
#               query_string {}
#             }
#
#             text_transformation {
#               priority = 0
#               type     = "URL_DECODE"
#             }
#             text_transformation {
#               priority = 1
#               type     = "LOWERCASE"
#             }
#           }
#         }
#
#         statement {
#           regex_pattern_set_reference_statement {
#             arn = aws_wafv2_regex_pattern_set.cmdi.arn
#
#             field_to_match {
#               cookies {
#                 match_pattern {
#                   all {}
#                 }
#                 match_scope       = "VALUE"
#                 oversize_handling = "CONTINUE"
#               }
#             }
#
#             text_transformation {
#               priority = 0
#               type     = "URL_DECODE"
#             }
#             text_transformation {
#               priority = 1
#               type     = "LOWERCASE"
#             }
#           }
#         }
#
#         statement {
#           regex_pattern_set_reference_statement {
#             arn = aws_wafv2_regex_pattern_set.cmdi.arn
#
#             field_to_match {
#               headers {
#                 match_pattern {
#                   all {}
#                 }
#                 match_scope       = "VALUE"
#                 oversize_handling = "MATCH"
#               }
#             }
#
#             text_transformation {
#               priority = 0
#               type     = "URL_DECODE"
#             }
#             text_transformation {
#               priority = 1
#               type     = "LOWERCASE"
#             }
#           }
#         }
#       }
#     }
#
#     visibility_config {
#       cloudwatch_metrics_enabled = true
#       metric_name                = "${var.rule_group_name}-cmdi"
#       sampled_requests_enabled   = true
#     }
#   }
#

#   # ===========================================================================
#   # Rule 4  -  SSTI  (priority 4)
#   # ===========================================================================
#   rule {
#     name     = "rule-4-ssti"
#     priority = 4
#
#     action {
#       block {}
#     }
#
#     statement {
#       or_statement {
#         statement {
#           regex_pattern_set_reference_statement {
#             arn = aws_wafv2_regex_pattern_set.ssti.arn
#
#             field_to_match {
#               body {
#                 oversize_handling = "CONTINUE"
#               }
#             }
#
#             text_transformation {
#               priority = 0
#               type     = "URL_DECODE"
#             }
#             text_transformation {
#               priority = 1
#               type     = "LOWERCASE"
#             }
#           }
#         }
#
#         statement {
#           regex_pattern_set_reference_statement {
#             arn = aws_wafv2_regex_pattern_set.ssti.arn
#
#             field_to_match {
#               json_body {
#                 match_pattern {
#                   all {}
#                 }
#                 match_scope               = "VALUE"
#                 invalid_fallback_behavior = "EVALUATE_AS_STRING"
#                 oversize_handling         = "CONTINUE"
#               }
#             }
#
#             text_transformation {
#               priority = 0
#               type     = "URL_DECODE"
#             }
#             text_transformation {
#               priority = 1
#               type     = "LOWERCASE"
#             }
#           }
#         }
#
#         statement {
#           regex_pattern_set_reference_statement {
#             arn = aws_wafv2_regex_pattern_set.ssti.arn
#
#             field_to_match {
#               query_string {}
#             }
#
#             text_transformation {
#               priority = 0
#               type     = "URL_DECODE"
#             }
#             text_transformation {
#               priority = 1
#               type     = "LOWERCASE"
#             }
#           }
#         }
#
#         statement {
#           regex_pattern_set_reference_statement {
#             arn = aws_wafv2_regex_pattern_set.ssti.arn
#
#             field_to_match {
#               cookies {
#                 match_pattern {
#                   all {}
#                 }
#                 match_scope       = "VALUE"
#                 oversize_handling = "CONTINUE"
#               }
#             }
#
#             text_transformation {
#               priority = 0
#               type     = "URL_DECODE"
#             }
#             text_transformation {
#               priority = 1
#               type     = "LOWERCASE"
#             }
#           }
#         }
#
#         statement {
#           regex_pattern_set_reference_statement {
#             arn = aws_wafv2_regex_pattern_set.ssti.arn
#
#             field_to_match {
#               headers {
#                 match_pattern {
#                   all {}
#                 }
#                 match_scope       = "VALUE"
#                 oversize_handling = "MATCH"
#               }
#             }
#
#             text_transformation {
#               priority = 0
#               type     = "URL_DECODE"
#             }
#             text_transformation {
#               priority = 1
#               type     = "LOWERCASE"
#             }
#           }
#         }
#       }
#     }
#
#     visibility_config {
#       cloudwatch_metrics_enabled = true
#       metric_name                = "${var.rule_group_name}-ssti"
#       sampled_requests_enabled   = true
#     }
#   }
#
  # ---------------------------------------------------------------------------
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = var.rule_group_name
    sampled_requests_enabled   = true
  }
}

# -----------------------------------------------------------------------------
# 3.  Outputs
# -----------------------------------------------------------------------------
output "rule_group_arn" {
  description = "Reference this in your WebACL via rule_group_reference_statement."
  value       = aws_wafv2_rule_group.baseline_1_3_bypass_closure.arn
}

output "rule_group_id" {
  description = "ID of the bypass-closure rule group."
  value       = aws_wafv2_rule_group.baseline_1_3_bypass_closure.id
}
