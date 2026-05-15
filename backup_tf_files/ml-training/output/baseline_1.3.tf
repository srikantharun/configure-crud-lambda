resource "aws_fms_policy" "baseline_1_3_global_block" {
  name          = "baseline_1_3_block_${var.policy_ver}"
  resource_type = "AWS::CloudFront::Distribution"

  delete_all_policy_resources        = true
  delete_unused_fm_managed_resources = false
  exclude_resource_tags              = false
  remediation_enabled                = true

  resource_tags = {
    "BASELINE:CYBERWASP:VERSION" : "1.3_block"
  }


  security_service_policy_data {
    type = "WAFV2"

    managed_service_data = jsonencode({

      type = "WAFV2"

      customRequestHandling = null
      customResponse        = null
      loggingConfiguration  = null

      # CLOUDFRONT - HEADERS/COOKIES ONLY
      associationConfig = {
        requestBody = {
          CLOUDFRONT = {
            defaultSizeInspectionLimit = "KB_64"
          }
        }
      }

      preProcessRuleGroups = [

        # LOG4J - ALWAYS BLOCK
        {
          ruleGroupType              = "RuleGroup"
          ruleGroupArn               = module.waf_rg_log4j.arn
          sampledRequestsEnabled     = true
          excludeRules               = []
          managedRuleGroupIdentifier = null

          overrideAction = {
            type = "NONE"
          }
        },

        # IP BLACKLIST - BLOCK
        {
          ruleGroupType              = "RuleGroup"
          ruleGroupArn               = module.waf_rg_ip_blacklist.arn
          sampledRequestsEnabled     = true
          excludeRules               = []
          managedRuleGroupIdentifier = null

          overrideAction = {
            type = "NONE"
          }
        },

        # SIZE RESTRICTIONS - BLOCK - Enforces Body > 64KB, Header > 8KB, Cookie > 8KB
        {
          ruleGroupType              = "RuleGroup"
          ruleGroupArn               = module.waf_rg_size_restrictions.arn
          sampledRequestsEnabled     = true
          excludeRules               = []
          managedRuleGroupIdentifier = null

          overrideAction = {
            type = "NONE"
          }
        },

        # CYBERWASP - BLOCK
        {
          ruleGroupType              = "RuleGroup"
          ruleGroupArn               = module.waf_rg_cyberwasp.arn
          sampledRequestsEnabled     = true
          excludeRules               = []
          managedRuleGroupIdentifier = null

          overrideAction = {
            type = "NONE"
          }
        },

        # COMMON RULE SET (CRS) - BLOCK
        {
          ruleGroupType          = "ManagedRuleGroup"
          ruleGroupArn           = null
          sampledRequestsEnabled = true
          excludeRules           = []

          managedRuleGroupIdentifier = {
            vendorName           = "AWS"
            managedRuleGroupName = "AWSManagedRulesCommonRuleSet"
            versionEnabled       = true
            version              = "Version_1.20"
          }

          overrideAction = {
            type = "NONE"
          }

          ruleActionOverrides = [
            {
              name = "NoUserAgent_HEADER"
              actionToUse = {
                count = {}
              }
            }
          ]
        },

        # SQLi - BLOCK
        {
          ruleGroupType          = "ManagedRuleGroup"
          ruleGroupArn           = null
          sampledRequestsEnabled = true
          excludeRules           = []

          managedRuleGroupIdentifier = {
            vendorName           = "AWS"
            managedRuleGroupName = "AWSManagedRulesSQLiRuleSet"
            versionEnabled       = true
            version              = "Version_2.0"
          }

          overrideAction = {
            type = "NONE"
          }
        },

        # KNOWN BAD INPUTS - BLOCK
        # Re-enabled in 1.3 (was commented out previously due to a name typo).
        # Correct managed-rule name is "AWSManagedRulesKnownBadInputsRuleSet"
        # with a trailing "s". This rule group catches known exploit/CVE
        # signatures, malformed-protocol patterns, and a number of RFI/SSRF
        # URL families that supplement waf_rg_hsbc_custom_v3.
        {
          ruleGroupType          = "ManagedRuleGroup"
          ruleGroupArn           = null
          sampledRequestsEnabled = true
          excludeRules           = []

          managedRuleGroupIdentifier = {
            vendorName           = "AWS"
            managedRuleGroupName = "AWSManagedRulesKnownBadInputsRuleSet"
            versionEnabled       = true
            version              = "Version_1.22"
          }

          overrideAction = {
            type = "NONE"
          }
        },

        # ADMIN PROTECTION - BLOCK
        {
          ruleGroupType          = "ManagedRuleGroup"
          ruleGroupArn           = null
          sampledRequestsEnabled = true
          excludeRules           = []

          managedRuleGroupIdentifier = {
            vendorName           = "AWS"
            managedRuleGroupName = "AWSManagedRulesAdminProtectionRuleSet"
            versionEnabled       = true
            version              = "Version_1.1"
          }

          overrideAction = {
            type = "NONE"
          }
        },

        # WINDOWS OS - BLOCK
        {
          ruleGroupType          = "ManagedRuleGroup"
          ruleGroupArn           = null
          sampledRequestsEnabled = true
          excludeRules           = []

          managedRuleGroupIdentifier = {
            vendorName           = "AWS"
            managedRuleGroupName = "AWSManagedRulesWindowsRuleSet"
            versionEnabled       = true
            version              = "Version_2.3"
          }

          overrideAction = {
            type = "NONE"
          }
        },

        # LINUX OS - BLOCK
        {
          ruleGroupType          = "ManagedRuleGroup"
          ruleGroupArn           = null
          sampledRequestsEnabled = true
          excludeRules           = []

          managedRuleGroupIdentifier = {
            vendorName           = "AWS"
            managedRuleGroupName = "AWSManagedRulesLinuxRuleSet"
            versionEnabled       = true
            version              = "Version_2.6"
          }

          overrideAction = {
            type = "NONE"
          }
        },

        # UNIX / POSIX - BLOCK
        {
          ruleGroupType          = "ManagedRuleGroup"
          ruleGroupArn           = null
          sampledRequestsEnabled = true
          excludeRules           = []

          managedRuleGroupIdentifier = {
            vendorName           = "AWS"
            managedRuleGroupName = "AWSManagedRulesUnixRuleSet"
            versionEnabled       = true
            version              = "Version_3.2"
          }

          overrideAction = {
            type = "NONE"
          }
        },

        # PHP - BLOCK
        {
          ruleGroupType          = "ManagedRuleGroup"
          ruleGroupArn           = null
          sampledRequestsEnabled = true
          excludeRules           = []

          managedRuleGroupIdentifier = {
            vendorName           = "AWS"
            managedRuleGroupName = "AWSManagedRulesPHPRuleSet"
            versionEnabled       = true
            version              = "Version_2.1"
          }

          overrideAction = {
            type = "NONE"
          }
        },

        # WORDPRESS - BLOCK
        {
          ruleGroupType          = "ManagedRuleGroup"
          ruleGroupArn           = null
          sampledRequestsEnabled = true
          excludeRules           = []

          managedRuleGroupIdentifier = {
            vendorName           = "AWS"
            managedRuleGroupName = "AWSManagedRulesWordPressRuleSet"
            versionEnabled       = true
            version              = "Version_1.3"
          }

          overrideAction = {
            type = "NONE"
          }
        },

        # LEGACY OWASP V2 - BLOCK (BASELINE COMPARISON)
        {
          ruleGroupType              = "RuleGroup"
          ruleGroupArn               = module.waf_rg_hsbc_custom_v3.arn
          sampledRequestsEnabled     = true
          excludeRules               = []
          managedRuleGroupIdentifier = null

          overrideAction = {
            type = "NONE"
          }
        }
      ]

      postProcessRuleGroups = []

      defaultAction = {
        type = "ALLOW"
      }
      sampledRequestsEnabledForDefaultActions = false
      overrideCustomerWebACLAssociation       = false
      optimizeUnassociatedWebACL              = true
      webACLSource                            = "RETROFIT_EXISTING"
    })
  }

  include_map {
    account = local.policy_scope_block
  }

  lifecycle {
    ignore_changes = [tags]
  }
}
