# =============================================================================
# variables.tf  -  inputs for the bypass-closure rule group
# =============================================================================
# Target stack: hashicorp/aws ~> 4.51, Terraform core 1.0+ (no optional() with
# defaults, no fancy features).
#
# What lives here:
#   - Basic rule-group metadata (name, scope, capacity, tags, description)
#   - One map `rule_families` keyed by attack family: rfi, lfi, cmdi, ssti,
#     sqli, xss. For each family you set `action` (count or block) and the
#     list of regex `patterns`.
#
# What does NOT live here (kept in rulegroups.tf because it rarely changes):
#   - Which placements to inspect (body, json_body, query_string, cookies,
#     headers, uri_path)
#   - Text transformations (URL_DECODE / HTML_ENTITY_DECODE / LOWERCASE)
#   - Visibility config
#
# Day-to-day edits for the junior engineer:
#   - Add a new regex to a family   ->  append to `patterns` for that family
#   - Promote a family count->block ->  change `action` for that family
# =============================================================================

variable "rule_group_name" {
  description = "Name of the AWS WAFv2 rule group."
  type        = string
  default     = "baseline-1-3-bypass-closure"
}

variable "scope" {
  description = "WAFv2 scope. Either CLOUDFRONT or REGIONAL."
  type        = string
  default     = "CLOUDFRONT"
}

variable "capacity" {
  description = "WCU capacity for the rule group. Max 1500."
  type        = number
  default     = 1500
}

variable "description" {
  description = "Description shown on the rule group resource."
  type        = string
  default     = "HSBC custom rule group closing 1.3b bypass gaps. Ships in COUNT; promote to BLOCK per family after measuring false-positive rate."
}

variable "tags" {
  description = "Tags applied to the rule group."
  type        = map(string)
  default = {
    Project   = "baseline-1.3"
    Component = "waf-rule-group"
    Purpose   = "bypass-closure"
    OwnedBy   = "WAFCoE"
  }
}

# -----------------------------------------------------------------------------
# Per-family settings.
#
# Map shape:
#   rule_families = {
#     <family-name> = {
#       action   = "count" | "block"
#       patterns = [ "<regex1>", "<regex2>", ... ]
#     }
#     ...
#   }
#
# Six keys are expected: rfi, lfi, cmdi, ssti, sqli, xss.
# -----------------------------------------------------------------------------
variable "rule_families" {
  description = "Per-family regex patterns and action (count or block)."

  type = map(object({
    action   = string
    patterns = list(string)
  }))

  default = {

    # ---- RFI : remote-URL inclusion (11 leakers on 1.3b run) -------------
    rfi = {
      action = "count"
      patterns = [
        # http(s)://hostname.tld/...  - the canonical RFI vector
        "(?:^|[\\s'\"=?&#])https?://[a-z0-9.\\-]+\\.[a-z]{2,}/",

        # SMB / UNC path  \\host\share
        "\\\\\\\\[a-z0-9.\\-]+\\\\",

        # Dangerous PHP-style URI wrappers
        "(?:php|data|expect|file|zip|glob|phar)://",

        # URL with a percent-encoded character inside the hostname (e.g. ev%69l.com)
        "https?://[a-z0-9.\\-]*%[0-9a-f]{2}[a-z0-9.\\-]*\\.[a-z]{2,}",
      ]
    }

    # ---- LFI : path traversal + sensitive files (4 leakers) --------------
    lfi = {
      action = "count"
      patterns = [
        # ../  ..\\  ....//  ..%2f  - all encodings of path traversal
        "(?:\\.{2,}|%2[eE]{1,2}){1,}[/\\\\%]",

        # Overlong UTF-8 representations of / and \\
        "(?:%c0%af|%c0%2f|%c1%9c)",

        # Sensitive Linux files
        "/etc/(?:passwd|shadow|hosts|fstab)|/proc/self/environ",

        # Sensitive Windows files
        "c:\\\\windows\\\\(?:win\\.ini|system32)",
      ]
    }

    # ---- CMDI : shell command injection (8 leakers) ----------------------
    cmdi = {
      action = "count"
      patterns = [
        # Shell separator + common Unix binary
        "(?:^|[\\s;&|`$(])(?:id|whoami|uname|cat|nc|wget|curl|sh|bash|ksh|powershell)\\b",

        # IFS bypass for space-stripped commands:  sh${IFS}-c${IFS}whoami
        "\\$(?:\\{IFS\\}|IFS\\b)",

        # Backtick command substitution:  `id`, `uname -a`
        "`[^`]{1,80}`",

        # $(...) and <(...) substitution
        "(?:\\$\\(|<\\()\\s*(?:id|whoami|uname|cat)",
      ]
    }

    # ---- SSTI : template-injection (10 leakers) --------------------------
    ssti = {
      action = "count"
      patterns = [
        # {{ ... }}  - Jinja / Twig / Handlebars
        "\\{\\{\\s*[\\w\\d.()*+/\\-]{1,50}\\s*\\}\\}",

        # ${...} and #{...}  - Spring SpEL / Freemarker / JSP EL / Ruby
        "(?:\\$|#)\\{\\s*[\\w\\d.()*+/\\-]{1,50}\\s*\\}",

        # <%= ... %>  - ERB / ASP / Java JSP
        "<%\\s*=",

        # Freemarker exploit (assigns Execute helper)
        "<#assign[^>]+freemarker\\.template",
      ]
    }

    # ---- SQLi : bypass variants the managed group misses (55 leakers) ----
    sqli = {
      action = "count"
      patterns = [
        # Quoted OR/AND with equality:  ' OR '1'='1, ') OR ('1'='1
        "(?:^|[\\s()'\"])'\\s*[)\\]]?\\s*(?:or|and)\\s+['\"]?[\\w\\d]+['\"]?\\s*=\\s*['\"]?[\\w\\d]+",

        # Quote + comment terminator:  admin'--   admin'#
        "['\"](?:\\s|\\+)*(?:-{2,}|#)",

        # Stacked destructive query:  ; DROP / INSERT / UPDATE / DELETE
        ";\\s*(?:drop|insert|update|delete)\\b",

        # UNION SELECT with optional comment padding
        "union(?:\\s|/\\*.*?\\*/)+select",
      ]
    }

    # ---- XSS : bypass variants the managed group misses (96 leakers) -----
    # Note: this family gets an extra HTML_ENTITY_DECODE text-transformation
    # in rulegroups.tf because attackers send &lt;script&gt; etc.
    xss = {
      action = "count"
      patterns = [
        # <script> or </script>, any case / spacing
        "<\\s*/?\\s*script[\\s>]",

        # Inline HTML event-handler attribute (onclick=, onerror= ...)
        "\\bon(?:click|load|error|mouseover|focus|blur|submit|change|key(?:up|down|press))\\s*=",

        # alert / prompt / confirm / eval with any-encoded opening paren
        "\\b(?:alert|prompt|confirm|eval)\\s*(?:\\(|\\\\x28|\\\\u0028)",

        # javascript: URI scheme
        "javascript\\s*:\\s*\\S",
      ]
    }
  }
}
