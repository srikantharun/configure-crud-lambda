# variables.tf

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Name of the project (used for resource naming)"
  type        = string
  default     = "simple-crud-api"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "api_stage_name" {
  description = "API Gateway stage name"
  type        = string
  default     = "prod"
}

variable "lambda_runtime" {
  description = "Lambda runtime version"
  type        = string
  default     = "python3.9"
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 30
}

variable "cloudfront_price_class" {
  description = "CloudFront price class"
  type        = string
  default     = "PriceClass_100"
  validation {
    condition = contains([
      "PriceClass_All", 
      "PriceClass_200", 
      "PriceClass_100"
    ], var.cloudfront_price_class)
    error_message = "CloudFront price class must be PriceClass_All, PriceClass_200, or PriceClass_100."
  }
}

variable "common_tags" {
  description = "Common tags to be applied to all resources"
  type        = map(string)
  default = {
    Project     = "simple-crud-api"
    Environment = "dev"
    ManagedBy   = "terraform"
    Owner       = "devops-team"
  }
}

# Variable for dynamic URI paths - supports nested paths
variable "uri_path_var" {
  description = "List of URI paths to create endpoints for (supports nested paths)"
  type        = list(string)
  default     = [
    "items",
    "products/food/beverages",
    "users/state/atlanta",
    "orders/receipt1/100"
  ]

  validation {
    condition = alltrue([
      for path in var.uri_path_var :
      can(regex("^/?[a-zA-Z0-9/_.-]+$", path))
    ])
    error_message = "URI paths must only contain alphanumeric characters, forward slashes, hyphens, underscores, and dots. Leading slash is optional."
  }
}
