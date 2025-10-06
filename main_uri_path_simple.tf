# main_uri_path_simple.tf - Simplified version using {proxy+} greedy path
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.0"
    }
  }
  required_version = ">= 1.0"
}

provider "aws" {
  region = var.aws_region
}

# Simple approach - Lambda handles ALL path routing
# No complex hierarchical resources needed!
locals {
  # Strip leading slashes from all paths for documentation
  cleaned_paths = [
    for path in var.uri_path_var :
    trimprefix(path, "/")
  ]
}

# Create the Lambda function code that handles multiple paths
resource "local_file" "lambda_code" {
  content = <<EOF
import json
import uuid
from datetime import datetime

# Simple in-memory storage for each path type
storage = {}

def handler(event, context):
    print(f"Event: {json.dumps(event)}")

    method = event.get('httpMethod', 'GET')
    path = event.get('path', '/')

    # Extract headers including Host header for WAF testing
    headers = event.get('headers', {})
    host_header = headers.get('Host', headers.get('host', 'default'))
    print(f"Host header: {host_header}")

    # Extract query parameters
    query_params = event.get('queryStringParameters') or {}
    request_param = query_params.get('request', '').lower()

    # Extract the resource type and item ID from path
    path_parts = path.strip('/').split('/')

    # For nested paths, we'll use the full path as resource type
    # but handle the last segment specially if it looks like an ID
    if path_parts:
        # Check if last part is a UUID-like ID
        potential_id = path_parts[-1] if len(path_parts) > 1 else None
        try:
            # Try to parse as UUID
            if potential_id and len(potential_id) == 36:
                uuid.UUID(potential_id)
                resource_type = '/'.join(path_parts[:-1])
                item_id = potential_id
            else:
                # Not an ID, treat full path as resource type
                resource_type = '/'.join(path_parts)
                item_id = None
        except:
            # Not a UUID, treat as part of path
            resource_type = '/'.join(path_parts)
            item_id = None
    else:
        resource_type = None
        item_id = None

    # Initialize storage for this resource type if not exists
    if resource_type and resource_type not in storage:
        storage[resource_type] = {}

    try:
        if method == 'GET':
            if item_id:
                # Get single item
                if item_id in storage[resource_type]:
                    return response(200, storage[resource_type][item_id])
                else:
                    return response(404, {"error": f"Item not found in {resource_type}"})
            else:
                # Get all items with optional filtering
                all_items = list(storage[resource_type].values())

                # Filter by request parameter if provided
                if request_param:
                    filtered_items = [
                        item for item in all_items
                        if request_param in item.get('name', '').lower()
                        or request_param in item.get('description', '').lower()
                    ]
                    return response(200, {
                        "resource_type": resource_type,
                        "items": filtered_items,
                        "count": len(filtered_items),
                        "filter": request_param,
                        "host_header": host_header
                    })

                # Filter by any other query parameters
                if query_params:
                    filtered_items = all_items
                    for key, value in query_params.items():
                        if key != 'request':
                            filtered_items = [
                                item for item in filtered_items
                                if str(item.get(key, '')).lower() == value.lower()
                            ]
                    return response(200, {
                        "resource_type": resource_type,
                        "items": filtered_items,
                        "count": len(filtered_items),
                        "filters": query_params,
                        "host_header": host_header
                    })

                return response(200, {
                    "resource_type": resource_type,
                    "items": all_items,
                    "count": len(all_items),
                    "host_header": host_header
                })

        elif method == 'POST':
            # Create new item
            body = json.loads(event.get('body', '{}'))
            new_id = str(uuid.uuid4())

            new_item = {
                "id": new_id,
                "name": body.get('name', f'Unnamed item in {resource_type}'),
                "description": body.get('description', ''),
                "resource_type": resource_type,
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat()
            }

            # Add any additional fields from body
            for key, value in body.items():
                if key not in new_item:
                    new_item[key] = value

            # Handle special request parameters
            if request_param == 'bulk':
                # Support bulk creation if multiple items in array
                if isinstance(body.get('items'), list):
                    created_items = []
                    for item_data in body['items']:
                        bulk_id = str(uuid.uuid4())
                        bulk_item = {
                            "id": bulk_id,
                            "name": item_data.get('name', f'Unnamed item in {resource_type}'),
                            "description": item_data.get('description', ''),
                            "resource_type": resource_type,
                            "created_at": datetime.now().isoformat(),
                            "updated_at": datetime.now().isoformat()
                        }
                        for k, v in item_data.items():
                            if k not in bulk_item:
                                bulk_item[k] = v
                        storage[resource_type][bulk_id] = bulk_item
                        created_items.append(bulk_item)
                    return response(201, {
                        "message": f"Bulk creation in {resource_type} successful",
                        "items": created_items,
                        "count": len(created_items)
                    })

            storage[resource_type][new_id] = new_item
            return response(201, new_item)

        elif method == 'PUT':
            # Update item
            if not item_id:
                path_segments = path.strip('/').split('/')
                if len(path_segments) >= 2:
                    potential_id = path_segments[-1]
                    try:
                        uuid.UUID(potential_id)
                        item_id = potential_id
                        resource_type = '/'.join(path_segments[:-1])
                        if resource_type not in storage:
                            storage[resource_type] = {}
                    except:
                        return response(400, {"error": "Item ID required for update"})
                else:
                    return response(400, {"error": "Item ID required for update"})

            if item_id not in storage[resource_type]:
                return response(404, {"error": f"Item not found in {resource_type}"})

            body = json.loads(event.get('body', '{}'))

            # Update with merge or replace based on request parameter
            if request_param == 'replace':
                storage[resource_type][item_id] = {
                    "id": item_id,
                    "name": body.get('name', f'Unnamed item in {resource_type}'),
                    "description": body.get('description', ''),
                    "resource_type": resource_type,
                    "created_at": storage[resource_type][item_id].get('created_at'),
                    "updated_at": datetime.now().isoformat()
                }
                for key, value in body.items():
                    if key not in ['id', 'created_at']:
                        storage[resource_type][item_id][key] = value
            else:
                storage[resource_type][item_id].update({
                    "name": body.get('name', storage[resource_type][item_id]['name']),
                    "description": body.get('description', storage[resource_type][item_id]['description']),
                    "updated_at": datetime.now().isoformat()
                })
                for key, value in body.items():
                    if key not in ['id', 'created_at']:
                        storage[resource_type][item_id][key] = value

            return response(200, storage[resource_type][item_id])

        elif method == 'DELETE':
            # Delete item
            if not item_id:
                if request_param == 'all':
                    count = len(storage[resource_type])
                    storage[resource_type].clear()
                    return response(200, {
                        "message": f"Deleted all items from {resource_type}",
                        "count": count
                    })
                else:
                    path_segments = path.strip('/').split('/')
                    if len(path_segments) >= 2:
                        potential_id = path_segments[-1]
                        try:
                            uuid.UUID(potential_id)
                            item_id = potential_id
                            resource_type = '/'.join(path_segments[:-1])
                        except:
                            return response(400, {"error": "Item ID required for deletion"})
                    else:
                        return response(400, {"error": "Item ID required for deletion"})

            if item_id not in storage[resource_type]:
                return response(404, {"error": f"Item not found in {resource_type}"})

            deleted_item = storage[resource_type].pop(item_id)
            return response(200, {"message": f"Item deleted from {resource_type}", "item": deleted_item})

        elif method == 'OPTIONS':
            # Handle CORS preflight
            return response(200, {})

        else:
            return response(405, {"error": f"Method {method} not allowed"})

    except Exception as e:
        print(f"Error: {str(e)}")
        return response(500, {"error": f"Internal server error: {str(e)}"})

def response(status_code, body):
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,Host'
        },
        'body': json.dumps(body, indent=2)
    }
EOF

  filename = "${path.module}/lambda_function_multi_path.py"
}

# Create ZIP file for Lambda
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = local_file.lambda_code.filename
  output_path = "${path.module}/crud_api_multi_path.zip"
  depends_on  = [local_file.lambda_code]
}

# IAM role for Lambda
resource "aws_iam_role" "lambda_role" {
  name = "${var.project_name}-lambda-role-multi"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = var.common_tags
}

# Attach basic execution policy
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = aws_iam_role.lambda_role.name
}

# Lambda function for CRUD operations
resource "aws_lambda_function" "crud_api" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.project_name}-api-multi"
  role            = aws_iam_role.lambda_role.arn
  handler         = "lambda_function_multi_path.handler"
  runtime         = var.lambda_runtime
  timeout         = var.lambda_timeout
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      ENVIRONMENT = var.environment
    }
  }

  tags = var.common_tags
}

# API Gateway
resource "aws_api_gateway_rest_api" "crud_api" {
  name        = "${var.project_name}-api-multi"
  description = "Multi-path CRUD REST API with Query Parameters"

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  tags = var.common_tags
}

# Create ONE proxy resource that catches ALL paths
resource "aws_api_gateway_resource" "proxy" {
  rest_api_id = aws_api_gateway_rest_api.crud_api.id
  parent_id   = aws_api_gateway_rest_api.crud_api.root_resource_id
  path_part   = "{proxy+}"
}

# Request validator that doesn't validate the path format (allows dots, etc.)
resource "aws_api_gateway_request_validator" "proxy_validator" {
  name                        = "${var.project_name}-proxy-validator"
  rest_api_id                 = aws_api_gateway_rest_api.crud_api.id
  validate_request_body       = false
  validate_request_parameters = false
}

# ANY method for the proxy resource (catches all HTTP methods)
resource "aws_api_gateway_method" "proxy_any" {
  rest_api_id   = aws_api_gateway_rest_api.crud_api.id
  resource_id   = aws_api_gateway_resource.proxy.id
  http_method   = "ANY"
  authorization = "NONE"
  request_validator_id = aws_api_gateway_request_validator.proxy_validator.id
  request_parameters = {
    "method.request.path.proxy" = false  # Don't require validation
    "method.request.header.Host" = false
  }
}

# Integration for proxy - with proper path handling
resource "aws_api_gateway_integration" "proxy_integration" {
  rest_api_id = aws_api_gateway_rest_api.crud_api.id
  resource_id = aws_api_gateway_resource.proxy.id
  http_method = aws_api_gateway_method.proxy_any.http_method
  integration_http_method = "POST"
  type        = "AWS_PROXY"
  uri         = aws_lambda_function.crud_api.invoke_arn

  # Cache key parameters - include the full proxy path
  cache_key_parameters = ["method.request.path.proxy"]

  # Request parameters mapping - pass through the proxy path as-is
  request_parameters = {
    "integration.request.path.proxy" = "method.request.path.proxy"
  }
}

# Lambda permissions for API Gateway
resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.crud_api.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.crud_api.execution_arn}/*/*"
}

# API Gateway Deployment
resource "aws_api_gateway_deployment" "crud_api" {
  depends_on = [
    aws_api_gateway_integration.proxy_integration,
  ]

  rest_api_id = aws_api_gateway_rest_api.crud_api.id
  stage_name  = var.api_stage_name

  lifecycle {
    create_before_destroy = true
  }
}

# CloudFront Distribution
resource "aws_cloudfront_distribution" "crud_api_cdn" {
  origin {
    domain_name = "${aws_api_gateway_rest_api.crud_api.id}.execute-api.${var.aws_region}.amazonaws.com"
    origin_id   = "APIGateway-${aws_api_gateway_rest_api.crud_api.id}"
    origin_path = "/${var.api_stage_name}"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  enabled = true
  comment = "${var.project_name} Multi-Path CloudFront Distribution"

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = "APIGateway-${aws_api_gateway_rest_api.crud_api.id}"

    forwarded_values {
      query_string = true
      headers      = ["Authorization", "Content-Type", "X-Forwarded-For", "Host"]

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 0
    max_ttl                = 86400
    compress               = true

    # Don't normalize URLs - preserve dots, special characters in paths
    smooth_streaming = false
  }

  # Cache behavior for static content (if any)
  ordered_cache_behavior {
    path_pattern     = "/static/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "APIGateway-${aws_api_gateway_rest_api.crud_api.id}"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  price_class = var.cloudfront_price_class

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = var.common_tags
}

# Data sources
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# Outputs
output "api_gateway_url" {
  description = "API Gateway URL"
  value       = "https://${aws_api_gateway_rest_api.crud_api.id}.execute-api.${var.aws_region}.amazonaws.com/${var.api_stage_name}"
}

output "cloudfront_url" {
  description = "CloudFront URL"
  value       = "https://${aws_cloudfront_distribution.crud_api_cdn.domain_name}"
}

output "lambda_function_name" {
  description = "Lambda function name"
  value       = aws_lambda_function.crud_api.function_name
}

output "api_gateway_id" {
  description = "API Gateway ID"
  value       = aws_api_gateway_rest_api.crud_api.id
}

output "cloudfront_distribution_id" {
  description = "CloudFront Distribution ID"
  value       = aws_cloudfront_distribution.crud_api_cdn.id
}

output "configured_paths" {
  description = "List of configured URI paths (cleaned, without leading slashes)"
  value       = local.cleaned_paths
}

output "endpoint_examples" {
  description = "Example endpoints - ALL paths work with the proxy+"
  value = {
    for path in local.cleaned_paths :
    path => {
      list_all    = "https://${aws_cloudfront_distribution.crud_api_cdn.domain_name}/${path}"
      get_by_id   = "https://${aws_cloudfront_distribution.crud_api_cdn.domain_name}/${path}/{id}"
      with_filter = "https://${aws_cloudfront_distribution.crud_api_cdn.domain_name}/${path}?request=search_term"
    }
  }
}

output "usage_note" {
  description = "How this simplified version works"
  value = <<-EOT
    This version uses API Gateway's {proxy+} greedy path variable.

    Benefits:
    - No circular dependencies!
    - Handles ANY path depth automatically
    - Single resource instead of hierarchical tree
    - Lambda does all the routing
    - Supports dots in paths (like v1.0)

    Configuration:
    - Request validator disabled for path validation
    - Paths with dots (.) are supported
    - Test directly via API Gateway first if CloudFront has issues

    The Lambda function parses the full path and handles it accordingly.
  EOT
}

output "direct_api_gateway_urls" {
  description = "Direct API Gateway URLs (bypass CloudFront) - Use these if you get 403 errors with dots in paths"
  value = {
    for path in local.cleaned_paths :
    path => {
      list_all = "https://${aws_api_gateway_rest_api.crud_api.id}.execute-api.${var.aws_region}.amazonaws.com/${var.api_stage_name}/${path}"
      post_create = "curl -X POST https://${aws_api_gateway_rest_api.crud_api.id}.execute-api.${var.aws_region}.amazonaws.com/${var.api_stage_name}/${path} -H 'Content-Type: application/json' -d '{\"name\":\"test\"}'"
    }
  }
}

output "cloudfront_urls" {
  description = "CloudFront URLs - May need URL encoding for paths with dots"
  value = {
    for path in local.cleaned_paths :
    path => {
      list_all = "https://${aws_cloudfront_distribution.crud_api_cdn.domain_name}/${path}"
      post_create = "curl -X POST https://${aws_cloudfront_distribution.crud_api_cdn.domain_name}/${path} -H 'Content-Type: application/json' -d '{\"name\":\"test\"}'"
    }
  }
}