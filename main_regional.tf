# main_regional.tf - Regional setup with ALB instead of CloudFront
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

# Local variables for path handling
locals {
  # Strip leading slashes from all paths for consistency
  cleaned_paths = [
    for path in var.uri_path_var :
    trimprefix(path, "/")
  ]
}

# VPC Configuration for ALB
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(
    var.common_tags,
    {
      Name = "${var.project_name}-vpc-regional"
    }
  )
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = merge(
    var.common_tags,
    {
      Name = "${var.project_name}-igw-regional"
    }
  )
}

# Public Subnets for ALB (minimum 2 for ALB)
resource "aws_subnet" "public" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.${count.index + 1}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  map_public_ip_on_launch = true

  tags = merge(
    var.common_tags,
    {
      Name = "${var.project_name}-public-subnet-${count.index + 1}"
    }
  )
}

# Route Table for Public Subnets
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = merge(
    var.common_tags,
    {
      Name = "${var.project_name}-public-rt"
    }
  )
}

# Route Table Associations
resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Security Group for ALB
resource "aws_security_group" "alb" {
  name_prefix = "${var.project_name}-alb-sg"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(
    var.common_tags,
    {
      Name = "${var.project_name}-alb-sg"
    }
  )
}

# Create the Lambda function code for ALB
resource "local_file" "lambda_code_alb" {
  content = <<EOF
import json
import uuid
from datetime import datetime
import base64

# Simple in-memory storage for each path type
storage = {}

def handler(event, context):
    print(f"ALB Event: {json.dumps(event)}")

    # ALB events have a different structure than API Gateway
    # Extract HTTP method and path
    method = event.get('httpMethod', 'GET')
    path = event.get('path', '/')

    # Extract headers including Host header for WAF testing
    headers = event.get('headers', {})
    host_header = headers.get('Host', headers.get('host', 'default'))
    print(f"Host header: {host_header}")

    # Extract query parameters
    query_params = event.get('queryStringParameters') or {}
    request_param = query_params.get('request', '').lower()

    # Extract body if present
    body_str = event.get('body', '')
    is_base64 = event.get('isBase64Encoded', False)

    if body_str and is_base64:
        body_str = base64.b64decode(body_str).decode('utf-8')

    # Parse path to extract resource type and item ID
    path_parts = path.strip('/').split('/')

    if path_parts:
        potential_id = path_parts[-1] if len(path_parts) > 1 else None
        try:
            if potential_id and len(potential_id) == 36:
                uuid.UUID(potential_id)
                resource_type = '/'.join(path_parts[:-1])
                item_id = potential_id
            else:
                resource_type = '/'.join(path_parts)
                item_id = None
        except:
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
                if item_id in storage[resource_type]:
                    return alb_response(200, storage[resource_type][item_id])
                else:
                    return alb_response(404, {"error": f"Item not found in {resource_type}"})
            else:
                all_items = list(storage[resource_type].values())

                if request_param:
                    filtered_items = [
                        item for item in all_items
                        if request_param in item.get('name', '').lower()
                        or request_param in item.get('description', '').lower()
                    ]
                    return alb_response(200, {
                        "resource_type": resource_type,
                        "items": filtered_items,
                        "count": len(filtered_items),
                        "filter": request_param,
                        "host_header": host_header
                    })

                if query_params:
                    filtered_items = all_items
                    for key, value in query_params.items():
                        if key != 'request':
                            filtered_items = [
                                item for item in filtered_items
                                if str(item.get(key, '')).lower() == value.lower()
                            ]
                    return alb_response(200, {
                        "resource_type": resource_type,
                        "items": filtered_items,
                        "count": len(filtered_items),
                        "filters": query_params,
                        "host_header": host_header
                    })

                return alb_response(200, {
                    "resource_type": resource_type,
                    "items": all_items,
                    "count": len(all_items),
                    "host_header": host_header
                })

        elif method == 'POST':
            body = json.loads(body_str) if body_str else {}
            new_id = str(uuid.uuid4())

            new_item = {
                "id": new_id,
                "name": body.get('name', f'Unnamed item in {resource_type}'),
                "description": body.get('description', ''),
                "resource_type": resource_type,
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat()
            }

            for key, value in body.items():
                if key not in new_item:
                    new_item[key] = value

            if request_param == 'bulk':
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
                    return alb_response(201, {
                        "message": f"Bulk creation in {resource_type} successful",
                        "items": created_items,
                        "count": len(created_items)
                    })

            storage[resource_type][new_id] = new_item
            return alb_response(201, new_item)

        elif method == 'PUT':
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
                        return alb_response(400, {"error": "Item ID required for update"})
                else:
                    return alb_response(400, {"error": "Item ID required for update"})

            if item_id not in storage[resource_type]:
                return alb_response(404, {"error": f"Item not found in {resource_type}"})

            body = json.loads(body_str) if body_str else {}

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

            return alb_response(200, storage[resource_type][item_id])

        elif method == 'DELETE':
            if not item_id:
                if request_param == 'all':
                    count = len(storage[resource_type])
                    storage[resource_type].clear()
                    return alb_response(200, {
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
                            return alb_response(400, {"error": "Item ID required for deletion"})
                    else:
                        return alb_response(400, {"error": "Item ID required for deletion"})

            if item_id not in storage[resource_type]:
                return alb_response(404, {"error": f"Item not found in {resource_type}"})

            deleted_item = storage[resource_type].pop(item_id)
            return alb_response(200, {"message": f"Item deleted from {resource_type}", "item": deleted_item})

        elif method == 'OPTIONS':
            return alb_response(200, {})

        else:
            return alb_response(405, {"error": f"Method {method} not allowed"})

    except Exception as e:
        print(f"Error: {str(e)}")
        return alb_response(500, {"error": f"Internal server error: {str(e)}"})

def alb_response(status_code, body):
    """ALB-specific response format"""
    return {
        'statusCode': status_code,
        'statusDescription': f'{status_code} OK' if status_code < 400 else f'{status_code} Error',
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,Host'
        },
        'isBase64Encoded': False,
        'body': json.dumps(body, indent=2)
    }
EOF

  filename = "${path.module}/lambda_function_alb.py"
}

# Create ZIP file for Lambda
data "archive_file" "lambda_zip_alb" {
  type        = "zip"
  source_file = local_file.lambda_code_alb.filename
  output_path = "${path.module}/crud_api_alb.zip"
  depends_on  = [local_file.lambda_code_alb]
}

# IAM role for Lambda
resource "aws_iam_role" "lambda_role_alb" {
  name = "${var.project_name}-lambda-role-alb"

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
resource "aws_iam_role_policy_attachment" "lambda_basic_alb" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = aws_iam_role.lambda_role_alb.name
}

# Lambda function for ALB
resource "aws_lambda_function" "crud_api_alb" {
  filename         = data.archive_file.lambda_zip_alb.output_path
  function_name    = "${var.project_name}-api-alb"
  role            = aws_iam_role.lambda_role_alb.arn
  handler         = "lambda_function_alb.handler"
  runtime         = var.lambda_runtime
  timeout         = var.lambda_timeout
  source_code_hash = data.archive_file.lambda_zip_alb.output_base64sha256

  environment {
    variables = {
      ENVIRONMENT = var.environment
    }
  }

  tags = var.common_tags
}

# Application Load Balancer
resource "aws_lb" "main" {
  name               = "${var.project_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets           = aws_subnet.public[*].id

  enable_deletion_protection = false
  enable_http2              = true
  enable_cross_zone_load_balancing = true

  tags = merge(
    var.common_tags,
    {
      Name = "${var.project_name}-alb"
    }
  )
}

# Target Group for Lambda
resource "aws_lb_target_group" "lambda" {
  name        = "${var.project_name}-lambda-tg"
  target_type = "lambda"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 35
    timeout             = 30
    path                = "/"
    matcher             = "200-299"
  }

  tags = var.common_tags
}

# Attach Lambda to Target Group
resource "aws_lb_target_group_attachment" "lambda" {
  target_group_arn = aws_lb_target_group.lambda.arn
  target_id        = aws_lambda_function.crud_api_alb.arn
  depends_on       = [aws_lambda_permission.alb]
}

# Lambda permission for ALB
resource "aws_lambda_permission" "alb" {
  statement_id  = "AllowExecutionFromALB"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.crud_api_alb.function_name
  principal     = "elasticloadbalancing.amazonaws.com"
  source_arn    = aws_lb_target_group.lambda.arn
}

# HTTP Listener
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.lambda.arn
  }
}

# Listener Rules for each path (optional - can use default action)
# Since Lambda will handle all routing internally, we can use a single default rule
# But if you want path-based routing at ALB level, uncomment below:

# dynamic "aws_lb_listener_rule" "path_rules" {
#   for_each = toset(var.uri_path_var)
#
#   listener_arn = aws_lb_listener.http.arn
#   priority     = 100 + index(var.uri_path_var, each.value)
#
#   action {
#     type             = "forward"
#     target_group_arn = aws_lb_target_group.lambda.arn
#   }
#
#   condition {
#     path_pattern {
#       values = ["/${each.value}/*", "/${each.value}"]
#     }
#   }
# }

# HTTPS Listener (optional - requires ACM certificate)
# Uncomment if you have an ACM certificate ARN
# resource "aws_lb_listener" "https" {
#   load_balancer_arn = aws_lb.main.arn
#   port              = "443"
#   protocol          = "HTTPS"
#   ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
#   certificate_arn   = var.acm_certificate_arn  # You need to provide this
#
#   default_action {
#     type             = "forward"
#     target_group_arn = aws_lb_target_group.lambda.arn
#   }
# }

# Data sources
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# Outputs
output "alb_dns_name" {
  description = "ALB DNS name"
  value       = aws_lb.main.dns_name
}

output "alb_zone_id" {
  description = "ALB Zone ID"
  value       = aws_lb.main.zone_id
}

output "alb_arn" {
  description = "ALB ARN"
  value       = aws_lb.main.arn
}

output "lambda_function_name_alb" {
  description = "Lambda function name for ALB"
  value       = aws_lambda_function.crud_api_alb.function_name
}

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "alb_endpoint_examples" {
  description = "Example endpoints for each configured path via ALB"
  value = {
    for path in local.cleaned_paths :
    path => {
      list_all    = "http://${aws_lb.main.dns_name}/${path}"
      get_by_id   = "http://${aws_lb.main.dns_name}/${path}/{id}"
      with_filter = "http://${aws_lb.main.dns_name}/${path}?request=search_term"
    }
  }
}

output "curl_test_examples" {
  description = "Example curl commands for testing with custom Host headers"
  value = {
    "basic_get"        = "curl -H 'Host: example.com' http://${aws_lb.main.dns_name}/items"
    "malicious_host"   = "curl -H 'Host: malicious-site.com' http://${aws_lb.main.dns_name}/products/food/beverages"
    "post_with_host"   = "curl -X POST -H 'Host: test.com' -H 'Content-Type: application/json' -d '{\"name\":\"test item\"}' http://${aws_lb.main.dns_name}/items"
  }
}