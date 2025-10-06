# main_regional_private.tf - Regional setup with Internal ALB in Private Subnets
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
  cleaned_paths_private = [
    for path in var.uri_path_var :
    trimprefix(path, "/")
  ]
}

# Variable to control ALB type
variable "alb_internal" {
  description = "Whether the ALB should be internal (private) or internet-facing"
  type        = bool
  default     = true  # Internal by default for organization use
}

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to access the internal ALB (e.g., corporate network ranges)"
  type        = list(string)
  default     = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]  # Private RFC1918 ranges
}

# VPC Configuration for Internal ALB
resource "aws_vpc" "main_private" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(
    var.common_tags,
    {
      Name = "${var.project_name}-vpc-private"
    }
  )
}

# Private Subnets for Internal ALB (minimum 2 for ALB)
resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main_private.id
  cidr_block        = "10.0.${count.index + 10}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = merge(
    var.common_tags,
    {
      Name = "${var.project_name}-private-subnet-${count.index + 1}"
      Type = "Private"
    }
  )
}

# Route Table for Private Subnets (no Internet Gateway)
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main_private.id

  tags = merge(
    var.common_tags,
    {
      Name = "${var.project_name}-private-rt"
    }
  )
}

# Route Table Associations for Private Subnets
resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# Security Group for Internal ALB
resource "aws_security_group" "alb_private" {
  name_prefix = "${var.project_name}-alb-private-sg"
  description = "Security group for internal ALB"
  vpc_id      = aws_vpc.main_private.id

  # HTTP from allowed corporate networks
  ingress {
    description = "HTTP from corporate networks"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # HTTPS from allowed corporate networks
  ingress {
    description = "HTTPS from corporate networks"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # Allow traffic within VPC (for testing from EC2/VPN)
  ingress {
    description = "HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main_private.cidr_block]
  }

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main_private.cidr_block]
  }

  egress {
    description = "Allow all outbound to VPC"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [aws_vpc.main_private.cidr_block]
  }

  tags = merge(
    var.common_tags,
    {
      Name = "${var.project_name}-alb-private-sg"
    }
  )
}

# VPC Endpoint for Lambda (allows Lambda to work in VPC without NAT)
resource "aws_vpc_endpoint" "lambda" {
  vpc_id              = aws_vpc.main_private.id
  service_name        = "com.amazonaws.${var.aws_region}.lambda"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = merge(
    var.common_tags,
    {
      Name = "${var.project_name}-lambda-endpoint"
    }
  )
}

# VPC Endpoint for CloudWatch Logs (for Lambda logging)
resource "aws_vpc_endpoint" "logs" {
  vpc_id              = aws_vpc.main_private.id
  service_name        = "com.amazonaws.${var.aws_region}.logs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = merge(
    var.common_tags,
    {
      Name = "${var.project_name}-logs-endpoint"
    }
  )
}

# Security Group for VPC Endpoints
resource "aws_security_group" "vpc_endpoints" {
  name_prefix = "${var.project_name}-vpc-endpoints-sg"
  description = "Security group for VPC endpoints"
  vpc_id      = aws_vpc.main_private.id

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main_private.cidr_block]
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
      Name = "${var.project_name}-vpc-endpoints-sg"
    }
  )
}

# Create the Lambda function code for Internal ALB
resource "local_file" "lambda_code_alb_private" {
  content = <<EOF
import json
import uuid
from datetime import datetime
import base64

# Simple in-memory storage for each path type
storage = {}

def handler(event, context):
    print(f"Internal ALB Event: {json.dumps(event)}")

    # ALB events have a different structure than API Gateway
    method = event.get('httpMethod', 'GET')
    path = event.get('path', '/')

    # Extract headers including Host header for WAF testing
    headers = event.get('headers', {})
    host_header = headers.get('Host', headers.get('host', 'default'))
    x_forwarded_for = headers.get('X-Forwarded-For', headers.get('x-forwarded-for', 'unknown'))

    print(f"Host header: {host_header}")
    print(f"X-Forwarded-For: {x_forwarded_for}")
    print(f"Source IP (for internal testing): {x_forwarded_for}")

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
                        "host_header": host_header,
                        "source_ip": x_forwarded_for,
                        "deployment": "internal-alb"
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
                        "host_header": host_header,
                        "source_ip": x_forwarded_for,
                        "deployment": "internal-alb"
                    })

                return alb_response(200, {
                    "resource_type": resource_type,
                    "items": all_items,
                    "count": len(all_items),
                    "host_header": host_header,
                    "source_ip": x_forwarded_for,
                    "deployment": "internal-alb"
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

  filename = "${path.module}/lambda_function_alb_private.py"
}

# Create ZIP file for Lambda
data "archive_file" "lambda_zip_alb_private" {
  type        = "zip"
  source_file = local_file.lambda_code_alb_private.filename
  output_path = "${path.module}/crud_api_alb_private.zip"
  depends_on  = [local_file.lambda_code_alb_private]
}

# IAM role for Lambda
resource "aws_iam_role" "lambda_role_alb_private" {
  name = "${var.project_name}-lambda-role-alb-private"

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
resource "aws_iam_role_policy_attachment" "lambda_basic_alb_private" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = aws_iam_role.lambda_role_alb_private.name
}

# Lambda function for Internal ALB
resource "aws_lambda_function" "crud_api_alb_private" {
  filename         = data.archive_file.lambda_zip_alb_private.output_path
  function_name    = "${var.project_name}-api-alb-private"
  role            = aws_iam_role.lambda_role_alb_private.arn
  handler         = "lambda_function_alb_private.handler"
  runtime         = var.lambda_runtime
  timeout         = var.lambda_timeout
  source_code_hash = data.archive_file.lambda_zip_alb_private.output_base64sha256

  environment {
    variables = {
      ENVIRONMENT = var.environment
    }
  }

  tags = var.common_tags
}

# Internal Application Load Balancer
resource "aws_lb" "main_private" {
  name               = "${var.project_name}-alb-private"
  internal           = var.alb_internal  # true = internal, false = internet-facing
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_private.id]
  subnets           = aws_subnet.private[*].id

  enable_deletion_protection = false
  enable_http2              = true
  enable_cross_zone_load_balancing = true

  tags = merge(
    var.common_tags,
    {
      Name = "${var.project_name}-alb-private"
      Type = "Internal"
    }
  )
}

# Target Group for Lambda
resource "aws_lb_target_group" "lambda_private" {
  name        = "${var.project_name}-lambda-tg-priv"
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
resource "aws_lb_target_group_attachment" "lambda_private" {
  target_group_arn = aws_lb_target_group.lambda_private.arn
  target_id        = aws_lambda_function.crud_api_alb_private.arn
  depends_on       = [aws_lambda_permission.alb_private]
}

# Lambda permission for Internal ALB
resource "aws_lambda_permission" "alb_private" {
  statement_id  = "AllowExecutionFromInternalALB"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.crud_api_alb_private.function_name
  principal     = "elasticloadbalancing.amazonaws.com"
  source_arn    = aws_lb_target_group.lambda_private.arn
}

# HTTP Listener
resource "aws_lb_listener" "http_private" {
  load_balancer_arn = aws_lb.main_private.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.lambda_private.arn
  }
}

# HTTPS Listener (optional - requires ACM certificate)
# resource "aws_lb_listener" "https_private" {
#   load_balancer_arn = aws_lb.main_private.arn
#   port              = "443"
#   protocol          = "HTTPS"
#   ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
#   certificate_arn   = var.acm_certificate_arn
#
#   default_action {
#     type             = "forward"
#     target_group_arn = aws_lb_target_group.lambda_private.arn
#   }
# }

# Data sources
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# Outputs
output "alb_private_dns_name" {
  description = "Internal ALB DNS name"
  value       = aws_lb.main_private.dns_name
}

output "alb_private_zone_id" {
  description = "Internal ALB Zone ID"
  value       = aws_lb.main_private.zone_id
}

output "alb_private_arn" {
  description = "Internal ALB ARN"
  value       = aws_lb.main_private.arn
}

output "lambda_function_name_alb_private" {
  description = "Lambda function name for Internal ALB"
  value       = aws_lambda_function.crud_api_alb_private.function_name
}

output "vpc_id_private" {
  description = "Private VPC ID"
  value       = aws_vpc.main_private.id
}

output "private_subnet_ids" {
  description = "Private subnet IDs"
  value       = aws_subnet.private[*].id
}

output "alb_private_endpoint_examples" {
  description = "Example endpoints for each configured path via Internal ALB"
  value = {
    for path in local.cleaned_paths_private :
    path => {
      list_all    = "http://${aws_lb.main_private.dns_name}/${path}"
      get_by_id   = "http://${aws_lb.main_private.dns_name}/${path}/{id}"
      with_filter = "http://${aws_lb.main_private.dns_name}/${path}?request=search_term"
    }
  }
}

output "curl_test_examples_private" {
  description = "Example curl commands for testing from within VPC (EC2, VPN, or Direct Connect)"
  value = {
    "basic_get"        = "curl -H 'Host: example.com' http://${aws_lb.main_private.dns_name}/items"
    "malicious_host"   = "curl -H 'Host: malicious-site.com' http://${aws_lb.main_private.dns_name}/products/food/beverages"
    "post_with_host"   = "curl -X POST -H 'Host: test.com' -H 'Content-Type: application/json' -d '{\"name\":\"test item\"}' http://${aws_lb.main_private.dns_name}/items"
  }
}

output "access_instructions" {
  description = "How to access the internal ALB"
  value = <<-EOT
    This is an INTERNAL ALB in private subnets. To access it, you need one of:

    1. EC2 Instance in the same VPC
       - Launch EC2 in one of the private subnets
       - Run curl commands from there

    2. VPN Connection
       - Set up AWS Client VPN or Site-to-Site VPN
       - Connect to VPC via VPN

    3. Direct Connect
       - If your organization has AWS Direct Connect
       - Access via private connection

    4. VPC Peering
       - Peer with another VPC that has VPN/bastion access

    5. Bastion Host
       - Launch bastion/jump host in a public subnet (if you add one)
       - SSH tunnel through bastion to access internal ALB

    The ALB is NOT accessible from the internet.
    DNS Name: ${aws_lb.main_private.dns_name}
  EOT
}