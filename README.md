# Simple CRUD API with Lambda

This repository contains Terraform configurations for deploying a serverless CRUD API with AWS Lambda, API Gateway, and either CloudFront or Application Load Balancer (ALB).

## Features

- ✅ Full CRUD operations (Create, Read, Update, Delete)
- ✅ Query parameter support for filtering and searching
- ✅ Bulk operations
- ✅ Two deployment options: CloudFront or ALB
- ✅ CORS enabled
- ✅ Comprehensive test scripts

## Query Parameter Features

### GET `/items`
- `?request=<term>` - Search items by name/description
- `?<field>=<value>` - Filter by any custom field (e.g., `?category=electronics`)

### POST `/items`
- `?request=bulk` - Create multiple items in one request
  ```json
  {"items": [{"name": "Item1"}, {"name": "Item2"}]}
  ```

### PUT `/items/{id}`
- `?request=replace` - Replace entire item (vs. default merge update)

### DELETE `/items`
- `?request=all` - Delete all items at once

## Architecture Options

### Option 1: CloudFront + API Gateway
```
Client → CloudFront → API Gateway → Lambda
```

**Files:**
- `main.tf` - CloudFront-based deployment
- `variables.tf` - Configuration variables
- `test_api.sh` - Test script for CloudFront

**Benefits:**
- Global edge caching
- DDoS protection
- Better for global distribution

### Option 2: Application Load Balancer
```
Client → ALB → Lambda
```

**Files:**
- `main_alb.tf` - ALB-based deployment
- `variables_alb.tf` - ALB configuration variables
- `test_api_alb.sh` - Test script for ALB

**Benefits:**
- Lower latency
- Direct Lambda integration
- Cost-effective
- Better for VPC workloads

## Prerequisites

- Terraform >= 1.0
- AWS CLI configured with appropriate credentials
- Python 3.x (for test scripts)
- curl
- bash

## Deployment

### CloudFront Deployment

```bash
# Initialize Terraform
terraform init

# Plan deployment
terraform plan

# Apply configuration
terraform apply

# Test the API
chmod +x test_api.sh
./test_api.sh
```

### ALB Deployment

```bash
# Initialize Terraform
terraform init

# Plan deployment (using ALB files)
terraform plan -var-file="variables_alb.tf"

# Apply configuration
terraform apply

# Test the API
chmod +x test_api_alb.sh
./test_api_alb.sh
```

## API Usage Examples

### Create an item
```bash
curl -X POST "https://your-endpoint/items" \
  -H "Content-Type: application/json" \
  -d '{"name": "Laptop", "description": "MacBook Pro", "category": "electronics", "price": 1999}'
```

### Get all items
```bash
curl "https://your-endpoint/items"
```

### Search items
```bash
curl "https://your-endpoint/items?request=laptop"
```

### Filter by category
```bash
curl "https://your-endpoint/items?category=electronics"
```

### Update item (merge)
```bash
curl -X PUT "https://your-endpoint/items/{id}" \
  -H "Content-Type: application/json" \
  -d '{"name": "Updated Name"}'
```

### Update item (replace)
```bash
curl -X PUT "https://your-endpoint/items/{id}?request=replace" \
  -H "Content-Type: application/json" \
  -d '{"name": "New Name", "description": "New Description"}'
```

### Bulk create
```bash
curl -X POST "https://your-endpoint/items?request=bulk" \
  -H "Content-Type: application/json" \
  -d '{"items": [{"name": "Item1"}, {"name": "Item2"}, {"name": "Item3"}]}'
```

### Delete item
```bash
curl -X DELETE "https://your-endpoint/items/{id}"
```

### Delete all items
```bash
curl -X DELETE "https://your-endpoint/items?request=all"
```

## Configuration Variables

### Common Variables (both deployments)

| Variable | Default | Description |
|----------|---------|-------------|
| `aws_region` | us-east-1 | AWS region for deployment |
| `project_name` | simple-crud-api | Project name for resources |
| `environment` | dev | Environment name |
| `api_stage_name` | prod | API Gateway stage |
| `lambda_runtime` | python3.9 | Lambda runtime version |
| `lambda_timeout` | 30 | Lambda timeout in seconds |

### CloudFront Specific

| Variable | Default | Description |
|----------|---------|-------------|
| `cloudfront_price_class` | PriceClass_100 | CloudFront price class |

### ALB Specific

| Variable | Default | Description |
|----------|---------|-------------|
| `alb_enable_deletion_protection` | false | Enable ALB deletion protection |
| `alb_idle_timeout` | 60 | ALB idle timeout in seconds |
| `health_check_interval` | 30 | Health check interval |

## Outputs

### CloudFront Deployment
- `api_gateway_url` - Direct API Gateway URL
- `cloudfront_url` - CloudFront distribution URL
- `lambda_function_name` - Lambda function name
- `cloudfront_distribution_id` - CloudFront distribution ID

### ALB Deployment
- `api_gateway_url` - Direct API Gateway URL
- `alb_url` - Application Load Balancer URL
- `alb_dns_name` - ALB DNS name
- `lambda_function_name` - Lambda function name
- `alb_arn` - ALB ARN

## Testing

Both deployment options include comprehensive test scripts:

```bash
# CloudFront tests
./test_api.sh

# ALB tests
./test_api_alb.sh
```

The test scripts include:
- 23 automated tests
- Query parameter validation
- Error handling tests
- Bulk operation tests
- Color-coded output

## Production Considerations

⚠️ **This is a development/demo configuration**

For production use, consider:

1. **Replace in-memory storage** with DynamoDB or RDS
2. **Add authentication** (API Gateway authorizers, Cognito)
3. **Enable CloudFront/ALB access logs**
4. **Add custom domain** with Route53
5. **Enable HTTPS** with ACM certificates
6. **Add rate limiting** and throttling
7. **Implement monitoring** with CloudWatch
8. **Add backup strategy** for data
9. **Enable deletion protection** for production resources
10. **Use separate AWS accounts** for dev/staging/prod

## Cost Estimation

### CloudFront Deployment
- Lambda: Free tier (1M requests/month)
- API Gateway: ~$3.50 per million requests
- CloudFront: ~$0.085 per GB + requests
- Estimated: ~$5-20/month for low traffic

### ALB Deployment
- Lambda: Free tier (1M requests/month)
- API Gateway: ~$3.50 per million requests
- ALB: ~$16/month + $0.008 per LCU-hour
- Estimated: ~$20-30/month for low traffic

## Cleanup

To destroy all resources:

```bash
terraform destroy
```

⚠️ This will delete all resources and data.

## License

MIT License

## Contributing

Pull requests are welcome! Please ensure:
1. Code follows Terraform best practices
2. All tests pass
3. Documentation is updated
4. Commit messages are clear

## Support

For issues or questions:
1. Check existing GitHub issues
2. Review AWS documentation
3. Create a new issue with detailed information

## Roadmap

- [ ] Add DynamoDB integration
- [ ] Implement authentication
- [ ] Add pagination support
- [ ] WebSocket support (ALB version)
- [ ] Custom domain configuration
- [ ] Automated backup strategy
- [ ] Monitoring dashboards
- [ ] CI/CD pipeline examples

  Key Features:

  1. Private Subnets Only

  - ✅ No Internet Gateway
  - ✅ Internal ALB (internal = true)
  - ✅ Only accessible within VPC or via VPN/Direct Connect

  2. VPC Endpoints (No NAT Gateway needed)

  - Lambda Endpoint: Allows Lambda execution without internet
  - CloudWatch Logs Endpoint: For Lambda logging without internet
  - Both use Interface endpoints with private DNS

  3. Security Configuration

  - ALB accepts traffic from:
    - Corporate CIDR blocks (configurable via allowed_cidr_blocks)
    - VPC internal traffic
    - Default: Private RFC1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)

  4. Access Methods

  You can access this internal ALB through:

  Option 1: EC2 in same VPC
  # Launch EC2 in private subnet, then:
  curl -H 'Host: malicious.com' http://internal-alb-dns/items

  Option 2: VPN Connection
  # Connect to AWS VPN, then:
  curl -H 'Host: test.com' http://internal-alb-dns/products/food/beverages

  Option 3: Direct Connect
  - If your organization has AWS Direct Connect

  Option 4: Systems Manager Session Manager
  # No SSH needed, use SSM:
  aws ssm start-session --target i-1234567890abcdef0
  curl http://internal-alb-dns/items

  5. Cost Savings vs Public ALB

  - ✅ No NAT Gateway costs ($0.045/hour + data transfer)
  - ✅ No Internet Gateway data transfer costs
  - ✅ VPC Endpoints: $0.01/hour per endpoint ($14/month total)
  - ✅ More secure for internal testing

  6. Customization Variables

  Add to your variables_tf_file.txt or terraform.tfvars:
  # Set to false if you want internet-facing ALB
  alb_internal = true

  # Your organization's CIDR blocks
  allowed_cidr_blocks = [
    "10.0.0.0/8",      # Your corporate network
    "172.16.0.0/12"    # Your VPN range
  ]

  What to Request from Your Organization:

  1. VPC/Network Access:
    - VPN credentials or Direct Connect access
    - Or permission to launch EC2 for testing
  2. CIDR Blocks:
    - "What are our corporate network CIDR ranges?"
    - "What CIDR ranges does our VPN use?"
  3. ACM Certificate (for HTTPS):
    - "Internal certificate for testpocalb.internal.yourcompany.com"
    - Or use existing wildcard cert

  This setup is perfect for WAF testing within your organization without exposing endpoints to the internet!
