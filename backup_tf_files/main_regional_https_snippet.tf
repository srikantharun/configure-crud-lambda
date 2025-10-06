# Add this variable to your variables file
variable "acm_certificate_arn" {
  description = "ACM certificate ARN for HTTPS listener"
  type        = string
  default     = "" # Set via terraform.tfvars or environment variable
}

# Add this to main_regional.tf (uncomment the existing HTTPS listener section)
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.lambda.arn
  }
}

# Optional: Redirect HTTP to HTTPS
resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.main.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# Update outputs for HTTPS
output "alb_https_endpoint_examples" {
  description = "HTTPS endpoint examples"
  value = {
    for path in var.uri_path_var :
    path => {
      list_all    = "https://${aws_lb.main.dns_name}/${path}"
      get_by_id   = "https://${aws_lb.main.dns_name}/${path}/{id}"
      with_filter = "https://${aws_lb.main.dns_name}/${path}?request=search_term"
    }
  }
}

# Route53 Record (if you manage DNS in Route53)
# resource "aws_route53_record" "alb" {
#   zone_id = var.route53_zone_id  # Your hosted zone ID
#   name    = "testpocalb.yourcompany.com"
#   type    = "A"
#
#   alias {
#     name                   = aws_lb.main.dns_name
#     zone_id                = aws_lb.main.zone_id
#     evaluate_target_health = true
#   }
# }