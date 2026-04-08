# DNS and TLS resources for SENTINEL
#
# Usage:
#   Set var.domain_name to your domain (e.g. "sentinel.example.com").
#   Set var.route53_zone_id to the hosted zone ID for that domain.
#   The ACM certificate will be auto-validated via DNS.
#   An A-alias record will point the domain at the ALB.

variable "domain_name" {
  description = "Primary domain name for the SENTINEL API (e.g. api.sentinel.example.com)"
  type        = string
  default     = ""
}

variable "route53_zone_id" {
  description = "Route53 hosted zone ID for var.domain_name"
  type        = string
  default     = ""
}

# ── ACM Certificate ──────────────────────────────────────────────────────────

resource "aws_acm_certificate" "sentinel_api" {
  count = var.domain_name != "" ? 1 : 0

  domain_name               = var.domain_name
  subject_alternative_names = ["*.${var.domain_name}"]
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name        = "${var.environment}-sentinel-api-cert"
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

# DNS validation records
resource "aws_route53_record" "cert_validation" {
  for_each = var.domain_name != "" ? {
    for dvo in aws_acm_certificate.sentinel_api[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = var.route53_zone_id
}

resource "aws_acm_certificate_validation" "sentinel_api" {
  count = var.domain_name != "" ? 1 : 0

  certificate_arn         = aws_acm_certificate.sentinel_api[0].arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}

# ── HTTPS Listener uses managed cert when available ──────────────────────────

# If var.ssl_certificate_arn is provided directly, it takes precedence.
# Otherwise the ACM cert above is used.
locals {
  effective_certificate_arn = (
    var.ssl_certificate_arn != ""
    ? var.ssl_certificate_arn
    : (var.domain_name != "" ? aws_acm_certificate.sentinel_api[0].arn : "")
  )
}

# ── Route53 A-record pointing domain at ALB ──────────────────────────────────

resource "aws_route53_record" "sentinel_api" {
  count = var.domain_name != "" && var.route53_zone_id != "" ? 1 : 0

  zone_id = var.route53_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_lb.sentinel_api_lb.dns_name
    zone_id                = aws_lb.sentinel_api_lb.zone_id
    evaluate_target_health = true
  }
}
