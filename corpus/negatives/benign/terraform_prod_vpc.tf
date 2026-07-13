# Production VPC. We use three availability zones because a single-AZ outage must not
# take the service down, and we size the NAT gateways per-AZ to avoid cross-AZ data
# charges. Private subnets hold the app tier so that the databases are never routable
# from the internet.

resource "aws_vpc" "prod" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_hostnames = true # needed so RDS endpoints resolve inside the VPC
}

# One private subnet per AZ. We reserve the high /20 range for future expansion.
resource "aws_subnet" "private" {
  for_each          = toset(["us-east-1a", "us-east-1b", "us-east-1c"])
  vpc_id            = aws_vpc.prod.id
  availability_zone = each.value
  cidr_block        = cidrsubnet(aws_vpc.prod.cidr_block, 4, index(local.azs, each.value))
}

# Flow logs to S3 for audit, in order to satisfy the SOC2 network-monitoring control.
resource "aws_flow_log" "prod" {
  vpc_id          = aws_vpc.prod.id
  traffic_type    = "ALL"
  log_destination = aws_s3_bucket.flow_logs.arn
}
