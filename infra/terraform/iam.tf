# Role assumed by the API pods and remediation workers via IRSA
resource "aws_iam_role" "remediation" {
  name = "platform-remediation"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "*" }
        Action    = "sts:AssumeRole"
      },
      {
        Effect    = "Allow"
        Principal = { Federated = "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com" }
        Action    = "sts:AssumeRoleWithWebIdentity"
      }
    ]
  })
}

resource "aws_iam_role_policy" "remediation" {
  name = "remediation-actions"
  role = aws_iam_role.remediation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Containment"
        Effect   = "Allow"
        Action   = ["ec2:*", "iam:*", "secretsmanager:*", "wafv2:*"]
        Resource = "*"
      },
      {
        Sid      = "Evidence"
        Effect   = "Allow"
        Action   = ["s3:*"]
        Resource = "*"
      },
      {
        Sid      = "CrossAccount"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = "arn:aws:iam::*:role/*"
      }
    ]
  })
}

# Template the customer deploys into their account to let us remediate
output "tenant_trust_policy" {
  value = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = aws_iam_role.remediation.arn }
      Action    = "sts:AssumeRole"
    }]
  })
}
