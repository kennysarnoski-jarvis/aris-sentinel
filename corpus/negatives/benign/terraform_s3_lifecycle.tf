# Artifact bucket lifecycle.
# We transition build artifacts to infrequent access after 30 days because almost nothing
# is downloaded after the first week, and we expire them at 180 days so that the bucket
# does not grow without bound. Release artifacts are tagged and excluded from expiry.
resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "tier-and-expire"
    status = "Enabled"
    filter { tag { key = "retain", value = "false" } }
    transition { days = 30, storage_class = "STANDARD_IA" }
    expiration { days = 180 }
  }
}
