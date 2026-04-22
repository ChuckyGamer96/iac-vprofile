resource "aws_s3_bucket" "r59" {
  bucket = "ahmed-eks-dataset-r59-2026"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "r59_enc" {
  bucket = aws_s3_bucket.r59.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}