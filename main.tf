terraform {
	required_providers {
		aws = {
			source = "hashicorp/aws"
			version = "~> 3.27"
		}
	}

	required_version = ">= 0.14.9"
}

provider "aws" {
	profile = "default"
	region = "us-west-2"
}

resource "aws_s3_bucket" "s3_user_file_store" {
	bucket = "${terraform.workspace}-user-file-store"
	acl = "private"

	lifecycle_rule {
		id = "cost saving"
		enabled = true

		prefix = ""

		transition {
			days = 30
			storage_class = "STANDARD_IA"
		}

		transition {
			days = 365
			storage_class = "GLACIER"
		}

		expiration {
			days = 730
		}
	}

	versioning {
		enabled = true
	}
}

resource "aws_s3_bucket_public_access_block" "block_all_public_access" {
  bucket = aws_s3_bucket.s3_user_file_store.id

  block_public_acls   = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}

resource "aws_cloudfront_distribution" "cf_user_file_store_cache" {
	origin {
		domain_name = aws_s3_bucket.s3_user_file_store.bucket_regional_domain_name
		origin_id = aws_s3_bucket.s3_user_file_store.id

		s3_origin_config {
		  origin_access_identity = aws_cloudfront_origin_access_identity.cf_user_file_store_oai.cloudfront_access_identity_path
		}
	}

	enabled = true
	is_ipv6_enabled = true
	comment = "CF Distro for User File Storage Cache"

	default_cache_behavior {
		trusted_key_groups = [aws_cloudfront_key_group.file_store_keygroup.id]

		allowed_methods = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
		cached_methods = ["GET", "HEAD"]
		target_origin_id = aws_s3_bucket.s3_user_file_store.id

		viewer_protocol_policy = "allow-all"
		min_ttl                = 0
    	default_ttl            = 0 
    	max_ttl                = 0 

		forwarded_values {
		  query_string = false

		  cookies {
			  forward = "none"
		  }
		}
	}

	tags = {
		Environment = "${terraform.workspace}"
	}

	restrictions {
	  geo_restriction {
		  restriction_type = "whitelist"
		  locations = ["US"]
	  }
	}

	viewer_certificate {
	  cloudfront_default_certificate = true
	}
}

resource "aws_cloudfront_origin_access_identity" "cf_user_file_store_oai" {
	comment = "origin access identity for s3_user_file_store bucket"
}

data "aws_iam_role" "file_management_lambdas_role" {
	name = "file-management-api-dev-us-west-2-lambdaRole"
}

data "aws_iam_policy_document" "user_file_store_s3_policy" {
	statement {
		actions = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
		resources = ["${aws_s3_bucket.s3_user_file_store.arn}/*"] 

		principals {
			type = "AWS"
			identifiers = [
				aws_cloudfront_origin_access_identity.cf_user_file_store_oai.iam_arn,
				data.aws_iam_role.file_management_lambdas_role.arn
			]
		}
	}
}

resource "aws_s3_bucket_policy" "s3_user_file_store_policy_attach" {
	bucket = aws_s3_bucket.s3_user_file_store.id
	policy = data.aws_iam_policy_document.user_file_store_s3_policy.json
}

resource "aws_cloudfront_public_key" "file_management_api_signed_pubkey" {
	comment = "public key for signed URLs from CF for file store"
	encoded_key = file("keys/cf_file_management_public_key.pem")
	name = "${terraform.workspace}-file-store-public-key"
}

resource "aws_cloudfront_key_group" "file_store_keygroup" {
	comment = "file store trusted keygroup"
	items = [aws_cloudfront_public_key.file_management_api_signed_pubkey.id]
	name = "${terraform.workspace}-file-store-keygroup"
}

resource "aws_secretsmanager_secret" "file_management_private_key" {
	name = "${terraform.workspace}-file-management-private-key"
}

resource "aws_secretsmanager_secret" "file_management_public_id" {
	name = "${terraform.workspace}-file-management-public-id"
}

resource "aws_dynamodb_table" "files_table" {
	name = "${terraform.workspace}-files"
	billing_mode = "PROVISIONED"
	read_capacity = 1
	write_capacity = 1
	hash_key = "FileID"

	attribute {
		name = "FileID"
		type = "S"
	}
	
	attribute {
		name = "UserID"
		type = "S"
	}

	global_secondary_index {
		name = "FileIDIndex"
		hash_key = "FileID"
		write_capacity = 1
		read_capacity = 1
		projection_type = "KEYS_ONLY"
	}

	global_secondary_index {
	  name = "UserIDIndex"
	  hash_key = "UserID"
	  write_capacity = 1
	  read_capacity = 1
	  projection_type = "KEYS_ONLY"
	}

	tags = {
		Name = "${terraform.workspace}-files-dynamodb-table"
		Environment = "${terraform.workspace}"
	}
}

#################### Front End Resources #########################3
resource "aws_s3_bucket" "s3_cloud_drive_front_end" {
	bucket = "${terraform.workspace}-cloud-drive-app"
	acl = "private"

	versioning {
		enabled = true
	}
}

resource "aws_s3_bucket_public_access_block" "block_all_public_access_cloud_drive_front_end" {
  bucket = aws_s3_bucket.s3_cloud_drive_front_end.id

  block_public_acls   = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}

resource "aws_cloudfront_distribution" "cf_cloud_drive_front_end" {
	origin {
		domain_name = aws_s3_bucket.s3_cloud_drive_front_end.bucket_regional_domain_name
		origin_id = aws_s3_bucket.s3_cloud_drive_front_end.id

		s3_origin_config {
		  origin_access_identity = aws_cloudfront_origin_access_identity.cf_cloud_drive_front_end_oai.cloudfront_access_identity_path
		}
	}

	default_root_object = "index.html"

	enabled = true
	is_ipv6_enabled = true
	comment = "CF Distro for User File Storage Cache"

	default_cache_behavior {
		allowed_methods = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
		cached_methods = ["GET", "HEAD"]
		target_origin_id = aws_s3_bucket.s3_cloud_drive_front_end.id

		viewer_protocol_policy = "allow-all"
		min_ttl                = 0
    	default_ttl            = 0 
    	max_ttl                = 0 

		forwarded_values {
		  query_string = false

		  cookies {
			  forward = "none"
		  }
		}
	}

	tags = {
		Environment = "${terraform.workspace}"
	}

	restrictions {
	  geo_restriction {
		  restriction_type = "whitelist"
		  locations = ["US"]
	  }
	}

	viewer_certificate {
	  cloudfront_default_certificate = true
	}
}

resource "aws_cloudfront_origin_access_identity" "cf_cloud_drive_front_end_oai" {
	comment = "origin access identity for cloud_drive_front_end bucket"
}

data "aws_iam_policy_document" "cloud_drive_front_end_s3_policy" {
	statement {
		actions = ["s3:GetObject"]
		resources = ["${aws_s3_bucket.s3_cloud_drive_front_end.arn}/*"] 

		principals {
			type = "AWS"
			identifiers = [
				aws_cloudfront_origin_access_identity.cf_cloud_drive_front_end_oai.iam_arn
			]
		}
	}
}

resource "aws_s3_bucket_policy" "s3_cloud_drive_front_end_policy_attach" {
	bucket = aws_s3_bucket.s3_cloud_drive_front_end.id
	policy = data.aws_iam_policy_document.cloud_drive_front_end_s3_policy.json
}