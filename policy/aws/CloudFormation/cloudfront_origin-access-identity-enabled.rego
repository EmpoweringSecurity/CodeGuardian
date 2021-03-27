package main

# __rego__metadoc__ := {
#   "id": "cloudfront_origin-access-identity-enabled",
#   "title": "CloudFront distributions should have origin access identity enabled",
#   "description": "This control checks whether an Amazon CloudFront distribution with Amazon S3 Origin type has Origin Access Identity (OAI) configured. The control fails if OAI is not configured.",
#   "custom": {
#     "controls": {
#       "AWS Foundational Security Best Practices": [
#         "CloudFront.2"
#       ]
#     }
#   }
# }

deny[msg] {
    input.Resources[_].Type == "AWS::CloudFront::Distribution" 
    input.Resources[_].Properties.DistributionConfig.Origins[_].S3OriginConfig != null
    input.Resources[_].Properties.DistributionConfig.Origins[_].S3OriginConfig.OriginAccessIdentity == null
    msg = "CloudFront distributions should have origin access identity enabled."
}