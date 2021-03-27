package main

# __rego__metadoc__ := {
#   "id": "cloudfront_origin-failover-enabled",
#   "title": "CloudFront distributions should have origin failover configured",
#   "description": "This control checks whether an Amazon CloudFront distribution is configured with an origin group that has two or more origins.",
#   "custom": {
#     "controls": {
#       "AWS Foundational Security Best Practices": [
#         "CloudFront.4"
#       ]
#     }
#   }
# }

deny[msg] {
    input.Resources[_].Type == "AWS::CloudFront::Distribution" 
    input.Resources[_].Properties.DistributionConfig.OriginGroups == null
    msg = "CloudFront distributions should have origin failover configured."
}

deny[msg] {
    input.Resources[_].Type == "AWS::CloudFront::Distribution" 
    input.Resources[_].Properties.DistributionConfig.OriginGroups.Item[_] == null
    msg = "CloudFront distributions should have origin failover configured."
}