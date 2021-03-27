package main

# __rego__metadoc__ := {
#   "id": "cloudfront_view-policy-https",
#   "title": "CloudFront distributions should require encryption in transit",
#   "description": "This control checks whether an Amazon CloudFront distribution requires viewers to use HTTPS directly or whether it uses redirection. The control fails if ViewerProtocolPolicy is set to allow-all for defaultCacheBehavior or for cacheBehaviors.",
#   "custom": {
#     "controls": {
#       "AWS Foundational Security Best Practices": [
#         "CloudFront.3"
#       ]
#     }
#   }
# }

deny[msg] {
    input.Resources[_].Type == "AWS::CloudFront::Distribution" 
    input.Resources[_].Properties.DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy != "allow-all"
    msg = "CloudFront distributions should require encryption in transit, check default cache behaviour."
}

deny[msg] {
    input.Resources[_].Type == "AWS::CloudFront::Distribution" 
    input.Resources[_].Properties.DistributionConfig.CacheBehaviors[_].ViewerProtocolPolicy != "allow-all"
    msg = "CloudFront distributions should require encryption in transit, check cache behaviours."
}