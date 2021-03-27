package main

# __rego__metadoc__ := {
#   "id": "cloudfront_default-root-object-configured",
#   "title": "CloudFront distributions should have a default root object configured",
#   "description": "This control checks whether an Amazon CloudFront distribution is configured to return a specific object that is the default root object. The control fails if the CloudFront distribution does not have a default root object configured.",
#   "custom": {
#     "controls": {
#       "AWS Foundational Security Best Practices": [
#         "CloudFront.1"
#       ]
#     }
#   }
# }

deny[msg] {
    input.Resources[_].Type == "AWS::CloudFront::Distribution" 
    input.Resources[_].Properties.DistributionConfig.DefaultRootObject == null
    msg = "CloudFront distributions should have a default root object configured."
}