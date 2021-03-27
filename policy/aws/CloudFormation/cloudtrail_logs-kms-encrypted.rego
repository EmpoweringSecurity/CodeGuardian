package main

# __rego__metadoc__ := {
#   "id": "cloudtrail_logs-kms-encrypted",
#   "title": "CloudTrail logs should be encrypted at rest using KMS CMKs",
#   "description": "CloudTrail logs can be configured to leverage server side encryption (SSE) and KMS customer created master keys (CMK) to further protect CloudTrail logs. It is recommended that CloudTrail be configured to use SSE-KMS.",
#   "custom": {
#     "controls": {
#       "CIS": [
#         "CIS_2-7"
#       ]
#     },
#     "severity": "Medium"
#   }
# }

deny[msg] {
    input.Resources[_].Type == "AWS::CloudTrail::Trail" 
    input.Resources[_].Properties.KMSKeyId == null 
    msg = "CloudTrail logs should be encrypted at rest using KMS CMKs."
}