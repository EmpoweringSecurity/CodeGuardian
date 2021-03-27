package main

# __rego__metadoc__ := {
#   "id": "cloudtrail_multi-region",
#   "title": "CloudTrail multi region should be enabled",
#   "description": "CloudTrail should have a trail that is multi-region. AWS CloudTrail is a web service that records AWS API calls for your account and delivers log files to you. The recorded information includes the identity of the API caller, the time of the API call, the source IP address of the API caller, the request parameters, and the response elements returned by the AWS service change tracking, and compliance auditing.",
#   "custom": {
#     "controls": {
#       "CIS": [
#         "CIS_2-2"
#       ],
#       "NIST": [
#         "NIST-800-53_AC-2g",
#         "NIST-800-53_AC-6 (9)"
#       ]
#     },
#     "severity": "Medium"
#   }
# }

deny[msg] {
    input.Resources[_].Type == "AWS::CloudTrail::Trail" 
    input.Resources[_].Properties.IsMultiRegionTrail == false 
    msg = "CloudTrail multi region should be enabled."
}