package main

# __rego__metadoc__ := {
#   "id": "cloudtrail_log-file-validation",
#   "title": "CloudTrail log file validation should be enabled",
#   "description": "CloudTrail log file validation should be enabled. It is recommended that file validation be enabled on all CloudTrail logs because it provides additional integrity checking of the log data.",
#   "custom": {
#     "controls": {
#       "CIS": [
#         "CIS_2-1"
#       ]
#     },
#     "severity": "Medium"
#   }
# }

deny[msg] {
    input.Resources[_].Type == "AWS::CloudTrail::Trail" 
    input.Resources[_].Properties.EnableLogFileValidation == false 
    msg = "CloudTrail log file validation should be enabled."
}