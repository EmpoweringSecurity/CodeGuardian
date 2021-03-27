package main

# __rego__metadoc__ := {
#   "id": "iam-user_policy-attached",
#   "title": "IAM policies should not be attached directly to users",
#   "description": "IAM policies should not be attached to users. Assigning privileges at the group or role level reduces the complexity of access management as the number of users grow. Reducing access management complexity may reduce opportunity for a principal to inadvertently receive or retain excessive privileges.",
#   "custom": {
#     "controls": {
#       "CIS": [
#         "CIS_1-16"
#       ],
#       "NIST": [
#         "NIST-800-53_AC-2 (7)(b)"
#       ]
#     },
#     "severity": "Low"
#   }
# }

deny[msg] {
    input.Resources[_].Type == "AWS::IAM::User" 
    input.Resources[_].Properties.Policies[_] != null 
    msg = "IAM policies should not be attached directly to users."
}

deny[msg] {
    input.Resources[_].Type == "AWS::IAM::User" 
    input.Resources[_].Properties.ManagedPolicyArns[_] != null 
    msg = "IAM managed policies should not be attached directly to users."
}