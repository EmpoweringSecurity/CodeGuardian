package main

# __rego__metadoc__ := {
#   "id": "iam-policy_admin-privileges",
#   "title": "IAM policies should not allow full '*:*' administrative privilege",
#   "description": "It's recommended and considered a standard security advice to grant least privilege—that is, granting only the permissions required to perform a task. Determine what users need to do and then craft policies that let the users perform only those tasks, instead of allowing full administrative privileges.",
#   "custom": {
#     "controls": {
#       "CIS": [
#         "CIS_1-22"
#       ]
#     },
#     "severity": "Low"
#   }
# }

deny[msg] {
    input.Resources[_].Properties.Policies[_].PolicyDocument.Statement[_].Action[_] == "*"
    input.Resources[_].Properties.Policies[_].PolicyDocument.Statement[_].Resource == "*"
    input.Resources[_].Properties.Policies[_].PolicyDocument.Statement[_].Effect == "Allow"
    msg = "IAM policies should not allow full '*:*' administrative privileges"
}