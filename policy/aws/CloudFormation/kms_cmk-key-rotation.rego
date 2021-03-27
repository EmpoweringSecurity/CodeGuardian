package main

# __rego__metadoc__ := {
#   "id": "kms_cmk-key-rotation",
#   "title": "Ensure KMS CMKs key rotation is enabled",
#   "description": "Rotating encryption keys helps reduce the potential impact of a compromised key as data encrypted with a new key cannot be accessed with a previous key that may have been exposed.",
#   "custom": {
#     "controls": {
#       "CIS": [
#         "CIS_2-8"
#       ]
#     },
#     "severity": "Medium"
#   }
# }

deny[msg] {
    input.Resources[_].Type == "AWS::KMS::Key" 
    input.Resources[_].Properties.EnableKeyRotation == false 
    msg = "Ensure KMS CMKs key rotation is enabled."
}