export default {
  "type": "object",
  "properties": {
    "reasons": {
      "type": "array",
      "items": {
        "$ref": "#/definitions/IPolicyStatementResult"
      }
    },
    "decision": {
      "$ref": "#/definitions/PolicyDecision"
    },
    "errors": {
      "type": "array",
      "items": {
        "type": "string"
      }
    }
  },
  "required": [
    "decision",
    "errors",
    "reasons"
  ],
  "definitions": {
    "IPolicyStatementResult": {
      "type": "object",
      "properties": {
        "policy_id": {
          "type": "string"
        },
        "invoked": {
          "type": "boolean"
        },
        "annotations": {
          "type": "object",
          "additionalProperties": {
            "type": "string"
          }
        }
      },
      "required": [
        "annotations",
        "invoked",
        "policy_id"
      ]
    },
    "PolicyDecision": {
      "enum": [
        "Allow",
        "Deny"
      ],
      "type": "string"
    }
  },
  "$schema": "http://json-schema.org/draft-07/schema#"
}