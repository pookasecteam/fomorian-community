# Office 365 Sigma Rules for BEC Detection

Sigma rules for detecting Business Email Compromise (BEC) attacks in Office 365 and Azure AD logs.

## Rules Included

| Rule | Technique | Level | Description |
|------|-----------|-------|-------------|
| o365_oauth_consent_phishing | T1566.002 | Medium | OAuth application consent (phishing) |
| o365_impossible_travel | T1078.004 | High | Impossible travel sign-in detection |
| o365_inbox_rule_creation | T1137.005 | High | Suspicious inbox rule creation |
| o365_email_forwarding_external | T1114.003 | High | Email forwarding to external address |
| o365_delegated_permission_grant | T1098.003 | High | Sensitive permission grants to apps |
| o365_mailbox_search | T1087.003 | Medium | Compliance search for financial keywords |
| o365_bulk_email_access | T1114.002 | Medium | Bulk mailbox item access |
| o365_audit_logging_disabled | T1562.008 | Critical | Audit logging disabled |
| o365_security_alert_deletion | T1070.008 | High | Security alert email deletion |
| o365_wire_fraud_email | T1534 | High | Wire fraud email subjects |
| o365_foreign_ip_signin | T1078.004 | Medium | Sign-in from suspicious countries |
| o365_gal_enumeration | T1087.003 | Low | Global Address List enumeration |

## Deployment

### Manual Import

Rules can be converted using sigmac or imported directly if your SIEM supports Sigma format.

## Log Sources Required

These rules require Office 365 and Azure AD logs to be ingested:

- Azure AD Audit Logs (`azure_ad.*` fields)
- Azure AD Sign-in Logs (`azure_ad_signin.*` fields)
- Office 365 Unified Audit Log (`office365.*` fields)

## Field Mappings

| Sigma Field | Fomorian/Wazuh Field |
|-------------|---------------------|
| azure.auditlogs.* | azure_ad.* |
| azure.signinlogs.* | azure_ad_signin.* |
| o365.* | office365.* |

## Testing

Use Fomorian to generate BEC attack scenarios:

```bash
fomorian generate --config ./config --engagement business_email_compromise --inject wazuh
```

## License

MIT
