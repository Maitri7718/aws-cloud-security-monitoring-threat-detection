# AWS Cloud Security Monitoring & Threat Detection

## Project Objective
Build a Python-based security monitoring prototype that analyzes
synthetic CloudTrail-style JSON events and identifies potentially
suspicious AWS activity.

## Data Source
Synthetic CloudTrail-style JSON events.
No live AWS account connection is required.

## Processing Pipeline
1. Event Parser
2. Event Normalizer
3. Detection Engine
4. Severity Classification
5. Alert Generator
6. Incident Investigation and Evidence Timeline
7. Security Report Generation
8. Security Recommendations

## Implemented Detection Rules

| Rule ID | Detection Scenario | Project Severity |
|---|---|---|
| IAM-001 | IAM inline policy modification | HIGH |
| IAM-002 | IAM access key creation | HIGH |
| IAM-003 | IAM login profile deletion | MEDIUM |
| AUTH-001 | Five or more failed console logins within five minutes for the same user | HIGH |

Severity classifications are defined by this project.
They are not official AWS severity ratings.

## Future Enhancement Scenarios
- Console login without MFA detection
- Unusual API activity detection
- Activity from unfamiliar source IP addresses

These scenarios are not currently implemented detection rules.

## Investigation and Reporting
- Chronological evidence timeline
- Event correlation by username
- Evidence-based investigation summaries
- Investigation status requiring further verification
- Structured JSON security reports
- Remediation recommendations

## Technology Stack
- Python 3.13
- JSON
- pytest
- Git and GitHub
- Kali Linux

## Security and Cost Boundaries
- Synthetic data only
- No AWS API calls
- No live IAM modifications
- No billable AWS resources
- Findings are indicators requiring investigation,
  not automatic proof of compromise.

## Project Outcome
Generate structured security findings, project-defined severity
classifications, local alerts, incident evidence timelines,
investigation summaries and remediation recommendations.

This project is a local simulation prototype, not a deployed
AWS monitoring integration.
