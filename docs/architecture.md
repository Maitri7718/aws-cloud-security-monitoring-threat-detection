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
6. Incident Reporting
7. Security Recommendations

## Initial Detection Scenarios
- Repeated failed authentication attempts
- Console login without MFA
- IAM policy modifications
- Access key creation
- Unusual API activity
- Activity from unfamiliar source IP addresses

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
Generate structured security findings, severity classifications,
incident evidence and remediation recommendations.
