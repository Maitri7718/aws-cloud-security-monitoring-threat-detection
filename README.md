# AWS Cloud Security Monitoring & Threat Detection

A Python-based cloud security monitoring prototype that analyzes
synthetic CloudTrail-style JSON events, detects suspicious IAM and
authentication activity, correlates evidence, and generates structured
security reports.

> **Project type:** Local security monitoring simulation
> **Environment:** Kali Linux
> **AWS integration:** None — synthetic data only

## Project Overview

This project demonstrates a local security monitoring and investigation
workflow inspired by AWS cloud security services and concepts.

It processes synthetic CloudTrail-style events through a detection
pipeline, generates security findings and alerts, builds an evidence
timeline, and produces a structured JSON report with remediation
recommendations.

The project does not connect to an AWS account or deploy AWS resources.

## Key Features

- CloudTrail-style JSON event parsing and normalization
- Detection of suspicious IAM activity
- Repeated failed console login detection
- Project-defined severity classification
- Structured local alert generation
- Chronological incident evidence timeline
- Event correlation by username
- Evidence-based investigation summaries
- JSON security report generation
- Remediation recommendations
- Automated unit and integration testing

## Implemented Detection Rules

| Rule ID | Detection | Severity |
|---|---|---|
| IAM-001 | IAM inline policy modification | HIGH |
| IAM-002 | IAM access key creation | HIGH |
| IAM-003 | IAM login profile deletion | MEDIUM |
| AUTH-001 | Five or more failed console logins within five minutes for the same user | HIGH |

Severity classifications are project-defined and are not official
AWS severity ratings.

## Architecture

Synthetic CloudTrail-style JSON Events
↓
Event Parser
↓
Event Normalizer
↓
Detection Engine
↓
Severity Classifier
↓
Alert Generator
↓
Incident Timeline and Investigation
↓
JSON Security Report and Remediation Recommendations

## Technology Stack

- Python 3.13
- JSON
- pytest
- Git
- GitHub
- Kali Linux

## Project Structure

```text
aws-cloud-security-monitoring-threat-detection/
├── docs/
│   └── architecture.md
├── sample_data/
│   └── events/
├── src/
│   ├── event_parser.py
│   ├── event_normalizer.py
│   ├── detection_engine.py
│   ├── pattern_detector.py
│   ├── severity_classifier.py
│   ├── alert_generator.py
│   ├── incident_timeline.py
│   ├── event_correlator.py
│   ├── investigation_analysis.py
│   ├── remediation_recommender.py
│   ├── report_generator.py
│   └── main.py
├── tests/
├── .gitignore
├── requirements.txt
└── README.md
