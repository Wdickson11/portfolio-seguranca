# API Threat Monitoring & Auto-Response on AWS

Serverless security layer that inspects API traffic in real time, blocks malicious requests dynamically, and alerts the security team automatically — built to close a gap identified during a third-party security audit (unmonitored, unprotected APIs handling sensitive data).

## Problem

APIs are the primary integration surface between internal and external systems, but they're also a growing attack surface: data leakage, DoS attempts, and no centralized visibility into traffic, abuse, or compliance posture (LGPD / PCI DSS). An internal audit flagged this gap directly — no monitoring, no automated response, no auditable trail.

## Architecture

```
Client → API Gateway (REST, regional) → Lambda (MonitoringAPI)
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    ▼                         ▼                         ▼
              AWS WAF (Web ACL)         Amazon SNS               Amazon CloudWatch
         dynamic IP Set + managed     real-time alerts to      centralized logs, custom
         rules (SQLi, XSS, rate      security team (email)    metrics, alarms (5xx spikes,
         limit 2000 req/5min/IP)                                WAF block rate, Lambda errors)
```

**Flow:** every request hits API Gateway → Lambda inspects source IP, User-Agent, path and payload → if a malicious pattern is detected (known bad IP, malicious UA, SQLi-like payload), Lambda updates the WAF IP Set in real time, blocking that origin for all future requests, and publishes an alert via SNS. Every event — clean or blocked — is logged to CloudWatch for full traceability.

## What's implemented

- **API Gateway (REST, regional)** — public endpoint, Lambda proxy integration for full HTTP event passthrough.
- **Lambda (`MonitoringAPI`, Python 3.13)** — inspects each request, runs threat-intel checks (suspicious IP / UA / payload patterns), triggers WAF updates and SNS alerts. Returns 403 on block, 200 on pass, 500 on controlled exception. Configuration (WAF region, IP Set ID, SNS topic ARN) is externalized via environment variables — no hardcoded values.
- **AWS WAF (Web ACL, regional)** — AWS managed rule groups (Common Rule Set, SQLi, Admin Protection) + a custom rate-based rule (2,000 requests / 5 min per source IP) + a dynamic IP Set updated programmatically by Lambda.
- **CloudWatch** — dedicated log groups per endpoint, custom metrics for error count and latency, Logs Insights queries for event correlation, and alarms on: 5xx error spikes, high WAF block rate, and Lambda execution errors.
- **SNS** — alert topic wired into CloudWatch alarms and directly into the Lambda's threat-detection path, notifying the security team by email in near real time.

## Validation

Instead of just describing the design, I ran controlled attack simulations against the deployed stack to prove the automated response actually works:

**SQL injection attempt, before WAF rules active:**
```
$ curl -X POST https://<api-id>.execute-api.us-east-1.amazonaws.com/default/monitoring \
    -d "id=1' OR '1'='1" --ssl-no-revoke
{"message": "API called successfully", "log": {...}}   # request passed through
```

**Same request, after WAF managed rules + custom SQLi protection active:**
```
$ curl -X POST https://<api-id>.execute-api.us-east-1.amazonaws.com/default/monitoring \
    -d "id=1' OR '1'='1" --ssl-no-revoke
{"message": "Forbidden"}   # blocked, HTTP 403
```

**Rate-limit test:** flooded the endpoint with >2,000 requests in under 5 minutes from a single source — WAF rate-based rule triggered, source blocked, CloudWatch alarm fired, SNS alert delivered to the security inbox within seconds.

**Dynamic IP blocking:** simulated requests from a flagged IP — Lambda detected the pattern, updated the WAF IP Set programmatically, and confirmed the same source was blocked on the next request without any manual intervention.

All three scenarios are logged end-to-end in CloudWatch, so every block, every alert, and every rule change is traceable — which is the actual point: not just stopping the request, but proving it happened and being able to show that proof in an audit.

## Results

- Malicious traffic (SQLi payloads, rate-limit abuse, flagged IPs) blocked automatically, with zero manual intervention after deployment.
- Full request-to-response traceability via CloudWatch — supports LGPD/PCI DSS audit requirements instead of just claiming compliance.
- Mean time to alert: seconds (SNS fires directly off the CloudWatch alarm and off the Lambda's own detection path).
- Entire stack built and tested on AWS Free Tier — zero infrastructure cost during development.

## Stack

`AWS API Gateway` · `AWS Lambda (Python)` · `AWS WAF` · `Amazon CloudWatch (Logs, Metrics, Alarms, Logs Insights)` · `Amazon SNS` · `IAM`

## Next steps (roadmap)

- Expand WAF custom rules to cover brute force and endpoint enumeration patterns.
- Feed CloudWatch/SNS events into a corporate SIEM/SOAR for centralized correlation.
- Restrict direct API Gateway access to CloudFront-originated traffic only (secret header / mutual auth).
- Build CloudWatch dashboards for real-time security/performance KPIs.
- Extend the architecture to multi-cloud (Azure, GCP) for cross-provider resilience and synchronized IP blocking.

---

*Originally developed as the applied capstone project for a postgraduate degree in Cloud Computing & AI (XP Educação, 2025). This repo presents the technical implementation; academic framing (Canvas, personas, business model canvas) was stripped out for portfolio purposes.*
