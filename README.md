# AI-Based Network Firewall (AWS WAF)

This project implements an AI-powered network firewall using AWS services, designed to detect and prevent network attacks in real-time while staying within AWS free tier limits.

## Architecture Components

1. **EC2 Instances**
   - Attacker Machine (t2.micro)
   - Victim Machine (t2.micro)

2. **Traffic Monitoring**
   - VPC Flow Logs
   - GuardDuty for anomaly detection

3. **AI-Based Threat Detection**
   - AWS Lambda for processing
   - SageMaker endpoint for inference
   - AWS WAF for protection

4. **Visualization**
   - AWS QuickSight for metrics visualization

## Setup Instructions

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Configure AWS credentials:
   ```bash
   aws configure
   ```

3. Deploy infrastructure:
   ```bash
   python deploy/setup.py
   ```

## Free Tier Usage

This project is designed to work within AWS Free Tier limits:
- EC2: Uses t2.micro instances
- Lambda: Stays within monthly free tier limit
- SageMaker: Uses smallest possible instance for minimal duration
- WAF: Basic rules within free tier ACL limits

## Research Components

The system is designed to:
1. Capture attack traffic
2. Analyze using pre-trained NIDS model
3. Update WAF rules automatically
4. Generate research data and metrics

## Security Notice

This project is for research purposes only. Always follow responsible security testing practices and obtain necessary permissions before conducting any security tests. 