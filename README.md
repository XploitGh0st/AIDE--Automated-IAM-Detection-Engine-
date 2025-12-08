# AIDE - Automated IAM Detection Engine

🛡️ **AI-Powered AWS Security Scanner**

AIDE scans your AWS environment for critical IAM misconfigurations and uses Google Gemini AI to generate secure remediation code (Terraform/CLI).

![Python](https://img.shields.io/badge/python-3.9+-blue.svg)
![Streamlit](https://img.shields.io/badge/streamlit-1.29+-red.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## 🎯 Features

### 9 Vulnerability Detection Rules

| Priority | Vulnerability | Description |
|----------|---------------|-------------|
| 🔴 CRITICAL | Privilege Escalation | PassRole + Compute action combinations |
| 🔴 CRITICAL | Wildcard Admin Access | `Action: *` with `Resource: *` |
| 🔴 CRITICAL | Missing MFA | Root/Admin accounts without MFA |
| 🟠 HIGH | Long-Lived Access Keys | Keys older than 90 days |
| 🟠 HIGH | Cross-Account Trust | Misconfigured trust policies |
| 🟠 HIGH | Inactive Credentials | Unused but active credentials |
| 🟡 MEDIUM | Over-Privileged Services | Service accounts with FullAccess |
| 🟡 MEDIUM | Public Policies | S3/ECR with `Principal: *` |
| 🟡 MEDIUM | Missing Permission Boundaries | IAM admins without boundaries |

### AI-Powered Remediation

- **Policy Rewriting**: Secure policy suggestions preserving functionality
- **Terraform Code**: Infrastructure as Code for fixes
- **AWS CLI Commands**: Quick command-line fixes
- **Explanation**: Detailed analysis of issues and fixes

## 🚀 Quick Start

### 1. Clone and Install

```bash
# Navigate to project directory
cd "AIDE (Automated IAM Detection Engine)"

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
# Copy example environment file
copy .env.example .env

# Edit .env with your settings:
# - GEMINI_API_KEY: Get from https://makersuite.google.com/app/apikey
# - AWS_REGION: Your AWS region
# - AWS_PROFILE: Your AWS CLI profile (optional)
```

### 3. Configure AWS Credentials

AIDE uses standard AWS credentials. Configure using one of these methods:

```bash
# Option 1: AWS CLI
aws configure

# Option 2: Environment variables
set AWS_ACCESS_KEY_ID=your-key
set AWS_SECRET_ACCESS_KEY=your-secret
set AWS_REGION=us-east-1

# Option 3: AWS Profile in .env
AWS_PROFILE=your-profile-name
```

Required IAM permissions for the scanner:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:ListUsers",
                "iam:ListRoles",
                "iam:ListPolicies",
                "iam:ListGroups",
                "iam:GetUser",
                "iam:GetRole",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:ListUserPolicies",
                "iam:ListRolePolicies",
                "iam:ListGroupPolicies",
                "iam:ListAttachedUserPolicies",
                "iam:ListAttachedRolePolicies",
                "iam:ListAttachedGroupPolicies",
                "iam:GetUserPolicy",
                "iam:GetRolePolicy",
                "iam:GetGroupPolicy",
                "iam:ListAccessKeys",
                "iam:GetAccessKeyLastUsed",
                "iam:ListMFADevices",
                "iam:GetAccountSummary",
                "iam:GenerateCredentialReport",
                "iam:GetCredentialReport",
                "iam:ListGroupsForUser",
                "s3:ListAllMyBuckets",
                "s3:GetBucketPolicy",
                "ecr:DescribeRepositories",
                "ecr:GetRepositoryPolicy",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

### 4. Run the Application

```bash
streamlit run app.py
```

The dashboard will open at `http://localhost:8501`

## 🎭 Demo Mode

Don't have AWS credentials? AIDE includes a demo mode with sample data:

1. Launch the app
2. Check "Demo Mode" in the sidebar, or
3. Click "Quick Demo" button

This demonstrates all features without requiring AWS access.

## 📁 Project Structure

```
AIDE/
├── app.py              # Streamlit dashboard
├── collector.py        # AWS data collection
├── analyzer.py         # Vulnerability detection (9 rules)
├── ai_engine.py        # Gemini AI integration
├── database.py         # SQLite storage
├── config.py           # Configuration settings
├── utils.py            # Utility functions
├── requirements.txt    # Python dependencies
├── .env.example        # Environment template
├── data/               # SQLite database storage
└── README.md           # This file
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GEMINI_API_KEY` | Google Gemini API key | Required for AI |
| `GEMINI_MODEL` | Gemini model name | `gemini-1.5-pro` |
| `AWS_REGION` | AWS region | `us-east-1` |
| `AWS_PROFILE` | AWS CLI profile | Default profile |
| `ACCESS_KEY_MAX_AGE_DAYS` | Max key age threshold | `90` |
| `INACTIVE_CREDENTIAL_DAYS` | Inactive credential threshold | `90` |

### Getting a Gemini API Key

1. Go to [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Click "Create API Key"
3. Copy the key to your `.env` file

## 🔍 Detection Logic Details

### 1. Privilege Escalation (CRITICAL)
Detects `iam:PassRole` combined with compute actions:
- `lambda:CreateFunction`
- `ec2:RunInstances`
- `ecs:RunTask`
- `glue:CreateDevEndpoint`
- `cloudformation:CreateStack`
- `sagemaker:CreateNotebookInstance`

### 2. Wildcard Admin (CRITICAL)
Detects policies with:
```json
{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
}
```

### 3. Missing MFA (CRITICAL)
Checks:
- Root account MFA status
- Users with `AdministratorAccess` policy

### 4. Long-Lived Access Keys (HIGH)
Flags active keys older than 90 days using `CreateDate`.

### 5. Cross-Account Trust (HIGH)
Analyzes trust policies for:
- `Principal: AWS: *`
- External accounts without `sts:ExternalId`

### 6. Inactive Credentials (HIGH)
Checks `PasswordLastUsed` and `LastUsedDate` for 90+ day inactivity.

### 7. Over-Privileged Services (MEDIUM)
Identifies service accounts with `*FullAccess` policies.

### 8. Public Policies (MEDIUM)
Scans S3 and ECR policies for `Principal: *` without IP/VPC conditions.

### 9. Missing Permission Boundaries (MEDIUM)
Flags IAM admin users/roles without permission boundaries.

## 🤖 AI Remediation

AIDE uses Gemini Pro 1.5 to generate fixes:

1. **Analysis**: Understands the vulnerability context
2. **Policy Rewrite**: Creates least-privilege replacement
3. **Terraform**: IaC code for the fix
4. **CLI Commands**: Quick manual remediation

Example prompt strategy:
```
Vulnerability: [TYPE]
Current Policy: [JSON]
Task: Rewrite to fix while preserving functionality
Output: Fixed JSON + Terraform + CLI commands
```

## 📊 Dashboard Features

- **Summary Metrics**: Critical/High/Medium counts
- **Filterable Findings**: Sort and filter by priority
- **Detail View**: Full policy JSON and context
- **Autofix Button**: Trigger AI remediation
- **Download Options**: Export fixes as files
- **Scan History**: Track past scans

## 🛠️ Development

### Running Tests

```bash
# Test the collector
python collector.py

# Test the analyzer
python analyzer.py

# Test the AI engine
python ai_engine.py

# Test the database
python database.py
```

### Adding New Detection Rules

1. Add vulnerability type to `config.py`:
```python
VULNERABILITY_TYPES = {
    "NEW_VULN": {
        "name": "New Vulnerability",
        "priority": Priority.HIGH,
        "description": "Description here"
    }
}
```

2. Add detection method to `analyzer.py`:
```python
def _check_new_vulnerability(self) -> None:
    # Detection logic
    pass
```

3. Call from `analyze_all()`:
```python
self._check_new_vulnerability()
```

## 📝 License

MIT License - feel free to use and modify.

## 🙏 Acknowledgments

- [Streamlit](https://streamlit.io/) - Web framework
- [Boto3](https://boto3.amazonaws.com/) - AWS SDK
- [Google Gemini](https://deepmind.google/technologies/gemini/) - AI model
- [SQLAlchemy](https://www.sqlalchemy.org/) - Database ORM

## ⚠️ Disclaimer

AIDE is a security scanning tool. Always:
- Review AI-generated fixes before applying
- Test changes in non-production first
- Follow your organization's change management process
- This tool provides recommendations, not guarantees

---

Built with ❤️ for cloud security
