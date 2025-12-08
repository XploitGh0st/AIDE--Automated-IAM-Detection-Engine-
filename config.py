"""
AIDE Configuration Module
Contains all configuration settings for the application.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Base Paths
BASE_DIR = Path(__file__).parent.absolute()
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

# Database Configuration
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DATA_DIR}/aide.db")

# AWS Configuration
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
AWS_PROFILE = os.getenv("AWS_PROFILE", None)

# Gemini AI Configuration
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5-pro")

# Scan Configuration
ACCESS_KEY_MAX_AGE_DAYS = int(os.getenv("ACCESS_KEY_MAX_AGE_DAYS", "90"))
INACTIVE_CREDENTIAL_DAYS = int(os.getenv("INACTIVE_CREDENTIAL_DAYS", "90"))

# Risk Priority Levels
class Priority:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"

# Vulnerability Types
VULNERABILITY_TYPES = {
    "PRIVILEGE_ESCALATION": {
        "name": "Privilege Escalation (PassRole + Compute)",
        "priority": Priority.CRITICAL,
        "description": "Allows a user to pass a role to a resource they create, effectively gaining that role's permissions."
    },
    "WILDCARD_ADMIN": {
        "name": "Wildcard Admin Access",
        "priority": Priority.CRITICAL,
        "description": "Full administrative takeover risk with unrestricted permissions."
    },
    "MISSING_MFA": {
        "name": "Missing MFA on Root/Admin",
        "priority": Priority.CRITICAL,
        "description": "Root or admin accounts without MFA are highly vulnerable to credential theft."
    },
    "LONG_LIVED_ACCESS_KEYS": {
        "name": "Long-Lived Access Keys",
        "priority": Priority.HIGH,
        "description": "Access keys older than 90 days increase the risk of key compromise."
    },
    "CROSS_ACCOUNT_TRUST": {
        "name": "Cross-Account Trust Misconfiguration",
        "priority": Priority.HIGH,
        "description": "Insecure cross-account trust allows unauthorized access from external accounts."
    },
    "INACTIVE_CREDENTIALS": {
        "name": "Inactive/Stale Credentials",
        "priority": Priority.HIGH,
        "description": "Unused but active credentials are potential attack vectors."
    },
    "OVER_PRIVILEGED_SERVICE": {
        "name": "Over-Privileged Service Accounts",
        "priority": Priority.MEDIUM,
        "description": "Service accounts with excessive permissions violate least privilege principle."
    },
    "PUBLIC_POLICY": {
        "name": "Public/Internet-Facing Policies",
        "priority": Priority.MEDIUM,
        "description": "Resource policies allowing public access without restrictions."
    },
    "MISSING_PERMISSION_BOUNDARY": {
        "name": "Lack of Permission Boundaries",
        "priority": Priority.MEDIUM,
        "description": "Users/roles with IAM privileges without permission boundaries can escalate privileges."
    }
}

# Dangerous action combinations for privilege escalation
PASSROLE_COMPUTE_ACTIONS = [
    "lambda:CreateFunction",
    "lambda:InvokeFunction",
    "ec2:RunInstances",
    "ecs:RunTask",
    "ecs:StartTask",
    "glue:CreateDevEndpoint",
    "datapipeline:CreatePipeline",
    "cloudformation:CreateStack",
    "sagemaker:CreateNotebookInstance",
    "sagemaker:CreateProcessingJob",
    "sagemaker:CreateTrainingJob"
]

# IAM administrative actions that require permission boundaries
IAM_ADMIN_ACTIONS = [
    "iam:CreatePolicy",
    "iam:CreatePolicyVersion",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:AttachGroupPolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:PutGroupPolicy",
    "iam:CreateUser",
    "iam:CreateRole"
]

# Full access policy patterns
FULL_ACCESS_PATTERNS = [
    "FullAccess",
    "AdministratorAccess",
    "PowerUserAccess"
]
