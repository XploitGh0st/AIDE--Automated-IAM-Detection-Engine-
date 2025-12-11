"""
Creates a test IAM user with unsafe policies:
- Inline policy: Action "*" on Resource "*"
- Allows iam:PassRole and sts:AssumeRole on all roles
- Creates an access key (long-lived credentials, no MFA)
"""

import argparse
import boto3
import json
from botocore.exceptions import NoCredentialsError, ProfileNotFound

USER_NAME = "aide-test-user"
PASSROLE_POLICY_NAME = "PassAnyRole"
ALLOWALL_POLICY_NAME = "AllowAllUnsafe"

def ensure_user(iam):
    try:
        iam.get_user(UserName=USER_NAME)
        print(f"User {USER_NAME} already exists.")
    except iam.exceptions.NoSuchEntityException:
        iam.create_user(UserName=USER_NAME)
        print(f"Created user {USER_NAME}.")

def put_allow_all_policy(iam):
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }]
    }
    iam.put_user_policy(
        UserName=USER_NAME,
        PolicyName=ALLOWALL_POLICY_NAME,
        PolicyDocument=json.dumps(policy_doc)
    )
    print("Attached inline AllowAll policy (wildcard admin).")

def put_passrole_policy(iam):
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["iam:PassRole", "sts:AssumeRole"],
            "Resource": "*"
        }]
    }
    iam.put_user_policy(
        UserName=USER_NAME,
        PolicyName=PASSROLE_POLICY_NAME,
        PolicyDocument=json.dumps(policy_doc)
    )
    print("Attached PassRole+AssumeRole policy without restrictions.")

def create_access_key(iam):
    key = iam.create_access_key(UserName=USER_NAME)["AccessKey"]
    print("Created access key (store securely for testing, then delete):")
    print(f"  AccessKeyId: {key['AccessKeyId']}")
    print(f"  SecretAccessKey: {key['SecretAccessKey']}")
    return key

def main():
    parser = argparse.ArgumentParser(description="Create intentionally unsafe IAM user for AIDE testing")
    parser.add_argument("--profile", default=None, help="AWS profile name to use (from ~/.aws/credentials)")
    parser.add_argument("--region", default=None, help="AWS region (optional for IAM)")
    args = parser.parse_args()

    try:
        session = boto3.session.Session(profile_name=args.profile, region_name=args.region)
    except ProfileNotFound as e:
        print(f"Profile not found: {e}")
        print("Set AWS credentials with `aws configure` or pass --profile <name>.")
        return

    try:
        iam = session.client("iam")
        ensure_user(iam)
        put_allow_all_policy(iam)
        put_passrole_policy(iam)
        create_access_key(iam)
        print("\nVulnerabilities introduced. Run AIDE scan now.")
        print("Remember to clean up after testing!\n")
    except NoCredentialsError:
        print("No AWS credentials found. Fix by either:")
        print("  1) Run `aws configure` to set access keys for the default profile")
        print("  2) Export AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY (and AWS_SESSION_TOKEN if using STS)")
        print("  3) Pass --profile <name> that has credentials in ~/.aws/credentials")
        return

if __name__ == "__main__":
    main()