"""
AIDE AWS Collector Module
Collects IAM data from AWS accounts using boto3.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

# ProfileNotFoundError may not exist in all botocore versions
try:
    from botocore.exceptions import ProfileNotFoundError
except ImportError:
    ProfileNotFoundError = Exception

from config import AWS_REGION, AWS_PROFILE

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AWSCollectorError(Exception):
    """Custom exception for AWS Collector errors."""
    pass


class AWSCollector:
    """
    Collects IAM and security-related data from AWS accounts.
    
    Handles pagination automatically and provides error handling
    for access denied scenarios.
    """
    
    def __init__(self, region: str = None, profile: str = None):
        """
        Initialize the AWS Collector.
        
        Args:
            region: AWS region (defaults to config value)
            profile: AWS profile name (defaults to config value)
        """
        self.region = region or AWS_REGION
        self.profile = profile or AWS_PROFILE
        self.session = self._create_session()
        self.iam_client = self.session.client('iam')
        self.sts_client = self.session.client('sts')
        self.s3_client = self.session.client('s3', region_name=self.region)
        self.ecr_client = self.session.client('ecr', region_name=self.region)
        self.account_id = None
        self._credential_report = None
        
    def _create_session(self) -> boto3.Session:
        """Create a boto3 session with optional profile."""
        try:
            if self.profile:
                return boto3.Session(profile_name=self.profile, region_name=self.region)
            return boto3.Session(region_name=self.region)
        except ProfileNotFoundError as e:
            raise AWSCollectorError(f"AWS profile '{self.profile}' not found: {e}")
        except NoCredentialsError as e:
            raise AWSCollectorError(f"No AWS credentials found: {e}")
    
    def get_account_id(self) -> str:
        """
        Get the current AWS account ID.
        
        Returns:
            The AWS account ID
        """
        if self.account_id is None:
            try:
                response = self.sts_client.get_caller_identity()
                self.account_id = response['Account']
            except ClientError as e:
                raise AWSCollectorError(f"Failed to get account ID: {e}")
        return self.account_id
    
    def get_users(self) -> List[Dict[str, Any]]:
        """
        Get all IAM users with their details.
        
        Returns:
            List of user dictionaries with attached policies and groups
        """
        users = []
        
        try:
            paginator = self.iam_client.get_paginator('list_users')
            
            for page in paginator.paginate():
                for user in page['Users']:
                    user_data = {
                        'UserName': user['UserName'],
                        'UserId': user['UserId'],
                        'Arn': user['Arn'],
                        'CreateDate': user.get('CreateDate'),
                        'PasswordLastUsed': user.get('PasswordLastUsed'),
                        'Path': user.get('Path', '/'),
                        'PermissionsBoundary': user.get('PermissionsBoundary'),
                        'Tags': user.get('Tags', []),
                        'AttachedPolicies': [],
                        'InlinePolicies': [],
                        'Groups': [],
                        'AccessKeys': []
                    }
                    
                    # Get attached managed policies
                    user_data['AttachedPolicies'] = self._get_attached_user_policies(user['UserName'])
                    
                    # Get inline policies
                    user_data['InlinePolicies'] = self._get_user_inline_policies(user['UserName'])
                    
                    # Get groups
                    user_data['Groups'] = self._get_user_groups(user['UserName'])
                    
                    # Get access keys
                    user_data['AccessKeys'] = self._get_user_access_keys(user['UserName'])
                    
                    # Get MFA devices
                    user_data['MFADevices'] = self._get_user_mfa_devices(user['UserName'])
                    
                    users.append(user_data)
                    
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                logger.warning("Access denied when listing IAM users. Check your permissions.")
                raise AWSCollectorError("Access Denied: iam:ListUsers permission required")
            raise AWSCollectorError(f"Error listing users: {e}")
        
        return users
    
    def _get_attached_user_policies(self, username: str) -> List[Dict[str, str]]:
        """Get managed policies attached to a user."""
        policies = []
        try:
            paginator = self.iam_client.get_paginator('list_attached_user_policies')
            for page in paginator.paginate(UserName=username):
                for policy in page['AttachedPolicies']:
                    policies.append({
                        'PolicyName': policy['PolicyName'],
                        'PolicyArn': policy['PolicyArn']
                    })
        except ClientError as e:
            logger.warning(f"Could not get attached policies for user {username}: {e}")
        return policies
    
    def _get_user_inline_policies(self, username: str) -> List[Dict[str, Any]]:
        """Get inline policies for a user."""
        policies = []
        try:
            paginator = self.iam_client.get_paginator('list_user_policies')
            for page in paginator.paginate(UserName=username):
                for policy_name in page['PolicyNames']:
                    try:
                        policy_response = self.iam_client.get_user_policy(
                            UserName=username,
                            PolicyName=policy_name
                        )
                        policies.append({
                            'PolicyName': policy_name,
                            'PolicyDocument': policy_response['PolicyDocument']
                        })
                    except ClientError:
                        pass
        except ClientError as e:
            logger.warning(f"Could not get inline policies for user {username}: {e}")
        return policies
    
    def _get_user_groups(self, username: str) -> List[str]:
        """Get groups a user belongs to."""
        groups = []
        try:
            paginator = self.iam_client.get_paginator('list_groups_for_user')
            for page in paginator.paginate(UserName=username):
                for group in page['Groups']:
                    groups.append(group['GroupName'])
        except ClientError as e:
            logger.warning(f"Could not get groups for user {username}: {e}")
        return groups
    
    def _get_user_access_keys(self, username: str) -> List[Dict[str, Any]]:
        """Get access keys for a user with last used information."""
        keys = []
        try:
            response = self.iam_client.list_access_keys(UserName=username)
            for key in response['AccessKeyMetadata']:
                key_data = {
                    'AccessKeyId': key['AccessKeyId'],
                    'Status': key['Status'],
                    'CreateDate': key['CreateDate']
                }
                
                # Get last used info
                try:
                    last_used = self.iam_client.get_access_key_last_used(
                        AccessKeyId=key['AccessKeyId']
                    )
                    key_data['LastUsedDate'] = last_used['AccessKeyLastUsed'].get('LastUsedDate')
                    key_data['LastUsedService'] = last_used['AccessKeyLastUsed'].get('ServiceName')
                    key_data['LastUsedRegion'] = last_used['AccessKeyLastUsed'].get('Region')
                except ClientError:
                    pass
                
                keys.append(key_data)
        except ClientError as e:
            logger.warning(f"Could not get access keys for user {username}: {e}")
        return keys
    
    def _get_user_mfa_devices(self, username: str) -> List[Dict[str, Any]]:
        """Get MFA devices for a user."""
        devices = []
        try:
            response = self.iam_client.list_mfa_devices(UserName=username)
            for device in response['MFADevices']:
                devices.append({
                    'SerialNumber': device['SerialNumber'],
                    'EnableDate': device.get('EnableDate')
                })
        except ClientError as e:
            logger.warning(f"Could not get MFA devices for user {username}: {e}")
        return devices
    
    def get_roles(self) -> List[Dict[str, Any]]:
        """
        Get all IAM roles with their details.
        
        Returns:
            List of role dictionaries with policies and trust relationships
        """
        roles = []
        
        try:
            paginator = self.iam_client.get_paginator('list_roles')
            
            for page in paginator.paginate():
                for role in page['Roles']:
                    # Decode the assume role policy document
                    trust_policy = role.get('AssumeRolePolicyDocument', {})
                    if isinstance(trust_policy, str):
                        trust_policy = json.loads(unquote(trust_policy))
                    
                    role_data = {
                        'RoleName': role['RoleName'],
                        'RoleId': role['RoleId'],
                        'Arn': role['Arn'],
                        'CreateDate': role.get('CreateDate'),
                        'Path': role.get('Path', '/'),
                        'Description': role.get('Description', ''),
                        'MaxSessionDuration': role.get('MaxSessionDuration', 3600),
                        'PermissionsBoundary': role.get('PermissionsBoundary'),
                        'AssumeRolePolicyDocument': trust_policy,
                        'Tags': role.get('Tags', []),
                        'AttachedPolicies': [],
                        'InlinePolicies': []
                    }
                    
                    # Get attached managed policies
                    role_data['AttachedPolicies'] = self._get_attached_role_policies(role['RoleName'])
                    
                    # Get inline policies
                    role_data['InlinePolicies'] = self._get_role_inline_policies(role['RoleName'])
                    
                    roles.append(role_data)
                    
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                logger.warning("Access denied when listing IAM roles. Check your permissions.")
                raise AWSCollectorError("Access Denied: iam:ListRoles permission required")
            raise AWSCollectorError(f"Error listing roles: {e}")
        
        return roles
    
    def _get_attached_role_policies(self, role_name: str) -> List[Dict[str, str]]:
        """Get managed policies attached to a role."""
        policies = []
        try:
            paginator = self.iam_client.get_paginator('list_attached_role_policies')
            for page in paginator.paginate(RoleName=role_name):
                for policy in page['AttachedPolicies']:
                    policies.append({
                        'PolicyName': policy['PolicyName'],
                        'PolicyArn': policy['PolicyArn']
                    })
        except ClientError as e:
            logger.warning(f"Could not get attached policies for role {role_name}: {e}")
        return policies
    
    def _get_role_inline_policies(self, role_name: str) -> List[Dict[str, Any]]:
        """Get inline policies for a role."""
        policies = []
        try:
            paginator = self.iam_client.get_paginator('list_role_policies')
            for page in paginator.paginate(RoleName=role_name):
                for policy_name in page['PolicyNames']:
                    try:
                        policy_response = self.iam_client.get_role_policy(
                            RoleName=role_name,
                            PolicyName=policy_name
                        )
                        policies.append({
                            'PolicyName': policy_name,
                            'PolicyDocument': policy_response['PolicyDocument']
                        })
                    except ClientError:
                        pass
        except ClientError as e:
            logger.warning(f"Could not get inline policies for role {role_name}: {e}")
        return policies
    
    def get_policies(self) -> List[Dict[str, Any]]:
        """
        Get all customer-managed IAM policies with their documents.
        
        Returns:
            List of policy dictionaries with full policy documents
        """
        policies = []
        
        try:
            paginator = self.iam_client.get_paginator('list_policies')
            
            # Only get customer managed policies
            for page in paginator.paginate(Scope='Local'):
                for policy in page['Policies']:
                    policy_data = {
                        'PolicyName': policy['PolicyName'],
                        'PolicyId': policy['PolicyId'],
                        'Arn': policy['Arn'],
                        'Path': policy.get('Path', '/'),
                        'DefaultVersionId': policy['DefaultVersionId'],
                        'AttachmentCount': policy.get('AttachmentCount', 0),
                        'IsAttachable': policy.get('IsAttachable', True),
                        'CreateDate': policy.get('CreateDate'),
                        'UpdateDate': policy.get('UpdateDate'),
                        'PolicyDocument': None
                    }
                    
                    # Get the policy document
                    try:
                        version_response = self.iam_client.get_policy_version(
                            PolicyArn=policy['Arn'],
                            VersionId=policy['DefaultVersionId']
                        )
                        policy_data['PolicyDocument'] = version_response['PolicyVersion']['Document']
                    except ClientError as e:
                        logger.warning(f"Could not get policy document for {policy['PolicyName']}: {e}")
                    
                    policies.append(policy_data)
                    
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                logger.warning("Access denied when listing IAM policies. Check your permissions.")
                raise AWSCollectorError("Access Denied: iam:ListPolicies permission required")
            raise AWSCollectorError(f"Error listing policies: {e}")
        
        return policies
    
    def get_managed_policy_document(self, policy_arn: str) -> Optional[Dict]:
        """
        Get the policy document for a managed policy.
        
        Args:
            policy_arn: The ARN of the policy
            
        Returns:
            The policy document dictionary or None
        """
        try:
            policy_response = self.iam_client.get_policy(PolicyArn=policy_arn)
            default_version = policy_response['Policy']['DefaultVersionId']
            
            version_response = self.iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=default_version
            )
            return version_response['PolicyVersion']['Document']
        except ClientError as e:
            logger.warning(f"Could not get policy document for {policy_arn}: {e}")
            return None
    
    def get_credential_report(self) -> List[Dict[str, Any]]:
        """
        Generate and retrieve the IAM credential report.
        
        Returns:
            List of credential report entries
        """
        if self._credential_report is not None:
            return self._credential_report
        
        try:
            # Generate the report
            while True:
                try:
                    response = self.iam_client.generate_credential_report()
                    if response['State'] == 'COMPLETE':
                        break
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ReportInProgress':
                        import time
                        time.sleep(2)
                        continue
                    raise
            
            # Get the report
            response = self.iam_client.get_credential_report()
            report_content = response['Content'].decode('utf-8')
            
            # Parse CSV
            import csv
            from io import StringIO
            
            reader = csv.DictReader(StringIO(report_content))
            self._credential_report = list(reader)
            
            return self._credential_report
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                logger.warning("Access denied when getting credential report. Check your permissions.")
                raise AWSCollectorError("Access Denied: iam:GenerateCredentialReport permission required")
            raise AWSCollectorError(f"Error getting credential report: {e}")
    
    def get_account_summary(self) -> Dict[str, int]:
        """
        Get the IAM account summary.
        
        Returns:
            Dictionary of account summary metrics
        """
        try:
            response = self.iam_client.get_account_summary()
            return response['SummaryMap']
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                logger.warning("Access denied when getting account summary.")
                return {}
            raise AWSCollectorError(f"Error getting account summary: {e}")
    
    def get_s3_bucket_policies(self) -> List[Dict[str, Any]]:
        """
        Get all S3 bucket policies.
        
        Returns:
            List of dictionaries with bucket names and their policies
        """
        bucket_policies = []
        
        try:
            response = self.s3_client.list_buckets()
            
            for bucket in response['Buckets']:
                bucket_name = bucket['Name']
                
                try:
                    policy_response = self.s3_client.get_bucket_policy(Bucket=bucket_name)
                    policy_document = json.loads(policy_response['Policy'])
                    
                    bucket_policies.append({
                        'BucketName': bucket_name,
                        'PolicyDocument': policy_document
                    })
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                        # Bucket has no policy, skip
                        continue
                    elif e.response['Error']['Code'] == 'AccessDenied':
                        logger.warning(f"Access denied for bucket policy: {bucket_name}")
                        continue
                    else:
                        logger.warning(f"Error getting policy for bucket {bucket_name}: {e}")
                        
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                logger.warning("Access denied when listing S3 buckets.")
                return []
            raise AWSCollectorError(f"Error listing S3 buckets: {e}")
        
        return bucket_policies
    
    def get_ecr_repository_policies(self) -> List[Dict[str, Any]]:
        """
        Get all ECR repository policies.
        
        Returns:
            List of dictionaries with repository names and their policies
        """
        repo_policies = []
        
        try:
            paginator = self.ecr_client.get_paginator('describe_repositories')
            
            for page in paginator.paginate():
                for repo in page['repositories']:
                    repo_name = repo['repositoryName']
                    
                    try:
                        policy_response = self.ecr_client.get_repository_policy(
                            repositoryName=repo_name
                        )
                        policy_document = json.loads(policy_response['policyText'])
                        
                        repo_policies.append({
                            'RepositoryName': repo_name,
                            'RepositoryArn': repo['repositoryArn'],
                            'PolicyDocument': policy_document
                        })
                    except ClientError as e:
                        if e.response['Error']['Code'] == 'RepositoryPolicyNotFoundException':
                            # Repository has no policy, skip
                            continue
                        elif e.response['Error']['Code'] == 'AccessDeniedException':
                            logger.warning(f"Access denied for ECR repository policy: {repo_name}")
                            continue
                        else:
                            logger.warning(f"Error getting policy for repository {repo_name}: {e}")
                            
        except ClientError as e:
            if e.response['Error']['Code'] in ['AccessDeniedException', 'AccessDenied']:
                logger.warning("Access denied when listing ECR repositories.")
                return []
            raise AWSCollectorError(f"Error listing ECR repositories: {e}")
        
        return repo_policies
    
    def get_groups(self) -> List[Dict[str, Any]]:
        """
        Get all IAM groups with their policies.
        
        Returns:
            List of group dictionaries with attached policies
        """
        groups = []
        
        try:
            paginator = self.iam_client.get_paginator('list_groups')
            
            for page in paginator.paginate():
                for group in page['Groups']:
                    group_data = {
                        'GroupName': group['GroupName'],
                        'GroupId': group['GroupId'],
                        'Arn': group['Arn'],
                        'CreateDate': group.get('CreateDate'),
                        'Path': group.get('Path', '/'),
                        'AttachedPolicies': [],
                        'InlinePolicies': []
                    }
                    
                    # Get attached managed policies
                    group_data['AttachedPolicies'] = self._get_attached_group_policies(group['GroupName'])
                    
                    # Get inline policies
                    group_data['InlinePolicies'] = self._get_group_inline_policies(group['GroupName'])
                    
                    groups.append(group_data)
                    
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                logger.warning("Access denied when listing IAM groups.")
                return []
            raise AWSCollectorError(f"Error listing groups: {e}")
        
        return groups
    
    def _get_attached_group_policies(self, group_name: str) -> List[Dict[str, str]]:
        """Get managed policies attached to a group."""
        policies = []
        try:
            paginator = self.iam_client.get_paginator('list_attached_group_policies')
            for page in paginator.paginate(GroupName=group_name):
                for policy in page['AttachedPolicies']:
                    policies.append({
                        'PolicyName': policy['PolicyName'],
                        'PolicyArn': policy['PolicyArn']
                    })
        except ClientError as e:
            logger.warning(f"Could not get attached policies for group {group_name}: {e}")
        return policies
    
    def _get_group_inline_policies(self, group_name: str) -> List[Dict[str, Any]]:
        """Get inline policies for a group."""
        policies = []
        try:
            paginator = self.iam_client.get_paginator('list_group_policies')
            for page in paginator.paginate(GroupName=group_name):
                for policy_name in page['PolicyNames']:
                    try:
                        policy_response = self.iam_client.get_group_policy(
                            GroupName=group_name,
                            PolicyName=policy_name
                        )
                        policies.append({
                            'PolicyName': policy_name,
                            'PolicyDocument': policy_response['PolicyDocument']
                        })
                    except ClientError:
                        pass
        except ClientError as e:
            logger.warning(f"Could not get inline policies for group {group_name}: {e}")
        return policies
    
    def collect_all(self) -> Dict[str, Any]:
        """
        Collect all IAM data from the AWS account.
        
        Returns:
            Dictionary containing all collected data
        """
        logger.info("Starting AWS data collection...")
        
        data = {
            'account_id': None,
            'collection_time': datetime.utcnow().isoformat(),
            'users': [],
            'roles': [],
            'policies': [],
            'groups': [],
            'credential_report': [],
            'account_summary': {},
            's3_bucket_policies': [],
            'ecr_repository_policies': [],
            'errors': []
        }
        
        # Get account ID
        try:
            data['account_id'] = self.get_account_id()
            logger.info(f"Collecting data for account: {data['account_id']}")
        except AWSCollectorError as e:
            data['errors'].append(str(e))
            logger.error(f"Failed to get account ID: {e}")
            return data
        
        # Collect users
        try:
            logger.info("Collecting IAM users...")
            data['users'] = self.get_users()
            logger.info(f"Found {len(data['users'])} users")
        except AWSCollectorError as e:
            data['errors'].append(str(e))
            logger.warning(f"Failed to collect users: {e}")
        
        # Collect roles
        try:
            logger.info("Collecting IAM roles...")
            data['roles'] = self.get_roles()
            logger.info(f"Found {len(data['roles'])} roles")
        except AWSCollectorError as e:
            data['errors'].append(str(e))
            logger.warning(f"Failed to collect roles: {e}")
        
        # Collect policies
        try:
            logger.info("Collecting IAM policies...")
            data['policies'] = self.get_policies()
            logger.info(f"Found {len(data['policies'])} policies")
        except AWSCollectorError as e:
            data['errors'].append(str(e))
            logger.warning(f"Failed to collect policies: {e}")
        
        # Collect groups
        try:
            logger.info("Collecting IAM groups...")
            data['groups'] = self.get_groups()
            logger.info(f"Found {len(data['groups'])} groups")
        except AWSCollectorError as e:
            data['errors'].append(str(e))
            logger.warning(f"Failed to collect groups: {e}")
        
        # Collect credential report
        try:
            logger.info("Generating credential report...")
            data['credential_report'] = self.get_credential_report()
            logger.info(f"Credential report contains {len(data['credential_report'])} entries")
        except AWSCollectorError as e:
            data['errors'].append(str(e))
            logger.warning(f"Failed to get credential report: {e}")
        
        # Get account summary
        try:
            logger.info("Getting account summary...")
            data['account_summary'] = self.get_account_summary()
        except AWSCollectorError as e:
            data['errors'].append(str(e))
            logger.warning(f"Failed to get account summary: {e}")
        
        # Collect S3 bucket policies
        try:
            logger.info("Collecting S3 bucket policies...")
            data['s3_bucket_policies'] = self.get_s3_bucket_policies()
            logger.info(f"Found {len(data['s3_bucket_policies'])} bucket policies")
        except AWSCollectorError as e:
            data['errors'].append(str(e))
            logger.warning(f"Failed to collect S3 bucket policies: {e}")
        
        # Collect ECR repository policies
        try:
            logger.info("Collecting ECR repository policies...")
            data['ecr_repository_policies'] = self.get_ecr_repository_policies()
            logger.info(f"Found {len(data['ecr_repository_policies'])} repository policies")
        except AWSCollectorError as e:
            data['errors'].append(str(e))
            logger.warning(f"Failed to collect ECR repository policies: {e}")
        
        logger.info("AWS data collection complete")
        return data


# Demo/Testing mode - generate sample data for development
def generate_sample_data() -> Dict[str, Any]:
    """
    Generate sample AWS data for testing without actual AWS credentials.
    
    Returns:
        Sample data dictionary
    """
    return {
        'account_id': '123456789012',
        'collection_time': datetime.utcnow().isoformat(),
        'users': [
            {
                'UserName': 'admin-user',
                'UserId': 'AIDAEXAMPLE1',
                'Arn': 'arn:aws:iam::123456789012:user/admin-user',
                'CreateDate': datetime(2023, 1, 15),
                'PasswordLastUsed': datetime(2024, 12, 1),
                'Path': '/',
                'PermissionsBoundary': None,
                'Tags': [],
                'AttachedPolicies': [
                    {'PolicyName': 'AdministratorAccess', 'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'}
                ],
                'InlinePolicies': [],
                'Groups': ['Admins'],
                'AccessKeys': [
                    {
                        'AccessKeyId': 'AKIAEXAMPLE1',
                        'Status': 'Active',
                        'CreateDate': datetime(2023, 1, 15),
                        'LastUsedDate': datetime(2024, 12, 1)
                    }
                ],
                'MFADevices': []  # No MFA - vulnerability!
            },
            {
                'UserName': 'service-account',
                'UserId': 'AIDAEXAMPLE2',
                'Arn': 'arn:aws:iam::123456789012:user/service-account',
                'CreateDate': datetime(2022, 6, 1),
                'PasswordLastUsed': None,
                'Path': '/service-accounts/',
                'PermissionsBoundary': None,
                'Tags': [{'Key': 'Service', 'Value': 'LambdaDeployer'}],
                'AttachedPolicies': [
                    {'PolicyName': 'AWSLambda_FullAccess', 'PolicyArn': 'arn:aws:iam::aws:policy/AWSLambda_FullAccess'}
                ],
                'InlinePolicies': [
                    {
                        'PolicyName': 'PassRolePolicy',
                        'PolicyDocument': {
                            'Version': '2012-10-17',
                            'Statement': [
                                {
                                    'Effect': 'Allow',
                                    'Action': ['iam:PassRole', 'lambda:CreateFunction', 'lambda:InvokeFunction'],
                                    'Resource': '*'
                                }
                            ]
                        }
                    }
                ],
                'Groups': [],
                'AccessKeys': [
                    {
                        'AccessKeyId': 'AKIAEXAMPLE2',
                        'Status': 'Active',
                        'CreateDate': datetime(2022, 6, 1),  # Old key - vulnerability!
                        'LastUsedDate': datetime(2024, 11, 15)
                    }
                ],
                'MFADevices': []
            },
            {
                'UserName': 'inactive-user',
                'UserId': 'AIDAEXAMPLE3',
                'Arn': 'arn:aws:iam::123456789012:user/inactive-user',
                'CreateDate': datetime(2021, 1, 1),
                'PasswordLastUsed': datetime(2023, 6, 15),  # Last used over 90 days ago
                'Path': '/',
                'PermissionsBoundary': None,
                'Tags': [],
                'AttachedPolicies': [
                    {'PolicyName': 'PowerUserAccess', 'PolicyArn': 'arn:aws:iam::aws:policy/PowerUserAccess'}
                ],
                'InlinePolicies': [],
                'Groups': [],
                'AccessKeys': [
                    {
                        'AccessKeyId': 'AKIAEXAMPLE3',
                        'Status': 'Active',
                        'CreateDate': datetime(2021, 1, 1),
                        'LastUsedDate': datetime(2023, 5, 1)  # Inactive key
                    }
                ],
                'MFADevices': []
            }
        ],
        'roles': [
            {
                'RoleName': 'AdminRole',
                'RoleId': 'AROAEXAMPLE1',
                'Arn': 'arn:aws:iam::123456789012:role/AdminRole',
                'CreateDate': datetime(2023, 1, 1),
                'Path': '/',
                'Description': 'Admin role for cross-account access',
                'MaxSessionDuration': 3600,
                'PermissionsBoundary': None,
                'AssumeRolePolicyDocument': {
                    'Version': '2012-10-17',
                    'Statement': [
                        {
                            'Effect': 'Allow',
                            'Principal': {'AWS': '*'},  # Wildcard principal - vulnerability!
                            'Action': 'sts:AssumeRole'
                        }
                    ]
                },
                'Tags': [],
                'AttachedPolicies': [
                    {'PolicyName': 'AdministratorAccess', 'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'}
                ],
                'InlinePolicies': []
            },
            {
                'RoleName': 'LambdaExecutionRole',
                'RoleId': 'AROAEXAMPLE2',
                'Arn': 'arn:aws:iam::123456789012:role/LambdaExecutionRole',
                'CreateDate': datetime(2023, 6, 1),
                'Path': '/service-role/',
                'Description': 'Role for Lambda execution',
                'MaxSessionDuration': 3600,
                'PermissionsBoundary': None,
                'AssumeRolePolicyDocument': {
                    'Version': '2012-10-17',
                    'Statement': [
                        {
                            'Effect': 'Allow',
                            'Principal': {'Service': 'lambda.amazonaws.com'},
                            'Action': 'sts:AssumeRole'
                        }
                    ]
                },
                'Tags': [],
                'AttachedPolicies': [],
                'InlinePolicies': [
                    {
                        'PolicyName': 'FullAccessPolicy',
                        'PolicyDocument': {
                            'Version': '2012-10-17',
                            'Statement': [
                                {
                                    'Effect': 'Allow',
                                    'Action': '*',  # Wildcard admin - vulnerability!
                                    'Resource': '*'
                                }
                            ]
                        }
                    }
                ]
            },
            {
                'RoleName': 'IAMAdminRole',
                'RoleId': 'AROAEXAMPLE3',
                'Arn': 'arn:aws:iam::123456789012:role/IAMAdminRole',
                'CreateDate': datetime(2023, 3, 15),
                'Path': '/',
                'Description': 'Role for IAM administration',
                'MaxSessionDuration': 3600,
                'PermissionsBoundary': None,  # Missing permission boundary - vulnerability!
                'AssumeRolePolicyDocument': {
                    'Version': '2012-10-17',
                    'Statement': [
                        {
                            'Effect': 'Allow',
                            'Principal': {'AWS': 'arn:aws:iam::123456789012:root'},
                            'Action': 'sts:AssumeRole'
                        }
                    ]
                },
                'Tags': [],
                'AttachedPolicies': [],
                'InlinePolicies': [
                    {
                        'PolicyName': 'IAMManagement',
                        'PolicyDocument': {
                            'Version': '2012-10-17',
                            'Statement': [
                                {
                                    'Effect': 'Allow',
                                    'Action': [
                                        'iam:CreatePolicy',
                                        'iam:AttachUserPolicy',
                                        'iam:AttachRolePolicy',
                                        'iam:PutUserPolicy'
                                    ],
                                    'Resource': '*'
                                }
                            ]
                        }
                    }
                ]
            }
        ],
        'policies': [
            {
                'PolicyName': 'CustomAdminPolicy',
                'PolicyId': 'ANPAEXAMPLE1',
                'Arn': 'arn:aws:iam::123456789012:policy/CustomAdminPolicy',
                'Path': '/',
                'DefaultVersionId': 'v1',
                'AttachmentCount': 2,
                'IsAttachable': True,
                'CreateDate': datetime(2023, 1, 1),
                'UpdateDate': datetime(2023, 1, 1),
                'PolicyDocument': {
                    'Version': '2012-10-17',
                    'Statement': [
                        {
                            'Effect': 'Allow',
                            'Action': '*',
                            'Resource': '*'
                        }
                    ]
                }
            }
        ],
        'groups': [
            {
                'GroupName': 'Admins',
                'GroupId': 'AGPAEXAMPLE1',
                'Arn': 'arn:aws:iam::123456789012:group/Admins',
                'CreateDate': datetime(2022, 1, 1),
                'Path': '/',
                'AttachedPolicies': [
                    {'PolicyName': 'AdministratorAccess', 'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'}
                ],
                'InlinePolicies': []
            }
        ],
        'credential_report': [
            {
                'user': '<root_account>',
                'arn': 'arn:aws:iam::123456789012:root',
                'user_creation_time': '2020-01-01T00:00:00+00:00',
                'password_enabled': 'true',
                'password_last_used': '2024-12-01T10:00:00+00:00',
                'mfa_active': 'false',  # Root without MFA - vulnerability!
                'access_key_1_active': 'true',
                'access_key_1_last_rotated': '2022-01-01T00:00:00+00:00',
                'access_key_2_active': 'false'
            }
        ],
        'account_summary': {
            'Users': 3,
            'Roles': 3,
            'Policies': 1,
            'Groups': 1,
            'MFADevices': 0,
            'AccountMFAEnabled': 0
        },
        's3_bucket_policies': [
            {
                'BucketName': 'public-data-bucket',
                'PolicyDocument': {
                    'Version': '2012-10-17',
                    'Statement': [
                        {
                            'Effect': 'Allow',
                            'Principal': '*',  # Public access - vulnerability!
                            'Action': 's3:GetObject',
                            'Resource': 'arn:aws:s3:::public-data-bucket/*'
                        }
                    ]
                }
            }
        ],
        'ecr_repository_policies': [],
        'errors': []
    }


if __name__ == "__main__":
    # Test the collector
    print("Testing AWS Collector...")
    
    try:
        collector = AWSCollector()
        data = collector.collect_all()
        print(f"Successfully collected data from account: {data['account_id']}")
        print(f"Users: {len(data['users'])}")
        print(f"Roles: {len(data['roles'])}")
        print(f"Policies: {len(data['policies'])}")
        print(f"Groups: {len(data['groups'])}")
        
        if data['errors']:
            print(f"\nErrors encountered:")
            for error in data['errors']:
                print(f"  - {error}")
    except AWSCollectorError as e:
        print(f"Collector error: {e}")
        print("\nUsing sample data for demonstration...")
        data = generate_sample_data()
        print(f"Sample data account: {data['account_id']}")
