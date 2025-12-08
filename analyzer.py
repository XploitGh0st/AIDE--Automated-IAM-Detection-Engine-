"""
AIDE Policy Analyzer Module
Implements detection logic for 9 IAM security vulnerabilities.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field, asdict

from config import (
    VULNERABILITY_TYPES, 
    PASSROLE_COMPUTE_ACTIONS,
    IAM_ADMIN_ACTIONS,
    FULL_ACCESS_PATTERNS,
    ACCESS_KEY_MAX_AGE_DAYS,
    INACTIVE_CREDENTIAL_DAYS,
    Priority
)
from utils import (
    calculate_age_days,
    normalize_policy_document,
    extract_actions,
    extract_resources,
    extract_principals,
    is_wildcard_action,
    is_wildcard_resource,
    is_wildcard_principal,
    has_external_id_condition,
    has_source_account_condition,
    has_ip_restriction,
    has_vpc_restriction,
    generate_finding_id,
    format_policy_json,
    get_account_id_from_arn,
    is_external_account
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """Represents a security finding."""
    finding_id: str
    vulnerability_type: str
    title: str
    priority: str
    description: str
    resource_type: str
    resource_name: str
    resource_arn: str
    affected_policy: Optional[Dict] = None
    policy_name: Optional[str] = None
    recommendation: str = ""
    details: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return asdict(self)


class PolicyAnalyzer:
    """
    Analyzes IAM policies and configurations for security vulnerabilities.
    
    Implements detection for 9 vulnerability types:
    - CRITICAL: Privilege Escalation, Wildcard Admin, Missing MFA
    - HIGH: Long-Lived Keys, Cross-Account Trust, Inactive Credentials
    - MEDIUM: Over-Privileged Services, Public Policies, Missing Permission Boundaries
    """
    
    def __init__(self, aws_data: Dict[str, Any]):
        """
        Initialize the analyzer with collected AWS data.
        
        Args:
            aws_data: Dictionary from AWSCollector.collect_all()
        """
        self.data = aws_data
        self.account_id = aws_data.get('account_id', '')
        self.findings: List[Finding] = []
        
    def analyze_all(self) -> List[Finding]:
        """
        Run all security checks and return findings.
        
        Returns:
            List of Finding objects
        """
        logger.info("Starting security analysis...")
        self.findings = []
        
        # CRITICAL Priority Checks
        logger.info("Checking for privilege escalation vulnerabilities...")
        self._check_privilege_escalation()
        
        logger.info("Checking for wildcard admin access...")
        self._check_wildcard_admin()
        
        logger.info("Checking for missing MFA on root/admin...")
        self._check_missing_mfa()
        
        # HIGH Priority Checks
        logger.info("Checking for long-lived access keys...")
        self._check_long_lived_access_keys()
        
        logger.info("Checking for cross-account trust misconfigurations...")
        self._check_cross_account_trust()
        
        logger.info("Checking for inactive credentials...")
        self._check_inactive_credentials()
        
        # MEDIUM Priority Checks
        logger.info("Checking for over-privileged service accounts...")
        self._check_over_privileged_services()
        
        logger.info("Checking for public/internet-facing policies...")
        self._check_public_policies()
        
        logger.info("Checking for missing permission boundaries...")
        self._check_missing_permission_boundaries()
        
        logger.info(f"Analysis complete. Found {len(self.findings)} issues.")
        return self.findings
    
    def _add_finding(self, vuln_type: str, resource_type: str, resource_name: str,
                     resource_arn: str, affected_policy: Optional[Dict] = None,
                     policy_name: Optional[str] = None, details: Optional[Dict] = None,
                     recommendation: str = "") -> None:
        """Helper to add a finding."""
        vuln_info = VULNERABILITY_TYPES[vuln_type]
        
        finding_data = {
            'vulnerability_type': vuln_type,
            'resource_type': resource_type,
            'resource_name': resource_name,
            'resource_arn': resource_arn
        }
        
        finding = Finding(
            finding_id=generate_finding_id(finding_data),
            vulnerability_type=vuln_type,
            title=vuln_info['name'],
            priority=vuln_info['priority'],
            description=vuln_info['description'],
            resource_type=resource_type,
            resource_name=resource_name,
            resource_arn=resource_arn,
            affected_policy=affected_policy,
            policy_name=policy_name,
            recommendation=recommendation,
            details=details or {}
        )
        
        self.findings.append(finding)
    
    # ==================== CRITICAL PRIORITY CHECKS ====================
    
    def _check_privilege_escalation(self) -> None:
        """
        Check for privilege escalation via PassRole + Compute actions.
        
        Identifies policies that allow iam:PassRole combined with actions
        that can use that role (Lambda, EC2, ECS, etc.)
        """
        # Check user inline policies
        for user in self.data.get('users', []):
            for policy in user.get('InlinePolicies', []):
                if self._policy_has_privilege_escalation(policy['PolicyDocument']):
                    self._add_finding(
                        vuln_type='PRIVILEGE_ESCALATION',
                        resource_type='IAM User',
                        resource_name=user['UserName'],
                        resource_arn=user['Arn'],
                        affected_policy=policy['PolicyDocument'],
                        policy_name=policy['PolicyName'],
                        details={
                            'dangerous_actions': self._get_dangerous_actions(policy['PolicyDocument'])
                        },
                        recommendation="Remove iam:PassRole or restrict the compute actions to specific resources."
                    )
        
        # Check role inline policies
        for role in self.data.get('roles', []):
            for policy in role.get('InlinePolicies', []):
                if self._policy_has_privilege_escalation(policy['PolicyDocument']):
                    self._add_finding(
                        vuln_type='PRIVILEGE_ESCALATION',
                        resource_type='IAM Role',
                        resource_name=role['RoleName'],
                        resource_arn=role['Arn'],
                        affected_policy=policy['PolicyDocument'],
                        policy_name=policy['PolicyName'],
                        details={
                            'dangerous_actions': self._get_dangerous_actions(policy['PolicyDocument'])
                        },
                        recommendation="Remove iam:PassRole or restrict the compute actions to specific resources."
                    )
        
        # Check customer managed policies
        for policy in self.data.get('policies', []):
            if policy.get('PolicyDocument'):
                if self._policy_has_privilege_escalation(policy['PolicyDocument']):
                    self._add_finding(
                        vuln_type='PRIVILEGE_ESCALATION',
                        resource_type='IAM Policy',
                        resource_name=policy['PolicyName'],
                        resource_arn=policy['Arn'],
                        affected_policy=policy['PolicyDocument'],
                        policy_name=policy['PolicyName'],
                        details={
                            'dangerous_actions': self._get_dangerous_actions(policy['PolicyDocument']),
                            'attachment_count': policy.get('AttachmentCount', 0)
                        },
                        recommendation="Remove iam:PassRole or restrict the compute actions to specific resources."
                    )
    
    def _policy_has_privilege_escalation(self, policy_doc: Dict) -> bool:
        """Check if a policy has privilege escalation risk."""
        policy = normalize_policy_document(policy_doc)
        statements = policy.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]
        
        has_pass_role = False
        has_compute_action = False
        
        for statement in statements:
            if statement.get('Effect') != 'Allow':
                continue
            
            actions = extract_actions(statement)
            
            for action in actions:
                action_lower = action.lower()
                
                # Check for PassRole
                if action_lower in ['iam:passrole', 'iam:*', '*']:
                    has_pass_role = True
                
                # Check for compute actions
                for compute_action in PASSROLE_COMPUTE_ACTIONS:
                    if action_lower == compute_action.lower() or action_lower == '*':
                        has_compute_action = True
                        break
                    # Check for wildcard patterns like lambda:*
                    if '*' in action_lower:
                        service = compute_action.split(':')[0]
                        if action_lower.startswith(f"{service.lower()}:"):
                            has_compute_action = True
                            break
        
        return has_pass_role and has_compute_action
    
    def _get_dangerous_actions(self, policy_doc: Dict) -> List[str]:
        """Extract the dangerous action combinations from a policy."""
        dangerous = []
        policy = normalize_policy_document(policy_doc)
        statements = policy.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]
        
        for statement in statements:
            if statement.get('Effect') != 'Allow':
                continue
            
            actions = extract_actions(statement)
            for action in actions:
                action_lower = action.lower()
                if action_lower in ['iam:passrole', '*', 'iam:*']:
                    dangerous.append(action)
                for compute_action in PASSROLE_COMPUTE_ACTIONS:
                    if action_lower == compute_action.lower():
                        dangerous.append(action)
        
        return list(set(dangerous))
    
    def _check_wildcard_admin(self) -> None:
        """
        Check for wildcard administrative access.
        
        Detects policies with Effect: Allow, Action: *, Resource: *
        """
        # Check user inline policies
        for user in self.data.get('users', []):
            for policy in user.get('InlinePolicies', []):
                if self._policy_has_wildcard_admin(policy['PolicyDocument']):
                    self._add_finding(
                        vuln_type='WILDCARD_ADMIN',
                        resource_type='IAM User',
                        resource_name=user['UserName'],
                        resource_arn=user['Arn'],
                        affected_policy=policy['PolicyDocument'],
                        policy_name=policy['PolicyName'],
                        recommendation="Replace wildcard (*) with specific actions and resources needed."
                    )
        
        # Check role inline policies
        for role in self.data.get('roles', []):
            for policy in role.get('InlinePolicies', []):
                if self._policy_has_wildcard_admin(policy['PolicyDocument']):
                    self._add_finding(
                        vuln_type='WILDCARD_ADMIN',
                        resource_type='IAM Role',
                        resource_name=role['RoleName'],
                        resource_arn=role['Arn'],
                        affected_policy=policy['PolicyDocument'],
                        policy_name=policy['PolicyName'],
                        recommendation="Replace wildcard (*) with specific actions and resources needed."
                    )
        
        # Check customer managed policies
        for policy in self.data.get('policies', []):
            if policy.get('PolicyDocument'):
                if self._policy_has_wildcard_admin(policy['PolicyDocument']):
                    self._add_finding(
                        vuln_type='WILDCARD_ADMIN',
                        resource_type='IAM Policy',
                        resource_name=policy['PolicyName'],
                        resource_arn=policy['Arn'],
                        affected_policy=policy['PolicyDocument'],
                        policy_name=policy['PolicyName'],
                        details={
                            'attachment_count': policy.get('AttachmentCount', 0)
                        },
                        recommendation="Replace wildcard (*) with specific actions and resources needed."
                    )
    
    def _policy_has_wildcard_admin(self, policy_doc: Dict) -> bool:
        """Check if a policy grants wildcard admin access."""
        policy = normalize_policy_document(policy_doc)
        statements = policy.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]
        
        for statement in statements:
            if statement.get('Effect') != 'Allow':
                continue
            
            actions = extract_actions(statement)
            resources = extract_resources(statement)
            
            has_wildcard_action = any(is_wildcard_action(a) for a in actions)
            has_wildcard_resource = any(is_wildcard_resource(r) for r in resources)
            
            if has_wildcard_action and has_wildcard_resource:
                return True
        
        return False
    
    def _check_missing_mfa(self) -> None:
        """
        Check for missing MFA on root account and admin users.
        
        Flags root account and users with AdministratorAccess who have MFA disabled.
        """
        # Check credential report for root account
        for cred in self.data.get('credential_report', []):
            if cred.get('user') == '<root_account>':
                mfa_active = cred.get('mfa_active', 'false').lower() == 'true'
                if not mfa_active:
                    self._add_finding(
                        vuln_type='MISSING_MFA',
                        resource_type='Root Account',
                        resource_name='root',
                        resource_arn=cred.get('arn', f'arn:aws:iam::{self.account_id}:root'),
                        details={
                            'password_enabled': cred.get('password_enabled', 'unknown'),
                            'last_used': cred.get('password_last_used', 'unknown')
                        },
                        recommendation="Enable MFA on the root account immediately. Use a hardware MFA device for best security."
                    )
        
        # Check account summary for root MFA
        account_summary = self.data.get('account_summary', {})
        if account_summary.get('AccountMFAEnabled', 0) == 0:
            # Only add if not already added from credential report
            root_finding_exists = any(
                f.vulnerability_type == 'MISSING_MFA' and f.resource_type == 'Root Account'
                for f in self.findings
            )
            if not root_finding_exists:
                self._add_finding(
                    vuln_type='MISSING_MFA',
                    resource_type='Root Account',
                    resource_name='root',
                    resource_arn=f'arn:aws:iam::{self.account_id}:root',
                    recommendation="Enable MFA on the root account immediately."
                )
        
        # Check users with AdministratorAccess
        for user in self.data.get('users', []):
            has_admin = False
            
            # Check attached policies
            for policy in user.get('AttachedPolicies', []):
                if policy['PolicyName'] == 'AdministratorAccess':
                    has_admin = True
                    break
            
            # Check group memberships for admin policies
            if not has_admin:
                for group_name in user.get('Groups', []):
                    for group in self.data.get('groups', []):
                        if group['GroupName'] == group_name:
                            for policy in group.get('AttachedPolicies', []):
                                if policy['PolicyName'] == 'AdministratorAccess':
                                    has_admin = True
                                    break
            
            # If admin user, check MFA
            if has_admin:
                mfa_devices = user.get('MFADevices', [])
                if not mfa_devices:
                    self._add_finding(
                        vuln_type='MISSING_MFA',
                        resource_type='IAM User',
                        resource_name=user['UserName'],
                        resource_arn=user['Arn'],
                        details={
                            'has_admin_access': True,
                            'groups': user.get('Groups', [])
                        },
                        recommendation="Enable MFA for this administrative user."
                    )
    
    # ==================== HIGH PRIORITY CHECKS ====================
    
    def _check_long_lived_access_keys(self) -> None:
        """
        Check for access keys older than 90 days.
        """
        for user in self.data.get('users', []):
            for key in user.get('AccessKeys', []):
                if key.get('Status') != 'Active':
                    continue
                
                create_date = key.get('CreateDate')
                age_days = calculate_age_days(create_date)
                
                if age_days > ACCESS_KEY_MAX_AGE_DAYS:
                    self._add_finding(
                        vuln_type='LONG_LIVED_ACCESS_KEYS',
                        resource_type='Access Key',
                        resource_name=key['AccessKeyId'],
                        resource_arn=user['Arn'],
                        details={
                            'username': user['UserName'],
                            'key_age_days': age_days,
                            'create_date': str(create_date) if create_date else 'unknown',
                            'last_used': str(key.get('LastUsedDate', 'never'))
                        },
                        recommendation=f"Rotate this access key. It is {age_days} days old (max recommended: {ACCESS_KEY_MAX_AGE_DAYS} days)."
                    )
    
    def _check_cross_account_trust(self) -> None:
        """
        Check for cross-account trust misconfigurations.
        
        Flags trust policies with:
        - Principal: AWS: * (wildcard)
        - External account IDs without ExternalId or SourceAccount conditions
        """
        for role in self.data.get('roles', []):
            trust_policy = role.get('AssumeRolePolicyDocument', {})
            if not trust_policy:
                continue
            
            statements = trust_policy.get('Statement', [])
            if isinstance(statements, dict):
                statements = [statements]
            
            for statement in statements:
                if statement.get('Effect') != 'Allow':
                    continue
                
                principals = extract_principals(statement)
                
                for principal in principals:
                    # Check for wildcard principal
                    if is_wildcard_principal(principal):
                        self._add_finding(
                            vuln_type='CROSS_ACCOUNT_TRUST',
                            resource_type='IAM Role',
                            resource_name=role['RoleName'],
                            resource_arn=role['Arn'],
                            affected_policy=trust_policy,
                            policy_name='Trust Policy',
                            details={
                                'issue': 'Wildcard principal allows any AWS account to assume this role',
                                'principal': principal
                            },
                            recommendation="Replace wildcard principal with specific account ARNs and add conditions."
                        )
                        continue
                    
                    # Check for external accounts without proper conditions
                    if principal.startswith('arn:aws:iam::'):
                        account_id = get_account_id_from_arn(principal)
                        if is_external_account(account_id, self.account_id):
                            has_external_id = has_external_id_condition(statement)
                            has_source_account = has_source_account_condition(statement)
                            
                            if not has_external_id and not has_source_account:
                                self._add_finding(
                                    vuln_type='CROSS_ACCOUNT_TRUST',
                                    resource_type='IAM Role',
                                    resource_name=role['RoleName'],
                                    resource_arn=role['Arn'],
                                    affected_policy=trust_policy,
                                    policy_name='Trust Policy',
                                    details={
                                        'issue': 'External account trust without ExternalId condition',
                                        'external_account': account_id,
                                        'principal': principal
                                    },
                                    recommendation="Add sts:ExternalId condition to prevent confused deputy attacks."
                                )
    
    def _check_inactive_credentials(self) -> None:
        """
        Check for inactive but active credentials.
        
        Flags credentials unused for > 90 days but still in Active status.
        """
        for user in self.data.get('users', []):
            # Check password last used
            password_last_used = user.get('PasswordLastUsed')
            if password_last_used:
                days_since_login = calculate_age_days(password_last_used)
                if days_since_login > INACTIVE_CREDENTIAL_DAYS:
                    self._add_finding(
                        vuln_type='INACTIVE_CREDENTIALS',
                        resource_type='IAM User',
                        resource_name=user['UserName'],
                        resource_arn=user['Arn'],
                        details={
                            'credential_type': 'Console Password',
                            'days_inactive': days_since_login,
                            'last_used': str(password_last_used)
                        },
                        recommendation=f"User has not logged in for {days_since_login} days. Consider disabling the console password."
                    )
            
            # Check access keys
            for key in user.get('AccessKeys', []):
                if key.get('Status') != 'Active':
                    continue
                
                last_used = key.get('LastUsedDate')
                if last_used:
                    days_inactive = calculate_age_days(last_used)
                    if days_inactive > INACTIVE_CREDENTIAL_DAYS:
                        self._add_finding(
                            vuln_type='INACTIVE_CREDENTIALS',
                            resource_type='Access Key',
                            resource_name=key['AccessKeyId'],
                            resource_arn=user['Arn'],
                            details={
                                'username': user['UserName'],
                                'credential_type': 'Access Key',
                                'days_inactive': days_inactive,
                                'last_used': str(last_used)
                            },
                            recommendation=f"Access key unused for {days_inactive} days. Deactivate or delete this key."
                        )
    
    # ==================== MEDIUM PRIORITY CHECKS ====================
    
    def _check_over_privileged_services(self) -> None:
        """
        Check for over-privileged service accounts.
        
        Identifies users/roles with FullAccess policies that appear to be service accounts.
        """
        # Check users that look like service accounts
        for user in self.data.get('users', []):
            is_service = self._is_service_account(user)
            
            if not is_service:
                continue
            
            # Check for FullAccess policies
            for policy in user.get('AttachedPolicies', []):
                if any(pattern in policy['PolicyName'] for pattern in FULL_ACCESS_PATTERNS):
                    self._add_finding(
                        vuln_type='OVER_PRIVILEGED_SERVICE',
                        resource_type='IAM User',
                        resource_name=user['UserName'],
                        resource_arn=user['Arn'],
                        details={
                            'policy_name': policy['PolicyName'],
                            'service_indicators': self._get_service_indicators(user)
                        },
                        recommendation="Replace FullAccess policy with least-privilege permissions for the specific service needs."
                    )
        
        # Check service roles
        for role in self.data.get('roles', []):
            # Check if it's a service role
            trust_policy = role.get('AssumeRolePolicyDocument', {})
            statements = trust_policy.get('Statement', [])
            if isinstance(statements, dict):
                statements = [statements]
            
            is_service_role = False
            for statement in statements:
                principals = extract_principals(statement)
                for principal in principals:
                    if '.amazonaws.com' in str(principal):
                        is_service_role = True
                        break
            
            if not is_service_role:
                continue
            
            # Check for FullAccess or wildcard policies
            for policy in role.get('AttachedPolicies', []):
                if any(pattern in policy['PolicyName'] for pattern in FULL_ACCESS_PATTERNS):
                    self._add_finding(
                        vuln_type='OVER_PRIVILEGED_SERVICE',
                        resource_type='IAM Role',
                        resource_name=role['RoleName'],
                        resource_arn=role['Arn'],
                        details={
                            'policy_name': policy['PolicyName'],
                            'role_path': role.get('Path', '/'),
                            'description': role.get('Description', '')
                        },
                        recommendation="Replace FullAccess policy with least-privilege permissions."
                    )
    
    def _is_service_account(self, user: Dict) -> bool:
        """Determine if a user appears to be a service account."""
        indicators = []
        
        # Check path
        path = user.get('Path', '/')
        if 'service' in path.lower() or 'automation' in path.lower():
            indicators.append('path')
        
        # Check username patterns
        username = user.get('UserName', '').lower()
        service_patterns = ['service', 'svc', 'bot', 'automation', 'deploy', 'cicd', 'jenkins', 'github']
        if any(pattern in username for pattern in service_patterns):
            indicators.append('username')
        
        # Check if password never used (programmatic access only)
        if user.get('PasswordLastUsed') is None:
            indicators.append('no_console')
        
        # Check tags
        for tag in user.get('Tags', []):
            if tag.get('Key', '').lower() in ['service', 'type', 'purpose']:
                if 'service' in tag.get('Value', '').lower():
                    indicators.append('tags')
        
        return len(indicators) >= 2
    
    def _get_service_indicators(self, user: Dict) -> List[str]:
        """Get the indicators that suggest this is a service account."""
        indicators = []
        
        path = user.get('Path', '/')
        if 'service' in path.lower():
            indicators.append(f"Path: {path}")
        
        if user.get('PasswordLastUsed') is None:
            indicators.append("No console password used")
        
        for tag in user.get('Tags', []):
            indicators.append(f"Tag: {tag.get('Key')}={tag.get('Value')}")
        
        return indicators
    
    def _check_public_policies(self) -> None:
        """
        Check for public/internet-facing resource policies.
        
        Flags S3 and ECR policies with Principal: * without IP/VPC restrictions.
        """
        # Check S3 bucket policies
        for bucket in self.data.get('s3_bucket_policies', []):
            policy = bucket.get('PolicyDocument', {})
            statements = policy.get('Statement', [])
            if isinstance(statements, dict):
                statements = [statements]
            
            for statement in statements:
                if statement.get('Effect') != 'Allow':
                    continue
                
                principals = extract_principals(statement)
                has_public_principal = any(is_wildcard_principal(p) for p in principals)
                
                if has_public_principal:
                    has_ip = has_ip_restriction(statement)
                    has_vpc = has_vpc_restriction(statement)
                    
                    if not has_ip and not has_vpc:
                        self._add_finding(
                            vuln_type='PUBLIC_POLICY',
                            resource_type='S3 Bucket',
                            resource_name=bucket['BucketName'],
                            resource_arn=f"arn:aws:s3:::{bucket['BucketName']}",
                            affected_policy=policy,
                            policy_name='Bucket Policy',
                            details={
                                'actions': extract_actions(statement),
                                'has_conditions': bool(statement.get('Condition'))
                            },
                            recommendation="Add IP or VPC restrictions to limit public access, or remove the wildcard principal."
                        )
        
        # Check ECR repository policies
        for repo in self.data.get('ecr_repository_policies', []):
            policy = repo.get('PolicyDocument', {})
            statements = policy.get('Statement', [])
            if isinstance(statements, dict):
                statements = [statements]
            
            for statement in statements:
                if statement.get('Effect') != 'Allow':
                    continue
                
                principals = extract_principals(statement)
                has_public_principal = any(is_wildcard_principal(p) for p in principals)
                
                if has_public_principal:
                    self._add_finding(
                        vuln_type='PUBLIC_POLICY',
                        resource_type='ECR Repository',
                        resource_name=repo['RepositoryName'],
                        resource_arn=repo.get('RepositoryArn', ''),
                        affected_policy=policy,
                        policy_name='Repository Policy',
                        details={
                            'actions': extract_actions(statement)
                        },
                        recommendation="Restrict the principal to specific AWS accounts or remove public access."
                    )
    
    def _check_missing_permission_boundaries(self) -> None:
        """
        Check for users/roles with IAM privileges but no permission boundary.
        
        Identifies principals that can create policies or attach permissions
        without being constrained by a permission boundary.
        """
        # Check users
        for user in self.data.get('users', []):
            if user.get('PermissionsBoundary'):
                continue  # Has boundary, skip
            
            has_iam_admin = self._has_iam_admin_permissions(user)
            
            if has_iam_admin:
                self._add_finding(
                    vuln_type='MISSING_PERMISSION_BOUNDARY',
                    resource_type='IAM User',
                    resource_name=user['UserName'],
                    resource_arn=user['Arn'],
                    details={
                        'iam_actions': self._get_iam_admin_actions(user)
                    },
                    recommendation="Attach a permission boundary to limit the scope of IAM permissions this user can grant."
                )
        
        # Check roles
        for role in self.data.get('roles', []):
            if role.get('PermissionsBoundary'):
                continue  # Has boundary, skip
            
            has_iam_admin = self._has_iam_admin_permissions(role)
            
            if has_iam_admin:
                self._add_finding(
                    vuln_type='MISSING_PERMISSION_BOUNDARY',
                    resource_type='IAM Role',
                    resource_name=role['RoleName'],
                    resource_arn=role['Arn'],
                    details={
                        'iam_actions': self._get_iam_admin_actions(role)
                    },
                    recommendation="Attach a permission boundary to limit the scope of IAM permissions this role can grant."
                )
    
    def _has_iam_admin_permissions(self, principal: Dict) -> bool:
        """Check if a user or role has IAM administrative permissions."""
        # Check inline policies
        for policy in principal.get('InlinePolicies', []):
            if self._policy_has_iam_admin(policy.get('PolicyDocument', {})):
                return True
        
        # Check attached policies (would need to fetch full policy doc for complete check)
        for policy in principal.get('AttachedPolicies', []):
            policy_name = policy.get('PolicyName', '')
            if policy_name in ['IAMFullAccess', 'AdministratorAccess']:
                return True
        
        return False
    
    def _policy_has_iam_admin(self, policy_doc: Dict) -> bool:
        """Check if a policy document has IAM admin actions."""
        policy = normalize_policy_document(policy_doc)
        statements = policy.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]
        
        for statement in statements:
            if statement.get('Effect') != 'Allow':
                continue
            
            actions = extract_actions(statement)
            
            for action in actions:
                action_lower = action.lower()
                
                if action_lower in ['iam:*', '*']:
                    return True
                
                for iam_action in IAM_ADMIN_ACTIONS:
                    if action_lower == iam_action.lower():
                        return True
        
        return False
    
    def _get_iam_admin_actions(self, principal: Dict) -> List[str]:
        """Get the IAM admin actions a principal has."""
        actions = set()
        
        for policy in principal.get('InlinePolicies', []):
            policy_doc = normalize_policy_document(policy.get('PolicyDocument', {}))
            statements = policy_doc.get('Statement', [])
            if isinstance(statements, dict):
                statements = [statements]
            
            for statement in statements:
                if statement.get('Effect') != 'Allow':
                    continue
                
                for action in extract_actions(statement):
                    action_lower = action.lower()
                    if action_lower.startswith('iam:') or action_lower == '*':
                        actions.add(action)
        
        return list(actions)
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of all findings.
        
        Returns:
            Dictionary with counts and breakdowns
        """
        summary = {
            'total_findings': len(self.findings),
            'by_priority': {
                Priority.CRITICAL: 0,
                Priority.HIGH: 0,
                Priority.MEDIUM: 0
            },
            'by_type': {},
            'by_resource_type': {}
        }
        
        for finding in self.findings:
            # Count by priority
            summary['by_priority'][finding.priority] = summary['by_priority'].get(finding.priority, 0) + 1
            
            # Count by vulnerability type
            summary['by_type'][finding.vulnerability_type] = summary['by_type'].get(finding.vulnerability_type, 0) + 1
            
            # Count by resource type
            summary['by_resource_type'][finding.resource_type] = summary['by_resource_type'].get(finding.resource_type, 0) + 1
        
        return summary


if __name__ == "__main__":
    # Test with sample data
    from collector import generate_sample_data
    
    print("Testing Policy Analyzer with sample data...")
    
    sample_data = generate_sample_data()
    analyzer = PolicyAnalyzer(sample_data)
    findings = analyzer.analyze_all()
    
    print(f"\nFound {len(findings)} security issues:\n")
    
    # Group by priority
    critical = [f for f in findings if f.priority == Priority.CRITICAL]
    high = [f for f in findings if f.priority == Priority.HIGH]
    medium = [f for f in findings if f.priority == Priority.MEDIUM]
    
    print(f"🔴 CRITICAL: {len(critical)}")
    for f in critical:
        print(f"   - {f.title}: {f.resource_type} '{f.resource_name}'")
    
    print(f"\n🟠 HIGH: {len(high)}")
    for f in high:
        print(f"   - {f.title}: {f.resource_type} '{f.resource_name}'")
    
    print(f"\n🟡 MEDIUM: {len(medium)}")
    for f in medium:
        print(f"   - {f.title}: {f.resource_type} '{f.resource_name}'")
    
    print("\n" + "=" * 60)
    summary = analyzer.get_summary()
    print(f"Summary: {json.dumps(summary, indent=2)}")
