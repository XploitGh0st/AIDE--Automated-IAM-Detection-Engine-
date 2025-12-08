"""
AIDE Utility Functions
Common helper functions used across the application.
"""

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
import hashlib


def calculate_age_days(date_value: Union[datetime, str, None]) -> int:
    """
    Calculate the age in days from a given date to now.
    
    Args:
        date_value: A datetime object or ISO format string
        
    Returns:
        Number of days since the date, or -1 if date is None/invalid
    """
    if date_value is None:
        return -1
    
    try:
        if isinstance(date_value, str):
            date_value = datetime.fromisoformat(date_value.replace('Z', '+00:00'))
        
        if date_value.tzinfo is None:
            date_value = date_value.replace(tzinfo=timezone.utc)
            
        now = datetime.now(timezone.utc)
        delta = now - date_value
        return delta.days
    except Exception:
        return -1


def normalize_policy_document(policy: Union[str, Dict]) -> Dict:
    """
    Normalize a policy document to a dictionary format.
    
    Args:
        policy: Policy as JSON string or dictionary
        
    Returns:
        Policy as dictionary
    """
    if isinstance(policy, str):
        try:
            return json.loads(policy)
        except json.JSONDecodeError:
            return {}
    return policy if isinstance(policy, dict) else {}


def extract_actions(statement: Dict) -> List[str]:
    """
    Extract actions from a policy statement, normalizing to a list.
    
    Args:
        statement: A policy statement dictionary
        
    Returns:
        List of action strings
    """
    actions = statement.get("Action", [])
    if isinstance(actions, str):
        return [actions]
    return actions


def extract_resources(statement: Dict) -> List[str]:
    """
    Extract resources from a policy statement, normalizing to a list.
    
    Args:
        statement: A policy statement dictionary
        
    Returns:
        List of resource strings
    """
    resources = statement.get("Resource", [])
    if isinstance(resources, str):
        return [resources]
    return resources


def extract_principals(statement: Dict) -> List[str]:
    """
    Extract principals from a policy statement, normalizing to a list.
    
    Args:
        statement: A policy statement dictionary
        
    Returns:
        List of principal strings
    """
    principal = statement.get("Principal", {})
    
    if isinstance(principal, str):
        return [principal]
    
    if isinstance(principal, dict):
        principals = []
        for key, value in principal.items():
            if isinstance(value, str):
                principals.append(value)
            elif isinstance(value, list):
                principals.extend(value)
        return principals
    
    return []


def matches_pattern(value: str, pattern: str) -> bool:
    """
    Check if a value matches an IAM pattern with wildcards.
    
    Args:
        value: The value to check
        pattern: The pattern (may contain * wildcards)
        
    Returns:
        True if the value matches the pattern
    """
    if pattern == "*":
        return True
    
    # Convert IAM pattern to regex
    regex_pattern = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
    return bool(re.match(regex_pattern, value, re.IGNORECASE))


def is_wildcard_action(action: str) -> bool:
    """
    Check if an action is a wildcard that grants all permissions.
    
    Args:
        action: The action string
        
    Returns:
        True if it's a wildcard action
    """
    return action in ["*", "*:*"]


def is_wildcard_resource(resource: str) -> bool:
    """
    Check if a resource is a wildcard.
    
    Args:
        resource: The resource string
        
    Returns:
        True if it's a wildcard resource
    """
    return resource == "*"


def is_wildcard_principal(principal: str) -> bool:
    """
    Check if a principal is a wildcard.
    
    Args:
        principal: The principal string
        
    Returns:
        True if it's a wildcard principal
    """
    return principal == "*"


def has_external_id_condition(statement: Dict) -> bool:
    """
    Check if a statement has an ExternalId condition.
    
    Args:
        statement: A policy statement dictionary
        
    Returns:
        True if ExternalId condition exists
    """
    condition = statement.get("Condition", {})
    
    for condition_operator, conditions in condition.items():
        if isinstance(conditions, dict):
            if "sts:ExternalId" in conditions:
                return True
    
    return False


def has_source_account_condition(statement: Dict) -> bool:
    """
    Check if a statement has a SourceAccount condition.
    
    Args:
        statement: A policy statement dictionary
        
    Returns:
        True if SourceAccount condition exists
    """
    condition = statement.get("Condition", {})
    
    for condition_operator, conditions in condition.items():
        if isinstance(conditions, dict):
            if "aws:SourceAccount" in conditions:
                return True
    
    return False


def has_ip_restriction(statement: Dict) -> bool:
    """
    Check if a statement has IP-based restrictions.
    
    Args:
        statement: A policy statement dictionary
        
    Returns:
        True if IP restriction exists
    """
    condition = statement.get("Condition", {})
    
    ip_condition_keys = ["aws:SourceIp", "aws:VpcSourceIp"]
    
    for condition_operator, conditions in condition.items():
        if isinstance(conditions, dict):
            for key in ip_condition_keys:
                if key in conditions:
                    return True
    
    return False


def has_vpc_restriction(statement: Dict) -> bool:
    """
    Check if a statement has VPC-based restrictions.
    
    Args:
        statement: A policy statement dictionary
        
    Returns:
        True if VPC restriction exists
    """
    condition = statement.get("Condition", {})
    
    vpc_condition_keys = ["aws:SourceVpc", "aws:SourceVpce", "aws:VpcSourceIp"]
    
    for condition_operator, conditions in condition.items():
        if isinstance(conditions, dict):
            for key in vpc_condition_keys:
                if key in conditions:
                    return True
    
    return False


def generate_finding_id(finding_data: Dict) -> str:
    """
    Generate a unique ID for a finding based on its content.
    
    Args:
        finding_data: The finding dictionary
        
    Returns:
        A unique hash ID
    """
    content = json.dumps(finding_data, sort_keys=True)
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def format_policy_json(policy: Dict) -> str:
    """
    Format a policy dictionary as pretty-printed JSON.
    
    Args:
        policy: Policy dictionary
        
    Returns:
        Formatted JSON string
    """
    return json.dumps(policy, indent=2, sort_keys=True)


def get_account_id_from_arn(arn: str) -> Optional[str]:
    """
    Extract the AWS account ID from an ARN.
    
    Args:
        arn: An AWS ARN string
        
    Returns:
        Account ID or None if not found
    """
    try:
        parts = arn.split(":")
        if len(parts) >= 5:
            return parts[4]
    except Exception:
        pass
    return None


def is_external_account(account_id: str, current_account: str) -> bool:
    """
    Check if an account ID is external to the current account.
    
    Args:
        account_id: Account ID to check
        current_account: Current AWS account ID
        
    Returns:
        True if the account is external
    """
    if not account_id or not current_account:
        return False
    return account_id != current_account


def severity_to_number(severity: str) -> int:
    """
    Convert severity string to number for sorting.
    
    Args:
        severity: CRITICAL, HIGH, or MEDIUM
        
    Returns:
        Numeric severity (higher = more severe)
    """
    severity_map = {
        "CRITICAL": 3,
        "HIGH": 2,
        "MEDIUM": 1
    }
    return severity_map.get(severity.upper(), 0)


def format_timestamp(dt: Optional[datetime]) -> str:
    """
    Format a datetime for display.
    
    Args:
        dt: Datetime object
        
    Returns:
        Formatted string
    """
    if dt is None:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
