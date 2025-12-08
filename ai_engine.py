"""
AIDE AI Remediation Engine
Uses Google Gemini Pro 1.5 to analyze policies and generate secure fixes.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass

import google.generativeai as genai

from config import GEMINI_API_KEY, GEMINI_MODEL, VULNERABILITY_TYPES

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class RemediationResult:
    """Represents the AI-generated remediation."""
    success: bool
    original_policy: Dict
    fixed_policy: Optional[Dict]
    explanation: str
    terraform_snippet: Optional[str]
    cli_commands: Optional[str]
    error: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            'success': self.success,
            'original_policy': self.original_policy,
            'fixed_policy': self.fixed_policy,
            'explanation': self.explanation,
            'terraform_snippet': self.terraform_snippet,
            'cli_commands': self.cli_commands,
            'error': self.error
        }


class AIRemediationEngine:
    """
    AI-powered remediation engine using Google Gemini Pro.
    
    Generates secure policy rewrites, Terraform code, and AWS CLI commands
    to fix identified IAM vulnerabilities.
    """
    
    def __init__(self, api_key: str = None):
        """
        Initialize the AI Remediation Engine.
        
        Args:
            api_key: Gemini API key (defaults to config value)
        """
        self.api_key = api_key or GEMINI_API_KEY
        self.model_name = GEMINI_MODEL
        self.model = None
        self._initialized = False
        
    def initialize(self) -> bool:
        """
        Initialize the Gemini model.
        
        Returns:
            True if initialization successful
        """
        if self._initialized:
            return True
            
        if not self.api_key or self.api_key == 'your-gemini-api-key-here':
            logger.warning("Gemini API key not configured. AI features will be disabled.")
            return False
        
        try:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel(self.model_name)
            self._initialized = True
            logger.info(f"Gemini model '{self.model_name}' initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize Gemini: {e}")
            return False
    
    def generate_remediation(self, finding: Dict) -> RemediationResult:
        """
        Generate remediation for a security finding.
        
        Args:
            finding: The finding dictionary from PolicyAnalyzer
            
        Returns:
            RemediationResult with fixed policy and code snippets
        """
        if not self._initialized and not self.initialize():
            return RemediationResult(
                success=False,
                original_policy=finding.get('affected_policy', {}),
                fixed_policy=None,
                explanation="AI engine not initialized. Please configure your Gemini API key.",
                terraform_snippet=None,
                cli_commands=None,
                error="API key not configured"
            )
        
        vuln_type = finding.get('vulnerability_type', '')
        vuln_info = VULNERABILITY_TYPES.get(vuln_type, {})
        policy = finding.get('affected_policy', {})
        resource_type = finding.get('resource_type', '')
        resource_name = finding.get('resource_name', '')
        
        if not policy:
            return RemediationResult(
                success=False,
                original_policy={},
                fixed_policy=None,
                explanation="No policy document found for this finding.",
                terraform_snippet=None,
                cli_commands=None,
                error="No policy to remediate"
            )
        
        try:
            prompt = self._build_prompt(
                vulnerability_name=vuln_info.get('name', vuln_type),
                vulnerability_description=vuln_info.get('description', ''),
                policy_json=policy,
                resource_type=resource_type,
                resource_name=resource_name,
                finding_details=finding.get('details', {})
            )
            
            response = self.model.generate_content(prompt)
            
            if not response or not response.text:
                raise Exception("Empty response from Gemini")
            
            result = self._parse_response(response.text, policy)
            return result
            
        except Exception as e:
            logger.error(f"Error generating remediation: {e}")
            return RemediationResult(
                success=False,
                original_policy=policy,
                fixed_policy=None,
                explanation=f"Failed to generate remediation: {str(e)}",
                terraform_snippet=None,
                cli_commands=None,
                error=str(e)
            )
    
    def _build_prompt(self, vulnerability_name: str, vulnerability_description: str,
                      policy_json: Dict, resource_type: str, resource_name: str,
                      finding_details: Dict) -> str:
        """Build the prompt for Gemini."""
        
        prompt = f"""You are an AWS IAM security expert. Analyze the following IAM policy that has a security vulnerability and provide a remediation.

## Vulnerability Details
- **Type**: {vulnerability_name}
- **Description**: {vulnerability_description}
- **Resource Type**: {resource_type}
- **Resource Name**: {resource_name}
- **Additional Details**: {json.dumps(finding_details, indent=2)}

## Current Policy (INSECURE)
```json
{json.dumps(policy_json, indent=2)}
```

## Your Task
1. **Analyze** the policy and identify the exact security issue
2. **Rewrite** the policy to fix the vulnerability while preserving legitimate functionality
3. **Provide** Terraform code to deploy the fixed policy
4. **Provide** AWS CLI commands to apply the fix

## Response Format
Please structure your response EXACTLY as follows (use these exact headers):

### EXPLANATION
[Explain what the security issue is and how your fix addresses it]

### FIXED_POLICY_JSON
```json
[The corrected IAM policy JSON]
```

### TERRAFORM_CODE
```hcl
[Terraform code to create/update this policy]
```

### AWS_CLI_COMMANDS
```bash
[AWS CLI commands to apply this fix]
```

## Important Guidelines
- Maintain the principle of least privilege
- Preserve any legitimate access patterns
- Use specific resource ARNs instead of wildcards where possible
- Add conditions to restrict access when appropriate
- For trust policies, add ExternalId conditions for cross-account access
- For resource policies, add IP/VPC restrictions if removing public access isn't feasible
"""
        
        return prompt
    
    def _parse_response(self, response_text: str, original_policy: Dict) -> RemediationResult:
        """Parse the Gemini response into structured components."""
        
        sections = {
            'explanation': '',
            'fixed_policy': None,
            'terraform': None,
            'cli': None
        }
        
        # Extract explanation
        if '### EXPLANATION' in response_text:
            start = response_text.find('### EXPLANATION') + len('### EXPLANATION')
            end = response_text.find('### FIXED_POLICY_JSON') if '### FIXED_POLICY_JSON' in response_text else len(response_text)
            sections['explanation'] = response_text[start:end].strip()
        
        # Extract fixed policy JSON
        if '### FIXED_POLICY_JSON' in response_text:
            start = response_text.find('### FIXED_POLICY_JSON')
            end = response_text.find('### TERRAFORM_CODE') if '### TERRAFORM_CODE' in response_text else len(response_text)
            policy_section = response_text[start:end]
            
            # Extract JSON from code block
            json_match = self._extract_code_block(policy_section, 'json')
            if json_match:
                try:
                    sections['fixed_policy'] = json.loads(json_match)
                except json.JSONDecodeError:
                    logger.warning("Failed to parse fixed policy JSON")
        
        # Extract Terraform code
        if '### TERRAFORM_CODE' in response_text:
            start = response_text.find('### TERRAFORM_CODE')
            end = response_text.find('### AWS_CLI_COMMANDS') if '### AWS_CLI_COMMANDS' in response_text else len(response_text)
            terraform_section = response_text[start:end]
            
            terraform_match = self._extract_code_block(terraform_section, 'hcl')
            if not terraform_match:
                terraform_match = self._extract_code_block(terraform_section, 'terraform')
            sections['terraform'] = terraform_match
        
        # Extract CLI commands
        if '### AWS_CLI_COMMANDS' in response_text:
            start = response_text.find('### AWS_CLI_COMMANDS')
            cli_section = response_text[start:]
            
            cli_match = self._extract_code_block(cli_section, 'bash')
            if not cli_match:
                cli_match = self._extract_code_block(cli_section, 'shell')
            sections['cli'] = cli_match
        
        # If we couldn't parse structured response, use raw text
        if not sections['explanation'] and not sections['fixed_policy']:
            sections['explanation'] = response_text
        
        return RemediationResult(
            success=sections['fixed_policy'] is not None,
            original_policy=original_policy,
            fixed_policy=sections['fixed_policy'],
            explanation=sections['explanation'],
            terraform_snippet=sections['terraform'],
            cli_commands=sections['cli']
        )
    
    def _extract_code_block(self, text: str, language: str = '') -> Optional[str]:
        """Extract code from a markdown code block."""
        import re
        
        # Try with specific language
        if language:
            pattern = rf'```{language}\n?(.*?)```'
            match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        # Try generic code block
        pattern = r'```\n?(.*?)```'
        match = re.search(pattern, text, re.DOTALL)
        if match:
            return match.group(1).strip()
        
        return None
    
    def analyze_policy_risk(self, policy: Dict) -> Dict[str, Any]:
        """
        Analyze a policy for potential risks using AI.
        
        Args:
            policy: The IAM policy document
            
        Returns:
            Risk analysis results
        """
        if not self._initialized and not self.initialize():
            return {
                'success': False,
                'error': 'AI engine not initialized'
            }
        
        prompt = f"""Analyze this IAM policy for security risks:

```json
{json.dumps(policy, indent=2)}
```

Provide a brief risk assessment including:
1. Overall risk level (Low/Medium/High/Critical)
2. List of identified risks
3. Recommendations for improvement

Keep the response concise and actionable."""

        try:
            response = self.model.generate_content(prompt)
            return {
                'success': True,
                'analysis': response.text
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }


# Demo mode - generate sample remediation without AI
def generate_sample_remediation(finding: Dict) -> RemediationResult:
    """
    Generate a sample remediation for demonstration without AI.
    
    Args:
        finding: The finding dictionary
        
    Returns:
        Sample RemediationResult
    """
    vuln_type = finding.get('vulnerability_type', '')
    policy = finding.get('affected_policy', {})
    resource_name = finding.get('resource_name', 'example-resource')
    
    # Sample remediations based on vulnerability type
    samples = {
        'WILDCARD_ADMIN': {
            'explanation': """The current policy grants full administrative access with Action: * and Resource: *. 
This is extremely dangerous as it allows any action on any resource in the AWS account.

The fix narrows down the permissions to only what's actually needed. In this example, 
we've limited it to specific S3 and Lambda actions on specific resources.""",
            'fixed_policy': {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObject",
                            "s3:PutObject",
                            "s3:ListBucket"
                        ],
                        "Resource": [
                            "arn:aws:s3:::my-bucket",
                            "arn:aws:s3:::my-bucket/*"
                        ]
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "lambda:InvokeFunction"
                        ],
                        "Resource": "arn:aws:lambda:*:*:function:my-function"
                    }
                ]
            },
            'terraform': f'''resource "aws_iam_policy" "{resource_name}_fixed" {{
  name        = "{resource_name}-fixed"
  description = "Least privilege policy - fixed from wildcard admin"
  
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::my-bucket",
          "arn:aws:s3:::my-bucket/*"
        ]
      }}
    ]
  }})
}}''',
            'cli': f'''# Create the fixed policy
aws iam create-policy-version \\
    --policy-arn arn:aws:iam::ACCOUNT_ID:policy/{resource_name} \\
    --policy-document file://fixed-policy.json \\
    --set-as-default'''
        },
        'PRIVILEGE_ESCALATION': {
            'explanation': """This policy combines iam:PassRole with compute service actions (like lambda:CreateFunction), 
creating a privilege escalation path. An attacker could create a Lambda function with a 
high-privilege role attached, then invoke it to gain those privileges.

The fix separates these permissions and adds resource constraints to limit what roles can be passed.""",
            'fixed_policy': {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "lambda:CreateFunction",
                            "lambda:InvokeFunction"
                        ],
                        "Resource": "arn:aws:lambda:*:*:function:allowed-*",
                        "Condition": {
                            "StringEquals": {
                                "lambda:FunctionArn": "arn:aws:lambda:*:*:function:allowed-*"
                            }
                        }
                    },
                    {
                        "Effect": "Allow",
                        "Action": "iam:PassRole",
                        "Resource": "arn:aws:iam::*:role/lambda-execution-role",
                        "Condition": {
                            "StringEquals": {
                                "iam:PassedToService": "lambda.amazonaws.com"
                            }
                        }
                    }
                ]
            },
            'terraform': '''resource "aws_iam_policy" "lambda_deploy_fixed" {
  name        = "lambda-deploy-fixed"
  description = "Fixed Lambda deployment policy with restricted PassRole"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:CreateFunction",
          "lambda:InvokeFunction"
        ]
        Resource = "arn:aws:lambda:*:*:function:allowed-*"
      },
      {
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = "arn:aws:iam::*:role/lambda-execution-role"
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "lambda.amazonaws.com"
          }
        }
      }
    ]
  })
}''',
            'cli': '''# Update the policy to fix privilege escalation
aws iam create-policy-version \\
    --policy-arn arn:aws:iam::ACCOUNT_ID:policy/lambda-deploy \\
    --policy-document file://fixed-passrole-policy.json \\
    --set-as-default'''
        },
        'CROSS_ACCOUNT_TRUST': {
            'explanation': """The trust policy allows any AWS account (Principal: *) to assume this role. 
This is extremely dangerous and could allow attackers from any AWS account to gain access.

The fix restricts the principal to a specific trusted account and adds an ExternalId condition 
to prevent confused deputy attacks.""",
            'fixed_policy': {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "arn:aws:iam::TRUSTED_ACCOUNT_ID:root"
                        },
                        "Action": "sts:AssumeRole",
                        "Condition": {
                            "StringEquals": {
                                "sts:ExternalId": "unique-external-id-here"
                            }
                        }
                    }
                ]
            },
            'terraform': f'''resource "aws_iam_role" "{resource_name}_fixed" {{
  name = "{resource_name}-fixed"
  
  assume_role_policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Effect = "Allow"
        Principal = {{
          AWS = "arn:aws:iam::TRUSTED_ACCOUNT_ID:root"
        }}
        Action = "sts:AssumeRole"
        Condition = {{
          StringEquals = {{
            "sts:ExternalId" = "unique-external-id-here"
          }}
        }}
      }}
    ]
  }})
}}''',
            'cli': '''# Update the trust policy
aws iam update-assume-role-policy \\
    --role-name AdminRole \\
    --policy-document file://fixed-trust-policy.json'''
        },
        'PUBLIC_POLICY': {
            'explanation': """The S3 bucket policy allows public access (Principal: *) without any restrictions.
This means anyone on the internet can access the bucket contents.

The fix adds an IP restriction condition to limit access to known IP ranges, 
or you could replace the wildcard principal with specific AWS accounts.""",
            'fixed_policy': {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::my-bucket/*",
                        "Condition": {
                            "IpAddress": {
                                "aws:SourceIp": [
                                    "203.0.113.0/24",
                                    "198.51.100.0/24"
                                ]
                            }
                        }
                    }
                ]
            },
            'terraform': '''resource "aws_s3_bucket_policy" "restricted" {
  bucket = aws_s3_bucket.example.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = "*"
        Action = "s3:GetObject"
        Resource = "${aws_s3_bucket.example.arn}/*"
        Condition = {
          IpAddress = {
            "aws:SourceIp" = ["203.0.113.0/24"]
          }
        }
      }
    ]
  })
}''',
            'cli': '''# Update the bucket policy with IP restrictions
aws s3api put-bucket-policy \\
    --bucket my-bucket \\
    --policy file://fixed-bucket-policy.json'''
        }
    }
    
    # Get sample or generate generic response
    sample = samples.get(vuln_type, {
        'explanation': f"This {finding.get('title', 'vulnerability')} should be addressed by applying the principle of least privilege.",
        'fixed_policy': policy,
        'terraform': "# Terraform code would be generated here",
        'cli': "# AWS CLI commands would be generated here"
    })
    
    return RemediationResult(
        success=True,
        original_policy=policy,
        fixed_policy=sample['fixed_policy'],
        explanation=sample['explanation'],
        terraform_snippet=sample['terraform'],
        cli_commands=sample['cli']
    )


if __name__ == "__main__":
    # Test the AI engine
    print("Testing AI Remediation Engine...")
    
    engine = AIRemediationEngine()
    
    if engine.initialize():
        print("✓ Gemini API initialized successfully")
        
        # Test with a sample finding
        test_finding = {
            'vulnerability_type': 'WILDCARD_ADMIN',
            'title': 'Wildcard Admin Access',
            'resource_type': 'IAM Policy',
            'resource_name': 'OverlyPermissivePolicy',
            'affected_policy': {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Allow',
                        'Action': '*',
                        'Resource': '*'
                    }
                ]
            },
            'details': {}
        }
        
        print("\nGenerating remediation for wildcard admin policy...")
        result = engine.generate_remediation(test_finding)
        
        if result.success:
            print("\n✓ Remediation generated successfully!")
            print(f"\nExplanation:\n{result.explanation[:500]}...")
            print(f"\nFixed Policy:\n{json.dumps(result.fixed_policy, indent=2)[:500]}...")
        else:
            print(f"\n✗ Remediation failed: {result.error}")
    else:
        print("✗ Gemini API not configured. Using sample remediation...")
        
        # Demo with sample
        test_finding = {
            'vulnerability_type': 'WILDCARD_ADMIN',
            'title': 'Wildcard Admin Access',
            'resource_type': 'IAM Policy',
            'resource_name': 'TestPolicy',
            'affected_policy': {
                'Version': '2012-10-17',
                'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]
            }
        }
        
        result = generate_sample_remediation(test_finding)
        print(f"\nSample Explanation:\n{result.explanation[:300]}...")
