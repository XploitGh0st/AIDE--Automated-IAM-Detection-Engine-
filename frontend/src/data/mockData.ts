import { Finding, ScanResult, RemediationRecord } from '@/types'

// Mock data for demonstration
export const mockFindings: Finding[] = [
  {
    id: 'f-001',
    severity: 'critical',
    findingType: 'PassRole Privilege Escalation',
    description: 'IAM role allows iam:PassRole with wildcard resource, enabling lateral movement to any AWS service.',
    resourceArn: 'arn:aws:iam::123456789012:role/AdminRole',
    resourceType: 'AWS::IAM::Role',
    accountId: '123456789012',
    region: 'us-east-1',
    detectedAt: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
    status: 'open',
    service: 'IAM',
    policyDocument: JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Action: ['iam:PassRole'],
          Resource: '*'
        },
        {
          Effect: 'Allow',
          Action: ['ec2:RunInstances', 'lambda:CreateFunction'],
          Resource: '*'
        }
      ]
    }, null, 2),
    offendingStatements: ['Statement[0]: iam:PassRole with Resource: *'],
    affectedResources: [
      {
        arn: 'arn:aws:iam::123456789012:role/AdminRole',
        type: 'AWS::IAM::Role',
        name: 'AdminRole',
        lastUsed: new Date(Date.now() - 1000 * 60 * 60 * 24 * 7).toISOString(),
        tags: { Environment: 'Production', Team: 'Platform' }
      }
    ],
    aiAnalysis: {
      riskExplanation: 'This configuration allows an attacker who compromises this role to pass any IAM role to any AWS service. This enables privilege escalation by creating EC2 instances or Lambda functions with more privileged roles, effectively inheriting those permissions.',
      suggestedPolicy: JSON.stringify({
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Action: ['iam:PassRole'],
            Resource: [
              'arn:aws:iam::123456789012:role/EC2-WebServer-Role',
              'arn:aws:iam::123456789012:role/Lambda-Processor-Role'
            ],
            Condition: {
              StringEquals: {
                'iam:PassedToService': ['ec2.amazonaws.com', 'lambda.amazonaws.com']
              }
            }
          },
          {
            Effect: 'Allow',
            Action: ['ec2:RunInstances', 'lambda:CreateFunction'],
            Resource: '*'
          }
        ]
      }, null, 2),
      explanation: '**Changes Made:**\n\n1. **Restricted Resource Scope**: Changed `Resource: "*"` to specific role ARNs that this role should be able to pass.\n\n2. **Added PassedToService Condition**: Added a condition to ensure roles can only be passed to specific AWS services (EC2 and Lambda), preventing misuse with other services.\n\n3. **Maintained Operational Capability**: The EC2 and Lambda permissions remain unchanged as they are appropriately scoped.\n\n**Impact Assessment:** This change will require identifying all legitimate roles that need to be passed. Monitor CloudTrail for any access denied errors after implementation.',
      confidenceScore: 0.92,
      terraformCode: `resource "aws_iam_policy" "admin_role_policy" {
  name = "AdminRolePolicy-Secure"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["iam:PassRole"]
        Resource = [
          "arn:aws:iam::123456789012:role/EC2-WebServer-Role",
          "arn:aws:iam::123456789012:role/Lambda-Processor-Role"
        ]
        Condition = {
          StringEquals = {
            "iam:PassedToService" = ["ec2.amazonaws.com", "lambda.amazonaws.com"]
          }
        }
      }
    ]
  })
}`,
      awsCliCommand: `aws iam put-role-policy \\
  --role-name AdminRole \\
  --policy-name SecurePassRole \\
  --policy-document file://secure-policy.json`,
      generatedAt: new Date().toISOString()
    },
    tags: { Environment: 'Production', CostCenter: 'Engineering' }
  },
  {
    id: 'f-002',
    severity: 'critical',
    findingType: 'Admin Access via CreateAccessKey',
    description: 'IAM user can create access keys for any user, enabling account takeover.',
    resourceArn: 'arn:aws:iam::123456789012:user/developer-jane',
    resourceType: 'AWS::IAM::User',
    accountId: '123456789012',
    region: 'us-east-1',
    detectedAt: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    status: 'open',
    service: 'IAM',
    policyDocument: JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Action: ['iam:CreateAccessKey', 'iam:DeleteAccessKey'],
          Resource: '*'
        }
      ]
    }, null, 2),
    tags: { Team: 'Development' }
  },
  {
    id: 'f-003',
    severity: 'high',
    findingType: 'Overly Permissive S3 Bucket Policy',
    description: 'S3 bucket policy allows public read access to sensitive data.',
    resourceArn: 'arn:aws:s3:::company-data-backup',
    resourceType: 'AWS::S3::Bucket',
    accountId: '123456789012',
    region: 'us-east-1',
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(),
    status: 'open',
    service: 'S3',
    policyDocument: JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: ['s3:GetObject'],
          Resource: 'arn:aws:s3:::company-data-backup/*'
        }
      ]
    }, null, 2),
    tags: { DataClassification: 'Confidential' }
  },
  {
    id: 'f-004',
    severity: 'high',
    findingType: 'Lambda Function with Admin Privileges',
    description: 'Lambda execution role has AdministratorAccess policy attached.',
    resourceArn: 'arn:aws:lambda:us-east-1:123456789012:function:data-processor',
    resourceType: 'AWS::Lambda::Function',
    accountId: '123456789012',
    region: 'us-east-1',
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 3).toISOString(),
    status: 'in-progress',
    service: 'Lambda',
    tags: { Application: 'DataPipeline' }
  },
  {
    id: 'f-005',
    severity: 'medium',
    findingType: 'Cross-Account AssumeRole Without ExternalId',
    description: 'IAM role trust policy allows cross-account access without external ID condition.',
    resourceArn: 'arn:aws:iam::123456789012:role/CrossAccountRole',
    resourceType: 'AWS::IAM::Role',
    accountId: '123456789012',
    region: 'us-east-1',
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 5).toISOString(),
    status: 'open',
    service: 'IAM',
    policyDocument: JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: {
            AWS: 'arn:aws:iam::987654321098:root'
          },
          Action: 'sts:AssumeRole'
        }
      ]
    }, null, 2),
    tags: { Partner: 'VendorX' }
  },
  {
    id: 'f-006',
    severity: 'medium',
    findingType: 'EC2 Instance Profile with Broad Permissions',
    description: 'EC2 instance profile allows listing all S3 buckets and DynamoDB tables.',
    resourceArn: 'arn:aws:iam::123456789012:instance-profile/WebServerProfile',
    resourceType: 'AWS::IAM::InstanceProfile',
    accountId: '123456789012',
    region: 'us-west-2',
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 8).toISOString(),
    status: 'open',
    service: 'EC2',
    tags: { Environment: 'Staging' }
  },
  {
    id: 'f-007',
    severity: 'low',
    findingType: 'Unused IAM Role',
    description: 'IAM role has not been used in the last 90 days.',
    resourceArn: 'arn:aws:iam::123456789012:role/LegacyMigrationRole',
    resourceType: 'AWS::IAM::Role',
    accountId: '123456789012',
    region: 'us-east-1',
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 12).toISOString(),
    status: 'open',
    service: 'IAM',
    tags: { Status: 'Deprecated' }
  },
  {
    id: 'f-008',
    severity: 'low',
    findingType: 'Missing CloudTrail Logging',
    description: 'KMS key does not have CloudTrail logging enabled for management events.',
    resourceArn: 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',
    resourceType: 'AWS::KMS::Key',
    accountId: '123456789012',
    region: 'us-east-1',
    detectedAt: new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString(),
    status: 'open',
    service: 'KMS',
    tags: { Purpose: 'DataEncryption' }
  },
]

export const mockLastScan: ScanResult = {
  id: 'scan-001',
  startedAt: new Date(Date.now() - 1000 * 60 * 35).toISOString(),
  completedAt: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
  status: 'completed',
  totalResources: 847,
  findings: {
    critical: 2,
    high: 2,
    medium: 2,
    low: 2,
  },
  scannedServices: ['IAM', 'S3', 'EC2', 'Lambda', 'KMS'],
}

export const mockRemediationHistory: RemediationRecord[] = [
  {
    id: 'rem-001',
    findingId: 'f-old-001',
    findingType: 'S3 Bucket Public Access',
    resourceArn: 'arn:aws:s3:::public-assets-bucket',
    severity: 'high',
    originalPolicy: '{ "Principal": "*" }',
    remediatedPolicy: '{ "Principal": { "AWS": "arn:aws:iam::123456789012:root" } }',
    appliedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 3).toISOString(),
    appliedBy: 'security-team',
    status: 'applied',
  },
  {
    id: 'rem-002',
    findingId: 'f-old-002',
    findingType: 'IAM User Inline Policy',
    resourceArn: 'arn:aws:iam::123456789012:user/legacy-service',
    severity: 'medium',
    originalPolicy: '{ "Action": "*" }',
    remediatedPolicy: '{ "Action": ["s3:GetObject"] }',
    appliedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 5).toISOString(),
    appliedBy: 'automation',
    status: 'applied',
  },
]
