"""
AIDE - Automated IAM Detection Engine
Flask API Backend for React Frontend
"""

import json
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from functools import wraps

from flask import Flask, jsonify, request
from flask_cors import CORS

from config import Priority, VULNERABILITY_TYPES, GEMINI_API_KEY
from collector import AWSCollector, AWSCollectorError
from analyzer import PolicyAnalyzer, Finding as AnalyzerFinding
from ai_engine import AIRemediationEngine, generate_sample_remediation
from database import get_db_manager, DatabaseManager, Finding as DBFinding, Scan, Remediation

# Initialize Flask app
app = Flask(__name__)
CORS(app, origins=['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:5173', 'http://127.0.0.1:5173'])

# Database manager
db = get_db_manager()

# In-memory storage for active scans
active_scans: Dict[str, Dict] = {}


def handle_errors(f):
    """Decorator to handle exceptions and return JSON errors"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            import traceback
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500
    return wrapper


def extract_service(arn: str) -> str:
    """Extract AWS service from ARN"""
    if not arn:
        return 'IAM'
    parts = arn.split(':')
    if len(parts) >= 3:
        service = parts[2].upper()
        service_map = {
            'IAM': 'IAM',
            'S3': 'S3',
            'EC2': 'EC2',
            'LAMBDA': 'Lambda',
            'KMS': 'KMS',
            'RDS': 'RDS',
            'ECR': 'ECR',
        }
        return service_map.get(service, service)
    return 'IAM'


def priority_to_severity(priority: str) -> str:
    """Convert Priority to lowercase severity string"""
    if isinstance(priority, str):
        return priority.lower()
    return 'medium'


def analyzer_finding_to_api(finding: AnalyzerFinding, finding_id: str = None) -> Dict[str, Any]:
    """Convert an analyzer Finding to the API format expected by the frontend"""
    return {
        'id': finding_id or finding.finding_id,
        'severity': priority_to_severity(finding.priority),
        'findingType': finding.title,
        'description': finding.description,
        'resourceArn': finding.resource_arn,
        'resourceType': finding.resource_type,
        'accountId': finding.resource_arn.split(':')[4] if ':' in finding.resource_arn else '123456789012',
        'region': 'us-east-1',
        'detectedAt': datetime.now().isoformat(),
        'status': 'open',
        'service': extract_service(finding.resource_arn),
        'policyDocument': json.dumps(finding.affected_policy, indent=2) if finding.affected_policy else None,
        'policyName': finding.policy_name,
        'offendingStatements': [],
        'affectedResources': [
            {
                'arn': finding.resource_arn,
                'type': finding.resource_type,
                'name': finding.resource_name,
            }
        ],
        'recommendation': finding.recommendation,
        'details': finding.details,
        'vulnerabilityType': finding.vulnerability_type,
        'aiAnalysis': None,
        'tags': {}
    }


def db_finding_to_api(finding: DBFinding) -> Dict[str, Any]:
    """Convert a database Finding to the API format expected by the frontend"""
    finding_dict = finding.to_dict()
    return {
        'id': str(finding_dict['id']),
        'severity': priority_to_severity(finding_dict['priority']),
        'findingType': finding_dict['title'],
        'description': finding_dict['description'],
        'resourceArn': finding_dict['resource_arn'],
        'resourceType': finding_dict['resource_type'],
        'accountId': finding_dict['resource_arn'].split(':')[4] if ':' in (finding_dict['resource_arn'] or '') else '123456789012',
        'region': 'us-east-1',
        'detectedAt': finding_dict.get('created_at', datetime.now().isoformat()),
        'status': 'remediated' if finding_dict.get('is_resolved') else 'open',
        'service': extract_service(finding_dict['resource_arn']),
        'policyDocument': json.dumps(finding_dict['affected_policy'], indent=2) if finding_dict.get('affected_policy') else None,
        'policyName': finding_dict.get('policy_name'),
        'offendingStatements': [],
        'affectedResources': [
            {
                'arn': finding_dict['resource_arn'],
                'type': finding_dict['resource_type'],
                'name': finding_dict['resource_name'],
            }
        ],
        'recommendation': finding_dict.get('recommendation', ''),
        'details': finding_dict.get('details', {}),
        'vulnerabilityType': finding_dict['vulnerability_type'],
        'aiAnalysis': None,
        'tags': {}
    }


# =============================================================================
# API Routes
# =============================================================================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
        'geminiConfigured': bool(GEMINI_API_KEY and GEMINI_API_KEY != 'your-gemini-api-key-here')
    })


@app.route('/api/account', methods=['GET'])
@handle_errors
def get_account_info():
    """Get AWS account information"""
    try:
        collector = AWSCollector()
        account_id = collector.get_account_id()
        return jsonify({
            'accountId': account_id,
            'region': collector.region,
            'profile': collector.profile or 'default',
            'connected': True,
        })
    except AWSCollectorError as e:
        return jsonify({
            'accountId': None,
            'region': None,
            'profile': None,
            'connected': False,
            'error': str(e),
        })


@app.route('/api/findings', methods=['GET'])
@handle_errors
def get_findings():
    """Get all security findings from the most recent scan"""
    # Get findings from database
    try:
        scans = db.get_all_scans(limit=1)
        if scans:
            latest_scan = scans[0]
            db_findings = db.get_findings_for_scan(latest_scan.id)
            if db_findings:
                return jsonify([db_finding_to_api(f) for f in db_findings])
    except Exception as e:
        print(f"Database error: {e}")
    
    # Return empty array if no findings - user needs to run a scan first
    return jsonify([])


@app.route('/api/findings/<finding_id>', methods=['GET'])
@handle_errors
def get_finding(finding_id: str):
    """Get a specific finding by ID"""
    # Try to get from database
    if finding_id.isdigit():
        db_finding = db.get_finding_by_id(int(finding_id))
        if db_finding:
            return jsonify(db_finding_to_api(db_finding))
    
    return jsonify({'error': 'Finding not found'}), 404


@app.route('/api/scan', methods=['POST'])
@handle_errors
def start_scan():
    """Start a new security scan"""
    data = request.get_json() or {}
    scan_type = data.get('type', 'full')
    
    scan_id = str(uuid.uuid4())
    
    # Initialize scan in database
    try:
        db_scan = db.create_scan(scan_id)
    except Exception as e:
        print(f"Failed to create scan in database: {e}")
        db_scan = None
    
    # Initialize scan state
    scan_state = {
        'id': scan_id,
        'status': 'running',
        'type': scan_type,
        'startedAt': datetime.now().isoformat(),
        'completedAt': None,
        'totalResources': 0,
        'findings': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
        'scannedServices': [],
    }
    active_scans[scan_id] = scan_state
    
    try:
        # Collect from AWS
        collector = AWSCollector()
        aws_data = collector.collect_all()
    except AWSCollectorError as e:
        print(f"AWS collection error: {e}")
        # Update scan state to failed
        scan_state.update({
            'status': 'failed',
            'error': str(e),
            'completedAt': datetime.now().isoformat(),
        })
        if db_scan:
            try:
                db.complete_scan(scan_id, {'total': 0, 'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0})
            except Exception as db_e:
                print(f"Failed to update scan in database: {db_e}")
        return jsonify(scan_state)
    
    # Analyze the data
    analyzer = PolicyAnalyzer(aws_data)
    findings = analyzer.analyze_all()
    
    # Count findings by severity
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    services = set()
    
    for finding in findings:
        severity = priority_to_severity(finding.priority)
        if severity in severity_counts:
            severity_counts[severity] += 1
        services.add(extract_service(finding.resource_arn))
        
        # Save to database
        if db_scan:
            try:
                db.add_finding(db_scan.id, finding.to_dict())
            except Exception as e:
                print(f"Failed to save finding: {e}")
    
    # Count total resources
    total_resources = (
        len(aws_data.get('users', [])) +
        len(aws_data.get('roles', [])) +
        len(aws_data.get('groups', [])) +
        len(aws_data.get('policies', [])) +
        len(aws_data.get('s3_bucket_policies', [])) +
        len(aws_data.get('ecr_repository_policies', []))
    )
    
    # Update scan state
    scan_state.update({
        'status': 'completed',
        'completedAt': datetime.now().isoformat(),
        'totalResources': total_resources,
        'findings': severity_counts,
        'scannedServices': list(services),
    })
    
    # Update database
    if db_scan:
        try:
            db.complete_scan(scan_id, {
                'total': sum(severity_counts.values()),
                'CRITICAL': severity_counts['critical'],
                'HIGH': severity_counts['high'],
                'MEDIUM': severity_counts['medium']
            })
        except Exception as e:
            print(f"Failed to complete scan in database: {e}")
    
    return jsonify(scan_state)


@app.route('/api/scan/<scan_id>', methods=['GET'])
@handle_errors
def get_scan_status(scan_id: str):
    """Get the status of a scan"""
    # Check in-memory first
    if scan_id in active_scans:
        return jsonify(active_scans[scan_id])
    
    # Check database
    db_scan = db.get_scan(scan_id)
    if db_scan:
        scan_dict = db_scan.to_dict()
        return jsonify({
            'id': scan_dict['scan_id'],
            'status': scan_dict['status'],
            'startedAt': scan_dict['started_at'],
            'completedAt': scan_dict['completed_at'],
            'totalResources': scan_dict['total_findings'] * 5,  # Approximate
            'findings': {
                'critical': scan_dict['critical_count'],
                'high': scan_dict['high_count'],
                'medium': scan_dict['medium_count'],
                'low': 0
            },
            'scannedServices': ['IAM', 'S3'],
        })
    
    return jsonify({'error': 'Scan not found'}), 404


@app.route('/api/findings/<finding_id>/remediate', methods=['POST'])
@handle_errors
def generate_remediation(finding_id: str):
    """Generate AI remediation for a finding"""
    
    # Get the finding from database
    finding_dict = None
    
    if finding_id.isdigit():
        db_finding = db.get_finding_by_id(int(finding_id))
        if db_finding:
            finding_dict = db_finding.to_dict()
    
    if not finding_dict:
        return jsonify({'error': 'Finding not found'}), 404
    
    # Try AI remediation if configured
    if GEMINI_API_KEY and GEMINI_API_KEY != 'your-gemini-api-key-here':
        try:
            ai_engine = AIRemediationEngine(GEMINI_API_KEY)
            if ai_engine.initialize():
                result = ai_engine.generate_remediation(finding_dict)
                if result.success:
                    return jsonify({
                        'riskExplanation': result.explanation,
                        'suggestedPolicy': json.dumps(result.fixed_policy, indent=2) if result.fixed_policy else None,
                        'explanation': result.explanation,
                        'confidenceScore': 0.92,
                        'terraformCode': result.terraform_snippet,
                        'awsCliCommand': result.cli_commands,
                        'generatedAt': datetime.now().isoformat(),
                    })
        except Exception as e:
            print(f"AI engine error: {e}")
    
    # Fall back to sample remediation
    sample_result = generate_sample_remediation(finding_dict)
    
    return jsonify({
        'riskExplanation': sample_result.explanation if hasattr(sample_result, 'explanation') else 'This policy grants excessive permissions.',
        'suggestedPolicy': json.dumps(sample_result.fixed_policy, indent=2) if hasattr(sample_result, 'fixed_policy') and sample_result.fixed_policy else json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": "arn:aws:s3:::my-bucket/*"
                }
            ]
        }, indent=2),
        'explanation': sample_result.explanation if hasattr(sample_result, 'explanation') else 'The policy has been scoped down to follow least privilege principles.',
        'confidenceScore': 0.85,
        'terraformCode': sample_result.terraform_snippet if hasattr(sample_result, 'terraform_snippet') else '''resource "aws_iam_policy" "secure_policy" {
  name = "SecurePolicy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = "arn:aws:s3:::my-bucket/*"
    }]
  })
}''',
        'awsCliCommand': sample_result.cli_commands if hasattr(sample_result, 'cli_commands') else '''aws iam create-policy-version \\
  --policy-arn arn:aws:iam::ACCOUNT_ID:policy/PolicyName \\
  --policy-document file://secure-policy.json \\
  --set-as-default''',
        'generatedAt': datetime.now().isoformat(),
    })


@app.route('/api/findings/<finding_id>/apply', methods=['POST'])
@handle_errors
def apply_remediation(finding_id: str):
    """Apply a remediation (placeholder - would integrate with AWS)"""
    record = {
        'id': str(uuid.uuid4()),
        'findingId': finding_id,
        'status': 'applied',
        'appliedAt': datetime.now().isoformat(),
        'appliedBy': 'security-admin',
    }
    
    # Mark finding as resolved in database
    if finding_id.isdigit():
        try:
            db.mark_finding_resolved(int(finding_id))
        except Exception as e:
            print(f"Failed to mark finding resolved: {e}")
    
    return jsonify(record)


@app.route('/api/remediation-history', methods=['GET'])
@handle_errors
def get_remediation_history():
    """Get remediation history"""
    # Try to get from database
    try:
        session = db.get_session()
        remediations = session.query(Remediation).order_by(Remediation.created_at.desc()).limit(50).all()
        
        if remediations:
            result = []
            for rem in remediations:
                rem_dict = rem.to_dict()
                # Get associated finding
                finding = db.get_finding_by_id(rem_dict['finding_id'])
                finding_dict = finding.to_dict() if finding else {}
                
                result.append({
                    'id': str(rem_dict['id']),
                    'findingId': str(rem_dict['finding_id']),
                    'findingType': finding_dict.get('title', 'Unknown'),
                    'resourceArn': finding_dict.get('resource_arn', 'Unknown'),
                    'severity': priority_to_severity(finding_dict.get('priority', 'MEDIUM')),
                    'originalPolicy': json.dumps(finding_dict.get('affected_policy', {})),
                    'remediatedPolicy': rem_dict.get('fixed_policy', '{}'),
                    'appliedAt': rem_dict['created_at'],
                    'appliedBy': 'security-admin',
                    'status': 'applied' if rem_dict['success'] else 'failed',
                })
            session.close()
            if result:
                return jsonify(result)
    except Exception as e:
        print(f"Error getting remediation history: {e}")
    
    # Return empty array if no remediation history
    return jsonify([])


@app.route('/api/dashboard/stats', methods=['GET'])
@handle_errors
def get_dashboard_stats():
    """Get dashboard statistics"""
    # Try to get from database
    try:
        stats = db.get_stats()
        if stats['total_findings'] > 0:
            return jsonify({
                'totalFindings': stats['total_findings'],
                'severityCounts': {
                    'critical': stats['by_priority'].get('CRITICAL', 0),
                    'high': stats['by_priority'].get('HIGH', 0),
                    'medium': stats['by_priority'].get('MEDIUM', 0),
                    'low': 0
                },
                'serviceBreakdown': {'IAM': stats['total_findings']},
                'lastScanAt': datetime.now().isoformat(),
                'totalResourcesScanned': stats['total_findings'] * 5,
                'resolvedFindings': stats['resolved_findings'],
                'openFindings': stats['open_findings'],
            })
    except Exception as e:
        print(f"Database stats error: {e}")
    
    # Return empty stats if no data in database
    return jsonify({
        'totalFindings': 0,
        'severityCounts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
        'serviceBreakdown': {},
        'lastScanAt': None,
        'totalResourcesScanned': 0,
        'resolvedFindings': 0,
        'openFindings': 0,
    })


@app.route('/api/settings', methods=['GET'])
@handle_errors
def get_settings():
    """Get current settings"""
    return jsonify({
        'awsProfile': 'default',
        'awsRegion': 'us-east-1',
        'multiRegionScanning': True,
        'assumeRoleArn': None,
        'geminiApiConfigured': bool(GEMINI_API_KEY and GEMINI_API_KEY != 'your-gemini-api-key-here'),
    })


@app.route('/api/settings', methods=['PUT'])
@handle_errors
def update_settings():
    """Update settings"""
    data = request.get_json() or {}
    
    # In a real implementation, this would persist settings
    return jsonify({
        'success': True,
        'message': 'Settings updated successfully',
    })


# =============================================================================
# Error Handlers
# =============================================================================

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║              AIDE - Automated IAM Detection Engine            ║
    ║                     Flask API Backend                         ║
    ╠═══════════════════════════════════════════════════════════════╣
    ║  API Server: http://localhost:5000                            ║
    ║  Health Check: http://localhost:5000/api/health               ║
    ║                                                               ║
    ║  Frontend: Run 'npm run dev' in the frontend directory        ║
    ║            to start the React dashboard at localhost:5173     ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
    )
