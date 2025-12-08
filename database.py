"""
AIDE Database Models
SQLite database for storing scan history and findings.
"""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from sqlalchemy.pool import StaticPool

from config import DATABASE_URL

Base = declarative_base()


class Scan(Base):
    """Represents a security scan run."""
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(64), unique=True, nullable=False)
    account_id = Column(String(12), nullable=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(20), default='running')  # running, completed, failed
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    errors = Column(Text, nullable=True)  # JSON array of errors
    raw_data = Column(Text, nullable=True)  # JSON of collected AWS data
    
    # Relationships
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'account_id': self.account_id,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'status': self.status,
            'total_findings': self.total_findings,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'medium_count': self.medium_count,
            'errors': json.loads(self.errors) if self.errors else []
        }


class Finding(Base):
    """Represents a security finding from a scan."""
    __tablename__ = 'findings'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(String(64), nullable=False)
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    vulnerability_type = Column(String(50), nullable=False)
    title = Column(String(200), nullable=False)
    priority = Column(String(20), nullable=False)
    description = Column(Text, nullable=True)
    resource_type = Column(String(50), nullable=False)
    resource_name = Column(String(200), nullable=False)
    resource_arn = Column(String(500), nullable=True)
    policy_name = Column(String(200), nullable=True)
    affected_policy = Column(Text, nullable=True)  # JSON
    recommendation = Column(Text, nullable=True)
    details = Column(Text, nullable=True)  # JSON
    is_resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime, nullable=True)
    
    # Relationships
    scan = relationship("Scan", back_populates="findings")
    remediations = relationship("Remediation", back_populates="finding", cascade="all, delete-orphan")
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'finding_id': self.finding_id,
            'scan_id': self.scan_id,
            'vulnerability_type': self.vulnerability_type,
            'title': self.title,
            'priority': self.priority,
            'description': self.description,
            'resource_type': self.resource_type,
            'resource_name': self.resource_name,
            'resource_arn': self.resource_arn,
            'policy_name': self.policy_name,
            'affected_policy': json.loads(self.affected_policy) if self.affected_policy else None,
            'recommendation': self.recommendation,
            'details': json.loads(self.details) if self.details else {},
            'is_resolved': self.is_resolved,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None
        }


class Remediation(Base):
    """Represents an AI-generated remediation for a finding."""
    __tablename__ = 'remediations'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(Integer, ForeignKey('findings.id'), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    success = Column(Boolean, default=False)
    explanation = Column(Text, nullable=True)
    fixed_policy = Column(Text, nullable=True)  # JSON
    terraform_snippet = Column(Text, nullable=True)
    cli_commands = Column(Text, nullable=True)
    error = Column(Text, nullable=True)
    
    # Relationships
    finding = relationship("Finding", back_populates="remediations")
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'finding_id': self.finding_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'success': self.success,
            'explanation': self.explanation,
            'fixed_policy': json.loads(self.fixed_policy) if self.fixed_policy else None,
            'terraform_snippet': self.terraform_snippet,
            'cli_commands': self.cli_commands,
            'error': self.error
        }


class DatabaseManager:
    """Manages database connections and operations."""
    
    def __init__(self, db_url: str = None):
        """
        Initialize the database manager.
        
        Args:
            db_url: SQLAlchemy database URL
        """
        self.db_url = db_url or DATABASE_URL
        
        # For SQLite, use StaticPool to allow multi-threaded access
        if 'sqlite' in self.db_url:
            self.engine = create_engine(
                self.db_url,
                connect_args={"check_same_thread": False},
                poolclass=StaticPool
            )
        else:
            self.engine = create_engine(self.db_url)
        
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        
    def create_tables(self):
        """Create all database tables."""
        Base.metadata.create_all(bind=self.engine)
    
    def get_session(self) -> Session:
        """Get a database session."""
        return self.SessionLocal()
    
    def create_scan(self, scan_id: str, account_id: str = None) -> Scan:
        """Create a new scan record."""
        session = self.get_session()
        try:
            scan = Scan(
                scan_id=scan_id,
                account_id=account_id,
                started_at=datetime.utcnow(),
                status='running'
            )
            session.add(scan)
            session.commit()
            session.refresh(scan)
            return scan
        finally:
            session.close()
    
    def update_scan(self, scan_id: str, **kwargs) -> Optional[Scan]:
        """Update a scan record."""
        session = self.get_session()
        try:
            scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
            if scan:
                for key, value in kwargs.items():
                    if hasattr(scan, key):
                        setattr(scan, key, value)
                session.commit()
                session.refresh(scan)
            return scan
        finally:
            session.close()
    
    def complete_scan(self, scan_id: str, findings_count: Dict[str, int], 
                      errors: List[str] = None, raw_data: Dict = None) -> Optional[Scan]:
        """Mark a scan as completed with results."""
        return self.update_scan(
            scan_id,
            status='completed',
            completed_at=datetime.utcnow(),
            total_findings=findings_count.get('total', 0),
            critical_count=findings_count.get('CRITICAL', 0),
            high_count=findings_count.get('HIGH', 0),
            medium_count=findings_count.get('MEDIUM', 0),
            errors=json.dumps(errors) if errors else None,
            raw_data=json.dumps(raw_data, default=str) if raw_data else None
        )
    
    def add_finding(self, scan_db_id: int, finding_data: Dict) -> Finding:
        """Add a finding to a scan."""
        session = self.get_session()
        try:
            finding = Finding(
                finding_id=finding_data.get('finding_id', ''),
                scan_id=scan_db_id,
                vulnerability_type=finding_data.get('vulnerability_type', ''),
                title=finding_data.get('title', ''),
                priority=finding_data.get('priority', 'MEDIUM'),
                description=finding_data.get('description', ''),
                resource_type=finding_data.get('resource_type', ''),
                resource_name=finding_data.get('resource_name', ''),
                resource_arn=finding_data.get('resource_arn', ''),
                policy_name=finding_data.get('policy_name'),
                affected_policy=json.dumps(finding_data.get('affected_policy')) if finding_data.get('affected_policy') else None,
                recommendation=finding_data.get('recommendation', ''),
                details=json.dumps(finding_data.get('details', {}))
            )
            session.add(finding)
            session.commit()
            session.refresh(finding)
            return finding
        finally:
            session.close()
    
    def add_remediation(self, finding_db_id: int, remediation_data: Dict) -> Remediation:
        """Add a remediation for a finding."""
        session = self.get_session()
        try:
            remediation = Remediation(
                finding_id=finding_db_id,
                success=remediation_data.get('success', False),
                explanation=remediation_data.get('explanation', ''),
                fixed_policy=json.dumps(remediation_data.get('fixed_policy')) if remediation_data.get('fixed_policy') else None,
                terraform_snippet=remediation_data.get('terraform_snippet'),
                cli_commands=remediation_data.get('cli_commands'),
                error=remediation_data.get('error')
            )
            session.add(remediation)
            session.commit()
            session.refresh(remediation)
            return remediation
        finally:
            session.close()
    
    def get_scan(self, scan_id: str) -> Optional[Scan]:
        """Get a scan by scan_id."""
        session = self.get_session()
        try:
            return session.query(Scan).filter(Scan.scan_id == scan_id).first()
        finally:
            session.close()
    
    def get_scan_by_db_id(self, db_id: int) -> Optional[Scan]:
        """Get a scan by database ID."""
        session = self.get_session()
        try:
            return session.query(Scan).filter(Scan.id == db_id).first()
        finally:
            session.close()
    
    def get_all_scans(self, limit: int = 50) -> List[Scan]:
        """Get all scans, most recent first."""
        session = self.get_session()
        try:
            return session.query(Scan).order_by(Scan.started_at.desc()).limit(limit).all()
        finally:
            session.close()
    
    def get_findings_for_scan(self, scan_db_id: int) -> List[Finding]:
        """Get all findings for a scan."""
        session = self.get_session()
        try:
            return session.query(Finding).filter(Finding.scan_id == scan_db_id).all()
        finally:
            session.close()
    
    def get_finding_by_id(self, finding_db_id: int) -> Optional[Finding]:
        """Get a finding by database ID."""
        session = self.get_session()
        try:
            return session.query(Finding).filter(Finding.id == finding_db_id).first()
        finally:
            session.close()
    
    def get_remediations_for_finding(self, finding_db_id: int) -> List[Remediation]:
        """Get all remediations for a finding."""
        session = self.get_session()
        try:
            return session.query(Remediation).filter(Remediation.finding_id == finding_db_id).order_by(Remediation.created_at.desc()).all()
        finally:
            session.close()
    
    def mark_finding_resolved(self, finding_db_id: int) -> Optional[Finding]:
        """Mark a finding as resolved."""
        session = self.get_session()
        try:
            finding = session.query(Finding).filter(Finding.id == finding_db_id).first()
            if finding:
                finding.is_resolved = True
                finding.resolved_at = datetime.utcnow()
                session.commit()
                session.refresh(finding)
            return finding
        finally:
            session.close()
    
    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and all related data."""
        session = self.get_session()
        try:
            scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
            if scan:
                session.delete(scan)
                session.commit()
                return True
            return False
        finally:
            session.close()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get overall statistics."""
        session = self.get_session()
        try:
            total_scans = session.query(Scan).count()
            total_findings = session.query(Finding).count()
            resolved_findings = session.query(Finding).filter(Finding.is_resolved == True).count()
            
            # Count by priority
            critical = session.query(Finding).filter(Finding.priority == 'CRITICAL').count()
            high = session.query(Finding).filter(Finding.priority == 'HIGH').count()
            medium = session.query(Finding).filter(Finding.priority == 'MEDIUM').count()
            
            return {
                'total_scans': total_scans,
                'total_findings': total_findings,
                'resolved_findings': resolved_findings,
                'open_findings': total_findings - resolved_findings,
                'by_priority': {
                    'CRITICAL': critical,
                    'HIGH': high,
                    'MEDIUM': medium
                }
            }
        finally:
            session.close()


# Global database manager instance
_db_manager = None


def get_db_manager() -> DatabaseManager:
    """Get the global database manager instance."""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
        _db_manager.create_tables()
    return _db_manager


if __name__ == "__main__":
    # Test the database
    print("Testing Database Manager...")
    
    import uuid
    
    db = get_db_manager()
    
    # Create a test scan
    test_scan_id = str(uuid.uuid4())[:8]
    print(f"\nCreating scan: {test_scan_id}")
    
    scan = db.create_scan(test_scan_id, account_id='123456789012')
    print(f"Scan created with DB ID: {scan.id}")
    
    # Add a finding
    finding_data = {
        'finding_id': 'test-finding-001',
        'vulnerability_type': 'WILDCARD_ADMIN',
        'title': 'Wildcard Admin Access',
        'priority': 'CRITICAL',
        'description': 'Test finding',
        'resource_type': 'IAM Policy',
        'resource_name': 'TestPolicy',
        'resource_arn': 'arn:aws:iam::123456789012:policy/TestPolicy',
        'affected_policy': {'Version': '2012-10-17', 'Statement': []},
        'recommendation': 'Fix the policy',
        'details': {'test': True}
    }
    
    finding = db.add_finding(scan.id, finding_data)
    print(f"Finding created with DB ID: {finding.id}")
    
    # Complete the scan
    db.complete_scan(test_scan_id, {'total': 1, 'CRITICAL': 1, 'HIGH': 0, 'MEDIUM': 0})
    print("Scan completed")
    
    # Get stats
    stats = db.get_stats()
    print(f"\nDatabase Stats: {json.dumps(stats, indent=2)}")
    
    # Cleanup
    db.delete_scan(test_scan_id)
    print(f"\nTest scan deleted")
