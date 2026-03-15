"""
SENTINEL Alert Service

Enterprise-grade alerting and notification service with support for
multiple notification channels (email, Slack, webhooks) and
comprehensive alert lifecycle management.
"""
import os
import json
import time
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
import logging
import redis
from enum import Enum
from typing import Dict, List, Optional, Any
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from concurrent.futures import ThreadPoolExecutor
import requests

# Initialize Flask app
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": os.environ.get('CORS_ORIGINS', '*').split(',')}})

# Configuration
app.config['REDIS_URL'] = os.environ.get('REDIS_URL', 'redis://localhost:6379')
app.config['SMTP_HOST'] = os.environ.get('SMTP_HOST', 'localhost')
app.config['SMTP_PORT'] = int(os.environ.get('SMTP_PORT', '587'))
app.config['SMTP_USER'] = os.environ.get('SMTP_USER', '')
app.config['SMTP_PASSWORD'] = os.environ.get('SMTP_PASSWORD', '')
app.config['SMTP_USE_TLS'] = os.environ.get('SMTP_USE_TLS', 'true').lower() == 'true'
app.config['NOTIFICATION_EMAIL'] = os.environ.get('NOTIFICATION_EMAIL', 'admin@example.com')
app.config['SLACK_WEBHOOK_URL'] = os.environ.get('SLACK_WEBHOOK_URL', '')

# Redis with connection pooling
redis_pool = redis.ConnectionPool.from_url(
    app.config['REDIS_URL'],
    max_connections=int(os.environ.get('REDIS_MAX_CONNECTIONS', '20'))
)
redis_client = redis.Redis(connection_pool=redis_pool, decode_responses=True)

# Thread pool for async notifications
notification_executor = ThreadPoolExecutor(max_workers=4)

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Enums
class AlertSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AlertStatus(Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    IGNORED = "ignored"

class AlertType(Enum):
    NETWORK_ANOMALY = "network_anomaly"
    BRUTE_FORCE = "brute_force"
    MALWARE_DETECTED = "malware_detected"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    SYSTEM_VULNERABILITY = "system_vulnerability"
    CONFIGURATION_CHANGE = "configuration_change"
    PERFORMANCE_ISSUE = "performance_issue"

class AlertEngine:
    def __init__(self):
        self.alert_thresholds = {
            AlertType.NETWORK_ANOMALY: AlertSeverity.MEDIUM,
            AlertType.BRUTE_FORCE: AlertSeverity.HIGH,
            AlertType.MALWARE_DETECTED: AlertSeverity.CRITICAL,
            AlertType.UNAUTHORIZED_ACCESS: AlertSeverity.HIGH,
            AlertType.SYSTEM_VULNERABILITY: AlertSeverity.MEDIUM,
            AlertType.CONFIGURATION_CHANGE: AlertSeverity.LOW,
            AlertType.PERFORMANCE_ISSUE: AlertSeverity.MEDIUM
        }

        # Notification channels
        self.notification_channels = {
            'email': self.send_email_notification,
            'slack': self.send_slack_notification,
            'webhook': self.send_webhook_notification
        }

    def create_alert(self, alert_data: Dict) -> str:
        """Create a new alert"""
        try:
            alert_id = f"alert_{int(time.time())}_{hash(str(alert_data)) % 10000}"

            alert_record = {
                'id': alert_id,
                'type': alert_data.get('type', 'unknown'),
                'severity': alert_data.get('severity', AlertSeverity.MEDIUM.value),
                'status': AlertStatus.NEW.value,
                'timestamp': datetime.utcnow().isoformat(),
                'description': alert_data.get('description', ''),
                'details': json.dumps(alert_data.get('details', {})),
                'source': alert_data.get('source', 'system'),
                'assigned_to': alert_data.get('assigned_to'),
                'due_date': alert_data.get('due_date'),
                'correlation_id': alert_data.get('correlation_id'),
                'tags': json.dumps(alert_data.get('tags', []))
            }

            # Store alert in Redis
            redis_client.hset(f"alert:{alert_id}", mapping=alert_record)
            redis_client.sadd('alerts:all', alert_id)
            redis_client.sadd(f"alerts:severity:{alert_record['severity']}", alert_id)
            redis_client.sadd(f"alerts:status:new", alert_id)

            # Set TTL for alert data (30 days)
            redis_client.expire(f"alert:{alert_id}", 2592000)  # 30 days
            redis_client.expire(f"alerts:severity:{alert_record['severity']}", 2592000)
            redis_client.expire(f"alerts:status:new", 2592000)

            # Trigger notifications
            self.trigger_notifications(alert_record)

            logger.info(f"Created alert: {alert_id}")
            return alert_id

        except Exception as e:
            logger.error(f"Error creating alert: {e}")
            raise

    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Get specific alert details"""
        try:
            alert_data = redis_client.hgetall(f"alert:{alert_id}")
            if not alert_data:
                return None

            # decode_responses=True means values are already strings
            return {
                'id': alert_data.get('id', ''),
                'type': alert_data.get('type', ''),
                'severity': alert_data.get('severity', ''),
                'status': alert_data.get('status', ''),
                'timestamp': alert_data.get('timestamp', ''),
                'description': alert_data.get('description', ''),
                'details': json.loads(alert_data.get('details', '{}')),
                'source': alert_data.get('source', ''),
                'assigned_to': alert_data.get('assigned_to') if alert_data.get('assigned_to') else None,
                'due_date': alert_data.get('due_date') if alert_data.get('due_date') else None,
                'correlation_id': alert_data.get('correlation_id') if alert_data.get('correlation_id') else None,
                'tags': json.loads(alert_data.get('tags', '[]'))
            }

        except Exception as e:
            logger.error(f"Error retrieving alert: {e}")
            return None

    def get_alerts(self,
                   severity: Optional[str] = None,
                   status: Optional[str] = None,
                   limit: int = 100,
                   offset: int = 0) -> List[Dict]:
        """Get list of alerts with filters"""
        try:
            # Determine which set to query
            if severity and status:
                # Intersection of severity and status sets
                alert_ids = redis_client.sinter(
                    f"alerts:severity:{severity}",
                    f"alerts:status:{status}"
                )
            elif severity:
                alert_ids = redis_client.smembers(f"alerts:severity:{severity}")
            elif status:
                alert_ids = redis_client.smembers(f"alerts:status:{status}")
            else:
                alert_ids = redis_client.smembers('alerts:all')

            # Convert to list and apply pagination
            alert_ids_list = [aid.decode() for aid in alert_ids]
            alert_ids_list = alert_ids_list[offset:offset + limit]

            alerts = []
            for alert_id in alert_ids_list:
                alert = self.get_alert(alert_id)
                if alert:
                    alerts.append(alert)

            return alerts

        except Exception as e:
            logger.error(f"Error retrieving alerts: {e}")
            return []

    def update_alert_status(self, alert_id: str, new_status: AlertStatus, assigned_to: Optional[str] = None) -> bool:
        """Update alert status"""
        try:
            # Get current alert
            current_alert = self.get_alert(alert_id)
            if not current_alert:
                return False

            # Update status
            redis_client.hset(f"alert:{alert_id}", "status", new_status.value)

            # Update sets
            old_status = current_alert['status']
            redis_client.srem(f"alerts:status:{old_status}", alert_id)
            redis_client.sadd(f"alerts:status:{new_status.value}", alert_id)

            # Update assignment if provided
            if assigned_to:
                redis_client.hset(f"alert:{alert_id}", "assigned_to", assigned_to)

            logger.info(f"Updated alert {alert_id} status to {new_status.value}")
            return True

        except Exception as e:
            logger.error(f"Error updating alert status: {e}")
            return False

    def trigger_notifications(self, alert_record: Dict[str, Any]) -> None:
        """Trigger appropriate notifications for alert asynchronously."""
        try:
            # Determine notification priority based on severity
            severity = AlertSeverity(alert_record['severity'])

            # Email notification for high/critical alerts (async)
            if severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
                notification_executor.submit(self._send_email_async, alert_record)
                
            # Slack notification if configured (async)
            if app.config['SLACK_WEBHOOK_URL'] and severity == AlertSeverity.CRITICAL:
                notification_executor.submit(self._send_slack_async, alert_record)

            # Always log to console
            self.log_notification(alert_record)

        except Exception as e:
            logger.error(f"Error triggering notifications: {e}")

    def _send_email_async(self, alert_record: Dict[str, Any]) -> None:
        """Send email notification asynchronously."""
        try:
            if not app.config['SMTP_USER'] or not app.config['SMTP_PASSWORD']:
                logger.warning("SMTP credentials not configured, skipping email notification")
                return
                
            msg = MIMEMultipart('alternative')
            msg['From'] = app.config['SMTP_USER']
            msg['To'] = app.config['NOTIFICATION_EMAIL']
            msg['Subject'] = f"[{alert_record['severity'].upper()}] Security Alert: {alert_record['type']}"

            # Plain text version
            text_body = f"""
Security Alert - SENTINEL

ID: {alert_record['id']}
Type: {alert_record['type']}
Severity: {alert_record['severity']}
Timestamp: {alert_record['timestamp']}
Description: {alert_record['description']}

Details:
{json.dumps(json.loads(alert_record['details']) if isinstance(alert_record['details'], str) else alert_record['details'], indent=2)}

Please investigate immediately.
            """
            
            # HTML version
            html_body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; padding: 20px;">
                <div style="background-color: #f44336; color: white; padding: 15px; border-radius: 5px;">
                    <h2 style="margin: 0;">Security Alert - {alert_record['severity'].upper()}</h2>
                </div>
                <div style="padding: 20px; background-color: #f9f9f9; border-radius: 5px; margin-top: 10px;">
                    <p><strong>Alert ID:</strong> {alert_record['id']}</p>
                    <p><strong>Type:</strong> {alert_record['type']}</p>
                    <p><strong>Severity:</strong> <span style="color: #f44336;">{alert_record['severity'].upper()}</span></p>
                    <p><strong>Timestamp:</strong> {alert_record['timestamp']}</p>
                    <p><strong>Description:</strong> {alert_record['description']}</p>
                </div>
                <p style="color: #666; font-size: 12px; margin-top: 20px;">
                    This is an automated notification from SENTINEL Security Platform.
                </p>
            </body>
            </html>
            """

            msg.attach(MIMEText(text_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))

            with smtplib.SMTP(app.config['SMTP_HOST'], app.config['SMTP_PORT'], timeout=30) as server:
                if app.config['SMTP_USE_TLS']:
                    server.starttls()
                server.login(app.config['SMTP_USER'], app.config['SMTP_PASSWORD'])
                server.sendmail(app.config['SMTP_USER'], app.config['NOTIFICATION_EMAIL'], msg.as_string())

            logger.info(f"Email notification sent for alert {alert_record['id']}")

        except smtplib.SMTPException as e:
            logger.error(f"SMTP error sending email notification: {e}")
        except Exception as e:
            logger.error(f"Error sending email notification: {e}")

    def _send_slack_async(self, alert_record: Dict[str, Any]) -> None:
        """Send Slack notification asynchronously."""
        try:
            webhook_url = app.config['SLACK_WEBHOOK_URL']
            if not webhook_url:
                return
                
            severity_colors = {
                'low': '#36a64f',
                'medium': '#ffc107',
                'high': '#ff9800',
                'critical': '#f44336'
            }
            
            payload = {
                'attachments': [{
                    'color': severity_colors.get(alert_record['severity'], '#808080'),
                    'title': f"Security Alert: {alert_record['type']}",
                    'text': alert_record['description'],
                    'fields': [
                        {'title': 'Alert ID', 'value': alert_record['id'], 'short': True},
                        {'title': 'Severity', 'value': alert_record['severity'].upper(), 'short': True},
                        {'title': 'Timestamp', 'value': alert_record['timestamp'], 'short': True},
                        {'title': 'Source', 'value': alert_record['source'], 'short': True}
                    ],
                    'footer': 'SENTINEL Security Platform'
                }]
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            logger.info(f"Slack notification sent for alert {alert_record['id']}")
            
        except requests.RequestException as e:
            logger.error(f"Error sending Slack notification: {e}")
        except Exception as e:
            logger.error(f"Error sending Slack notification: {e}")

    def send_webhook_notification(self, alert_record: Dict[str, Any], webhook_url: str) -> bool:
        """Send webhook notification to custom endpoint."""
        try:
            response = requests.post(
                webhook_url,
                json=alert_record,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            response.raise_for_status()
            logger.info(f"Webhook notification sent for alert {alert_record['id']}")
            return True
        except Exception as e:
            logger.error(f"Error sending webhook notification: {e}")
            return False

    def log_notification(self, alert_record: Dict[str, Any]) -> None:
        """Log notification to console for development."""
        logger.info(f"ALERT NOTIFICATION: [{alert_record['severity']}] {alert_record['type']} - {alert_record['description']}")

# Initialize alert engine
alert_engine = AlertEngine()

# Flask routes
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat()
    }), 200

@app.route('/api/v1/alerts', methods=['GET'])
def get_alerts():
    """Get list of alerts"""
    try:
        severity = request.args.get('severity')
        status = request.args.get('status')
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))

        alerts = alert_engine.get_alerts(severity=severity, status=status, limit=limit, offset=offset)

        return jsonify({
            'alerts': alerts,
            'total': len(alerts),
            'limit': limit,
            'offset': offset
        }), 200

    except Exception as e:
        logger.error(f"Get alerts error: {e}")
        return jsonify({'error': 'Failed to retrieve alerts'}), 500

@app.route('/api/v1/alerts', methods=['POST'])
def create_alert():
    """Create a new alert"""
    try:
        data = request.get_json()

        if not data or 'type' not in data or 'description' not in data:
            return jsonify({'error': 'Missing required fields: type, description'}), 400

        alert_id = alert_engine.create_alert(data)

        return jsonify({
            'message': 'Alert created successfully',
            'alert_id': alert_id
        }), 201

    except Exception as e:
        logger.error(f"Create alert error: {e}")
        return jsonify({'error': 'Failed to create alert'}), 500

@app.route('/api/v1/alerts/<alert_id>', methods=['GET'])
def get_alert(alert_id):
    """Get specific alert details"""
    try:
        alert = alert_engine.get_alert(alert_id)
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404

        return jsonify(alert), 200

    except Exception as e:
        logger.error(f"Get alert error: {e}")
        return jsonify({'error': 'Failed to retrieve alert'}), 500

@app.route('/api/v1/alerts/<alert_id>', methods=['PUT'])
def update_alert(alert_id):
    """Update alert status or other properties"""
    try:
        data = request.get_json()
        new_status = data.get('status')

        if not new_status:
            return jsonify({'error': 'Status is required'}), 400

        try:
            status_enum = AlertStatus(new_status)
        except ValueError:
            return jsonify({'error': 'Invalid status value'}), 400

        success = alert_engine.update_alert_status(alert_id, status_enum, data.get('assigned_to'))

        if not success:
            return jsonify({'error': 'Alert not found'}), 404

        return jsonify({'message': 'Alert updated successfully'}), 200

    except Exception as e:
        logger.error(f"Update alert error: {e}")
        return jsonify({'error': 'Failed to update alert'}), 500

@app.route('/api/v1/alerts/<alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    """Acknowledge an alert"""
    try:
        success = alert_engine.update_alert_status(alert_id, AlertStatus.ACKNOWLEDGED)

        if not success:
            return jsonify({'error': 'Alert not found'}), 404

        return jsonify({'message': 'Alert acknowledged successfully'}), 200

    except Exception as e:
        logger.error(f"Acknowledge alert error: {e}")
        return jsonify({'error': 'Failed to acknowledge alert'}), 500

@app.route('/api/v1/alerts/<alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    """Resolve an alert"""
    try:
        success = alert_engine.update_alert_status(alert_id, AlertStatus.RESOLVED)

        if not success:
            return jsonify({'error': 'Alert not found'}), 404

        return jsonify({'message': 'Alert resolved successfully'}), 200

    except Exception as e:
        logger.error(f"Resolve alert error: {e}")
        return jsonify({'error': 'Failed to resolve alert'}), 500

@app.route('/api/v1/alerts/statistics', methods=['GET'])
def get_alert_statistics():
    """Get alert statistics"""
    try:
        # Get counts by severity
        severity_counts = {}
        for severity in AlertSeverity:
            count = redis_client.scard(f"alerts:severity:{severity.value}")
            severity_counts[severity.value] = count

        # Get counts by status
        status_counts = {}
        for status in AlertStatus:
            count = redis_client.scard(f"alerts:status:{status.value}")
            status_counts[status.value] = count

        # Get total count
        total_count = redis_client.scard('alerts:all')

        return jsonify({
            'total_alerts': total_count,
            'by_severity': severity_counts,
            'by_status': status_counts,
            'timestamp': datetime.utcnow().isoformat()
        }), 200

    except Exception as e:
        logger.error(f"Get alert statistics error: {e}")
        return jsonify({'error': 'Failed to retrieve alert statistics'}), 500

@app.route('/api/v1/alerts/types', methods=['GET'])
def get_alert_types():
    """Get available alert types"""
    return jsonify({
        'types': [atype.value for atype in AlertType],
        'severities': [asev.value for asev in AlertSeverity],
        'statuses': [astat.value for astat in AlertStatus]
    }), 200

if __name__ == '__main__':
    # For development only - use gunicorn in production
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    
    if debug_mode:
        logger.warning("Running in DEBUG mode - DO NOT use in production!")
        
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', '5002')),
        debug=debug_mode
    )