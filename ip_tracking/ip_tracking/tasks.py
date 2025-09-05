from celery import shared_task
from django.utils import timezone
from django.db import transaction
from datetime import timedelta
from collections import Counter
import logging
from .models import RequestLog, SuspiciousIP, BlockedIP

logger = logging.getLogger(__name__)


@shared_task
def detect_suspicious_ips():
    """
    Celery task to detect suspicious IP addresses
    Runs hourly to analyze request patterns and flag anomalies
    """
    try:
        logger.info("Starting suspicious IP detection task")
        
        # Get the last hour of requests
        one_hour_ago = timezone.now() - timedelta(hours=1)
        recent_requests = RequestLog.objects.filter(timestamp__gte=one_hour_ago)
        
        # Counter for requests per IP
        ip_request_counts = Counter()
        sensitive_path_access = {}
        
        # Define sensitive paths
        sensitive_paths = ['/admin', '/login', '/api/admin', '/dashboard/admin', 
                         '/wp-admin', '/phpmyadmin', '/admin.php', '/administrator']
        
        # Analyze requests
        for request in recent_requests:
            ip = request.ip_address
            path = request.path
            
            # Count requests per IP
            ip_request_counts[ip] += 1
            
            # Track sensitive path access
            if any(path.startswith(sensitive) for sensitive in sensitive_paths):
                if ip not in sensitive_path_access:
                    sensitive_path_access[ip] = []
                sensitive_path_access[ip].append(path)
        
        # Flag IPs with excessive requests (>100 per hour)
        flagged_ips = set()
        for ip, count in ip_request_counts.items():
            if count > 100:
                reason = f"Excessive requests: {count} requests in 1 hour (threshold: 100)"
                flag_suspicious_ip(ip, reason)
                flagged_ips.add(ip)
                logger.warning(f"Flagged IP {ip} for excessive requests: {count}")
        
        # Flag IPs accessing multiple sensitive paths
        for ip, paths in sensitive_path_access.items():
            unique_sensitive_paths = len(set(paths))
            total_sensitive_requests = len(paths)
            
            if unique_sensitive_paths >= 3 or total_sensitive_requests >= 10:
                reason = (f"Suspicious admin access: {total_sensitive_requests} requests "
                         f"to {unique_sensitive_paths} sensitive paths")
                flag_suspicious_ip(ip, reason)
                flagged_ips.add(ip)
                logger.warning(f"Flagged IP {ip} for suspicious admin access")
        
        # Additional anomaly detection patterns
        detect_rapid_requests(recent_requests, flagged_ips)
        detect_unusual_user_agents(recent_requests, flagged_ips)
        
        logger.info(f"Suspicious IP detection completed. Flagged {len(flagged_ips)} IPs")
        return {
            'status': 'success',
            'flagged_ips_count': len(flagged_ips),
            'flagged_ips': list(flagged_ips)
        }
        
    except Exception as e:
        logger.error(f"Error in suspicious IP detection task: {e}")
        return {'status': 'error', 'message': str(e)}


def flag_suspicious_ip(ip_address, reason):
    """Helper function to flag a suspicious IP"""
    try:
        # Check if IP is already blocked
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return
        
        # Check if already flagged with same reason in last 24 hours
        one_day_ago = timezone.now() - timedelta(days=1)
        existing_flag = SuspiciousIP.objects.filter(
            ip_address=ip_address,
            reason=reason,
            flagged_at__gte=one_day_ago
        ).first()
        
        if not existing_flag:
            with transaction.atomic():
                SuspiciousIP.objects.create(
                    ip_address=ip_address,
                    reason=reason
                )
            logger.info(f"Flagged suspicious IP: {ip_address} - {reason}")
    
    except Exception as e:
        logger.error(f"Error flagging suspicious IP {ip_address}: {e}")


def detect_rapid_requests(requests, flagged_ips):
    """Detect IPs making rapid sequential requests"""
    try:
        ip_timestamps = {}
        
        for request in requests.order_by('timestamp'):
            ip = request.ip_address
            timestamp = request.timestamp
            
            if ip not in ip_timestamps:
                ip_timestamps[ip] = []
            ip_timestamps[ip].append(timestamp)
        
        # Check for rapid requests (more than 10 requests in 1 minute)
        for ip, timestamps in ip_timestamps.items():
            if len(timestamps) < 10:
                continue
                
            for i in range(len(timestamps) - 9):
                time_window = timestamps[i+9] - timestamps[i]
                if time_window <= timedelta(minutes=1):
                    reason = "Rapid requests: 10+ requests within 1 minute"
                    flag_suspicious_ip(ip, reason)
                    flagged_ips.add(ip)
                    break
                    
    except Exception as e:
        logger.error(f"Error in rapid requests detection: {e}")


def detect_unusual_user_agents(requests, flagged_ips):
    """Detect unusual or suspicious user agents (placeholder for future enhancement)"""
    # This would require storing user agent in RequestLog model
    # For now, just a placeholder for future enhancement
    pass


@shared_task
def auto_block_persistent_suspicious_ips():
    """
    Auto-block IPs that have been flagged multiple times
    This task can run daily to automatically block repeat offenders
    """
    try:
        logger.info("Starting auto-block task for persistent suspicious IPs")
        
        # Get IPs flagged more than 3 times in the last 7 days
        seven_days_ago = timezone.now() - timedelta(days=7)
        
        from django.db.models import Count
        persistent_ips = (SuspiciousIP.objects
                         .filter(flagged_at__gte=seven_days_ago, is_resolved=False)
                         .values('ip_address')
                         .annotate(flag_count=Count('id'))
                         .filter(flag_count__gte=3))
        
        blocked_count = 0
        for ip_data in persistent_ips:
            ip_address = ip_data['ip_address']
            flag_count = ip_data['flag_count']
            
            # Check if already blocked
            if not BlockedIP.objects.filter(ip_address=ip_address).exists():
                with transaction.atomic():
                    BlockedIP.objects.create(
                        ip_address=ip_address,
                        reason=f"Auto-blocked: {flag_count} suspicious activity flags in 7 days"
                    )
                    
                    # Mark suspicious IP records as resolved
                    SuspiciousIP.objects.filter(
                        ip_address=ip_address,
                        is_resolved=False
                    ).update(is_resolved=True)
                    
                blocked_count += 1
                logger.warning(f"Auto-blocked IP {ip_address} after {flag_count} flags")
        
        logger.info(f"Auto-block task completed. Blocked {blocked_count} IPs")
        return {
            'status': 'success',
            'blocked_count': blocked_count
        }
        
    except Exception as e:
        logger.error(f"Error in auto-block task: {e}")
        return {'status': 'error', 'message': str(e)}


@shared_task
def cleanup_old_logs():
    """
    Clean up old request logs to prevent database bloat
    Removes logs older than 30 days
    """
    try:
        thirty_days_ago = timezone.now() - timedelta(days=30)
        
        deleted_count = RequestLog.objects.filter(
            timestamp__lt=thirty_days_ago
        ).delete()[0]
        
        logger.info(f"Cleaned up {deleted_count} old request logs")
        return {
            'status': 'success',
            'deleted_count': deleted_count
        }
        
    except Exception as e:
        logger.error(f"Error in cleanup task: {e}")
        return {'status': 'error', 'message': str(e)}


@shared_task
def generate_security_report():
    """
    Generate daily security report with statistics
    """
    try:
        logger.info("Generating daily security report")
        
        now = timezone.now()
        yesterday = now - timedelta(days=1)
        
        # Get statistics for the last 24 hours
        daily_requests = RequestLog.objects.filter(timestamp__gte=yesterday).count()
        unique_ips = (RequestLog.objects
                     .filter(timestamp__gte=yesterday)
                     .values('ip_address')
                     .distinct()
                     .count())
        
        new_suspicious_ips = SuspiciousIP.objects.filter(
            flagged_at__gte=yesterday
        ).count()
        
        new_blocked_ips = BlockedIP.objects.filter(
            created_at__gte=yesterday
        ).count()
        
        # Top countries by requests
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT country, COUNT(*) as count 
                FROM request_logs 
                WHERE timestamp >= %s AND country IS NOT NULL
                GROUP BY country 
                ORDER BY count DESC 
                LIMIT 5
            """, [yesterday])
            top_countries = cursor.fetchall()
        
        report = {
            'date': now.strftime('%Y-%m-%d'),
            'daily_requests': daily_requests,
            'unique_ips': unique_ips,
            'new_suspicious_ips': new_suspicious_ips,
            'new_blocked_ips': new_blocked_ips,
            'top_countries': top_countries
        }
        
        logger.info(f"Security report generated: {report}")
        
        # You can extend this to send email notifications, save to file, etc.
        return {
            'status': 'success',
            'report': report
        }
        
    except Exception as e:
        logger.error(f"Error generating security report: {e}")
        return {'status': 'error', 'message': str(e)}