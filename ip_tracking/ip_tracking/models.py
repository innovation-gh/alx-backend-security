from django.db import models
from django.utils import timezone


class RequestLog(models.Model):
    """Model to log all incoming requests with IP, timestamp, path, and geolocation data"""
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(default=timezone.now)
    path = models.CharField(max_length=500)
    country = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    
    class Meta:
        db_table = 'request_logs'
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.ip_address} - {self.path} - {self.timestamp}"


class BlockedIP(models.Model):
    """Model to store blacklisted IP addresses"""
    ip_address = models.GenericIPAddressField(unique=True)
    created_at = models.DateTimeField(default=timezone.now)
    reason = models.TextField(blank=True, null=True)
    
    class Meta:
        db_table = 'blocked_ips'
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"
    
    def __str__(self):
        return self.ip_address


class SuspiciousIP(models.Model):
    """Model to flag suspicious IP addresses detected by anomaly detection"""
    ip_address = models.GenericIPAddressField()
    reason = models.TextField()
    flagged_at = models.DateTimeField(default=timezone.now)
    is_resolved = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'suspicious_ips'
        ordering = ['-flagged_at']
    
    def __str__(self):
        return f"{self.ip_address} - {self.reason[:50]}..."