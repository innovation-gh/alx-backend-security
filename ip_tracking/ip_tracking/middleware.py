import logging
from django.http import HttpResponseForbidden
from django.core.cache import cache
from django.utils.deprecation import MiddlewareMixin
from django.db import transaction
from .models import RequestLog, BlockedIP
import requests
import json

logger = logging.getLogger(__name__)


class IPTrackingMiddleware(MiddlewareMixin):
    """Middleware for IP tracking, logging, and blocking"""
    
    def get_client_ip(self, request):
        """Extract client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def get_geolocation(self, ip_address):
        """Get geolocation data for IP address with caching"""
        cache_key = f"geo_{ip_address}"
        cached_data = cache.get(cache_key)
        
        if cached_data:
            return cached_data
        
        # Skip geolocation for private/local IPs
        if (ip_address.startswith('127.') or 
            ip_address.startswith('192.168.') or 
            ip_address.startswith('10.') or 
            ip_address == '::1'):
            geo_data = {'country': 'Local', 'city': 'Local'}
        else:
            try:
                # Using ip-api.com as it's free and doesn't require API key
                response = requests.get(
                    f'http://ip-api.com/json/{ip_address}',
                    timeout=5
                )
                if response.status_code == 200:
                    data = response.json()
                    geo_data = {
                        'country': data.get('country', 'Unknown'),
                        'city': data.get('city', 'Unknown')
                    }
                else:
                    geo_data = {'country': 'Unknown', 'city': 'Unknown'}
            except Exception as e:
                logger.warning(f"Geolocation lookup failed for {ip_address}: {e}")
                geo_data = {'country': 'Unknown', 'city': 'Unknown'}
        
        # Cache for 24 hours (86400 seconds)
        cache.set(cache_key, geo_data, 86400)
        return geo_data
    
    def is_blocked(self, ip_address):
        """Check if IP address is in the blacklist"""
        cache_key = f"blocked_{ip_address}"
        cached_result = cache.get(cache_key)
        
        if cached_result is not None:
            return cached_result
        
        try:
            blocked = BlockedIP.objects.filter(ip_address=ip_address).exists()
            # Cache the result for 10 minutes to reduce database queries
            cache.set(cache_key, blocked, 600)
            return blocked
        except Exception as e:
            logger.error(f"Error checking blocked IP {ip_address}: {e}")
            return False
    
    def process_request(self, request):
        """Process incoming request for IP tracking and blocking"""
        ip_address = self.get_client_ip(request)
        
        # Skip processing for certain paths to avoid noise
        skip_paths = ['/favicon.ico', '/robots.txt', '/static/', '/media/']
        if any(request.path.startswith(path) for path in skip_paths):
            return None
        
        # Check if IP is blocked
        if self.is_blocked(ip_address):
            logger.warning(f"Blocked IP attempt: {ip_address} trying to access {request.path}")
            return HttpResponseForbidden("Your IP address has been blocked.")
        
        # Get geolocation data
        geo_data = self.get_geolocation(ip_address)
        
        # Log the request (use transaction to handle potential database issues)
        try:
            with transaction.atomic():
                RequestLog.objects.create(
                    ip_address=ip_address,
                    path=request.path,
                    country=geo_data['country'],
                    city=geo_data['city']
                )
        except Exception as e:
            logger.error(f"Failed to log request from {ip_address}: {e}")
        
        # Add IP to request for use in views
        request.client_ip = ip_address
        
        return None
    
    def process_response(self, request, response):
        """Process response (optional logging)"""
        # You can add additional logging here if needed
        return response