from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponseTooManyRequests
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django_ratelimit.decorators import ratelimit
from django_ratelimit.exceptions import Ratelimited
from django.utils.decorators import method_decorator
from django.views import View
from .models import RequestLog, BlockedIP, SuspiciousIP
import json
import logging

logger = logging.getLogger(__name__)


# Custom rate limit handler
def ratelimited(request, exception):
    """Custom handler for rate limit exceeded"""
    return HttpResponseTooManyRequests(
        "Rate limit exceeded. Please try again later.",
        content_type="text/plain"
    )


@ratelimit(key='ip', rate='5/m', method='POST', block=True)
@csrf_exempt
@require_http_methods(["GET", "POST"])
def login_view(request):
    """
    Login view with rate limiting
    - Anonymous users: 5 requests per minute
    - This is applied to both GET and POST requests to the login endpoint
    """
    if request.method == 'GET':
        return render(request, 'login.html')
    
    elif request.method == 'POST':
        try:
            data = json.loads(request.body) if request.content_type == 'application/json' else request.POST
            username = data.get('username')
            password = data.get('password')
            
            if not username or not password:
                return JsonResponse({
                    'success': False, 
                    'error': 'Username and password required'
                }, status=400)
            
            user = authenticate(request, username=username, password=password)
            
            if user is not None:
                login(request, user)
                logger.info(f"Successful login for user {username} from IP {getattr(request, 'client_ip', 'unknown')}")
                return JsonResponse({'success': True, 'message': 'Login successful'})
            else:
                logger.warning(f"Failed login attempt for user {username} from IP {getattr(request, 'client_ip', 'unknown')}")
                return JsonResponse({
                    'success': False, 
                    'error': 'Invalid credentials'
                }, status=401)
                
        except json.JSONDecodeError:
            return JsonResponse({
                'success': False, 
                'error': 'Invalid JSON'
            }, status=400)
        except Exception as e:
            logger.error(f"Login error: {e}")
            return JsonResponse({
                'success': False, 
                'error': 'Internal server error'
            }, status=500)


@ratelimit(key='user', rate='10/m', method=['GET', 'POST'], block=True)
@login_required
def dashboard_view(request):
    """
    Dashboard view with rate limiting for authenticated users
    - Authenticated users: 10 requests per minute
    """
    try:
        # Get some basic stats
        total_requests = RequestLog.objects.count()
        blocked_ips_count = BlockedIP.objects.count()
        suspicious_ips_count = SuspiciousIP.objects.filter(is_resolved=False).count()
        
        # Recent requests
        recent_requests = RequestLog.objects.order_by('-timestamp')[:10]
        
        context = {
            'total_requests': total_requests,
            'blocked_ips_count': blocked_ips_count,
            'suspicious_ips_count': suspicious_ips_count,
            'recent_requests': recent_requests,
            'user_ip': getattr(request, 'client_ip', 'unknown')
        }
        
        return render(request, 'dashboard.html', context)
    
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return JsonResponse({
            'error': 'Failed to load dashboard'
        }, status=500)


@ratelimit(key='ip', rate='20/m', method='GET', block=True)
def api_stats(request):
    """
    API endpoint to get IP tracking stats
    - Rate limited to 20 requests per minute per IP
    """
    try:
        # Get request count by country
        from django.db import connection
        
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT country, COUNT(*) as count 
                FROM request_logs 
                WHERE country IS NOT NULL 
                GROUP BY country 
                ORDER BY count DESC 
                LIMIT 10
            """)
            country_stats = [
                {'country': row[0], 'count': row[1]} 
                for row in cursor.fetchall()
            ]
        
        # Get hourly request counts for the last 24 hours
        from django.utils import timezone
        from datetime import timedelta
        
        last_24h = timezone.now() - timedelta(hours=24)
        hourly_requests = RequestLog.objects.filter(
            timestamp__gte=last_24h
        ).extra({
            'hour': "date_trunc('hour', timestamp)"
        }).values('hour').annotate(
            count=models.Count('id')
        ).order_by('hour')
        
        return JsonResponse({
            'country_stats': country_stats,
            'hourly_requests': list(hourly_requests),
            'total_requests': RequestLog.objects.count(),
            'unique_ips': RequestLog.objects.values('ip_address').distinct().count()
        })
        
    except Exception as e:
        logger.error(f"API stats error: {e}")
        return JsonResponse({'error': 'Failed to get stats'}, status=500)


class AdminIPManagementView(View):
    """
    Admin view for IP management with enhanced rate limiting
    """
    
    @method_decorator(login_required)
    @method_decorator(ratelimit(key='user', rate='30/m', method='GET', block=True))
    def get(self, request):
        """Get blocked and suspicious IPs"""
        try:
            blocked_ips = BlockedIP.objects.all().order_by('-created_at')
            suspicious_ips = SuspiciousIP.objects.filter(
                is_resolved=False
            ).order_by('-flagged_at')
            
            context = {
                'blocked_ips': blocked_ips,
                'suspicious_ips': suspicious_ips
            }
            return render(request, 'admin_ips.html', context)
            
        except Exception as e:
            logger.error(f"Admin IP management error: {e}")
            return JsonResponse({'error': 'Failed to load IP management'}, status=500)
    
    @method_decorator(login_required)
    @method_decorator(ratelimit(key='user', rate='10/m', method='POST', block=True))
    def post(self, request):
        """Block or unblock IP addresses"""
        try:
            action = request.POST.get('action')
            ip_address = request.POST.get('ip_address')
            reason = request.POST.get('reason', 'Blocked by admin')
            
            if not action or not ip_address:
                return JsonResponse({
                    'success': False, 
                    'error': 'Action and IP address required'
                }, status=400)
            
            if action == 'block':
                blocked_ip, created = BlockedIP.objects.get_or_create(
                    ip_address=ip_address,
                    defaults={'reason': reason}
                )
                if created:
                    return JsonResponse({
                        'success': True, 
                        'message': f'IP {ip_address} blocked successfully'
                    })
                else:
                    return JsonResponse({
                        'success': False, 
                        'error': f'IP {ip_address} is already blocked'
                    })
            
            elif action == 'unblock':
                deleted_count = BlockedIP.objects.filter(ip_address=ip_address).delete()[0]
                if deleted_count > 0:
                    return JsonResponse({
                        'success': True, 
                        'message': f'IP {ip_address} unblocked successfully'
                    })
                else:
                    return JsonResponse({
                        'success': False, 
                        'error': f'IP {ip_address} not found in blocklist'
                    })
            
            else:
                return JsonResponse({
                    'success': False, 
                    'error': 'Invalid action'
                }, status=400)
                
        except Exception as e:
            logger.error(f"Admin IP action error: {e}")
            return JsonResponse({
                'success': False, 
                'error': 'Internal server error'
            }, status=500)