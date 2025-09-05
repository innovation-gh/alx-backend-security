import os
from django.core.management.base import BaseCommand, CommandError
from django.core.cache import cache
from ip_tracking.models import BlockedIP


class Command(BaseCommand):
    help = 'Block or unblock IP addresses'

    def add_arguments(self, parser):
        parser.add_argument(
            'action',
            choices=['block', 'unblock', 'list'],
            help='Action to perform: block, unblock, or list blocked IPs'
        )
        parser.add_argument(
            '--ip',
            type=str,
            help='IP address to block or unblock'
        )
        parser.add_argument(
            '--reason',
            type=str,
            default='Blocked by administrator',
            help='Reason for blocking the IP address'
        )
        parser.add_argument(
            '--file',
            type=str,
            help='File containing list of IP addresses to block (one per line)'
        )

    def handle(self, *args, **options):
        action = options['action']
        
        if action == 'block':
            self.handle_block(options)
        elif action == 'unblock':
            self.handle_unblock(options)
        elif action == 'list':
            self.handle_list()

    def handle_block(self, options):
        """Block IP addresses"""
        ip_addresses = []
        
        if options['ip']:
            ip_addresses.append(options['ip'])
        
        if options['file']:
            if not os.path.exists(options['file']):
                raise CommandError(f"File '{options['file']}' does not exist.")
            
            try:
                with open(options['file'], 'r') as f:
                    for line in f:
                        ip = line.strip()
                        if ip and not ip.startswith('#'):  # Skip comments and empty lines
                            ip_addresses.append(ip)
            except IOError as e:
                raise CommandError(f"Error reading file '{options['file']}': {e}")
        
        if not ip_addresses:
            raise CommandError("Please provide either --ip or --file option")
        
        blocked_count = 0
        already_blocked = 0
        
        for ip in ip_addresses:
            try:
                blocked_ip, created = BlockedIP.objects.get_or_create(
                    ip_address=ip,
                    defaults={'reason': options['reason']}
                )
                
                if created:
                    # Clear cache for this IP
                    cache.delete(f"blocked_{ip}")
                    blocked_count += 1
                    self.stdout.write(
                        self.style.SUCCESS(f"Successfully blocked IP: {ip}")
                    )
                else:
                    already_blocked += 1
                    self.stdout.write(
                        self.style.WARNING(f"IP already blocked: {ip}")
                    )
                    
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"Error blocking IP {ip}: {e}")
                )
        
        self.stdout.write(
            self.style.SUCCESS(
                f"\nSummary: {blocked_count} IPs blocked, "
                f"{already_blocked} already blocked"
            )
        )

    def handle_unblock(self, options):
        """Unblock IP addresses"""
        if not options['ip']:
            raise CommandError("Please provide --ip option for unblocking")
        
        ip = options['ip']
        
        try:
            blocked_ip = BlockedIP.objects.get(ip_address=ip)
            blocked_ip.delete()
            
            # Clear cache for this IP
            cache.delete(f"blocked_{ip}")
            
            self.stdout.write(
                self.style.SUCCESS(f"Successfully unblocked IP: {ip}")
            )
        except BlockedIP.DoesNotExist:
            self.stdout.write(
                self.style.WARNING(f"IP not found in blocklist: {ip}")
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f"Error unblocking IP {ip}: {e}")
            )

    def handle_list(self):
        """List all blocked IP addresses"""
        blocked_ips = BlockedIP.objects.all().order_by('-created_at')
        
        if not blocked_ips:
            self.stdout.write("No blocked IP addresses found.")
            return
        
        self.stdout.write(f"\nTotal blocked IPs: {blocked_ips.count()}\n")
        self.stdout.write(f"{'IP Address':<15} {'Blocked At':<20} {'Reason'}")
        self.stdout.write("-" * 60)
        
        for blocked_ip in blocked_ips:
            reason = (blocked_ip.reason[:30] + "...") if len(blocked_ip.reason) > 30 else blocked_ip.reason
            self.stdout.write(
                f"{blocked_ip.ip_address:<15} "
                f"{blocked_ip.created_at.strftime('%Y-%m-%d %H:%M'):<20} "
                f"{reason}"
            )