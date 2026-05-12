"""
Django management command to delete expired OTPs.
Run this periodically using cron job or Django celery beat.
"""

from django.core.management.base import BaseCommand
from django.utils import timezone
from apps.accounts.models import OTPVerification


class Command(BaseCommand):
    help = 'Delete expired OTP codes from the database'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting',
        )

    def handle(self, *args, **options):
        dry_run = options.get('dry_run', False)
        
        # Find expired OTPs
        expired_otps = OTPVerification.objects.filter(
            expires_at__lt=timezone.now()
        )
        
        count = expired_otps.count()
        
        if dry_run:
            self.stdout.write(
                self.style.WARNING(f'[DRY RUN] Would delete {count} expired OTP(s)')
            )
            for otp in expired_otps[:10]:  # Show first 10
                self.stdout.write(
                    f'  - OTP for {otp.user.email} (expired at {otp.expires_at})'
                )
        else:
            expired_otps.delete()
            self.stdout.write(
                self.style.SUCCESS(f'Successfully deleted {count} expired OTP(s)')
            )
