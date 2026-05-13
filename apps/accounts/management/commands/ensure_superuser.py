"""
Create or update a superuser from environment variables.
Useful for first-time deployment environments such as Render.
"""

import os

from django.core.management.base import BaseCommand, CommandError

from apps.accounts.models import User


class Command(BaseCommand):
    help = 'Create or update a superuser from ADMIN_EMAIL, ADMIN_PASSWORD, and ADMIN_USERNAME.'

    def handle(self, *args, **options):
        email = os.getenv('ADMIN_EMAIL', '').strip()
        password = os.getenv('ADMIN_PASSWORD', '').strip()
        username = os.getenv('ADMIN_USERNAME', 'admin').strip() or 'admin'

        if not email or not password:
            raise CommandError('ADMIN_EMAIL and ADMIN_PASSWORD must be set.')

        user = User.objects.filter(email=email).first()

        if user is None:
            user = User.objects.create_superuser(
                email=email,
                password=password,
                username=username,
            )
            self.stdout.write(self.style.SUCCESS(f'Created superuser: {email}'))
            return

        changed = False

        if user.username != username:
            user.username = username
            changed = True
        if not user.is_active:
            user.is_active = True
            changed = True
        if not user.is_staff:
            user.is_staff = True
            changed = True
        if not user.is_superuser:
            user.is_superuser = True
            changed = True
        if not user.is_email_verified:
            user.is_email_verified = True
            changed = True
        if not user.email_verified:
            user.email_verified = True
            changed = True
        if user.role != 'admin':
            user.role = 'admin'
            changed = True

        user.set_password(password)
        changed = True

        if changed:
            user.save()
            self.stdout.write(self.style.SUCCESS(f'Updated superuser: {email}'))
        else:
            self.stdout.write(self.style.SUCCESS(f'Superuser already ready: {email}'))
