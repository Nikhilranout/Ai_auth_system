from django.db import migrations


def activate_staff_superusers(apps, schema_editor):
    User = apps.get_model('accounts', 'User')
    User.objects.filter(is_staff=True).update(
        is_active=True,
        email_verified=True,
        is_email_verified=True,
    )
    User.objects.filter(is_superuser=True).update(
        is_active=True,
        email_verified=True,
        is_email_verified=True,
        role='admin',
    )


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_user_is_email_verified_alter_user_is_active'),
    ]

    operations = [
        migrations.RunPython(activate_staff_superusers, noop),
    ]
