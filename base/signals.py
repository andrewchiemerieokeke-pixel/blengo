# signals.py
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User  # IMPORT THIS
from .models import Wallet

@receiver(post_save, sender=User)
def create_user_wallet(sender, instance, created, **kwargs):
    """Create a wallet automatically when a new user is created"""
    if created:
        Wallet.objects.get_or_create(user=instance)