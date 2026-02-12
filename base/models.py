from django.contrib.auth.models import User
from django.db import models
import os
from django.utils.timezone import now 
class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    referral_code = models.CharField(max_length=150, unique=True)  # Increased max_length
    referred_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='referrals')
    total_referrals = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def save(self, *args, **kwargs):
        # Generate referral code from username if not set
        if not self.referral_code and self.user:
            # Use username as referral code
            self.referral_code = self.user.username.upper()
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.user.username}'s Profile"
    
    class Meta:
        verbose_name = 'User Profile'
        verbose_name_plural = 'User Profiles'

class RegistrationFee(models.Model):
    image_upload = models.ImageField(upload_to='registration_fees/')
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE)
    date_uploaded = models.DateTimeField(auto_now_add=True)
    confirmed = models.BooleanField(default=False)
    image_cleared = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.uploaded_by.username} - {self.confirmed}"
    
class AccountDetail(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='account_details')
    bank_name = models.CharField(max_length=100)
    account_name = models.CharField(max_length=100)
    account_number = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['-updated_at']
    
    def __str__(self):
        return f"{self.bank_name} - {self.account_name}"
    
class Wallet(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='wallet')
    balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "Wallet"
        verbose_name_plural = "Wallets"
        ordering = ['-updated_at']
    
    def __str__(self):
        return f"{self.user.username}'s Wallet - ₦{self.balance}"

class Transaction(models.Model):
    TRANSACTION_TYPES = (
        ('deposit', 'Deposit'),
        ('withdrawal', 'Withdrawal'),
        ('bonus', 'Bonus'),
    )
    
    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name='transactions')
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPES)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    description = models.TextField(blank=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.transaction_type} - ₦{self.amount} - {self.wallet.user.username}"
    



class Thrifts(models.Model):
    thriftname = models.CharField(max_length=200)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.thriftname
    
    @property
    def max_images(self):
        """Returns max images allowed for this package type"""
        if 'basic' in self.thriftname:
            return 12
        elif 'plus' in self.thriftname:
            return 12
        elif 'max' in self.thriftname:
            return 1
class UserPurchase(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='purchases')
    thrift = models.ForeignKey(Thrifts, on_delete=models.CASCADE, related_name='purchases')
    purchase_id = models.CharField(max_length=20, unique=True)
    plan_type = models.CharField(max_length=20)
    interest_rate = models.CharField(max_length=10)
    price_range = models.CharField(max_length=50)
    purchased_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, default='pending')  # pending, awaiting_approval, active, completed, cancelled
    
    def __str__(self):
        return f"{self.user.username} - {self.thrift.thriftname} - {self.purchase_id}"
    
    def save(self, *args, **kwargs):
        if not self.purchase_id:
            # Generate a unique 8-character purchase ID
            import random
            import string
            while True:
                purchase_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
                if not UserPurchase.objects.filter(purchase_id=purchase_id).exists():
                    self.purchase_id = purchase_id
                    break
        super().save(*args, **kwargs)
        
def get_package_image_upload_path(instance, filename):
    ext = filename.split('.')[-1]
    filename = f"package_{instance.id}_{now().timestamp()}.{ext}"
    return os.path.join("packages/", filename)

class PaymentImage(models.Model):
    purchase = models.ForeignKey(UserPurchase, on_delete=models.CASCADE, related_name='payment_images')
    image = models.ImageField(upload_to=get_package_image_upload_path)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    is_approved = models.BooleanField(default=False)
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_images')
    approved_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-uploaded_at']
    
    def __str__(self):
        return f"Payment for {self.purchase.purchase_id} - {self.uploaded_at}"
    
class ContactMessage(models.Model):
    name = models.CharField(max_length=100, blank=True)
    email = models.EmailField()
    message = models.TextField()
    submitted_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return f"{self.email} - {self.submitted_at.strftime('%Y-%m-%d %H:%M')}"