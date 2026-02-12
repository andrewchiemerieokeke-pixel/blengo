from django.shortcuts import render,redirect,get_object_or_404
from django.http import Http404
from django.contrib import messages
from django.contrib.auth import login, authenticate
import re
from django.contrib.auth.models import User
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from .models import UserProfile,RegistrationFee,AccountDetail,Wallet,Transaction,Thrifts,UserPurchase,ContactMessage,PaymentImage  # Create this model first
from django.http import HttpResponseForbidden
from django.db.models import Q,Sum
import uuid
import os
from django.core.exceptions import ValidationError
#from axes.decorators import axes_dispatch
from django.contrib.auth import authenticate,login
from django.conf import settings
from django.core.files.storage import FileSystemStorage

from django.http import JsonResponse
from django.utils.timezone import now 
from django.utils import timezone

from django.views.decorators.csrf import csrf_exempt

from django_ratelimit.decorators import ratelimit





def custom_404(request, exception):
    return render(request, '404.html', status=404)






def home(request):
    context = {}
    thrift_count = Thrifts.objects.count()
    #purchase_count = UserPurchase.objects.filter(user=request.user).count()
    if request.user.is_authenticated:
        purchase_count = UserPurchase.objects.filter(user=request.user).count()
        context['purchase_count'] = purchase_count
    else:
        context['purchase_count'] = 0
    # Add purchase count for authenticated users
    #if request.user.is_authenticated:
        #purchase_count = Thrifts.objects.filter(user=request.user).count()
    #else:
        #purchase_count = 0
    
    # Add referral code from URL for signup form
    referral_code = request.GET.get('ref', '')
    if referral_code:
        context['referral_code'] = referral_code
    
    # Add thrift_count and purchase_count to context for ALL users
    context['thrift_count'] = thrift_count
    #context['purchase_count'] = purchase_count
    
    if request.user.is_authenticated:
        # Use get_or_create to ensure profile exists
        profile, created = UserProfile.objects.get_or_create(
            user=request.user,
            defaults={
                'referred_by': None,
                'total_referrals': 0,
                'referral_code': f"REF{request.user.username.upper()}{request.user.id}"
            }
        )
        
        # Get or create wallet for user
        wallet, wallet_created = Wallet.objects.get_or_create(
            user=request.user,
            defaults={'balance': Decimal('0.00')}
        )
        
        # Get user's transaction history
        transactions = Transaction.objects.filter(
            wallet=wallet
        ).select_related('created_by').order_by('-created_at')[:20]
        
        # Get user's purchases
        #purchases = Purchase.objects.filter(user=request.user).order_by('-datepurchased')
        
        # If profile was just created, save it to ensure referral_code is generated
        if created:
            profile.save()
        
        # Get users who were referred by this user
        referred_users = User.objects.filter(profile__referred_by=request.user)
        
        # Calculate referral statistics
        active_referrals = referred_users.filter(is_active=True).count()
        
        # Calculate earnings (assuming each active referral earns you 100)
        referral_earnings = active_referrals * 100
        pending_earnings = referred_users.filter(is_active=False).count() * 100
        
        # Prepare referred users data with their profiles
        referred_users_data = []
        for user in referred_users:
            try:
                user_profile = user.profile
                # Get earnings for this specific referral
                earned_amount = 100 if user.is_active else 0
                referred_users_data.append({
                    'user': user,
                    'user_profile': user_profile,
                    'earned_amount': earned_amount
                })
            except UserProfile.DoesNotExist:
                continue
        
        # Check if user has uploaded registration fee and if it's confirmed
        registration_fee = None
        registration_status = "inactive"
        
        try:
            registration_fee = RegistrationFee.objects.get(uploaded_by=request.user)
            if registration_fee.confirmed:
                registration_status = "active"
            else:
                registration_status = "pending"
        except RegistrationFee.DoesNotExist:
            registration_status = "inactive"
        
        context.update({
            'referral_count': profile.total_referrals,
            'user_profile': profile,
            'referred_users': referred_users_data,
            'active_referrals': active_referrals,
            'referral_earnings': referral_earnings,
            'pending_earnings': pending_earnings,
            'registration_fee': registration_fee,
            'registration_status': registration_status,
            'wallet_balance': wallet.balance,
            'transactions': transactions,
            'purchase_count': purchase_count, 
             # Add purchases to context
        })
    
    return render(request, 'home.html', context)




@login_required(login_url='sign-in')
def delete_transaction(request):
    try:
        transaction_id = request.POST.get('transaction_id')
        
        # Get the transaction
        transaction = get_object_or_404(Transaction, id=transaction_id)
        
        # Verify the transaction belongs to the user
        if transaction.wallet.user != request.user:
            messages.error(request, 'You are not authorized to delete this transaction.')
            return redirect('home')
        
        # Get the user's wallet
        wallet = transaction.wallet
        
        # Adjust wallet balance based on transaction type
        if transaction.transaction_type == 'deposit':
            # Remove the deposit amount
            wallet.balance -= transaction.amount
        elif transaction.transaction_type == 'withdrawal':
            # Add back the withdrawal amount
            wallet.balance += transaction.amount
        # For other types, no adjustment needed
        
        # Save the updated wallet balance
        wallet.save()
        
        # Store transaction details for the message before deleting
        transaction_details = {
            'type': transaction.transaction_type,
            'amount': transaction.amount,
            'new_balance': wallet.balance
        }
        
        # Delete the transaction
        transaction.delete()
        
        # Success message
        messages.success(request, 
            f'Successfully deleted {transaction_details["type"]} of ₦{transaction_details["amount"]:.2f}. '
            f'New wallet balance: ₦{transaction_details["new_balance"]:.2f}'
        )
        
    except Transaction.DoesNotExist:
        messages.error(request, 'Transaction not found.')
    except Exception as e:
        messages.error(request, f'An error occurred: {str(e)}')
    
    return redirect('home')


def sign_in(request):
    if request.user.is_authenticated:
        return redirect('home')
    else:
        if request.method == "POST":
            username = request.POST.get('username', '').strip().lower()
            password = request.POST.get('password', '')
            
            # Prepare context to preserve form data
            context = {
                'username': username,
            }
            
            # Basic validation
            if not username or not password:
                messages.error(request, 'Please fill in all fields')
                return render(request, 'sign-in.html', context)
            
            # Authenticate user
            user = authenticate(request, username=username, password=password)
            
            if user is not None:
                # Login successful
                login(request, user)
                #messages.success(request, f'Welcome back, {user.username}!')
                return redirect('home')
            else:
                # Login failed
                messages.error(request, 'Invalid username or password')
                return render(request, 'sign-in.html', context)
        
    # GET request - show empty form
    return render(request, 'sign-in.html')

def account_locked(request):
    return render(request, 'account_locked.html')

def create_account(request):
    if request.user.is_authenticated:
        
        messages.info(request, "You are already logged in and not authorized to access this page.")
        return redirect("home")
    else:
        if request.method == "POST":
            username = request.POST.get('username', '').strip().lower()
            email = request.POST.get('email', '').strip().lower()
            password = request.POST.get('password', '')
            confirmpassword = request.POST.get('confirmpassword', '')
            terms_accepted = request.POST.get('terms') == 'on'
            referral_code = request.POST.get('referral_code', '').strip()
            
            # Prepare context to preserve form data
            context = {
                'username': username,
                'email': email,
                'referral_code': referral_code,
            }

            # Validation checks
            if not terms_accepted:
                messages.error(request, 'You must accept the terms and conditions')
                return render(request, 'create-account.html', context)

            if len(password) < 8:
                messages.error(request, 'Password must be at least 8 characters long!')
                return render(request, 'create-account.html', context)

            if not re.search(r'[A-Z]', password):
                messages.error(request, 'Password must contain at least one uppercase letter!')
                return render(request, 'create-account.html', context)
            
            if not re.search(r'[a-z]', password):
                messages.error(request, 'Password must contain at least one lowercase letter!')
                return render(request, 'create-account.html', context)
            
            if not re.search(r'[0-9]', password):
                messages.error(request, 'Password must contain at least one number!')
                return render(request, 'create-account.html', context)

            if password != confirmpassword:
                messages.error(request, 'Passwords do not match!')
                return render(request, 'create-account.html', context)

            if User.objects.filter(username=username).exists():
                messages.error(request, 'Username already taken!')
                return render(request, 'create-account.html', context)

            if User.objects.filter(email=email).exists():
                messages.error(request, 'Email already in use!')
                return render(request, 'create-account.html', context)

            try:
                # Create user
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password
                )
                
                # Check if UserProfile already exists
                if UserProfile.objects.filter(user=user).exists():
                    # If it exists, get it instead of creating new
                    profile = UserProfile.objects.get(user=user)
                    messages.warning(request, 'Profile already exists for this user.')
                else:
                    # Create UserProfile - referral_code will be auto-generated from username in save() method
                    profile = UserProfile.objects.create(
                        user=user,
                        referred_by=None  # Will be updated if valid referral
                    )
                
                # Process referral if code is provided
                if referral_code:
                    try:
                        # Convert referral code to uppercase (since usernames are stored in lowercase)
                        referral_code_upper = referral_code.upper()
                        
                        # Find the user who referred this new user by their referral code (username)
                        referrer_profile = UserProfile.objects.get(referral_code=referral_code_upper)
                        
                        # Make sure user is not referring themselves
                        if referrer_profile.user != user:
                            # Update the new user's profile
                            profile.referred_by = referrer_profile.user
                            profile.save()
                            
                            # Update referrer's referral count
                            referrer_profile.total_referrals += 1
                            referrer_profile.save()
                            
                            messages.success(request, f'Successfully joined using referral code: {referral_code}')
                        else:
                            messages.info(request, 'You cannot refer yourself!')
                            
                    except UserProfile.DoesNotExist:
                        messages.info(request, f'Referral code "{referral_code}" not found. Account created without referral.')
                
                # Auto login after registration
                user = authenticate(request, username=username, password=password)
                if user is not None:
                    login(request, user)
                    messages.success(request, f'Account created successfully! Your referral code: {user.username.upper()}')
                    return redirect('home')
                else:
                    messages.error(request, 'Auto login failed. Please login manually.')
                    return redirect('sign-in')
                    
            except Exception as e:
                # Clean up: delete the user if profile creation failed
                if 'user' in locals() and user:
                    user.delete()
                messages.error(request, f'An error occurred: {str(e)}')
                return render(request, 'create-account.html', context)

        # GET request - check for referral code in URL
        referral_code = request.GET.get('ref', '')
        context = {'referral_code': referral_code}
        return render(request, 'create-account.html', context)

@login_required(login_url='sign-in')
def sign_out(request):
    """
    Log out the current user and redirect to sign-in page
    """
    logout(request)
    messages.success(request, 'You have been successfully logged out.')
    return redirect('sign-in')


# Allowed file extensions
ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.pdf']
# Max file size: 5MB
MAX_FILE_SIZE = 5 * 1024 * 1024

def validate_file_extension(file):
    """Validate file extension"""
    import os
    ext = os.path.splitext(file.name)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValidationError(f'Unsupported file type. Allowed types: {", ".join(ALLOWED_EXTENSIONS)}')

def validate_file_size(file):
    """Validate file size"""
    if file.size > MAX_FILE_SIZE:
        raise ValidationError(f'File too large. Max size: {MAX_FILE_SIZE//(1024*1024)}MB')
@login_required(login_url='sign-in')
def registration_fee(request):
    # Get ALL images (for admin view)
    all_images = RegistrationFee.objects.all().order_by('-date_uploaded')
    
    # Get the current user's uploaded receipt if exists
    user_receipt = RegistrationFee.objects.filter(uploaded_by=request.user).first()
    
    if request.method == 'POST':
        image_upload = request.FILES.get('image_upload')
        
        if image_upload:
            # === SECURITY CHECKS ===
            
            # 1. Validate file extension
            try:
                validate_file_extension(image_upload)
            except ValidationError as e:
                return render(request, 'registration-fee.html', {
                    'user_receipt': user_receipt,
                    'all_images': all_images,
                    'error': str(e)
                })
            
            # 2. Validate file size
            try:
                validate_file_size(image_upload)
            except ValidationError as e:
                return render(request, 'registration-fee.html', {
                    'user_receipt': user_receipt,
                    'all_images': all_images,
                    'error': str(e)
                })
            
            # 3. Validate file content
            if not is_valid_file_content(image_upload):
                return render(request, 'registration-fee.html', {
                    'user_receipt': user_receipt,
                    'all_images': all_images,
                    'error': 'Invalid or corrupted file. Please upload a valid image or PDF.'
                })
            
            # 4. Sanitize filename
            filename = sanitize_filename(image_upload.name)
            image_upload.name = filename
            
            # Check if user already uploaded a receipt
            existing_receipt = RegistrationFee.objects.filter(uploaded_by=request.user).first()
            
            # 5. Rate limiting
            recent_uploads = RegistrationFee.objects.filter(
                uploaded_by=request.user,
                date_uploaded__gte=timezone.now() - timedelta(hours=1)
            ).count()
            
            if recent_uploads >= 5:
                return render(request, 'registration-fee.html', {
                    'user_receipt': user_receipt,
                    'all_images': all_images,
                    'error': 'Too many upload attempts. Please try again later.'
                })
            
            # === FIXED: Use MEDIA_ROOT instead of SECURE_UPLOAD_ROOT ===
            # Store files in media/receipts/ which is served by Django
            
            try:
                if existing_receipt:
                    # Delete old file before saving new one
                    if existing_receipt.image_upload:
                        existing_receipt.image_upload.delete(save=False)
                    
                    # Save new file - Django will automatically save to MEDIA_ROOT/receipts/
                    existing_receipt.image_upload = image_upload
                    existing_receipt.date_uploaded = timezone.now()
                    existing_receipt.save()
                else:
                    # Create new receipt
                    RegistrationFee.objects.create(
                        image_upload=image_upload,
                        uploaded_by=request.user,
                        date_uploaded=timezone.now()
                    )
                
                return redirect('registration-fee')
                
            except Exception as e:
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"File upload failed for user {request.user.id}: {str(e)}")
                
                return render(request, 'registration-fee.html', {
                    'user_receipt': user_receipt,
                    'all_images': all_images,
                    'error': f'Upload failed: {str(e)}'
                })
    
    context = {
        'user_receipt': user_receipt,
        'all_images': all_images,
        'allowed_extensions': ALLOWED_EXTENSIONS,
        'max_file_size_mb': MAX_FILE_SIZE // (1024 * 1024),
    }
    return render(request, 'registration-fee.html', context)
def sanitize_filename(filename):
    """Remove special characters and spaces from filename"""
    import re
    from django.utils.text import slugify
    
    # Split filename and extension
    name, ext = os.path.splitext(filename)
    
    # Remove special characters and spaces
    name = slugify(name)
    if not name:  # If slugify returns empty string
        import uuid
        name = str(uuid.uuid4())[:8]
    
    # Add timestamp to prevent filename collision
    from datetime import datetime
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    return f"{name}_{timestamp}{ext}"

def is_valid_file_content(file):
    """
    Validate file content by checking magic bytes/signatures
    Prevents files with double extensions or malicious content
    """
    import imghdr
    import magic  # python-magic library
    
    # Read first 2048 bytes for validation
    file.seek(0)
    header = file.read(2048)
    file.seek(0)  # Reset file pointer
    
    # Check if it's actually an image
    if file.name.lower().endswith(('.jpg', '.jpeg', '.png', '.gif')):
        image_type = imghdr.what(None, h=header)
        if not image_type:
            return False
    
    # Use python-magic to detect mime type
    try:
        mime = magic.from_buffer(header, mime=True)
        
        # Allowed mime types
        allowed_mimes = [
            'image/jpeg', 'image/png', 'image/gif',
            'application/pdf', 'image/jpg'
        ]
        
        if mime not in allowed_mimes:
            return False
            
    except ImportError:
        # python-magic not installed, skip this check
        pass
    
    return True




@login_required(login_url='/sign-in/')
def manager(request):
    
    if request.user.username == 'manager':
        # Get all registration fees
        registration_fees = RegistrationFee.objects.select_related('uploaded_by').all()
        
        # Get confirmed fees count
        confirmed_fees = registration_fees.filter(confirmed=True).count()
        
        # Get pending fees count
        pending_fees = registration_fees.filter(confirmed=False).count()
        
        # Get total users count
        total_users = User.objects.count()
        
        # Get users who haven't uploaded registration fee
        users_with_fee = registration_fees.values_list('uploaded_by_id', flat=True)
        users_without_fee = User.objects.exclude(id__in=users_with_fee)
        
        context = {
            'registration_fees': registration_fees,
            'confirmed_fees': confirmed_fees,
            'pending_fees': pending_fees,
            'total_users': total_users,
            'users_without_fee': users_without_fee,
        }
        return render(request, "manager.html", context)
    else:
        return render(request, "manager.html")
    
@login_required(login_url='/sign-in/')
def confirm_registration_fee(request, fee_id):
    if request.user.username == 'manager':
        fee = get_object_or_404(RegistrationFee, id=fee_id)
        fee.confirmed = True
        fee.save()
        messages.success(request, f'Registration fee for {fee.uploaded_by.username} confirmed successfully!')
    else:
        messages.error(request, 'You are not authorized to perform this action.')
    return redirect('manager')

@login_required(login_url='/sign-in/')
def delete_registration_fee(request, fee_id):
    if request.user.username == 'manager':
        fee = get_object_or_404(RegistrationFee, id=fee_id)
        username = fee.uploaded_by.username
        fee.delete()
        messages.success(request, f'Registration fee for {username} deleted successfully!')
    else:
        messages.error(request, 'You are not authorized to perform this action.')
    return redirect('manager')

@login_required(login_url='/sign-in/')
def delete_registration_image(request, fee_id):
    if request.user.username == 'manager':
        fee = get_object_or_404(RegistrationFee, id=fee_id)
        username = fee.uploaded_by.username
        
        if not fee.image_upload:
            messages.warning(request, f'No image to delete for {username}.')
            return redirect('manager')
        
        try:
            # Delete the physical image file
            if fee.image_upload and os.path.isfile(fee.image_upload.path):
                os.remove(fee.image_upload.path)
            
            # Clear the image field (keeps the record and confirmation status)
            fee.image_upload.delete(save=False)
            fee.image_upload = None
            fee.save()
            
            messages.success(request, f'✅ Image for {username} deleted successfully! Confirmation status maintained.')
            
        except Exception as e:
            messages.error(request, f'❌ Error deleting image for {username}: {str(e)}')
            
    else:
        messages.error(request, '❌ You are not authorized to perform this action.')
    
    return redirect('manager')

#ACCOUNT BANK DETAILS

@login_required(login_url='/sign-in/')
def account_details(request):
    try:
        account = AccountDetail.objects.get(user=request.user)
        has_account = True
    except AccountDetail.DoesNotExist:
        account = None
        has_account = False
    
    context = {
        'account': account,
        'has_account': has_account,
    }
    return render(request, "account-details.html", context)

@login_required(login_url='/sign-in/')
def add_account(request):
    if request.method == 'POST':
        # Check if user already has an account
        if AccountDetail.objects.filter(user=request.user).exists():
            messages.error(request, 'You already have an account. Please update your existing account.')
            return redirect('account-details')
        
        bank_name = request.POST.get('bank_name', '').strip()
        account_name = request.POST.get('account_name', '').strip()
        account_number = request.POST.get('account_number', '').strip()
        
        # Validation
        errors = []
        if not bank_name:
            errors.append("Bank name is required")
        if not account_name:
            errors.append("Account name is required")
        if not account_number:
            errors.append("Account number is required")
        
        if errors:
            for error in errors:
                messages.error(request, error)
        else:
            # Create new account
            account = AccountDetail.objects.create(
                user=request.user,
                bank_name=bank_name,
                account_name=account_name,
                account_number=account_number
            )
            messages.success(request, 'Account added successfully!')
    
    return redirect('account-details')

@login_required(login_url='/sign-in/')
def update_account(request, account_id):
    account = get_object_or_404(AccountDetail, id=account_id, user=request.user)
    
    if request.method == 'POST':
        bank_name = request.POST.get('bank_name', '').strip()
        account_name = request.POST.get('account_name', '').strip()
        account_number = request.POST.get('account_number', '').strip()
        
        # Validation
        errors = []
        if not bank_name:
            errors.append("Bank name is required")
        if not account_name:
            errors.append("Account name is required")
        if not account_number:
            errors.append("Account number is required")
        
        if errors:
            for error in errors:
                messages.error(request, error)
        else:
            # Update account
            account.bank_name = bank_name
            account.account_name = account_name
            account.account_number = account_number
            account.save()
            messages.success(request, 'Account updated successfully!')
    
    return redirect('account-details')

def about(request):
    return render(request,'About.html')

@login_required(login_url='sign-in')
def purchase_thrifts(request):
    return render(request,'purchase-thrifts.html')


#WALLET HANDLING
from decimal import Decimal
from django.db import models
@login_required(login_url='/sign-in/')
def wallet_manager(request):
    
    if request.user.username != 'manager':
        messages.error(request, 'Access denied.')
        return redirect('home')
    
    # Get all wallets
    wallets = Wallet.objects.all().select_related('user').order_by('-updated_at')
    
    # Search functionality
    search_query = request.GET.get('search', '')
    if search_query:
        wallets = wallets.filter(
            Q(user__username__icontains=search_query) |
            Q(user__first_name__icontains=search_query) |
            Q(user__last_name__icontains=search_query)
        )
    
    # Handle wallet updates
    if request.method == 'POST':
        wallet_id = request.POST.get('wallet_id')
        action = request.POST.get('action')
        amount_str = request.POST.get('amount')
        description = request.POST.get('description', '')
        
        try:
            wallet = Wallet.objects.get(id=wallet_id)
            amount = Decimal(amount_str)  # Convert to Decimal instead of float
            
            if action == 'deposit':
                wallet.balance += amount  # Now both are Decimal objects
                transaction_type = 'deposit'
                action_text = 'added to'
            elif action == 'withdraw':
                if wallet.balance >= amount:
                    wallet.balance -= amount  # Now both are Decimal objects
                    transaction_type = 'withdrawal'
                    action_text = 'withdrawn from'
                else:
                    messages.error(request, f'Insufficient balance in {wallet.user.username}\'s wallet')
                    return redirect('wallet-manager')
            elif action == 'set':
                wallet.balance = amount  # Direct assignment works fine
                transaction_type = 'deposit'
                action_text = 'set for'
            else:
                messages.error(request, 'Invalid action')
                return redirect('wallet-manager')
            
            # Save wallet
            wallet.save()
            
            # Create transaction record
            Transaction.objects.create(
                wallet=wallet,
                transaction_type=transaction_type,
                amount=amount,  # This should also be a DecimalField
                description=description,
                created_by=request.user
            )
            
            # Format amounts for display
            formatted_amount = f'{amount:,.2f}'
            formatted_balance = f'{wallet.balance:,.2f}'
            messages.success(request, f'Successfully ₦{formatted_amount} {action_text} {wallet.user.username}\'s wallet. New balance: ₦{formatted_balance}')
            
        except Wallet.DoesNotExist:
            messages.error(request, 'Wallet not found')
        except ValueError as e:
            messages.error(request, f'Invalid amount: {str(e)}')
        except Exception as e:
            messages.error(request, f'An error occurred: {str(e)}')
    
    # Calculate total balance for stats
    total_balance = wallets.aggregate(total=models.Sum('balance'))['total'] or Decimal('0.00')
    
    # Get recent wallets (last 24 hours)
    from django.utils.timezone import now, timedelta
    recent_wallets = wallets.filter(updated_at__gte=now() - timedelta(days=1))
    
    context = {
        'wallets': wallets,
        'search_query': search_query,
        'total_balance': total_balance,
        'recent_wallets': recent_wallets,
    }
    return render(request, "wallet-manager.html", context)



@login_required(login_url='/sign-in/')
def All_referrals(request):
    if request.user.username != 'manager':
        messages.error(request, 'Access denied.')
        return redirect('home')
    # Get all users with their profiles and referrals
    users = User.objects.all().select_related('profile').order_by('-profile__total_referrals')
    
    # Search functionality
    search_query = request.GET.get('search', '')
    if search_query:
        users = users.filter(
            Q(username__icontains=search_query) |
            Q(first_name__icontains=search_query) |
            Q(last_name__icontains=search_query) |
            Q(profile__referral_code__icontains=search_query)
        )
    
    # Calculate statistics
    total_users = users.count()
    
    # Get total referrals by summing all users' referral counts
    total_referrals_count = 0
    users_with_referrals_count = 0
    
    # Prepare context with user data and their referrals
    users_data = []
    for user in users:
        try:
            profile = user.profile
            referral_count = profile.total_referrals
            
            # Get direct referrals for this user
            direct_referrals = User.objects.filter(profile__referred_by=user)
            
            # Update statistics
            total_referrals_count += referral_count
            if referral_count > 0:
                users_with_referrals_count += 1
            
            # Get referral details
            referral_details = []
            for referral in direct_referrals:
                try:
                    referral_profile = referral.profile
                    referral_details.append({
                        'username': referral.username,
                        'joined_date': referral.date_joined.strftime('%Y-%m-%d'),
                        'status': 'Active' if referral.is_active else 'Inactive'
                    })
                except:
                    referral_details.append({
                        'username': referral.username,
                        'joined_date': referral.date_joined.strftime('%Y-%m-%d'),
                        'status': 'Unknown'
                    })
            
            users_data.append({
                'user': user,
                'profile': profile,
                'referral_count': referral_count,
                'referral_code': profile.referral_code,
                'referral_details': referral_details,
                'joined_date': user.date_joined.strftime('%Y-%m-%d'),
            })
            
        except UserProfile.DoesNotExist:
            # Skip users without profile
            continue
    
    # Sort by referral count (descending)
    users_data = sorted(users_data, key=lambda x: x['referral_count'], reverse=True)
    
    # Top referrers (top 5)
    top_referrers = users_data[:5]
    
    context = {
        'users_data': users_data,
        'total_users': total_users,
        'total_referrals': total_referrals_count,
        'users_with_referrals': users_with_referrals_count,
        'top_referrers': top_referrers,
        'search_query': search_query,
    }
    
    return render(request, 'All-referrals.html', context)



##THRIFTS
@login_required(login_url='sign-in')
def purchase_thrifts(request):
    thrifts = Thrifts.objects.all()
    return render(request, 'purchase-thrifts.html', {'thrifts': thrifts})




# View to create a new thrift
@login_required
def enroll_plan(request):
    if request.method == 'POST':
        thrift_id = request.POST.get('thrift_id')
        plan_type = request.POST.get('plan_type')
        interest_rate = request.POST.get('interest_rate')
        price_range = request.POST.get('price_range')
        
        thrift = get_object_or_404(Thrifts, id=thrift_id)
        
        # Create purchase with PENDING status
        purchase = UserPurchase.objects.create(
            user=request.user,
            thrift=thrift,
            plan_type=plan_type,
            interest_rate=interest_rate,
            price_range=price_range,
            status='pending'  # Waiting for payment confirmation
        )
        
        # Check if this is an AJAX request
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({
                'success': True,
                'purchase_id': purchase.purchase_id,
                'redirect_url': f'/purchase-detail/{purchase.purchase_id}/'
            })
        else:
            messages.success(request, f'Successfully enrolled in {thrift.thriftname} Plan! Please upload payment confirmation.')
            return redirect('my-purchases')
    
    return redirect('purchase-thrifts')
from datetime import timedelta
@login_required(login_url='sign-in')
def my_purchases(request):
    purchases = UserPurchase.objects.filter(user=request.user).select_related('thrift').order_by('-purchased_at')
    
    # Calculate payout date for each purchase (exactly one year from purchase date)
    for purchase in purchases:
        purchase.payout_date = purchase.purchased_at + timedelta(days=365)
    
    context = {
        'purchases': purchases,
    }
    return render(request, 'my-purchases.html', context)


import io

from PIL import Image
ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif']
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
def validate_payment_image(file):
    """Simple but effective file validation using PIL"""
    
    # 1. CHECK FILE SIZE
    if file.size > MAX_FILE_SIZE:
        raise ValidationError(f'File too large. Max size: {MAX_FILE_SIZE // (1024 * 1024)}MB')
    
    # 2. CHECK FILE EXTENSION
    ext = os.path.splitext(file.name)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValidationError(f'Invalid file type. Allowed: {", ".join(ALLOWED_EXTENSIONS)}')
    
    # 3. CHECK IF ACTUALLY AN IMAGE USING PILLOW
    try:
        file.seek(0)
        img = Image.open(io.BytesIO(file.read()))
        img.verify()  # Verify it's a valid image
        file.seek(0)
    except Exception:
        raise ValidationError('File is not a valid image')
    
    # 4. PREVENT DOUBLE EXTENSIONS
    if file.name.count('.') > 1:
        raise ValidationError('Invalid filename format')
    
    return True

@login_required(login_url='sign-in')
def purchase_detail(request, purchase_id):
    """Display specific purchase and allow payment image uploads"""
    
    purchase = get_object_or_404(
        UserPurchase,
        purchase_id=purchase_id,
        user=request.user
    )
    
    if request.method == 'POST' and 'payment_image' in request.FILES:
        
        image = request.FILES['payment_image']
        
        # ========== 🔐 CRITICAL SECURITY CHECK ==========
        try:
            validate_payment_image(image)
        except ValidationError as e:
            messages.error(request, str(e))
            return redirect("purchase_detail", purchase_id=purchase.purchase_id)
        
        # Check max uploads
        current_images = purchase.payment_images.count()
        max_images = purchase.thrift.max_images if hasattr(purchase, 'thrift') else 5
        
        if current_images >= max_images:
            messages.error(
                request,
                f'Maximum {max_images} image(s) allowed for this plan.'
            )
            return redirect("purchase_detail", purchase_id=purchase.purchase_id)
        
        # Save image - YOUR MODEL HANDLES FILENAME
        payment_image = PaymentImage.objects.create(
            purchase=purchase,
            image=image
        )
        
        # Update status if needed
        if purchase.plan_type == 'max' and current_images == 0:
            purchase.status = 'awaiting_approval'
            purchase.save()
            messages.success(
                request,
                "Payment proof uploaded successfully! Awaiting approval."
            )
        else:
            messages.success(
                request,
                f"Payment proof uploaded! {current_images + 1}/{max_images} images uploaded."
            )
        
        return redirect("purchase_detail", purchase_id=purchase.purchase_id)
    
    return render(request, "purchase-detail.html", {
        "purchase": purchase
    })


@login_required(login_url='sign-in')
def purchased_thrifts(request):
    purchases = UserPurchase.objects.filter(user=request.user).order_by('-purchased_at')
    return render(request, 'purchased-thrifts.html', {'purchases': purchases})






@login_required(login_url='sign-in')
def create_thrift(request):
    if request.user.username != 'manager':
        messages.error(request, 'Access denied.')
        return redirect('home')
    if request.method == 'POST':
        thriftname = request.POST.get('thriftname')
        
        if thriftname:
                thrift = Thrifts.objects.create(
                    thriftname=thriftname,
                  
                )
                messages.success(request, 'Thrift item created successfully!')
                return redirect('create-thrift')  # or 'thrift-list'
            
       
    
    return render(request, 'create-thrift.html')




@login_required(login_url='sign-in')
def delete_thrift(request, id):
    """
    Delete a thrift plan - Only accessible by staff or manager
    """
    if not (request.user.is_staff or request.user.username == "manager"):
        messages.error(request, 'You do not have permission to delete plans.')
        return redirect('purchase-thrifts')
    
    thrift = get_object_or_404(Thrifts, id=id)
    thrift_name = thrift.thriftname
    
    # Check if there are active purchases for this plan
    active_purchases = UserPurchase.objects.filter(thrift=thrift, status='active').count()
    
    if request.method == 'POST':
        try:
            # Delete the thrift plan
            thrift.delete()
            messages.success(request, f'Successfully deleted {thrift_name|upper} Plan and all associated records.')
        except Exception as e:
            messages.error(request, f'Error deleting plan: {str(e)}')
        
        return redirect('purchase-thrifts')
    
    # GET request - show confirmation page (though we're using modals, this is a fallback)
    context = {
        'thrift': thrift,
        'active_purchases': active_purchases
    }
    return render(request, 'delete_thrift_confirm.html', context)


@login_required(login_url='sign-in')
def edit_thrift(request, id):
    """
    Edit a thrift plan - Only accessible by staff or manager
    """
    if not (request.user.is_staff or request.user.username == "manager"):
        messages.error(request, 'You do not have permission to edit plans.')
        return redirect('purchase-thrifts')
    
    thrift = get_object_or_404(Thrifts, id=id)
    
    if request.method == 'POST':
        thriftname = request.POST.get('thriftname')
        
        if thriftname:
            # Validate that the plan name is one of the allowed types
            allowed_plans = ['basic', 'plus', 'max']
            if thriftname.lower() not in allowed_plans:
                messages.error(request, f'Plan name must be one of: {", ".join(allowed_plans)}')
                return redirect('edit_thrift', id=thrift.id)
            
            # Check if another plan already exists with this name (excluding current one)
            existing = Thrifts.objects.filter(thriftname__iexact=thriftname).exclude(id=thrift.id)
            if existing.exists():
                messages.error(request, f'A plan named "{thriftname}" already exists.')
                return redirect('edit_thrift', id=thrift.id)
            
            # Update the thrift plan
            thrift.thriftname = thriftname.lower()
            thrift.save()
            
            messages.success(request, f'Successfully updated {thriftname} Plan!')
            return redirect('purchase-thrifts')
        else:
            messages.error(request, 'Plan name cannot be empty.')
    
    context = {
        'thrift': thrift,
        'is_edit': True
    }
    return render(request, 'create-thrift.html', context)

#######
from django.db.models import Count, Q
@login_required(login_url='sign-in')
def thrifts_confirmation(request):
    """Manager-only view to confirm payment images"""
    # Check if user is manager
    if request.user.username != "manager":
        messages.error(request, "You don't have permission to access this page.")
        return redirect('my_purchases')
    
    # Get all purchases with payment images
    purchases = UserPurchase.objects.filter(
        payment_images__isnull=False
    ).distinct().select_related(
        'user', 'thrift'
    ).prefetch_related(
        'payment_images'
    ).order_by('-purchased_at')
    
    # Prepare data for template
    purchases_with_images = []
    total_pending = 0
    total_approved = 0
    total_images = 0
    
    for purchase in purchases:
        images = purchase.payment_images.all()
        pending_images = images.filter(is_approved=False, image__isnull=False)
        approved_images = images.filter(is_approved=True, image__isnull=False)
        
        total_pending += pending_images.count()
        total_approved += approved_images.count()
        total_images += images.count()
        
        # Calculate payout date
        purchase.payout_date = purchase.purchased_at + timedelta(days=365)
        
        purchases_with_images.append({
            'purchase': purchase,
            'images': images,
            'uploaded_count': images.filter(image__isnull=False).count(),
            'has_pending': pending_images.exists()
        })
    
    context = {
        'purchases_with_images': purchases_with_images,
        'pending_count': total_pending,
        'approved_count': total_approved,
        'total_images': total_images,
        'total_users': UserPurchase.objects.values('user').distinct().count(),
    }
    return render(request, 'thrifts-confirmation.html', context)


@login_required(login_url='sign-in')
def confirm_payment_image(request, image_id):
    """Confirm a payment image and delete the file only"""
    if request.user.username != "manager":
        messages.error(request, "You don't have permission to confirm payments.")
        return redirect('my_purchases')
    
    image = get_object_or_404(PaymentImage, id=image_id)
    
    if not image.is_approved and image.image:
        # Store image path before deletion
        image_path = image.image.path if image.image else None
        
        # Delete the actual file from storage
        if image_path and os.path.isfile(image_path):
            try:
                os.remove(image_path)
            except Exception as e:
                print(f"Error deleting image file: {e}")
        
        # Nullify the image field but keep the record
        image.image = None
        image.is_approved = True
        image.approved_by = request.user
        image.approved_at = timezone.now()
        image.save()
        
        # Check if all images for this purchase are approved
        purchase = image.purchase
        all_images = purchase.payment_images.all()
        approved_count = all_images.filter(is_approved=True).count()
        max_images = purchase.thrift.max_images
        
        # Check if all required images are approved
        if approved_count >= max_images:
            purchase.status = 'active'
            purchase.save()
            messages.success(request, f'All payments confirmed! Plan is now active.')
        else:
            images_left = max_images - approved_count
            messages.success(request, f'Payment proof confirmed! {images_left} more payment(s) needed.')
    
    return redirect('thrifts-confirmation')


@login_required(login_url='sign-in')
def delete_payment_image(request, image_id):
    """Delete a payment image file and nullify the record"""
    if request.user.username != "manager":
        messages.error(request, "You don't have permission to delete payment images.")
        return redirect('my_purchases')
    
    image = get_object_or_404(PaymentImage, id=image_id)
    
    # Store image path for deletion
    image_path = None
    if image.image:
        try:
            image_path = image.image.path
        except:
            pass
    
    # Delete the actual file from storage
    if image_path and os.path.isfile(image_path):
        try:
            os.remove(image_path)
        except Exception as e:
            print(f"Error deleting image file: {e}")
    
    # Nullify the image field but keep the record
    image.image = None
    image.save()
    
    messages.success(request, f'Payment proof image deleted successfully.')
    return redirect('thrifts-confirmation')

#Email

def success(request, uid):
    """
    Success page after password reset or other successful operations
    """
    context = {
        'user_id': uid,
        'message': 'Operation completed successfully!'
    }
    return render(request, 'success.html', context)

def terms(request):
    return render(request,'terms-and-conditions.html')

def privacy_policy(request):
    """Display privacy policy page"""
    return render(request, 'privacy-policy.html')

def contact(request):
    if request.method == "POST":
        name = request.POST.get("name", "")
        email = request.POST.get("email")
        message_text = request.POST.get("message")

        ContactMessage.objects.create(
            name=name,
            email=email,
            message=message_text,
            user=request.user if request.user.is_authenticated else None
        )

        messages.success(request, "Your message has been submitted successfully!")
        return redirect('contact')  # redirect to same page

    return render(request, 'contact.html')

@login_required
def complaints_view(request):
    # Only allow staff or user with username 'manager'
    if request.user.username == "manager":
        messages_list = ContactMessage.objects.order_by('-submitted_at')
    else:
        messages.error(request, "You are not authorized to view this page.")
        return redirect('home')  # Redirect unauthorized users

    context = {'messages_list': messages_list}
    return render(request, 'complaints.html', context)