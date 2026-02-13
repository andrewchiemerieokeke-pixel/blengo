# yourapp/context_processors.py
from .models import RegistrationFee

def registration_status_processor(request):
    """Makes registration_status available to all templates"""
    context = {}
    
    if request.user.is_authenticated:
        try:
            registration_fee = RegistrationFee.objects.get(uploaded_by=request.user)
            if registration_fee.confirmed:
                context['registration_status'] = "active"
            else:
                context['registration_status'] = "pending"
        except RegistrationFee.DoesNotExist:
            context['registration_status'] = "inactive"
    else:
        context['registration_status'] = None  # or "inactive" if you prefer
    
    return context