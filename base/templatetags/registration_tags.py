from django import template
from base.models import RegistrationFee  # Using 'base' as your app name

register = template.Library()

@register.simple_tag(takes_context=True)
def get_registration_status(context):
    request = context['request']
    if not request.user.is_authenticated:
        return 'inactive'
    
    # Check if user has approved registration
    if RegistrationFee.objects.filter(
        uploaded_by=request.user,
        status='approved'
    ).exists():
        return 'active'
    # Check for pending
    elif RegistrationFee.objects.filter(
        uploaded_by=request.user,
        status='pending'
    ).exists():
        return 'pending'
    return 'inactive'