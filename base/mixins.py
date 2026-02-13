# yourapp/mixins.py
from .models import RegistrationFee

class RegistrationStatusMixin:
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.request.user.is_authenticated:
            try:
                registration_fee = RegistrationFee.objects.get(
                    uploaded_by=self.request.user
                )
                if registration_fee.confirmed:
                    context['registration_status'] = "active"
                else:
                    context['registration_status'] = "pending"
            except RegistrationFee.DoesNotExist:
                context['registration_status'] = "inactive"
        return context