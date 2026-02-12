from django.contrib import admin
from . models import RegistrationFee,AccountDetail,Thrifts,Wallet,Transaction,UserPurchase,PaymentImage
# Register your models here.
admin.site.register(RegistrationFee)
admin.site.register(AccountDetail)
admin.site.register(Thrifts)
admin.site.register(Wallet)
admin.site.register(Transaction)
admin.site.register(UserPurchase)
admin.site.register(PaymentImage)