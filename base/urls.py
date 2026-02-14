
from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('', views.home,name='home'),
    path('sign-in/', views.sign_in,name='sign-in'),
    path('create-account/', views.create_account,name='create-account'),
    path('sign-out/', views.sign_out, name='sign-out'),
    path('create-account/<str:ref_code>/', views.create_account, name='create-account-with-ref'),
    path('About/', views.about,name='About'),
    path('purchase-thrifts/', views.purchase_thrifts,name='purchase-thrifts'),

    path('registration-fee/', views.registration_fee,name='registration-fee'),
    


    path('manager/', views.manager, name='manager'),
    path('confirm-registration-fee/<int:fee_id>/', views.confirm_registration_fee, name='confirm-registration-fee'),
    #path('delete-registration-fee/<int:fee_id>/', views.delete_registration_fee, name='delete-registration-fee'),
    path('delete-registration-image/<int:fee_id>/', views.delete_registration_image, name='delete-registration-image'),

    path('account-details/', views.account_details, name='account-details'),
    path('add-account/', views.add_account, name='add-account'),
    path('update-account/<int:account_id>/', views.update_account, name='update-account'),


    #Wallet urls
   path('wallet-manager/', views.wallet_manager, name='wallet-manager'),
   path('All-referrals/', views.All_referrals, name='All-referrals'),
path('delete-transaction/', views.delete_transaction, name='delete-transaction'),

     ##THRIFTS
     path('delete-payment-image/<int:image_id>/', views.delete_payment_image, name='delete_payment_image'),
     path('thrifts-confirmation/', views.thrifts_confirmation, name='thrifts-confirmation'),
path('confirm-payment-image/<int:image_id>/', views.confirm_payment_image, name='confirm_payment_image'),
     path('my-purchases/', views.my_purchases, name='my-purchases'),
    path('purchase-thrifts', views.purchase_thrifts, name='purchase-thrifts'),
    path('create-thrift/', views.create_thrift, name='create-thrift'),
     path('enroll-plan/', views.enroll_plan, name='enroll_plan'),
    path('purchase-detail/<str:purchase_id>/', views.purchase_detail, name='purchase_detail'),
    path('purchased-thrifts/', views.purchased_thrifts, name='purchased_thrifts'),
    path('delete-thrift/<int:id>/', views.delete_thrift, name='delete_thrift'),
    path('edit-thrift/<int:id>/', views.edit_thrift, name='edit_thrift'),
    
    #####Password Reset


    path('password_reset_form/',auth_views.PasswordResetView.as_view(template_name='password_reset_form.html'),name='password_reset'),

    path('password_reset_done/',auth_views.PasswordResetDoneView.as_view(template_name='password_reset_done.html'),name='password_reset_done'),

    path('password_reset_confirm/<uidb64>/<token>/',auth_views.PasswordResetConfirmView.as_view(template_name='password_reset_confirm.html'),name='password_reset_confirm'),
    #for success
    path('success/<int:uid>/',views.success, name='success'),
    path('password_reset_complete/',auth_views.PasswordResetCompleteView.as_view(template_name='password_reset_complete.html'),name='password_reset_complete'),
    path('terms-and-conditions',views.terms,name='terms-and-conditions'),
    path('privacy-policy/', views.privacy_policy, name='privacy-policy'),
    path('contact/',views.contact,name='contact'),
    path('complaints/', views.complaints_view, name='complaints'),
    path('account-locked/', views.account_locked, name='account_locked'),

     path('manager/account-details/', views.check_account_details, name='check-account-details'),

]
