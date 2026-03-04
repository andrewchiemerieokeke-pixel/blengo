from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from base import views

handler404 = views.custom_404

urlpatterns = [
    path('my-new-secret/', admin.site.urls),
    path('', include('base.urls')),
    path("accounts/", include("allauth.urls")),
]

# Only for local development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)