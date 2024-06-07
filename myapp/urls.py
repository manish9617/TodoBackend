from django.urls import path
from .views import *

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('protected/', ProtectedView.as_view(), name='protected'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('items/', ItemViewSet.as_view(), name='items'),
     path('items/<int:pk>/', ItemViewSet.as_view(), name='item-edit'),
]
