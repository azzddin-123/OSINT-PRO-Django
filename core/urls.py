from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('download/', views.download_results, name='download_results'),
    path('logout/', views.logout_view, name='logout'),
]