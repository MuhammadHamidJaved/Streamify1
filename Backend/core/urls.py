# urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    RegisterView,
    LoginView,
    LogoutView,
    PostViewSet,
    CommentViewSet,
    ProfileViewSet,
    UserViewSet,

    get_comments,
)
from rest_framework_simplejwt.views import TokenRefreshView
from django.contrib.auth import views as auth_views

# Set up routers for ViewSets
router = DefaultRouter()
router.register(r'posts', PostViewSet, basename='posts')
router.register(r'comments', CommentViewSet, basename='comments')
router.register(r'profiles', ProfileViewSet, basename='profile')
router.register(r'users', UserViewSet, basename='user')
urlpatterns = [
    # Authentication routes
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Password reset routes
    path(
        'password_reset/',
        auth_views.PasswordResetView.as_view(
            template_name="registration/password_reset_form.html"
        ),
        name='password_reset',
    ),
    path(
        'password_reset/done/',
        auth_views.PasswordResetDoneView.as_view(
            template_name="registration/password_reset_done.html"
        ),
        name='password_reset_done',
    ),
    path(
        'reset/<uidb64>/<token>/',
        auth_views.PasswordResetConfirmView.as_view(
            template_name="registration/password_reset_confirm.html"
        ),
        name='password_reset_confirm',
    ),
    path(
        'reset/done/',
        auth_views.PasswordResetCompleteView.as_view(
            template_name="registration/password_reset_complete.html"
        ),
        name='password_reset_complete',
    ),

    # API routes
    path('', include(router.urls)),  # Include router URLs for posts and comments
    path('comments/<str:type>/<int:id>/', get_comments, name='get_comments'),
]
