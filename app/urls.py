from django.urls import path
from app import views

urlpatterns = [
    path('user/login/', views.login, name="login"),
    path('user/signup/', views.signup, name="signup"),
    path('user/<int:id>/update/', views.update_profile, name="update_user"),
    path('user/<int:id>', views.get_user_profile_by_id, name="get_user_profile_by_id"),
    path(
        'user/<str:username>/',
        views.get_user_profile_by_username,
        name="get_user_profile_by_username",
    ),
    path('user/<int:id>/delete/', views.delete_user, name="delete_user"),
    path('post/create/', views.create_post, name="create_post"),
    path('post/<int:id>/update/', views.update_post, name="update_post"),
    path('post/<int:id>', views.get_post_by_id, name="get_post_by_id"),
    path(
        'post/user/<str:username>',
        views.get_posts_by_username,
        name="get_posts_by_username",
    ),
    path(
        'post/all/',
        views.get_all_posts,
        name="get_all_posts",
    ),
    path('post/<int:id>/delete/', views.delete_post, name="delete_post"),
    path('post/<int:id>/like/', views.like_post, name="like_post"),
    path('post/<int:id>/comment/', views.comment_post, name="comment_post"),
]
