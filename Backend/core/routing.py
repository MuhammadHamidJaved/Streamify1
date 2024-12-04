from django.urls import re_path
from .consumers import PostConsumer, CommentConsumer

websocket_urlpatterns = [
    re_path(r"^ws/posts/$", PostConsumer.as_asgi()),
    re_path(r"^ws/comments/(?P<type>\w+)/(?P<id>\d+)/$", CommentConsumer.as_asgi()),
]
