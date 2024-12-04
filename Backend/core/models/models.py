# models.py
from django.db import models
from django.contrib.auth.models import User
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey

class Post(models.Model):
    id = models.AutoField(primary_key=True)
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    media = models.FileField(upload_to='postmedia/', blank=True, null=True,max_length=255)
    public_id = models.CharField(max_length=255, blank=True, null=True)


class LikeDislike(models.Model):
    LIKE_CHOICES = [
        ('like', 'Like'),
        ('dislike', 'Dislike'),
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="reactions")
    like_type = models.CharField(max_length=10, choices=LIKE_CHOICES)

    class Meta:
        unique_together = ('user', 'post')  # Ensure a user can react only once per post



class Comment(models.Model):
    # This will allow us to have comments on either Post or Movie
    movie = models.IntegerField(null=True)
    post = models.ForeignKey(Post, on_delete=models.CASCADE, null=True)
    
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    likes = models.ManyToManyField(User, related_name='comment_likes', blank=True)
    
    def __str__(self):
        return f"Comment by {self.author} on {self.content_object}"
    
    
    
class Profile(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="profiles")
    name = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    image_url = models.CharField(blank=True, null=True)

    def __str__(self):
        return f"{self.name} ({self.user.username})"

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["user", "name"], name="unique_profile_per_user"),
        ]
        ordering = ["created_at"]

    def watchlist_limit_reached(self):
        """Check if the profile has reached the max watchlist limit."""
        return self.watchlist.count() >= 10

    def watch_history_limit_reached(self):
        """Check if the profile has reached the max history limit."""
        return self.watch_history.count() >= 10


class Watchlist(models.Model):
    profile = models.ForeignKey(Profile, on_delete=models.CASCADE, related_name="watchlist")
    tmdb_movie_id = models.PositiveIntegerField()  # TMDb movie ID
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["profile", "tmdb_movie_id"], name="unique_movie_in_watchlist"),
        ]
        ordering = ["-added_at"]

    def __str__(self):
        return f"TMDb ID {self.tmdb_movie_id} in {self.profile.name}'s Watchlist"


class WatchHistory(models.Model):
    profile = models.ForeignKey(Profile, on_delete=models.CASCADE, related_name="watch_history")
    tmdb_movie_id = models.PositiveIntegerField()  # TMDb movie ID
    watched_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["profile", "tmdb_movie_id"], name="unique_movie_in_history"),
        ]
        ordering = ["-watched_at"]

    def __str__(self):
        return f"TMDb ID {self.tmdb_movie_id} watched by {self.profile.name}"