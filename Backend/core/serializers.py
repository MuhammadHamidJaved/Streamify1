from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate
from .models import Post, Comment, LikeDislike, Profile, Watchlist, WatchHistory



class UserSerializer(serializers.ModelSerializer):
    class Meta:
       model = User
       fields = ['id', 'username', 'email', 'first_name', 'last_name', 'is_superuser', 'is_active', 'date_joined']


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'confirm_password')

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        return attrs

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        validated_data['password'] = make_password(validated_data['password'])
        return User.objects.create(**validated_data)


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        email = attrs['email']
        password = attrs['password']

        # Try to get user by email
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid email or password.")

        # Authenticate user using the username and password
        user = authenticate(username=user.username, password=password)
        if not user:
            raise serializers.ValidationError("Invalid email or password.")
        
        # Check if the user is active
        if not user.is_active:
            raise serializers.ValidationError("This account is inactive.")

        # Store the authenticated user for later use
        self.user = user
        return attrs

    def create_tokens(self, user):
        refresh = RefreshToken.for_user(user)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }


class LikeDislikeSerializer(serializers.ModelSerializer):
    user = serializers.ReadOnlyField(source='user.username')
    content_type = serializers.CharField(source='content_type.model', read_only=True)

    class Meta:
        model = LikeDislike
        fields = ['id', 'user', 'like', 'created_at', 'content_type', 'object_id']


class CommentSerializer(serializers.ModelSerializer):
    author = serializers.ReadOnlyField(source='author.username')

    class Meta:
        model = Comment
        fields = ['id', 'author', 'message', 'created_at']


class PostSerializer(serializers.ModelSerializer):
    author = serializers.ReadOnlyField(source='author.username')
    comments = CommentSerializer(many=True, read_only=True)
    likes_count = serializers.SerializerMethodField()
    dislikes_count = serializers.SerializerMethodField()
    media_url = serializers.SerializerMethodField()
    user_like_status = serializers.SerializerMethodField()

    class Meta:
        model = Post
        fields = [
            'id', 'author', 'content', 'created_at', 'likes_count', 
            'dislikes_count', 'comments', 'media_url', 'user_like_status'
        ]

    def get_likes_count(self, obj):
        return obj.reactions.filter(like_type='like').count()

    def get_dislikes_count(self, obj):
        return obj.reactions.filter(like_type='dislike').count()

    def get_media_url(self, obj):
        if obj.media:
            return str(obj.media)  # Media URL logic (Cloudinary or other)
        return None

    def get_user_like_status(self, obj):
        user = self.context['request'].user
        if user.is_authenticated:
            reaction = obj.reactions.filter(user=user).first()
            if reaction:
                return reaction.like_type
        return None
        
        



class WatchlistSerializer(serializers.ModelSerializer):
    class Meta:
        model = Watchlist
        fields = ['id', 'tmdb_movie_id', 'added_at']

class WatchHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = WatchHistory
        fields = ['id', 'tmdb_movie_id', 'watched_at']

class ProfileSerializer(serializers.ModelSerializer):
    watchlist = WatchlistSerializer(many=True, read_only=True)
    watch_history = WatchHistorySerializer(many=True, read_only=True)

    class Meta:
        model = Profile
        fields = ['id', 'user','image_url', 'name', 'created_at', 'watchlist', 'watch_history']
        
    def validate_name(self, value):
        if not value:
            raise serializers.ValidationError("Name is required")
        return value

    def validate_image_url(self, value):
        # You can add URL validation if necessary
        if value and not value.startswith('http'):
            raise serializers.ValidationError("Invalid image URL")
        return value