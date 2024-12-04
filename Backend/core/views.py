from rest_framework import status, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import action, api_view
from django.core.exceptions import ValidationError
from storages.backends.s3boto3 import S3Boto3Storage  # Ensure django-storages is installed
from django.contrib.auth.models import User
from .models import Post, Comment, Profile, Watchlist, WatchHistory
from .serializers import (PostSerializer, CommentSerializer, RegisterSerializer, LoginSerializer,
    ProfileSerializer, WatchlistSerializer, WatchHistorySerializer, UserSerializer
    
    )

from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.exceptions import PermissionDenied



class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer  # Define a serializer for User model
    permission_classes = [IsAuthenticated]  # Require authentication for all actions

    def get_queryset(self):
        """
        This viewset will return all users only if the authenticated user is a superuser.
        """
        user = self.request.user
        if user.is_superuser:
            return User.objects.all()  # Return all users if superuser
        else:
            raise PermissionDenied("You do not have permission to view all users.")

    @action(detail=True, methods=['delete'], permission_classes=[IsAdminUser])
    def remove_user(self, request):
        """
        Custom action to remove a user. Only available to superusers or admins.
        """
        user = self.get_object()  # Get the user object based on pk
        if user != request.user:  # Make sure the admin is not trying to delete themselves
            user.delete()  # Delete the user
            return Response({"message": "User deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
        else:
            return Response({"error": "You cannot delete your own account."}, status=status.HTTP_400_BAD_REQUEST)
        
    @action(detail=True, methods=['get'])  # Change POST to GET
    def verify_admin(self, request, pk=None):
        """
        Custom action to verify if the user is an admin.
        """
        print("verify_admin", request.user)
        user = self.get_object()
        print ("user", user)
        if not request.user.is_staff:  # Only allow if the requester is a staff member
            return Response({"error": "You do not have permission to view this user."}, status=status.HTTP_403_FORBIDDEN)
        
        if user.is_staff:
            return Response({"message": "User is an admin."})
        return Response({"message": "User is not an admin."})
    
    @action(detail=True, methods=['get'])
    def get_userProfiles(self, request, pk=None):
        """
        Custom action to get all user profiles.
        """
        user = self.get_object()
        profiles = Profile.objects.filter(user=user)
        serializer = ProfileSerializer(profiles, many=True)
        return Response(serializer.data)
    
    



class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            refresh = RefreshToken.for_user(user)
            return Response({
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                },
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request):
        
        # print("LoginView", request.data)
        
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            
            user = serializer.user
            refresh = RefreshToken.for_user(user)
            return Response({
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                },
            }, status=status.HTTP_200_OK)
        else:
            print("LoginView", serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "User logged out successfully"}, status=status.HTTP_200_OK)
        except Exception:
            return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)


class PostViewSet(viewsets.ModelViewSet):
    queryset = Post.objects.all().order_by('-created_at')
    serializer_class = PostSerializer
    parser_classes = (MultiPartParser, FormParser)

    def perform_create(self, serializer):
        media = self.request.FILES.get('media')
        if media:
            try:
                media_url = self.upload_media_to_backblaze(media)
                serializer.save(author=self.request.user, media=media_url)
            except ValidationError as e:
                raise ValidationError({"error": f"Media upload failed: {str(e)}"})
        else:
            serializer.save(author=self.request.user)

    def upload_media_to_backblaze(self, media_file):
        if not media_file:
            raise ValidationError("No media file provided.")

        storage = S3Boto3Storage()
        valid_media_types = ['image/', 'video/']
        if not any(media_file.content_type.startswith(media_type) for media_type in valid_media_types):
            raise ValidationError("Invalid media type. Only images and videos are allowed.")

        file_name = f'postmedia/{media_file.name}'
        try:
            file_url = storage.save(file_name, media_file)
            return storage.url(file_url)
        except Exception as e:
            raise ValidationError(f"Error uploading to Backblaze: {str(e)}")

    @action(detail=True, methods=['POST'])
    def like(self, request, pk=None):
        post = self.get_object()
        user = request.user
        if user in post.reactions.filter(like_type='like').values_list('user', flat=True):
            post.reactions.filter(user=user).delete()
        else:
            post.reactions.create(user=user, like_type='like')
        return Response({"message": "Reaction updated"}, status=status.HTTP_200_OK)


class CommentViewSet(viewsets.ModelViewSet):
    queryset = Comment.objects.all()
    serializer_class = CommentSerializer

    @action(detail=True, methods=['POST'])
    def like(self, request, pk=None):
        comment = self.get_object()
        user = request.user
        # if user in comment.likes.all():
        #     comment.likes.remove(user)
        # else:
        #     comment.likes.add(user)
        # return Response({"message": "Comment like updated"}, status=status.HTTP_200_OK)


@api_view(['GET'])
def get_comments(request, type, id):
    """
    Fetches comments for a given type (either 'post' or 'movie') and id.
    """
    try:
        if type == "post":
            post = Post.objects.get(id=id)
            comments = Comment.objects.filter(post=post)
        elif type == "movie":
            comments = Comment.objects.filter(movie=id)
        else:
            return Response({"error": "Invalid type. Use 'post' or 'movie'."}, status=status.HTTP_400_BAD_REQUEST)

        serializer = CommentSerializer(comments, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    except Post.DoesNotExist:
        return Response({"error": "Post not found."}, status=status.HTTP_404_NOT_FOUND)
    except Comment.DoesNotExist:
        return Response({"error": "Comments not found."}, status=status.HTTP_404_NOT_FOUND)
    


class ProfileViewSet(viewsets.ModelViewSet):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer
    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def create_profile(self, request):
        # Extract the user from the JWT token (this is done automatically by the JWTAuthentication middleware)
        user = request.user
        if not user:
            return Response({"error": "Invalid or missing JWT token"}, status=status.HTTP_401_UNAUTHORIZED)

        # Check if the user already has a profile
        if Profile.objects.filter(user=user).exists():
            return Response({"error": "Profile already exists for the user"}, status=status.HTTP_400_BAD_REQUEST)

        # Extract profile data from request
        name = request.data.get("name")
        image_url = request.data.get("image_url")

        if not name:
            return Response({"error": "Name is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Create and save the profile
        try:
            profile = Profile.objects.create(
                user=user,
                name=name,
                image_url=image_url
            )
            return Response({"message": "Profile created successfully"}, status=status.HTTP_201_CREATED)
        except ValidationError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['post'])
    def add_to_watchlist(self, request, pk=None):
        profile = self.get_object()
        tmdb_movie_id = request.data.get('tmdb_movie_id')
        if not tmdb_movie_id:
            return Response({'error': 'tmdb_movie_id is required'}, status=status.HTTP_400_BAD_REQUEST)

        if profile.watchlist.count() >= 10:
            return Response({'error': 'Watchlist can have a maximum of 10 movies.'}, status=status.HTTP_400_BAD_REQUEST)

        watchlist_item, created = Watchlist.objects.get_or_create(profile=profile, tmdb_movie_id=tmdb_movie_id)
        if created:
            return Response({'message': 'Movie added to watchlist'}, status=status.HTTP_201_CREATED)
        return Response({'error': 'Movie is already in watchlist'}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['post'])
    def remove_from_watchlist(self, request, pk=None):
        profile = self.get_object()
        tmdb_movie_id = request.data.get('tmdb_movie_id')
        print("tmdb_movie_id", tmdb_movie_id)
        if not tmdb_movie_id:
            return Response({'error': 'tmdb_movie_id is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            watchlist_item = Watchlist.objects.get(profile=profile, tmdb_movie_id=tmdb_movie_id)
            watchlist_item.delete()
            return Response({'message': 'Movie removed from watchlist'}, status=status.HTTP_200_OK)
        except Watchlist.DoesNotExist:
            return Response({'error': 'Movie not found in watchlist'}, status=status.HTTP_404_NOT_FOUND)

    @action(detail=True, methods=['post'])
    def add_to_watch_history(self, request, pk=None):
        profile = self.get_object()
        tmdb_movie_id = request.data.get('tmdb_movie_id')

        # Validate input
        if not tmdb_movie_id:
            return Response(
                {'error': 'tmdb_movie_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Check if the movie is already in the watch history
            exists = WatchHistory.objects.filter(profile=profile, tmdb_movie_id=tmdb_movie_id).exists()
            if exists:
                return Response(
                    {'error': 'Movie is already in watch history'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Add the movie to the watch history
            WatchHistory.objects.create(profile=profile, tmdb_movie_id=tmdb_movie_id)

            # Ensure the watch history contains a maximum of 10 entries
            if profile.watch_history.count() > 10:
                oldest = profile.watch_history.order_by('watched_at').first()
                oldest.delete()

            return Response(
                {'message': 'Movie added to watch history'},
                status=status.HTTP_201_CREATED
            )

        except IntegrityError:
            return Response(
                {'error': 'Database error occurred. Please try again.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=['get'])
    def get_watchlist(self, request, pk=None):
        profile = self.get_object()
        serializer = WatchlistSerializer(profile.watchlist, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def get_watch_history(self, request, pk=None):
        profile = self.get_object()
        serializer = WatchHistorySerializer(profile.watch_history, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def remove_from_watch_history(self, request, pk=None):
        profile = self.get_object()
        tmdb_movie_id = request.data.get('tmdb_movie_id')
        if not tmdb_movie_id:
            return Response({'error': 'tmdb_movie_id is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            watch_history_item = WatchHistory.objects.get(profile=profile, tmdb_movie_id=tmdb_movie_id)
            watch_history_item.delete()
            return Response({'message': 'Movie removed from watch history'}, status=status.HTTP_200_OK)
        except WatchHistory.DoesNotExist:
            return Response({'error': 'Movie not found in watch history'}, status=status.HTTP_404_NOT_FOUND)