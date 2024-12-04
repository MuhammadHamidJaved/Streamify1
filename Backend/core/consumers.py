import json
from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import sync_to_async
from django.core.files.base import ContentFile
import base64
from uuid import uuid4
from cloudinary.uploader import upload
import hashlib



class PostConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.group_name = "posts"
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            action = data.get('action')  # "create", "like", or "dislike"

            if action == "create":
                await self.handle_post_creation(data)
            elif action in ["like", "dislike"]:
                await self.handle_like_dislike(data)

        except Exception as e:
            print(f"Error in PostConsumer: {e}")
            await self.send(text_data=json.dumps({'error': str(e)}))

    async def handle_post_creation(self, data):
        post_content = data['content']
        media = data.get('media')  # Optional base64-encoded media
        access_token = data.get('access_token')

        # Validate access token and get the user
        from django.contrib.auth.models import User
        user_id = await sync_to_async(self.get_user_from_token)(access_token)
        user = await sync_to_async(User.objects.get)(id=user_id)
        if not user:
            raise ValueError("Invalid access token")

        # Save the post asynchronously
        media_url, publicID = await sync_to_async(self.save_media_file)(media) if media else (None, None)
        post_id = await sync_to_async(self.save_post)(post_content, media_url=media_url, user=user, publicId=publicID)

        # Broadcast the new post content and ID
        await self.channel_layer.group_send(
            self.group_name,
            {
                'type': 'broadcast_post',
                'id': post_id,
                'message': post_content,
                'media_url': media_url,
            }
        )

    async def handle_like_dislike(self, data):
        post_id = data['id']
        action = data['action']  # "like" or "dislike"
        access_token = data.get('access_token')

        # Validate access token and get the user
        from django.contrib.auth.models import User
        from .models import Post
        user_id = await sync_to_async(self.get_user_from_token)(access_token)
        user = await sync_to_async(User.objects.get)(id=user_id)
        post = await sync_to_async(Post.objects.get)(id=post_id)

        if not user or not post:
            raise ValueError("Invalid user or post")

        # Perform like or dislike
        result = await sync_to_async(self.toggle_like_dislike)(post, user, action)

        # Broadcast the updated like/dislike count
        await self.channel_layer.group_send(
            self.group_name,
            {
                'type': 'broadcast_reaction',
                'id': post_id,
                'likes_count': result['likes'],
                'dislikes_count': result['dislikes'],
            }
        )

    def toggle_like_dislike(self, post, user, action):
        from .models import LikeDislike
        existing_reaction = LikeDislike.objects.filter(post=post, user=user).first()

        if existing_reaction:
            if existing_reaction.like_type == action:
                # If the reaction is the same as the current action, remove it
                existing_reaction.delete()
            else:
                # Update the reaction to the new action
                existing_reaction.like_type = action
                existing_reaction.save()
        else:
            # Create a new reaction
            LikeDislike.objects.create(post=post, user=user, like_type=action)

        # Return updated counts
        return {
            'likes': LikeDislike.objects.filter(post=post, like_type='like').count(),
            'dislikes': LikeDislike.objects.filter(post=post, like_type='dislike').count(),
        }

    async def broadcast_post(self, event):
        await self.send(text_data=json.dumps({
            'id': event['id'],
            'message': event['message'],
            'media_url': event['media_url'],
        }))

    async def broadcast_reaction(self, event):
        await self.send(text_data=json.dumps({
            'id': event['id'],
            'likes_count': event['likes_count'],
            'dislikes_count': event['dislikes_count'],
        }))

    def get_user_from_token(self, access_token):
        try:
            from rest_framework_simplejwt.tokens import AccessToken
            token = AccessToken(access_token)
            return token.payload.get('user_id')
        except Exception:
            return None

    def save_media_file(self, media_data):
        try:
            # Decode the base64 media data
            format, imgstr = media_data.split(';base64,')
            ext = format.split('/')[-1]  # Extract the file extension (e.g., jpg, png)
            file_name = f"{uuid4().hex}.{ext}"  # Generate a unique file name

            # Decode and create a ContentFile object
            media_content = ContentFile(base64.b64decode(imgstr), name=file_name)

            # Create a hash from the media content to use as a public_id
            file_hash = hashlib.md5(media_content.read()).hexdigest()
            
            from core.models import Post
            
            try:
                post = Post.objects.filter(public_id=file_hash)
                if post.exists():
                    print(post.first().content)  # Access the post's content or any other field
                    return str(post.first().media), file_hash
            except Post.DoesNotExist:
                print(f"Post with public_id {file_hash} does not exist.")

            # Reset the file pointer to the beginning after reading
            media_content.seek(0)

            # Upload to Cloudinary using the file hash as public_id to prevent duplicates
            result = upload(media_content.file, public_id=file_hash, folder="posts", overwrite=False)  # overwrite=False prevents overwriting
            media_url = result['secure_url']  # Get the secure URL of the uploaded file

            return media_url,file_hash
        except Exception as e:
            print(f"Error saving media file: {e}")
            return None
    def save_post(self, content, media_url, user,publicId):
        from .models import Post
        post = Post.objects.create(content=content, media=media_url, author=user,public_id=publicId)
        return post.id




class CommentConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.post_id = self.scope['url_route']['kwargs'].get('post_id')
        self.movie_id = self.scope['url_route']['kwargs'].get('movie_id')
        if self.post_id:
            self.group_name = f"comments_post_{self.post_id}"
        elif self.movie_id:
            self.group_name = f"comments_movie_{self.movie_id}"
        else:
            self.group_name = "comments"
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            comment_content = data['content']
            access_token = data.get('access_token')

            # Validate access token and get the user
            from django.contrib.auth.models import User
            
            user_id = await sync_to_async(self.get_user_from_token)(access_token)
            user = await sync_to_async(User.objects.get)(id=user_id)
            if not user:
                raise ValueError("Invalid access token")

            # Determine whether the comment is for a post or a movie
            content_object = None
            
            if data.get('post_id'):
                from .models import Post
                content_object = await sync_to_async(Post.objects.get)(id=data['post_id'])
                content_object = ['post',content_object]
                print('content_object', content_object)
            elif data.get('movie_id'):
                # from .models import Movie make constant content_object
                content_object = data.get('movie_id')
                content_object = ['movie',content_object]

            if content_object:
                if content_object[0] == 'post':
                    comment_id = await sync_to_async(self.save_comment)(comment_content,post=content_object[1], user=user)
                elif content_object[0] == 'movie':
                    comment_id = await sync_to_async(self.save_comment)(comment_content,movie=content_object[1], user=user)
                # Broadcast the new comment content and ID
                await self.channel_layer.group_send(
                    self.group_name,
                    {
                        'type': 'broadcast_comment',
                        'id': comment_id,
                        'post_id': data.get('post_id'),
                        'message': comment_content,
                        'movie_id': data.get('movie_id'),
                    }
                )
            else:
                raise ValueError("Invalid content object")

        except Exception as e:
            print(f"Error in CommentConsumer: {e}")
            await self.send(text_data=json.dumps({'error': str(e)}))

    async def broadcast_comment(self, event):
        await self.send(text_data=json.dumps({
            'id': event['id'],
            'message': event['message'],
            'post_id': event.get('post_id'),
            'movie_id': event.get('movie_id'),
        }))

    def get_user_from_token(self, access_token):
        try:
            from rest_framework_simplejwt.tokens import AccessToken
            token = AccessToken(access_token)
            return token.payload.get('user_id')
        except Exception:
            return None

    def save_comment(self, content,post=None,movie=None, user=None):
        from .models import Comment
        if user:
            
            if movie is not None:
                comment = Comment.objects.create(message=content, movie=movie, author=user)
            elif post is not None:
                comment = Comment.objects.create(message=content, post=post, author=user)
            else :
                raise ValueError("Invalid content object")
            return comment.id
