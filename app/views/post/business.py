from . import accessor
from ..user import accessor as user_accessor
from django.forms.models import model_to_dict


def handle_create_post(data, files):
    data_dict = {key: data.get(key) for key in data}
    data_dict['image'] = None
    validated_data = validate_post_create(data_dict)
    if not validated_data:
        return ({"message": "Validation error"}, 400)
    post = accessor.create_post(validated_data)
    return (get_post_data(post), 201)


def handle_update_post(data, files, id):
    data_dict = {key: data.get(key) for key in data}
    data_dict['image'] = files.get('image')
    validated_data = validate_post_update(data_dict, id)
    if not validated_data:
        return ({"message": "Validation error"}, 400)
    post = accessor.update_post(validated_data, id)
    return (get_post_data(post), 201)


def handle_delete(id):
    post = accessor.get_post_by_id(id)
    if not post:
        return ({'message': 'Post doesnot exists'}, 400)
    accessor.delete_post(id)
    return ({'message': 'Post deleted'}, 204)


def handle_like_post(id, data):
    post = accessor.get_post_by_id(id)
    if not post:
        return ({'message': 'Post doesnot exists'}, 400)
    user = user_accessor.get_user_by_id(data.get('user'))
    if not user:
        return ({'message': 'User doesnot exists'}, 400)
    liked = accessor.get_like(post, user)
    if liked:
        return ({'message': 'Already liked'}, 400)
    accessor.like_post(post, user)
    return ({'message': f'{user.username} liked {post.content}'}, 201)


def handle_comment_post(id, data):
    post = accessor.get_post_by_id(id)
    if not post:
        return ({'message': 'Post doesnot exists'}, 400)
    user = user_accessor.get_user_by_id(data.get('user'))
    if not user:
        return ({'message': 'User doesnot exists'}, 400)
    comment = accessor.comment_post(post, user, data.get('text'))
    return (model_to_dict(comment), 201)


def validate_data(data, required_fields, optional_fields):
    validated_data = {}
    data_keys = data.keys()
    for field in required_fields:
        if field not in data_keys:
            return False
        validated_data[field] = data[field]
    for opt_field in optional_fields:
        try:
            validated_data[opt_field] = data[opt_field]
        except:
            pass
    return validated_data


def validate_post_create(data):
    required_fields = ['user', 'content']
    optional_fields = ['image']
    if not data['user']:
        return False
    user = user_accessor.get_user_by_id(data['user'])
    if not user:
        return False
    data['user'] = user
    return validate_data(data, required_fields, optional_fields)


def validate_post_update(data, id):
    required_fields = []
    optional_fields = ['image', 'content']
    post = accessor.get_post_by_id(id)
    if not post:
        return False
    if not data['image']:
        data['image'] = post.image
    return validate_data(data, required_fields, optional_fields)


def get_post_data(post):
    num_likes = post.likes.count()
    num_comments = post.comments.count()
    comments = accessor.get_comments_of_post(post)
    comments_in_dict = [model_to_dict(comment) for comment in comments]
    post_data = {
        'id': post.id,
        'user': post.user.id,
        'image_url': post.image.url if post.image else None,
        'content': post.content,
        'created_at': post.created_at,
        'num_likes': num_likes,
        'num_comments': num_comments,
        'comments': comments_in_dict,
    }
    return post_data


def handle_get_post(id):
    post = accessor.get_post_by_id(id)
    if not post:
        return ({'message': 'Post not found'}, 404)
    return (get_post_data(post), 200)


def handle_get_all_posts():
    posts = accessor.get_posts()
    if not posts:
        return ({'message': 'Post not found'}, 404)
    return ([get_post_data(post) for post in posts], 200)


def handle_get_users_post(username):
    user = user_accessor.get_user_by_username(username)
    if not user:
        return ({'message': 'User does not exists'}, 400)
    posts = accessor.get_posts_by_user(user)
    if not posts:
        return ({'message': 'Posts not found'}, 404)
    return ([get_post_data(post) for post in posts], 201)
