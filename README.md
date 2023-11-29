# USOF API
  API based on JS Express for programming forums like stackoverflow.
# How to run
-npm start

# Endpoints

# Authentication module:
POST /api/auth/register: Register a new user. Required parameters are [login, password, fullName, email, avatar].
POST /api/auth/login: Log in a user. Required parameters are [login, password]. Only users with a confirmed email can sign in.
POST /api/auth/logout: Log out an authorized user.
GET /api/auth/confirm/<token>: Email confirmation.
POST /api/auth/password-reset: Send a reset link to the user's email. Required parameter is [email].
POST /api/auth/password-reset/<token>: Changing password with token from [email].

# User Module:
GET /api/users: Get all users.
GET /api/users/<user_id>: Get specified user data.
GET /api/users/<user_id>/posts: Get all posts by user with such id.
POST /api/users: Create a new user. Required parameters are [login, password, email, role]. This feature must be accessible only for admins.
POST /api/users/edit: Gain access to the profile editing menu.
PATCH /api/users/avatar: Upload user avatar.
PATCH /api/users/<user_id>: Update user data.
DELETE /api/users/<user_id>: Delete a user.

# Admins Module:
GET /api/admins/<user_id>: Checks user access to the admin panel.

# Search Module:
GET /api/search/users: Search for users by their login.

# File Module:
GET /api/files/<file>: Returns the path to the file by its name.

# Status Module:
PATCH /api/status/posts/<post_id>: Changes the status of a post by its ID to the opposite one
PATCH /api/status/comments/<comment_id>: Changes the status of a сomment by its ID to the opposite one

# Like Module:
POST /api/like/posts/<post_id>: Create a new like under a post.
GET /api/like/posts/<post_id>: Get all likes undet the specified post.
GET /api/like/comments/<comment_id>: Get all likes under the specified comment.
POST /api/like/posts/<post_id>: Create a new like under a post.
POST /api/like/comments/<comment_id>: Create a new like under a comment.
DELETE /api/like/posts/<post_id>: Delete a like under a post.
DELETE /api/like/comments/<comment_id>: Delete a like under a comment.

# Post Module:
GET /api/posts: Get all posts. This endpoint doesn't require any role, it is public. Implement pagination if there are too many posts.
GET /api/posts/<post_id>/files: Returns the path to the files of a specific post by its ID.
GET /api/posts/user/<user_id>: Returns posts of a specific user by his ID.
GET /api/posts/<post_id>: Get specified post data. Endpoint is public.
GET /api/posts/<post_id>/comments: Get all comments for the specified post. Endpoint is public.
POST /api/posts/<post_id>/comments: Create a new comment. Required parameter is [content].
GET /api/<post_id>/categories: Get all categories associated with the specified post.
GET /api/posts/<post_id>/like: Get all likes under the specified post.
POST /api/posts: Create a new post. Required parameters are [title, content, categories].
PATCH /api/posts/<post_id>: Update the specified post (its title, body, or category). It's accessible only for the creator of the post.
DELETE /api/posts/<post_id>: Delete a post.

# Categories Module:
GET /api/categories: Get all categories.
GET /api/category/<category_id>: Get specified category data.
GET /api/category/<category_id>/posts: Get all posts associated with the specified category.
POST /api/categories: Create a new category. Required parameter is [title].
PATCH /api/categories/<category_id>: Update specified category data.
DELETE /api/categories/<category_id>: Delete a category.

# Comments Module:
GET /api/comments/<comment_id>: Get specified comment data.
PATCH /api/comments/<comment_id>: Update specified comment data.
DELETE /api/comments/<comment_id>: Delete a comment.
