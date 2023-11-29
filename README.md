# USOF API<br/>
  API based on JS Express for programming forums like stackoverflow.<br/>
# How to run<br/>
-npm start<br/>

# Endpoints<br/>

# Authentication module:<br/>
POST /api/auth/register: Register a new user. Required parameters are [login, password, fullName, email, avatar].<br/>
POST /api/auth/login: Log in a user. Required parameters are [login, password]. Only users with a confirmed email can sign in.<br/>
POST /api/auth/logout: Log out an authorized user.<br/>
GET /api/auth/confirm/<token>: Email confirmation.<br/>
POST /api/auth/password-reset: Send a reset link to the user's email. Required parameter is [email].<br/>
POST /api/auth/password-reset/<token>: Changing password with token from [email].<br/>

# User Module:<br/>
GET /api/users: Get all users.<br/>
GET /api/users/<user_id>: Get specified user data.<br/>
GET /api/users/<user_id>/posts: Get all posts by user with such id.<br/>
POST /api/users: Create a new user. Required parameters are [login, password, email, role]. This feature must be accessible only for admins.<br/>
POST /api/users/edit: Gain access to the profile editing menu.<br/>
PATCH /api/users/avatar: Upload user avatar.<br/>
PATCH /api/users/<user_id>: Update user data.<br/>
DELETE /api/users/<user_id>: Delete a user.<br/>

# Admins Module:<br/>
GET /api/admins/<user_id>: Checks user access to the admin panel.<br/>

# Search Module:<br/>
GET /api/search/users: Search for users by their login.<br/>

# File Module:<br/>
GET /api/files/<file>: Returns the path to the file by its name.<br/>

# Status Module:<br/>
PATCH /api/status/posts/<post_id>: Changes the status of a post by its ID to the opposite one.<br/>
PATCH /api/status/comments/<comment_id>: Changes the status of a сomment by its ID to the opposite one.<br/>

# Like Module:<br/>
POST /api/like/posts/<post_id>: Create a new like under a post.<br/>
GET /api/like/posts/<post_id>: Get all likes undet the specified post.<br/>
GET /api/like/comments/<comment_id>: Get all likes under the specified comment.<br/>
POST /api/like/posts/<post_id>: Create a new like under a post.<br/>
POST /api/like/comments/<comment_id>: Create a new like under a comment.<br/>
DELETE /api/like/posts/<post_id>: Delete a like under a post.<br/>
DELETE /api/like/comments/<comment_id>: Delete a like under a comment.<br/>

# Post Module:<br/>
GET /api/posts: Get all posts. This endpoint doesn't require any role, it is public. Implement pagination if there are too many posts.<br/>
GET /api/posts/<post_id>/files: Returns the path to the files of a specific post by its ID.<br/>
GET /api/posts/user/<user_id>: Returns posts of a specific user by his ID.<br/>
GET /api/posts/<post_id>: Get specified post data. Endpoint is public.<br/>
GET /api/posts/<post_id>/comments: Get all comments for the specified post. Endpoint is public.<br/>
POST /api/posts/<post_id>/comments: Create a new comment. Required parameter is [content].<br/>
GET /api/<post_id>/categories: Get all categories associated with the specified post.<br/>
GET /api/posts/<post_id>/like: Get all likes under the specified post.<br/>
POST /api/posts: Create a new post. Required parameters are [title, content, categories].<br/>
PATCH /api/posts/<post_id>: Update the specified post (its title, body, or category). It's accessible only for the creator of the post.<br/>
DELETE /api/posts/<post_id>: Delete a post.<br/>

# Categories Module:<br/>
GET /api/categories: Get all categories.<br/>
GET /api/category/<category_id>: Get specified category data.<br/>
GET /api/category/<category_id>/posts: Get all posts associated with the specified category.<br/>
POST /api/categories: Create a new category. Required parameter is [title].<br/>
PATCH /api/categories/<category_id>: Update specified category data.<br/>
DELETE /api/categories/<category_id>: Delete a category.<br/>

# Comments Module:
GET /api/comments/<comment_id>: Get specified comment data.<br/>
PATCH /api/comments/<comment_id>: Update specified comment data.<br/>
DELETE /api/comments/<comment_id>: Delete a comment.<br/>
