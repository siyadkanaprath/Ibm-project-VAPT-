# init_db.py
from app import app, db, User, Post, Comment # Import the app and models
from datetime import datetime

with app.app_context():
    db.create_all()
    print("Database tables created.")

    # --- Create an admin user (for demonstration) ---
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        admin_user = User(username='admin', password='adminpassword', email='admin@example.com', is_admin=True) # VULNERABILITY: Still using plaintext password
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created: username='admin', password='adminpassword'")

    # --- Create some sample posts ---
    if not Post.query.first():
        user = User.query.first() # Get the first user to associate with the posts
        if user:
            post1 = Post(title='First Blog Post', slug='first-blog-post', content='This is the content of the very first blog post. It might contain some interesting information or just be placeholder text.', pub_date=datetime.utcnow(), user_id=user.id)
            post2 = Post(title='Another Great Article', slug='another-great-article', content='Here\'s another insightful piece of writing for our readers to enjoy. We hope you find it informative.', pub_date=datetime.utcnow(), user_id=user.id)
            db.session.add_all([post1, post2])
            db.session.commit()
            print("Sample blog posts created.")
        else:
            print("No users found to associate with the sample posts.")

    print("Database initialization complete.")