# django-finance
Django-based backend for the Finance App


# Setup Instructions

## 1. Install Django Framework
- Open the terminal and run the following command to install Django:
 
  ```bash
  pip install django
  ```
![alt text](pip_install_django.png)  

## 2. Create Project Structure
- Initialize a new Django project by running:
  
  ```bash
  django-admin startproject config .
  ```  

In this command, config is the name of the main project module, and the dot (.) specifies that the project should be created in the current directory.
  
## 3. Run the Development Server
- To start the local development server, use the following command:
 
  ```bash
  python manage.py runserver
  ```
  
![alt text](run_server.png)

- Result: 

![alt text](result.png)

# Design Database Schema
- **Database Engine**: MySQL (using `django.db.backends.mysql` in Django settings)
    **Database Configuration:**
    + This project uses **MySQL** as its primary database. Make sure to configure your `settings.py` with the appropriate credentials:
      DATABASES = {
          'default': {
              'ENGINE': 'django.db.backends.mysql',
              'NAME': 'your_db_name',
              'USER': 'your_db_user',
              'PASSWORD': 'your_db_password',
              'HOST': '',
          }
      }
    + Run the following to set up your schema:
      **python manage.py migrate**
- Erd Diagram:
![alt text](ERD.png)
- Models Overview
    + **Users**: Stores user details
    + **Categories**: Hierarchical transaction categories
    + **Transactions**: One-time financial transactions
    + **RecurringTransactions**: Automatically repeating transactions
    + **Settings**: User preferences
