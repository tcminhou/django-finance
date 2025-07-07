# django-finance
Django-based backend for the Finance App


# Setup Instructions

## 1. Install Django Framework
- Open the terminal and run the following command to install Django:
 
  ```bash
  pip install django
  ```
  
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

# Design Database Schema
- Models Overview
    + **Users**: Stores user details
    + **Categories**: Hierarchical transaction categories
    + **Transactions**: One-time financial transactions
    + **RecurringTransactions**: Automatically repeating transactions
    + **Settings**: User preferences
- Erd Diagram:
![alt text](ERD.png)
