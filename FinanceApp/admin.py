# admin.py
from django.contrib import admin
from .models import Users, Categories, Transactions, RecurringTransactions, Settings
from django.contrib.auth.models import Group

admin.site.unregister(Group)

admin.site.register(Users)
admin.site.register(Categories)
admin.site.register(Transactions)
admin.site.register(RecurringTransactions)
admin.site.register(Settings)
