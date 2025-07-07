from django.db import models


class BaseModel(models.Model):
    create_date = models.DateTimeField(auto_now_add=True, null=False)
    update_date = models.DateTimeField(auto_now=True, null=False)
    active = models.BooleanField(default=True)

    class Meta:
        abstract = True


class Users(BaseModel):
    email = models.CharField(max_length=255, unique=False)
    password_hash = models.CharField(max_length=255, null=False)
    name = models.CharField(max_length=100, null=False)
    timezone = models.CharField(max_length=50, null=False)

    def __str__(self):
        return self.email


class Categories(BaseModel):
    name = models.CharField(max_length=100, null=False)
    user_id = models.ForeignKey(Users, on_delete=models.SET_NULL, null=True, blank=True)
    parent_category_id = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True,
                                           related_name='parent_cate')

    def __str__(self):
        return self.name


class Transactions(BaseModel):
    TRANSACTION_TYPES = [
        ('income', 'Income'),
        ('expense', 'Expense'),
    ]
    date = models.DateField(null=False)
    amount = models.DecimalField(max_digits=10, decimal_places=2, null=False)
    type = models.CharField(max_length=10, choices=TRANSACTION_TYPES)
    notes = models.TextField(blank=True, null=False)
    attachment_url = models.URLField(max_length=255)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE, null=False, blank=False)
    category_id = models.ForeignKey(Categories, on_delete=models.SET_NULL, null=True, blank=True, default=None)

    def __str__(self):
        return f"{self.amount} ({self.type}) on {self.date}"


class RecurringTransactions(BaseModel):
    TRANSACTION_TYPES = [
        ('income', 'Income'),
        ('expense', 'Expense'),
    ]

    RECURRENCE_TYPES = [
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
        ('yearly', 'Yearly'),
    ]

    amount = models.DecimalField(max_digits=10, decimal_places=2, null=False)
    type = models.CharField(max_length=10, choices=TRANSACTION_TYPES, null=False)
    notes = models.TextField(blank=True, null=False)
    start_date = models.DateField(null=False)
    end_date = models.DateField(null=False, blank=True)
    recurrence_type = models.CharField(max_length=10, choices=RECURRENCE_TYPES, null=False)
    next_occurrence = models.DateField(null=False)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE, null=False, blank=True)
    category_id = models.ForeignKey(Categories, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return f"{self.amount} {self.type} ({self.recurrence_type})"


class Settings(BaseModel):
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE, null=False, blank=True)
    currency = models.CharField(max_length=10, null=False, default='USD')
    language = models.CharField(max_length=10, null=False, default='en')

    def __str__(self):
        return f"{self.user_id.email} - {self.currency} / {self.language}"
