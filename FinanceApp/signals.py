from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from .models import Transactions
from .search_indexes import TransactionDocument
from django.core.cache import cache


# -------------------------------
# Create or Update transaction
# -------------------------------
@receiver(post_save, sender=Transactions)
def save_transaction_in_es(sender, instance, created, **kwargs):
    TransactionDocument().update(instance)

    cache_key = f"search_results_{instance.notes}"
    cache.delete(cache_key)

    if created:
        print(f"Transaction {instance.id} created and indexed in ES.")
    else:
        print(f"Transaction {instance.id} updated in ES.")


# -------------------------------
# Delete transaction
# -------------------------------
@receiver(post_delete, sender=Transactions)
def delete_transaction_in_es(sender, instance, **kwargs):
    TransactionDocument().delete(instance.id)
    cache_key = f"search_results_{instance.notes}"
    cache.delete(cache_key)
    print(f"Transaction {instance.id} deleted from ES.")
