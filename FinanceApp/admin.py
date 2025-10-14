from django.contrib import admin
<<<<<<< Updated upstream
from .models import Users, Categories, Transactions, RecurringTransactions, Settings
=======
from django.contrib.auth.models import Group
from django.core.cache import cache
from django.db.models.expressions import RawSQL
from elasticsearch.helpers import scan
from elasticsearch_dsl.connections import connections
from .search_indexes import TransactionDocument
from .models import Users, Categories, Transactions, RecurringTransactions, Settings

# Ẩn Group mặc định
admin.site.unregister(Group)
>>>>>>> Stashed changes


@admin.register(Users)
class UsersAdmin(admin.ModelAdmin):
    list_display = ("id", "email", "name", "timezone", "is_active", "is_staff", "date_joined")
    search_fields = ("email__icontains", "name__icontains")
    list_filter = ("is_active", "is_staff", "timezone")
    ordering = ("-date_joined",)


@admin.register(Categories)
class CategoriesAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "user_id", "parent_category_id")
    search_fields = ("name__icontains",)
    list_filter = ("user_id",)
    autocomplete_fields = ("user_id", "parent_category_id")  # không load hết dropdown


@admin.register(Transactions)
class TransactionsAdmin(admin.ModelAdmin):
    list_display = ("id", "amount", "type", "date", "user_id", "category_id", "short_notes")
    search_fields = ("notes",)
    list_filter = ("type", "date")

    def short_notes(self, obj):
        if obj.notes and len(obj.notes) > 150:
            return obj.notes[:150] + "....."
        else:
            return obj.notes

    short_notes.short_description = "Notes"

    def get_search_results(self, request, queryset, search_term):
        if not search_term:
            return queryset, False

        cache_key = f"search_results_{search_term}"
        cached_results = cache.get(cache_key)

        # Check if already have cache
        if cached_results is not None:
            return queryset.filter(id__in=cached_results), False

        if search_term:
            client = connections.get_connection()
            scan_results = scan(
                client,
                query={"query": {"match_phrase": {"notes": search_term}}},
                index="transactions",
            )
            ids = [doc["_id"] for doc in scan_results]

            if ids:
                cache.set(cache_key, ids, timeout=60 * 60 * 24 * 7)
                return queryset.filter(id__in=ids), False
            else:
                return queryset.none(), False

        return queryset, False


@admin.register(RecurringTransactions)
class RecurringTransactionsAdmin(admin.ModelAdmin):
    list_display = ("id", "amount", "type", "recurrence_type", "start_date", "end_date", "user_id")
    search_fields = ("notes__icontains",)
    list_filter = ("type", "recurrence_type", "user_id")
    ordering = ("-start_date",)
    list_select_related = ("user_id", "category_id")
    autocomplete_fields = ("user_id", "category_id")


@admin.register(Settings)
class SettingsAdmin(admin.ModelAdmin):
    list_display = ("id", "user_id", "currency", "language")
    list_filter = ("currency", "language")
    search_fields = ("user_id__email__icontains",)
    autocomplete_fields = ("user_id",)
