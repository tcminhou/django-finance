from django.apps import AppConfig


class FinanceappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'FinanceApp'

    def ready(self):
        from django.contrib import admin
        from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
        from rest_framework.authtoken.models import Token

        for model in [BlacklistedToken, OutstandingToken, Token]:
            try:
                admin.site.unregister(model)
            except admin.sites.NotRegistered:
                pass
