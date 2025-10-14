from django.db import migrations

class Migration(migrations.Migration):

    dependencies = [
        ("FinanceApp", "0007_revokedaccesstoken"),  # thay bằng migration trước đó
    ]

    operations = [
        migrations.RunSQL(
            sql="ALTER TABLE financeapp_transactions ADD FULLTEXT INDEX idx_notes_fulltext (notes);",
            reverse_sql="ALTER TABLE transactions DROP INDEX idx_notes_fulltext;",
        ),

        migrations.RunSQL(
            sql="ALTER TABLE financeapp_recurringtransactions ADD FULLTEXT INDEX idx_notes_fulltext (notes);",
            reverse_sql="ALTER TABLE transactions DROP INDEX idx_notes_fulltext;",
        ),
    ]

