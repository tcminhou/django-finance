from django_elasticsearch_dsl import Document, Index, fields
from django_elasticsearch_dsl.registries import registry
from .models import Transactions

# Tạo index
transactions_index = Index('transactions')
transactions_index.settings(
    number_of_shards=1,
    number_of_replicas=0
)


@registry.register_document
class TransactionDocument(Document):
    id = fields.IntegerField(attr='id')
    amount = fields.FloatField(attr='amount')
    type = fields.KeywordField(attr='type')
    date = fields.DateField(attr='date')
    notes = fields.TextField(
        fields={
            'raw': fields.KeywordField(),  # dùng cho exact match hoặc sort
        }
    )
    # Mapping FK fields
    user_id = fields.IntegerField(attr='user_id_id')  # nếu FK field là user_id
    category_id = fields.IntegerField(attr='category_id_id')  # nếu FK field là category_id

    class Index:
        name = 'transactions'

    class Django:
        model = Transactions
        fields = []
