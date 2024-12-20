# Generated by Django 5.0.6 on 2024-07-15 06:05

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0003_alter_contrato_abogado_alter_contrato_cliente'),
    ]

    operations = [
        migrations.AlterField(
            model_name='contrato',
            name='abogado',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='contratos_abogado', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='contrato',
            name='cliente',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]
