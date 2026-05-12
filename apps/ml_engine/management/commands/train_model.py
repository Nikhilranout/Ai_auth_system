"""
Management command to train ML model.
"""

import logging

from django.core.management.base import BaseCommand

from apps.ml_engine.train_model import ModelTrainer

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Train the ML model for behavioral authentication'

    def add_arguments(self, parser):
        parser.add_argument(
            '--model-type',
            type=str,
            default='random_forest',
            help='Type of model to train (random_forest, logistic_regression, decision_tree)'
        )

    def handle(self, *args, **options):
        model_type = options['model_type']

        self.stdout.write(f'Training {model_type} model...')

        trainer = ModelTrainer()
        success = trainer.train(model_type=model_type)

        if success:
            trainer.save_model()
            self.stdout.write(
                self.style.SUCCESS(
                    f'Model trained successfully!\n'
                    f'  Type: {trainer.model_type}\n'
                    f'  Accuracy: {trainer.accuracy:.2%}'
                )
            )
        else:
            self.stdout.write(
                self.style.ERROR('Model training failed.')
            )
