from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()


class Resource(models.Model):
    """
    Resource model for demonstrating permission-based access control
    """
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    content = models.TextField()
    permission_required = models.CharField(
        max_length=100,
        help_text="Permission code required to access this resource"
    )
    created_by = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='created_resources'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'resources'
        ordering = ['-created_at']

    def __str__(self):
        return self.name
