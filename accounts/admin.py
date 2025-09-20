from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.translation import gettext_lazy as _
from .models import User


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    # Display fields in the list view
    list_display = ('email', 'first_name', 'last_name', 'is_staff',
                    'is_active', 'is_deleted')
    list_filter = ('is_staff', 'is_active', 'is_deleted', 'created_at')
    search_fields = ('email', 'first_name', 'last_name')
    ordering = ('email',)
    readonly_fields = ('last_login', 'created_at', 'updated_at')

    # Fieldsets for edit view
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name')}),
        (_('Permissions'), {
            'fields': ('is_active', 'is_staff', 'is_superuser',
                       'groups', 'user_permissions'),
        }),
        (_('Important dates'), {'fields': ('last_login', 'created_at',
                                           'updated_at')}),
        (_('Soft Delete Status'), {'fields': ('is_deleted', 'deleted_at')}),
    )

    # Fieldsets for add view
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'first_name', 'last_name',
                       'password1', 'password2'),
        }),
    )
