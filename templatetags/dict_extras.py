from django import template

register = template.Library()

@register.filter
def get_item(dictionary, key):
    """Get item from dictionary using key"""
    if isinstance(dictionary, dict):
        return dictionary.get(key, 0)
    return 0

@register.filter
def replace(value, args):
    """Replace characters in string"""
    if args:
        old, new = args.split('|')
        return value.replace(old, new)
    return value
