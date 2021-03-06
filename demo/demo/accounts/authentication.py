from rest_framework.authentication import TokenAuthentication

from .models import APIToken


class APITokenAuthentication(TokenAuthentication):
    model = APIToken
