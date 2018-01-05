from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.utils.translation import gettext as _

from rest_auth_toolkit.utils import get_setting


User = get_user_model()


class ResetPasswordForm(forms.Form):
    email = forms.EmailField(label=_("Email"), max_length=254)

    def send_mail(self, context, to_email):
        """
        Sends a django.core.mail.EmailMultiAlternatives to `to_email`.
        """
        subject = _('Reset password')
        from_address = get_setting('email_confirmation_from')
        text_content = render_to_string('rest_auth_toolkit/email_reset_password.txt',
                                        context)

        html_content = render_to_string('rest_auth_toolkit/email_reset_password.html',
                                        context)
        send_mail(subject=subject,
                  from_email=from_address, recipient_list=[to_email],
                  message=text_content, html_message=html_content,
                  fail_silently=False)

    def get_users(self, email):
        """Given an email, return matching user(s) who should receive a reset.

        This allows subclasses to more easily customize the default policies
        that prevent inactive users and users with unusable passwords from
        resetting their password.
        """
        active_users = User.objects.filter(**{
            '%s__iexact' % User.get_email_field_name(): email,
            'is_active': True,
        })
        return (u for u in active_users if u.has_usable_password())

    def save(self, use_https=False, token_generator=default_token_generator,
             request=None):
        """
        Generates a one-use only link for resetting password and sends to the
        user.
        """
        email = self.cleaned_data["email"]
        for user in self.get_users(email):
            current_site = get_current_site(request)
            site_name = current_site.name
            domain = current_site.domain

            context = {
                'email': email,
                'domain': domain,
                'site_name': site_name,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'user': user,
                'token': token_generator.make_token(user),
                'protocol': 'https' if use_https else 'http',
            }
            self.send_mail(context, email)
