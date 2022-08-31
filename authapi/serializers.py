from dataclasses import fields
from unittest.util import _MAX_LENGTH
from xml.dom import ValidationErr
from rest_framework import serializers

from authapi.models import User
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from authapi.utils import Util

class UserRegistrationSerializer(serializers.ModelSerializer):
    password2= serializers.CharField(style={'input_type':'password'},write_only=True)

    class Meta:
        model = User
        fields=['email','name','password','password2','tc']
        extra_kwargs={
            'password':{'write_only':True}
        }

    def validate(self, attrs):

        password=attrs.get('password')
        password2=attrs.get('password2')
        
        if password!=password2:
            raise ValidationErr("password mismatch!")


        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

class UserLoginSerializer(serializers.ModelSerializer):
    email=serializers.EmailField(max_length=255)
    class Meta:
        model=User
        fields=['email','password']

class UserProfileSerializer(serializers.ModelSerializer):
    
    class Meta:
        model=User
        fields=['id','name','email']

class UserChangePasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(style={'input_type':'password'},write_only=True)
    password2 = serializers.CharField(style={'input_type':'password'},write_only=True)
    class Meta:
        model=User
        fields=['password','password2']

    def validate(self, attrs):
        password=attrs.get('password')
        password2=attrs.get('password2')
        user=self.context.get('user')
        if password!=password2:
            raise ValidationErr("password mismatch!")

        user.set_password(password)
        user.save()

        return attrs

class SendPasswordResetEmailSerializer(serializers.Serializer):
    email=serializers.EmailField(max_length=255)
    class Meta:
        model=User
        fields=['email']

    def validate(self, attrs):
        email=attrs.get('email')
        if User.objects.filter(email=email).exists():
            user=User.objects.get(email=email)
            uid= urlsafe_base64_encode(force_bytes(user.id))
            token=PasswordResetTokenGenerator().make_token(user) 
            link='http://localhost:3000/api/user/reset/'+uid+'/'+token
            print("password reset link: ",link)
            # sendemail
            body='Click following link to reset your password: '+link
            data={
                'subject':'Reset password ',
                'body':body,
                'to':user.email
            }
            Util.send_emial(data)
            return attrs
        else:
            raise ValidationErr("Invalid email!")

    
class UserResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(style={'input_type':'password'},write_only=True)
    password2 = serializers.CharField(style={'input_type':'password'},write_only=True)
    class Meta:
        model=User
        fields=['password','password2']

    def validate(self, attrs):
        try:
            password=attrs.get('password')
            password2=attrs.get('password2')
            uid=self.context.get('uid')
            token=self.context.get('token')
            
            if password!=password2:
                raise ValidationErr("password mismatch!")
            id=smart_str(urlsafe_base64_decode(uid))
            user=User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user,token):
                raise ValidationErr('Token is either invalid or expired')
            user.set_password(password)
            user.save()

            return attrs
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user,token)
            raise ValidationErr('Token is not valid or expired')



