
from logging import raiseExceptions
from multiprocessing import context
from urllib import request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from authapi.serializers import SendPasswordResetEmailSerializer
from authapi.models import User
from authapi.serializers import UserProfileSerializer
from authapi.serializers import UserLoginSerializer
from authapi.serializers import UserRegistrationSerializer,UserChangePasswordSerializer,UserResetPasswordSerializer
from django.contrib.auth import authenticate
from authapi.renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
# Create your views here.
# 
# Creating tokens manually.
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class UserRegistrationView(APIView):
    renderer_classes=[UserRenderer]
    def post(self,request,format=None):
        serializer=UserRegistrationSerializer(data=request.data)  

        if serializer.is_valid(raise_exception=True):
            user=serializer.save()
            token=get_tokens_for_user(user)
            return Response({'token':token,'msg':'Registration successful'},status=status.HTTP_201_CREATED ) 
               
        
        return Response(serializer.errors,status=status.HTTP_401_UNAUTHORIZED)


class UserLoginView(APIView):
    renderer_classes=[UserRenderer]
    def post(self,request,format=None):
        serializer=UserLoginSerializer(data=request.data)
 
        if serializer.is_valid(raise_exception=True):
            email=serializer.data.get('email')
            password=serializer.data.get('password')
            user=authenticate(email=email, password=password)

            if user is not None:
                token=get_tokens_for_user(user)
                return Response({'token':token,'msg':'Login Successs'},status=status.HTTP_202_ACCEPTED)
            else:
                return Response({'errors':{'non_field':['Email or password is not valid']}},status=status.HTTP_404_NOT_FOUND)

class UserProfileView(APIView):
    renderer_classes=[UserRenderer]
    permission_classes=[IsAuthenticated]
    def get(self,request,format=None):
        serializer=UserProfileSerializer(request.user)
        return Response(serializer.data,status=status.HTTP_200_OK)


class UserChangePasswordView(APIView):
    renderer_classes=[UserRenderer]
    permission_classes=[IsAuthenticated]
    def post(self,request,format=None):
        serializer=UserChangePasswordSerializer(data=request.data,context={'user':request.user})

        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'Login Successs'},status=status.HTTP_202_ACCEPTED)

        return Response({'errors':{'non_field':['Email or password is not valid']}},status=status.HTTP_404_NOT_FOUND)

class SendPasswordResetEmailView(APIView):
    renderer_classes=[UserRenderer]
    def post(self,request,format=None):
        serializer=SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'password link sent, Please check email'},status=status.HTTP_202_ACCEPTED)


class UserResetPasswordView(APIView):
    renderer_classes=[UserRenderer]
    def post(self,request,uid,token,format=None):
        serializer=UserResetPasswordSerializer(data=request.data,context={'uid':uid,'token':token})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'password reset successfully'},status=status.HTTP_202_ACCEPTED)

