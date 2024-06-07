from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from rest_framework import status, views
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from .serializers import UserSerializer, ItemSerializer
from .models import Item



class ProtectedView(views.APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({'message': 'This is a protected endpoint, only accessible with a valid token.'})

class LogoutView(views.APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            token = request.auth
            if token:
                token.delete()
                return Response({'message': 'Logged out successfully.'}, status=status.HTTP_200_OK)
            return Response({'error': 'Token not provided.'}, status=status.HTTP_400_BAD_REQUEST)
        except Token.DoesNotExist:
            return Response({'error': 'Invalid token.'}, status=status.HTTP_400_BAD_REQUEST)

class RegisterView(views.APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            token, created = Token.objects.get_or_create(user=user)
            return Response({'token': token.key}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(views.APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)
        if user:
            token, created = Token.objects.get_or_create(user=user)
            return Response({'token': token.key}, status=status.HTTP_200_OK)
        return Response({'error': 'Invalid Credentials'}, status=status.HTTP_400_BAD_REQUEST)

class ItemViewSet(views.APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        items = Item.objects.filter(user=request.user)
        serializer = ItemSerializer(items, many=True)
        return Response(serializer.data)

    def post(self, request):
        user=request.user
        print(user.id)
        data=request.data
        combined_data = {**data, 'user': user.id}
        serializer = ItemSerializer(data=combined_data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def patch(self, request, pk):  # Ensure pk is passed to the method
        try:
            item = Item.objects.get(id=pk)  # Pass pk to get method
            serializer = ItemSerializer(item, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data,status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Item.DoesNotExist:
            return Response({'error': 'Item not found.'}, status=status.HTTP_404_NOT_FOUND)
            

    def delete(self, request, pk):
        item = Item.objects.get(id=pk)
        item.delete()
        return Response({'message': 'Item deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)
