import urllib.request
from django import views
from django.forms import ValidationError
from . import models
from rest_framework import viewsets , permissions , response , status , exceptions , views
from . import serializers
from auth_rest_phone import models as bmodels
from datetime import date , timedelta
from django.utils.dateparse import parse_date
from role_manager.permissions import HasGroupRolePermission

# def get_week():
#     today = date.today()
#     week_lable = {7 : 'shanbe' , 1:'yekshanbe' , 2:'dosh' , 3:'sesh' , 4 :'charsh' , 5:'pansh' , 6:'jome'}
#     days = []
#     for day in range(7):
#         today += timedelta(days = 1)
#         weekday = (today.isoweekday() % 7) +1
#         days.append({'day' :week_lable[weekday] , 'date' : today})

#     return days


class TaketimeView(viewsets.ModelViewSet):
    queryset = models.Time.objects.all()
    serializer_class = serializers.TimeSerializer  
    # permission_classes = [permissions.IsAuthenticated , HasGroupRolePermission]
    
    def get_queryset(self):
            assert self.queryset is not None, (
            "'%s' should either include a `queryset` attribute, "
            "or override the `get_queryset()` method."
            % self.__class__.__name__
        )

            if self.request.user.is_superuser:
                queryset=models.Time.objects.all()
            else:
                today=date.today()
                queryset = models.Time.objects.filter(date__gte=today,is_active=True)
                
            return queryset

    def create(self, request, *args, **kwargs):
        # today = date.today()
        # today=str(today)
        # # date_order = request.date.get('date' , None)
        # days = get_week()
        data = request.data
        date=data.get('date')
        date=parse_date(date)
        week_lable = {7 : 'shanbe' , 1:'yekshanbe' , 2:'doshanbe' , 3:'seshanbe' , 4 :'charshanbe' , 5:'panjshanbe' , 6:'jome'}
        days = []
        # date += timedelta(days = 1)
        weekday = (date.isoweekday() % 7) +1
        days=week_lable[weekday]
        # data['day']=days
        _time=data.get('time')
        _date=data.get('date')
        time_date, created=models.Time.objects.get_or_create(date = _date,time = _time, defaults={'day':days,'is_active':True} )
        # if data['date'] < today:
        #     assert exceptions.NotAcceptable(detail='date does not exist' , code='date_does_not_exist')
        #     return response.Response(data=None, status=status.HTTP_406_NOT_ACCEPTABLE)
        # try:
        #         data['date']=data['date']
        # except :
        #     assert exceptions.NotFound(detail='date does not' , code='date_does_not')
        
            # return response.Response(serializer.data )
        # data=dict(time)
        # serializer = self.get_serializer(data=dict(time_date))
        serializer = self.get_serializer(time_date)
        # serializer=list(serializer.data)
        # serializer.is_valid(raise_exception=True)
        # self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return response.Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)


class ReserveTimeAPIView(views.APIView):
    def post(self , request):
        time_id = request.query_params.get('time_id' , 0)
        user=request.user.id
        if time_id==0:
            raise ValidationError(code = 'time_id_is_required' , detail= 'please enter time id')
        else:
            time = models.Time.objects.filter(id = time_id) 
            time_ser=serializers.TimeSerializer(time, many=True)
            time_ser.data[0]['is_active']=0
            time_ser.data[0]['user']=user
            print(time_ser.data[0]['is_active'])  
            return response.Response(time_ser.data)