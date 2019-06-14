from django.shortcuts import render
from Alipay.pay import AliPay
from django.shortcuts import HttpResponse, render, redirect
from django.conf import settings
import time


# Create your views here.
def aliPay():
    obj = AliPay(
        appid=settings.APPID,
        app_notify_url=settings.NOTIFY_URL,
        app_private_key_path=settings.PRI_KEY_PATH,
        alipay_public_key_path=settings.PUB_KEY_PATH,
        return_url=settings.RETURN_URL,
        debug=True
    )
    return obj


def alipay(request):
    if request.method == 'GET':
        return render(request, 'index.html')
    obj = aliPay()
    article = str(request.POST.get('article'))
    serial_number = str(time.time())
    price = float(request.POST.get('price'))
    pay_url = obj.direct_pay(
        subject=article,
        out_trade_no=serial_number,
        total_amount=price)
    completion_url = 'https://openapi.alipaydev.com/gateway.do?{}'.format(pay_url)
    return redirect(completion_url)


def ok(request):
    params = request.GET.dict()
    sign = params.pop('sign', None)
    obj = aliPay()
    ret = obj.verify(params, sign)
    if ret:
        return HttpResponse('支付成功')
    return HttpResponse("支付失败")
