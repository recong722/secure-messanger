import requests


url="https://bbangket.com/shop_view/?idx=83"
while(1):
    r=requests.get(url)
    print(r.text)

