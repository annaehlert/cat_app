import requests

BASE = "http://127.0.0.1:5000/"
#
#
data = [{"fact": "smelly cat, smelly cat"},
        {"fact": "cats are big"},
        {"fact": "kitty cat"},
        {"fact": "cats have 7 lifes"}]

for i in range(len(data)):
    response = requests.put(BASE, data[i])
    print(response.json())

