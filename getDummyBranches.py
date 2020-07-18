import urllib.request as request
import json

url = "https://atlas.api.barclays/open-banking/v2.1/branches"

with request.urlopen(url) as response:
    if response.getcode() == 200:
        source = response.read()
        data = json.loads(source)
    else:
        print('An error occurred while attempting to retrieve data from the API.')

with open('branches.json', 'w') as f:
  json.dump(data, f, indent = 4, sort_keys = True)

record = (data['data'][0]['Brand'][0]['Branch'])
for item in range(len(record)):
    print("**********************************STOP******************************************")
    print(record[item]['PostalAddress'])

def searchbyloc()