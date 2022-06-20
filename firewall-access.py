import requests
from bs4 import BeautifulSoup as bs
import time
import csv
import os
import pandas as pd
""" #Logic courtesy for the api call : Alex Cormier
r = requests.get('https://console.prod.awn/api/v2/customer-cse-list?format=json')
data_dump = r.json()


ids=[]
endclient = []
id = input("Enter MSP name: ")
for i in data_dump:
    if id == i['msp']:
        endclient.append(i['id'])


data_dump = 0
print (endclient) """

#generating a list of all the firewalls a clients has

url = requests.get(f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/amplify/summ/cust-firewall/Firewall-type%3Dconfigured-parser,Firewall%20Name=source.host/count=count/?limit=100&days=10&end=now')
soup = bs(url.content,'html.parser')

filename = '/Users/moiz.lakdawala/projects/firewall-assess/test.csv'

csv_writer = open('/Users/moiz.lakdawala/projects/firewall-assess/test.csv','w')
csv_writer1 = csv.writer(csv_writer)
#csv_writer1 = csv.writer(open(filename,'w'))


heading = soup.find('table')

print(heading.text)


for tr in soup.find_all('tr'):
    data = []

    for th in tr.find_all('th'):
        data.append(th.text)

    if data:
        print("Inserting headers : {}".format(','.join(data)))
        csv_writer1.writerow(data)
        continue

    for td in tr.find_all('td'):
        data.append(td.text.strip())

    if data:
        print("Inserting Table Data:{}".format(','.join(data)))
        csv_writer1.writerow(data)
csv_writer.close()
        
        


#checkfile = "cat /Users/moiz.lakdawala/projects/correlation/read_input_csv/names.csv"

#os.system(checkfile)

print("\n")
print("rendering the csv and generating the list")
time.sleep(3)


filename = open('/Users/moiz.lakdawala/projects/firewall-assess/test.csv', 'r')
 
# creating dictreader object
file = csv.DictReader(filename)
 
# creating empty lists
IP = []

 
# iterating over each row and append
# values to empty list
for col in file:
    IP.append(col['Firewall-type'])
    
 
#printing lists
#print('Names:', IP)

print (IP[0])

if IP[0] == 'fw-watchguard':
    cmd='clear'
    os.system(cmd)
    print("looks like your client has a Watchguard firewall")
elif IP[0] == 'fw-palo-alto':
    cmd='clear'
    os.system(cmd)
    filename = open('/Users/moiz.lakdawala/projects/firewall-assess/test.csv', 'r')
    # creating dictreader object
    file = csv.DictReader(filename)
    # creating empty lists
    fwname = []
    # iterating over each row and append
    # values to empty list
    for col in file:
        fwname.append(col['Firewall Name'])
    print(fwname)
    #paloalto host file type block
    i = 0
    fw_output = []
    for i in range(len(fwname)):
        url = requests.get(f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/amplify/summ/cust-firewall/Firewall-type%3Dconfigured-parser,Firewall%20Name=source.host,firewall.type=firewall.type/count=count/?limit=100&days=7&end=now&source.host={fwname[i]}')
        soup = bs(url.content,'html.parser')

        filename = '/Users/moiz.lakdawala/projects/firewall-assess/fw_type.csv'

        csv_writer = open('/Users/moiz.lakdawala/projects/firewall-assess/fw_type.csv','w')
        csv_writer1 = csv.writer(csv_writer)
        #csv_writer1 = csv.writer(open(filename,'w'))


        heading = soup.find('table')

        print(heading.text)


        for tr in soup.find_all('tr'):
            data = []

            for th in tr.find_all('th'):
                data.append(th.text)

            if data:
                print("Inserting headers : {}".format(','.join(data)))
                csv_writer1.writerow(data)
                continue

            for td in tr.find_all('td'):
                data.append(td.text.strip())

            if data:
                print("Inserting Table Data:{}".format(','.join(data)))
                csv_writer1.writerow(data)
        csv_writer.close()
                
                


        #checkfile = "cat /Users/moiz.lakdawala/projects/correlation/read_input_csv/names.csv"

        #os.system(checkfile)

        print("\n")
        print("rendering the csv and generating the list")
        time.sleep(3)


        filename = open('/Users/moiz.lakdawala/projects/firewall-assess/fw_type.csv', 'r')
        
        # creating dictreader object
        file = csv.DictReader(filename)
        
        # creating empty lists
        fw_type = []

        
        # iterating over each row and append
        # values to empty list
        for col in file:
            fw_type.append(col['firewall.type'])
            
        
        #printing lists
        #print('Names:', IP)

        print (fw_type)
        ogfw_type = ['GLOBALPROTECT', 'HIPMATCH', 'SYSTEM', 'THREAT', 'TRAFFIC', 'CONFIG']
        fw_output.append((set(ogfw_type).difference(fw_type)))
        #print(input('press enter to continue'))
    i = i + 1
    #print(fw_output)
    df = pd.DataFrame(list(zip(fwname,fw_output)),
               columns =['Firewall-Name', 'Missing Log Types'])
    print(df)
    df.to_csv('/Users/moiz.lakdawala/projects/firewall-assess/amplify.csv')
else:
    print("not sure what firewall it is , Moiz has not written that far ahead")
