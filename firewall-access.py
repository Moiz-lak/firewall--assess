"""####### ArcticWolf Firewall Assessment Script #######

Authors:
    - Moiz Lakdawala (moiz.lakdawala@arcticwolf.com)
    - Ethan Berg (ethan.berg@arcticwolf.com)
"""
import requests
import pandas as pd
from bs4 import BeautifulSoup as bs
import urllib3


# Disable warning about not verifying HTTPS Cert
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
client = ['ardx']
#client = ['amplify']

def get_firewall(aperture_url):
    html_dump = bs(requests.get(aperture_url, verify=False).content, 'html.parser')
    scrape_table = pd.concat(pd.read_html(str(html_dump.find_all("table"))))
    firewall_type = list(scrape_table['Firewall-type'])
    firewall_type = list(dict.fromkeys(firewall_type))
    firewall_name = list(scrape_table['Firewall Name'])
    firewall_name = list(dict.fromkeys(firewall_name))
    return firewall_type,firewall_name

def get_firewall_events(aperture_url):
    html_dump = bs(requests.get(aperture_url, verify=False).content, 'html.parser')
    scrape_table = pd.concat(pd.read_html(str(html_dump.find_all("table"))))
    Event_type = list(scrape_table['Event-Type'])
    
    return Event_type


aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/Firewall-type%3Dconfigured-parser,Firewall%20Name=source.host/count=count/?limit=100&days=10&end=now'

Firewall_Details=get_firewall(aperture_url)

Firewall_Type=Firewall_Details[0]
Firewall_Name=Firewall_Details[1]
Events = []
main_df= []
#print(Firewall_Name)
#print(Firewall_Type)

if Firewall_Type[0] == 'fw-palo-alto':
    print("Firewall Type is Paloalto")
    for i in range(len(Firewall_Name)):
        aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/Firewall-type%3Dconfigured-parser,Firewall%20Name=source.host,Event-Type=firewall.type/count=count/?limit=100&days=7&end=now&source.host={Firewall_Name[i]}'
        Output = get_firewall_events(aperture_url)
        Events.append(Output)

    df = pd.DataFrame(list(zip(Firewall_Name,Events)),
        columns=['Firewall Name', 'Events seen']) 
    print(df)   
elif Firewall_Type[0] == 'fw-fortinet':
    print('Firewall_Name is Fortinet')
    """ for i in range(len(Firewall_Name)):
        aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/Firewall-type%3Dconfigured-parser,Firewall%20Name=source.host,Event-Type=firewall.type/count=count/?limit=100&days=7&end=now&source.host={Firewall_Name[i]}'
        Output = get_firewall_events(aperture_url)
        Events.append(Output)

    df = pd.DataFrame(list(zip(Firewall_Name,Events)),
        columns=['Firewall Name', 'Events seen']) 
    print(df)   """
elif Firewall_Type[0] == 'fw-firepower-asa':
    print('Firewall_Name is ASA')
    """ for i in range(len(Firewall_Name)):
        aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/Firewall-type%3Dconfigured-parser,Firewall%20Name=source.host,Event-Type=firewall.type/count=count/?limit=100&days=7&end=now&source.host={Firewall_Name[i]}'
        Output = get_firewall_events(aperture_url)
        Events.append(Output)

    df = pd.DataFrame(list(zip(Firewall_Name,Events)),
        columns=['Firewall Name', 'Events seen']) 
    print(df)    """
elif Firewall_Type[0] == 'fw-sonicwall':
    print('Firewall_Name is Sonicwall')
    for i in range(len(Firewall_Name)):
        aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/Firewall-type%3Dconfigured-parser,Firewall%20Name=source.host,Event-Type=firewall.severity/count=count/?limit=100&days=7&end=now&source.host={Firewall_Name[i]}&firewall.severity__exists=true'
        Output = get_firewall_events(aperture_url)
        Events.append(Output)
  
    df = pd.DataFrame(list(zip(Firewall_Name,Events)),
        columns=['Firewall Name', 'Events seen'])   
    print(df)  
elif Firewall_Type[0] == 'fw-meraki':
    print('Firewall_Name is Meraki')
else:
    print('no clue man') 








#scraped_data = bs(requests.get(f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/amplify/summ/cust-firewall/Firewall-type%3Dconfigured-parser,Firewall%20Name=source.host/count=count/?limit=100&days=10&end=now', verify=False).content, 'html.parser')
#table_data = pd.concat(pd.read_html(str(scraped_data.find_all("table"))))

#print (table_data)
