"""####### ArcticWolf Firewall Assessment cript #######

Authors:
    - Moiz Lakdawala (moiz.lakdawala@arcticwolf.com) 
    - Ethan Berg (ethan.berg@arcticwolf.com) 
"""
from turtle import clear
import requests
import pandas as pd
from bs4 import BeautifulSoup as bs
import urllib3


# Disable warning about not verifying HTTPS Cert
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
#client = ['ardx']
#client = ['amplify']
#client = ['ruggeriparksweinberg']
#client = ['acctechnical']
#client = ['partnerit']
#client = ['ajdwoskin']
client = ['joviafinancial']

#Function to Grab Firewall type and Firewall names 
def get_firewall(aperture_url):
    html_dump = bs(requests.get(aperture_url, verify=False).content, 'html.parser')
    scrape_table = pd.concat(pd.read_html(str(html_dump.find_all("table"))))
    firewall_type = list(scrape_table['Firewall-type'])
    firewall_type = list(dict.fromkeys(firewall_type))
    firewall_name = list(scrape_table['Firewall Name'])
    firewall_name = list(dict.fromkeys(firewall_name))
    firewall_name_MX = list(scrape_table['Firewall Name-MX'])
    firewall_name_MX = list(dict.fromkeys(firewall_name_MX))
    return firewall_type,firewall_name,firewall_name_MX
#Function to Process and collect event types
def get_firewall_events(aperture_url):
    html_dump = bs(requests.get(aperture_url, verify=False).content, 'html.parser')
    scrape_table = pd.concat(pd.read_html(str(html_dump.find_all("table"))))
    Event_type = list(scrape_table['Event-Type'])
    return Event_type

#Function to perform assessment of Clear teext protocol , DNS over TLS and SMTP traffic
def get_Assement_data(aperture_url):
    html_dump = bs(requests.get(aperture_url, verify=False).content, 'html.parser')
    scrape_table = pd.concat(pd.read_html(str(html_dump.find_all("table"))))
    scrape_table = scrape_table.dropna(how='all', axis=1)
    return scrape_table



aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/Firewall-type%3Dconfigured-parser,Firewall%20Name=source.host,Firewall%20Name-MX=firewall.identifier/count=count/?limit=100&days=10&end=now'

Firewall_Details=get_firewall(aperture_url)

Firewall_Type=Firewall_Details[0]
Firewall_Name=Firewall_Details[1]
Firewall_Name_MX=Firewall_Details[2]
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
    aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/source.host=source.host,firewall.subtype=firewall.subtype,Destination=s-ip,Destination-port=s-port/count=count/?.title=Firewall%20Analysis%20-%20Cleartext%20Traffic%20Protocols%20US&limit=500&!firewall.subtype=drop,deny&s-port__exists=true&s-port=143,110,21,23'
    clear_text_protocol=get_Assement_data(aperture_url)
    aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/source.host=source.host,Firewall Action=firewall.action,Destination=s-ip,Destination-port=s-port/count=count/?&limit=500&s-port__exists=true&s-port=853&days=30&!firewall.action=reset-both,deny,drop'
    DNS_over_TLS_protocol=get_Assement_data(aperture_url)
    aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/source.host=source.host,Firewall Action=firewall.action,Destination=s-ip,Destination-port=s-port/count=count/?&limit=500&s-port__exists=true&s-port=25&days=30&!firewall.action=reset-both,deny,drop'
    SMTP_Traffic=get_Assement_data(aperture_url)

    print(df)
    print(clear_text_protocol)
    print(DNS_over_TLS_protocol)
    print(SMTP_Traffic)   
elif Firewall_Type[0] == 'fw-fortinet':
    print('Firewall_Name is Fortinet')
    for i in range(len(Firewall_Name)):
        aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/Firewall-type%3Dconfigured-parser,Firewall%20Name=source.host,Event-Type=firewall.severity/count=count/?limit=100&days=7&end=now&source.host={Firewall_Name[i]}'
        Output = get_firewall_events(aperture_url)
        Events.append(Output)

    df = pd.DataFrame(list(zip(Firewall_Name,Events)),
        columns=['Firewall Name', 'Events seen']) 
    aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/source.host=source.host,firewall.subtype=firewall.subtype,Destination=s-ip,Destination-port=s-port/count=count/?.title=Firewall%20Analysis%20-%20Cleartext%20Traffic%20Protocols%20US&limit=500&!firewall.subtype=drop,deny&s-port__exists=true&s-port=143,110,21,23'
    clear_text_protocol=get_Assement_data(aperture_url)
    aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/source.host=source.host,Firewall Action=firewall.action,Destination=s-ip,Destination-port=s-port/count=count/?&limit=500&s-port__exists=true&s-port=853&days=30&!firewall.action=reset-both,deny,drop'
    DNS_over_TLS_protocol=get_Assement_data(aperture_url)
    aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/source.host=source.host,Firewall Action=firewall.action,Destination=s-ip,Destination-port=s-port/count=count/?&limit=500&s-port__exists=true&s-port=25&days=30&!firewall.action=reset-both,deny,drop'
    SMTP_Traffic=get_Assement_data(aperture_url)
    print(df)
    print(clear_text_protocol)
    print(DNS_over_TLS_protocol)
    print(SMTP_Traffic)    
elif Firewall_Type[0] == 'fw-firepower-asa':
    print('Firewall_Name is ASA')
    for i in range(len(Firewall_Name)):
        aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/Firewall-type%3Dconfigured-parser,Firewall%20Name=source.host,Event-Type=firewall.severity/count=count/?limit=100&days=7&end=now&source.host={Firewall_Name[i]}'
        Output = get_firewall_events(aperture_url)
        Events.append(Output)

    df = pd.DataFrame(list(zip(Firewall_Name,Events)),
        columns=['Firewall Name', 'Events seen']) 
    aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/source.host=source.host,firewall.subtype=firewall.subtype,Destination=s-ip,Destination-port=s-port/count=count/?.title=Firewall%20Analysis%20-%20Cleartext%20Traffic%20Protocols%20US&limit=500&!firewall.subtype=drop,deny&s-port__exists=true&s-port=143,110,21,23'
    clear_text_protocol=get_Assement_data(aperture_url)
    aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/source.host=source.host,Firewall Action=firewall.action,Destination=s-ip,Destination-port=s-port/count=count/?&limit=500&s-port__exists=true&s-port=853&days=30&!firewall.action=reset-both,deny,drop'
    DNS_over_TLS_protocol=get_Assement_data(aperture_url)
    aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/source.host=source.host,Firewall Action=firewall.action,Destination=s-ip,Destination-port=s-port/count=count/?&limit=500&s-port__exists=true&s-port=25&days=30&!firewall.action=reset-both,deny,drop'
    SMTP_Traffic=get_Assement_data(aperture_url)
    print(df)
    print(clear_text_protocol)
    print(DNS_over_TLS_protocol)
    print(SMTP_Traffic)
elif Firewall_Type[0] == 'fw-watchguard':
    print('Firewall_Name is Watch guard')
    for i in range(len(Firewall_Name)):
        aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/Firewall-type%3Dconfigured-parser,Firewall%20Name=source.host,Event-Type=firewall.type/count=count/?limit=100&days=7&end=now&source.host={Firewall_Name[i]}'
        Output = get_firewall_events(aperture_url)
        Events.append(Output)

    df = pd.DataFrame(list(zip(Firewall_Name,Events)),
        columns=['Firewall Name', 'Events seen']) 
    aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/source.host=source.host,firewall.subtype=firewall.subtype,Destination=s-ip,Destination-port=s-port/count=count/?.title=Firewall%20Analysis%20-%20Cleartext%20Traffic%20Protocols%20US&limit=500&!firewall.action=drop,deny,Deny&s-port__exists=true&s-port=143,110,21,23'
    clear_text_protocol=get_Assement_data(aperture_url)
    aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/source.host=source.host,Firewall Action=firewall.action,Destination=s-ip,Destination-port=s-port/count=count/?&limit=500&s-port__exists=true&s-port=853&days=30&!firewall.action=reset-both,deny,drop,Deny'
    DNS_over_TLS_protocol=get_Assement_data(aperture_url)
    aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/source.host=source.host,Firewall Action=firewall.action,Destination=s-ip,Destination-port=s-port/count=count/?&limit=500&s-port__exists=true&s-port=25&days=30&!firewall.action=reset-both,deny,drop,Deny'
    SMTP_Traffic=get_Assement_data(aperture_url)   
    print(df)
    print(clear_text_protocol)
    print(DNS_over_TLS_protocol)
    print(SMTP_Traffic)     
elif Firewall_Type[0] == 'fw-sonicwall':
    print('Firewall_Name is Sonicwall')
    for i in range(len(Firewall_Name)):
        aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/Firewall-type%3Dconfigured-parser,Firewall%20Name=source.host,Event-Type=firewall.severity/count=count/?limit=100&days=7&end=now&source.host={Firewall_Name[i]}&firewall.severity__exists=true'
        Output = get_firewall_events(aperture_url)
        Events.append(Output)
  
    df = pd.DataFrame(list(zip(Firewall_Name,Events)),
        columns=['Firewall Name', 'Events seen'])
    aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/source.host=source.host,firewall.subtype=firewall.subtype,Destination=s-ip,Destination-port=s-port/count=count/?.title=Firewall%20Analysis%20-%20Cleartext%20Traffic%20Protocols%20US&limit=500&!firewall.subtype=drop,deny&s-port__exists=true&s-port=143,110,21,23'
    clear_text_protocol=get_Assement_data(aperture_url)
    aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/source.host=source.host,Firewall Action=firewall.action,Destination=s-ip,Destination-port=s-port/count=count/?&limit=500&s-port__exists=true&s-port=853&days=30&!firewall.action=reset-both,deny,drop'
    DNS_over_TLS_protocol=get_Assement_data(aperture_url)
    aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/source.host=source.host,Firewall Action=firewall.action,Destination=s-ip,Destination-port=s-port/count=count/?&limit=500&s-port__exists=true&s-port=25&days=30&!firewall.action=reset-both,deny,drop'
    SMTP_Traffic=get_Assement_data(aperture_url)   
    print(df)
    print(clear_text_protocol)
    print(DNS_over_TLS_protocol)
    print(SMTP_Traffic)  
elif Firewall_Type[0] == 'fw-meraki':
    print('Firewall_Name is Meraki')
    for i in range(len(Firewall_Name_MX)):
        aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/Firewall-type%3Dconfigured-parser,Firewall%20Name=firewall.identifier,Event-Type=firewall.type/count=count/?limit=100&days=7&end=now&firewall.identifier={Firewall_Name_MX[i]}'
        Output = get_firewall_events(aperture_url)
        Events.append(Output)
  
    df = pd.DataFrame(list(zip(Firewall_Name_MX,Events)),
        columns=['Firewall Name', 'Events seen'])
    aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/Firewall=firewall.identifier,URL=http.url,Destination=s-ip,Event-Type=firewall.type,Destination-port=s-port,action=action/count=count/?.title=Firewall%20Analysis%20-%20Cleartext%20Traffic%20Protocols%20US&limit=500&!firewall.subtype=drop,deny&s-port__exists=true&s-port=143,110,21,23'
    clear_text_protocol=get_Assement_data(aperture_url)
    aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/Firewall=firewall.identifier,URL=http.url,Destination=s-ip,Event-Type=firewall.type,Destination-port=s-port,action=action/count=count/?.title=Firewall%20Analysis%20-%20Cleartext%20Traffic%20Protocols%20US&limit=500&!firewall.subtype=drop,deny&s-port__exists=true&s-port=853'
    DNS_over_TLS_protocol=get_Assement_data(aperture_url)
    aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/Firewall=firewall.identifier,URL=http.url,Destination=s-ip,Event-Type=firewall.type,Destination-port=s-port,action=action/count=count/?.title=Firewall%20Analysis%20-%20Cleartext%20Traffic%20Protocols%20US&limit=500&!firewall.subtype=drop,deny&s-port__exists=true&s-port=25'
    SMTP_Traffic=get_Assement_data(aperture_url)   
    print(df)
    print(clear_text_protocol)
    print(DNS_over_TLS_protocol)
    print(SMTP_Traffic) 

else:
    print('no clue man') 


#Clear test passowrdhttps://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/amplify/summ/cust-firewall/source.host=source.host,firewall.subtype=firewall.subtype,Destination=s-ip,Destination-port=s-port/count=count/?.title=Firewall%20Analysis%20-%20Cleartext%20Traffic%20Protocols%20US&limit=500&!firewall.subtype=drop,deny&s-port__exists=true&s-port=143,110,21,23





#scraped_data = bs(requests.get(f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/amplify/summ/cust-firewall/Firewall-type%3Dconfigured-parser,Firewall%20Name=source.host/count=count/?limit=100&days=10&end=now', verify=False).content, 'html.parser')
#table_data = pd.concat(pd.read_html(str(scraped_data.find_all("table"))))

#print (table_data)
