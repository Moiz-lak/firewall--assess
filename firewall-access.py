

from http import client
import requests
import pandas as pd
from bs4 import BeautifulSoup as bs
import urllib3
import os

# Disable warning about not verifying HTTPS Cert
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
#client = ['ardx']

client = ['amplify']
#client = ['ruggeriparksweinberg']
#client = ['acctechnical']
#client = ['partnerit']
#client = ['ajdwoskin']
#client = ['communicorp'

#Function to Grab Firewall type
def get_firewall(aperture_url):
    fw_type_dump = bs(requests.get(aperture_url, verify=False).content, 'html.parser')
    fw_table = pd.concat(pd.read_html(str(fw_type_dump.find_all("table"))))
    firewall_type = list(fw_table['Firewall-type'])
    firewall_type = list(dict.fromkeys(firewall_type))
    return firewall_type
#Function to Grab Firewall type
def get_firewall_name(Events_url):
    html_dump = bs(requests.get(Events_url, verify=False).content, 'html.parser')
    scrape_table = pd.concat(pd.read_html(str(html_dump.find_all("table"))))
    firewall_name = list(scrape_table['Firewall Name'])
    firewall_name = list(dict.fromkeys(firewall_name))
    return firewall_name


#Function to Process and collect event types
def get_firewall_events(aperture_url):
    html_dump = bs(requests.get(aperture_url, verify=False).content, 'html.parser')
    scrape_table = pd.concat(pd.read_html(str(html_dump.find_all("table"))))
    Event_type = list(scrape_table['Event-Type'])

    return Event_type

def get_Assement_data(analysis_url):
    html_dump = bs(requests.get(analysis_url, verify=False).content, 'html.parser')
    scrape_table = pd.concat(pd.read_html(str(html_dump.find_all("table"))))
    scrape_table = scrape_table.dropna(how='all', axis=1)
    return scrape_table
def create_excel(filename,df,Analysis):
    with pd.ExcelWriter(filename) as writer:
            df.to_excel(writer, sheet_name="Events", index=False)
            Analysis.to_excel(writer, sheet_name="Events Analysis", index=False)


def main():
    
    aperture_url = f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/Firewall-type%3Dconfigured-parser/count=count/?limit=100&days=10&end=now'
    Firewall_type=get_firewall(aperture_url)
    print(Firewall_type)
    Events_url = f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/Firewall-type%3Dconfigured-parser,Firewall%20Name={"firewall.identifier" if Firewall_type[0] == "fw-meraki" else "source.host"}/count=count/?limit=100&days=10&end=now'
    Firewall_name=get_firewall_name(Events_url)
    print(Firewall_name)
    Events=[]
    Analysis=[]
    for i in range(len(Firewall_name)):
        aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/Firewall-type%3Dconfigured-parser,Firewall%20Name=source.host,Event-Type={"firewall.type" if Firewall_type[0] == "fw-palo-alto" else "firewall.severity" if Firewall_type[0] == "fw-fortinet" else "firewall.type" if Firewall_type[0] == "fw-watchguard" else "firewall.type" if Firewall_type[0] == "fw-meraki" else "firewall.severity"}/count=count/?limit=100&days=7&end=now&{"firewall.identifier" if Firewall_type[0] == "fw-meraki" else "source.host"}={Firewall_name[i]}'
        #print(aperture_url)
        Output = get_firewall_events(aperture_url)
        Events.append(Output)
        analysis_url= f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client[0]}/summ/cust-firewall/source.host=source.host,firewall.subtype=firewall.subtype,Destination=s-ip,Destination-port=s-port/count=count/?.title=Firewall%20Analysis%20-%20Cleartext%20Traffic%20Protocols%20US&limit=500&!firewall.subtype=drop,deny&s-port__exists=true&s-port=143,110,21,23,853,25'
        temp_analysis=get_Assement_data(analysis_url)
        Analysis=get_Assement_data(analysis_url)
        df = pd.DataFrame(list(zip(Firewall_name,Events)),
        columns=['Firewall Name', 'Events seen']) 
        filename=F"~/Desktop/firewall_assessment/{client[0]}.xlsx"
        create_excel(filename,df,Analysis)

    
   
    print("Firewal Assement Complete")
    


if __name__ == '__main__':
    main()
