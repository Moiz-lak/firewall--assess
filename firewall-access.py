"""####### ArcticWolf Firewall Assessment Report Generation #######
    - Moiz Lakdawala 
    - Ethan Berg 
"""
from http import client
import requests
import pandas as pd
from bs4 import BeautifulSoup as bs
import urllib3
import os

# Disable warning about not verifying HTTPS Cert
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_msp_children():
    """ Using the v2 Customers API, we pull a list of all child customers for a MSP and append their ID to that list """
    try:
        parent_customer_id = input("Enter MSP Customer ID: ")
        with requests.get(f"https://console.prod.awn/api/v2/customers/{parent_customer_id}", verify=False) as data_dump:
            if 'children' in data_dump.json():
                clients = data_dump.json()['children']
                clients.append(parent_customer_id)
            else:
                clients = [parent_customer_id]
            return clients
    except Exception as e:
        print(f"INVALID MSP: No data found for key {e}")
        exit()

#Function to Grab Firewall type
def get_firewall(client):
    aperture_url = f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client}/summ/cust-firewall/Firewall-type%3Dconfigured-parser/count=count/?limit=100&days=10&end=now'
    fw_type_dump = bs(requests.get(aperture_url, verify=False).content, 'html.parser')
    fw_table = pd.concat(pd.read_html(str(fw_type_dump.find_all("table"))))
    firewall_type = list(fw_table['Firewall-type'])
    firewall_type = list(dict.fromkeys(firewall_type))
    return firewall_type
#Function to Grab Firewall name
def get_firewall_name(client,Firewall_Type):
    Events_url = f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client}/summ/cust-firewall/Firewall-type%3Dconfigured-parser,Firewall%20Name={"firewall.identifier" if Firewall_Type == "fw-meraki" else "source.host"}/count=count/?limit=100&days=10&end=now'
    html_dump = bs(requests.get(Events_url, verify=False).content, 'html.parser')
    scrape_table = pd.concat(pd.read_html(str(html_dump.find_all("table"))))
    firewall_name = list(scrape_table['Firewall Name'])
    firewall_name = list(dict.fromkeys(firewall_name))
    return firewall_name

#Function to Process and collect event types
def get_firewall_events(client,Firewall_Type,fw_name):
    aperture_url=f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client}/summ/cust-firewall/Firewall-type%3Dconfigured-parser,Firewall%20Name=source.host,Event-Type={"firewall.type" if Firewall_Type == "fw-palo-alto" else "firewall.severity" if Firewall_Type == "fw-fortinet" else "firewall.type" if Firewall_Type == "fw-watchguard" else "firewall.type" if Firewall_Type == "fw-meraki" else "firewall.severity"}/count=count/?limit=100&days=7&end=now&{"firewall.identifier" if Firewall_Type == "fw-meraki" else "source.host"}={fw_name}'
    html_dump = bs(requests.get(aperture_url, verify=False).content, 'html.parser')
    scrape_table = pd.concat(pd.read_html(str(html_dump.find_all("table"))))
    Event_type = list(scrape_table['Event-Type'])
    return Event_type

def get_Assement_data(client):
    analysis_url= f'https://aperture.aperture.prod.us001-prod.rtkwlf.io/aperture/{client}/summ/cust-firewall/source.host=source.host,firewall.subtype=firewall.subtype,Destination=s-ip,Destination-port=s-port/count=count/?.title=Firewall%20Analysis%20-%20Cleartext%20Traffic%20Protocols%20US&limit=500&!firewall.subtype=drop,deny&s-port__exists=true&s-port=143,110,21,23,853,25'
    html_dump = bs(requests.get(analysis_url, verify=False).content, 'html.parser')
    scrape_table = pd.concat(pd.read_html(str(html_dump.find_all("table"))))
    scrape_table = scrape_table.dropna(how='all', axis=1)
    return scrape_table
def create_excel(filename,df,Analysis):
    with pd.ExcelWriter(filename) as writer:
            df.to_excel(writer, sheet_name="Events", index=False)
            Analysis.to_excel(writer, sheet_name="Events Analysis", index=False)


def main():
    end_client = get_msp_children()
    
    for client in end_client:
        Firewall_type=get_firewall(client)
        if not Firewall_type:
            print(f'no firewall found for {client}')
            continue
        else:
            Firewall_Type=Firewall_type[0]
            Firewall_name=get_firewall_name(client,Firewall_Type)
            Events=[]
            Analysis=[]
            for fw_name in Firewall_name:
                #print(aperture_url)
                Output = get_firewall_events(client,Firewall_Type,fw_name)
                Events.append(Output)
                #temp_analysis=get_Assement_data(analysis_url)
                Analysis=get_Assement_data(client)
                df = pd.DataFrame(list(zip(Firewall_name,Events)),
                columns=['Firewall Name', 'Events seen']) 
                filename=f"~/Desktop/firewall_assessment/{client}.xlsx"
                create_excel(filename,df,Analysis)

            print("Firewal Assement Complete")
    
if __name__ == '__main__':
    main()

