import dns
import dns.name
import dns.message
import dns.query
import dns.resolver

import time 
from datetime import datetime

root_servers = [
    "198.41.0.4", 
    "199.9.14.201", 
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "193.0.14.129",
    "199.7.83.42",
    "202.12.27.33"
]

domain = input("Enter domain name: ")

def get_tld_servers(domain, root_server_count):
    response = None
    for index in range(root_server_count, len(root_servers)):
        try:
            query = dns.message.make_query(domain, dns.rdatatype.NS)
            response = dns.query.udp(query, root_servers[index])
            root_server_count += 1
            return response.additional[0][0].to_text()
        except:
            if (root_server_count == 12):
                print("Domain could not be found in any root servers.")
                return None
            continue
    return response

def recursive_whatever(domain, name_server_ip):
    query = dns.message.make_query(domain, dns.rdatatype.A)
    response = dns.query.udp(query, name_server_ip)
    # print(response)
    if(response.answer):
        if(response.answer[0].rdtype == dns.rdatatype.A):
            # print(response.answer[0])
            return response.answer[0]
        else:
            domain = response.answer[0][0].to_text()
            tld_ip = get_tld_servers(domain, 0)
            return recursive_whatever(domain, tld_ip)
        # return response.answer[0][0].to_text()
    elif(response.additional):
        additionals = response.get_rrset(
                dns.message.ADDITIONAL,
                dns.name.from_text(response.additional[0].name.to_text()),
                dns.rdataclass.IN,
                dns.rdatatype.A)
        if not additionals:
            print("Additional responses cannot be understood")
            return None
        
        for add in additionals:
            ns_ip = add.to_text()
            res = recursive_whatever(domain, ns_ip)
            if(res):
                return res
    elif(response.authority):
        authorities = response.get_rrset(
            dns.message.AUTHORITY,
            dns.name.from_text(response.authority[0].name.to_text()),
            dns.rdataclass.IN,
            dns.rdatatype.NS)
        # print(dns.name.from_text(domain))
        if not authorities:
            print("No suitable authorative server could be found")
            return None
        for auth in authorities:
            tld_response_ns = get_tld_servers(auth.to_text(), 0)
            ns_ip = recursive_whatever(auth.to_text(), tld_response_ns)[0].to_text()
            res = recursive_whatever(domain, ns_ip)
            if (res):
                return res
    print("Nothing could be found")
    return None

question = None
try:
    question = dns.message.make_query(domain, dns.rdatatype.A)
    when = datetime.now().ctime()
    print("QUESTION SECTION: ")
    print(question.question[0], "\n")
    print("ANSWER SECTION: ")
    start_time = time.time()
    tld_ip = get_tld_servers(domain, 0)
    if (tld_ip != None):
        res = recursive_whatever(domain, tld_ip)
        if(res != None):
            res.name = dns.name.from_text(domain)
            print(res)
    end_time = time.time()
    query_time = (end_time - start_time) * 1000
    print()
    print("Query time: ", query_time)
    print("WHEN: " + when)
except:
    when = datetime.now().ctime()
    print("QUESTION SECTION: ")
    print(domain, "\n")
    print("ANSWER SECTION: ")
    print("Invalid domain name")
    start_time = time.time()
    end_time = time.time()
    query_time = (end_time - start_time) * 1000
    print()
    print("Query time: ", query_time)
    print("WHEN: " + when)



