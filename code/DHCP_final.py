import subprocess    #Module to put in commands in the Linux terminal
import logging      #Module to log in errors from another module
import random     #Module to call in random numbers
import sys          #Module to call in system functions



#Logging in errrors from the scapy module when being imported
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)


from scapy.all import *   #Importing the Scapy module


all_leases_given = [] #List will store all the IP leases
server_list = [] #List will store the server IPs
mac_client_id = [] #List will store the MAC addresses of the client


net_iface = raw_input("Enter the interface to the target network: ")
subprocess.call(["ifconfig", net_iface, "promisc"], stdout=None, stderr=None, shell=False) #Setting the interface in promiscous mode
print '\nThe interface %s has been set up in promiscous mode' %net_iface

conf.checkIPaddr = False #ensuring that responses come from different IP addresses

#This function will send DHCP Discover and Request packets and receive Offer and Ack packets from Server
def dhcp_packets():
    global all_leases_given
    
    x_id = random.randrange(1, 1000000) #This generates a sequence ID which will be used in the DHCP packet
    mac = "00:00:5e" + str(RandMAC())[8:] #This will generate a mac address for the client
    mac_str = mac2str(mac) #This converts Mac to string
    
    #Saving the Discover Packet into a variable
    dhcp_dis_pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac)/IP(src="0.0.0.0",dst="255.255.255.255") / UDP(sport=68,dport=67)/BOOTP(op=1, xid=x_id, chaddr=mac_str)/DHCP(options=[("message-type","discover"),("end")])
    
    #Sending the Discover packet and receiving the offer packet
    list_1, list_2 = srp(dhcp_dis_pkt, iface = pkt_inf, timeout = 2.5, verbose = 0)
    
    
    offered_ip = list_1[0][1][BOOTP].yiaddr #Extracting the IP address
    
    print "\n"
    
    
    #Saving the Request Packet and receiving the acknowledge packet
    dhcp_req_pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac)/IP(src="0.0.0.0",dst="255.255.255.255") / UDP(sport=68,dport=67)/BOOTP(op=1, xid=x_id, chaddr=mac_str)/DHCP(options=[("message-type","request"),("requested_addr", offered_ip),("end")])
    
    
    req_list_1, req_list_2 = srp(dhcp_req_pkt, iface=pkt_inf, timeout = 2.5, verbose=0)
    
    
    offered_ip_ack = req_list_1[0][1][BOOTP].yiaddr #Extracting the IP from the acknowledgment packet
    
    server_ip = req_list_1[0][1][IP].src #Extracting the Server IP
    
    print "The Chosen IP is: ", offered_ip_ack
    print "The DHCP server is that provided the IP: ", server_ip
    print "\n"
    
    
    all_leases_given.append(offered_ip_ack) #Appending all offered IP to a list
    
    print "All IPs leases: ", all_leases_given
    
    print "\n"
    
    server_list.append(server_ip) #Appending Server IPs to a list
    mac_client_id.append(mac)  #Appending the Mac IDs to a list
    
    return all_leases_given, server_list, mac_client_id

#This function will DHCP Release packets to the Server
def dhcp_release(ip,mac,server):
    
    x_id = random.randrange(1, 1000000)
    mac_str = mac2str(mac)
    
    #Saving the RELEASE packet
    dhcp_rls_pkt = IP(src=ip,dst=server) / UDP(sport=68,dport=67)/BOOTP(chaddr=mac_str, ciaddr=ip, xid=x_id)/DHCP(options=[("message-type","release"),("server_id", server),("end")])
    
    #Sending the RELEASE packet
    send(dhcp_rls_pkt, verbose=0)
    
    
try:
    #Enter option for the first screen
    while True:
        print "\nChoose the below options:\n's' - Simulate DHCP Clients\n'r' - Simulate DHCP Release\nAny other Key - Exit program\n"
        
        user_option_selected = raw_input("Enter your choice: ")
        
        if user_option_selected == "s":
            print "\nObtained leases will be exported to 'Leases_given.txt'!"
            
            pkt_no = raw_input("\nNumber of DHCP clients to simulate: ")
            
            pkt_inf = raw_input("Interface on which to send packets: ")
            
            print "\nWaiting for clients to obtain IP addresses...\n"
            
            try:
                #Calling the function for the number of clients needed for the user
                for iterate in range(0, int(pkt_no)):
                    all_leased_ips = dhcp_packets()[0] #Stores in all Leases given
                      
                
                
            except IndexError:
                print "No DHCP Server detected or connection is broken."
                print "Check your network settings and try again.\n"
                sys.exit()
                
            #List of all leased IPs
            dhcp_leases = open("Leases_given.txt", "w")
            
            
            #Print each leased IP to the file
            for index, each_ip in enumerate(all_leased_ips):
                
                print >>dhcp_leases, each_ip + "," + server_list[index] + "," + mac_client_id[index] #Writing information to the file
                
            dhcp_leases.close()
            
            continue

        elif user_option_selected == "r":
            while True:
                print "\n's' - Release a single address\n'a' - Release all addresses\nAny other key - Exit to the previous screen\n"
                
                user_option_release = raw_input("Enter your choice: ")
                
                if user_option_release == "s":
                    print "\n"
                    
                    user_option = raw_input("Enter IP address to release: ")
                    
                    
                    try:
                        #Check if required IP is in the list and run the release function for it
                        if user_option in all_leased_ips:
                            index = all_leased_ips.index(user_option)

                            dhcp_release(user_option, mac_client_id[index], server_list[index]) #Realease the selected the IP address
                            
                            print "\nSending RELEASE packet...\n"
                            
                        else:
                            print "IP Address not in list.\n"
                            continue
                    
                    except (NameError, IndexError):
                        print "\nSimulating DHCP RELEASES cannot be done separately, without prior DHCP Client simulation."
                        print "Restart the program and simulate DHCP Clients and RELEASES in the same program session.\n"
                        sys.exit()
                
                elif user_option_release == "a":
                    
                    
                    try:
                        #Check if required IP is in the list and run the release function for it
                        for user_option in all_leased_ips:
                            
                            index = all_leased_ips.index(user_option)

                            dhcp_release(user_option, mac_client_id[index], server_list[index])
                            
                    except (NameError, IndexError):
                        print "\nSimulating DHCP RELEASES cannot be done separately, without prior DHCP Client simulation."
                        print "Restart the program and simulate DHCP Clients and RELEASES in the same program session.\n"
                        sys.exit()
                    
                    print "\nThe RELEASE packets have been sent.\n"
                    
                    #Erasing all leases from the file
                    open("Leases_given.txt", "w").close()
                    
                    print "File 'Leases_given.txt' has been cleared."
                    
                    continue
                
                else:
                    break
            
        else:
            print "Exiting the application"
            sys.exit()

except KeyboardInterrupt:
    print "\n\nProgram aborted!\n"
    sys.exit()            
    


    
    
    
    
    
    
    

    



