import requests
import telnetlib
from time import sleep

main_menu = '''(1) Configuração completa provedor
(2) Liberar acesso remoto
(3) Finalizar script\n'''

advanced_menu = '''### CONFIGURAÇÕES AVANÇADAS ###
(1) WLAN
(2) Aplicação
(3) LAN
(4) WAN\n'''

wan_menu = '''### WAN ###
(1) PPPOE
(2) VLAN
(3) DNS
(4) modo do roteador (bridge/router)\n'''

lan_menu = '''### LAN ###
(1) IP
(2) Marcara de rede
(3) Range dhcp
(4) Mascara dhcp
(5) Tempo de renovação dhcp\n'''

wlan_menu = '''### WLAN ###
(1) 2.4
(2) 5.8\n'''

wlanoptions_menu = '''(1) Habilitar / Desabilitar
(2) Nome
(3) Senha
(4) Protocolo de autenticação
(5) Tipo de criptografia
(6) Ocultar wifi
(7) Canal
(8) Largura
(9) Modo de operação (bgn)
(0) Potencia de transmissão\n'''

aplication_menu = '''### APLICAÇÃO ###
(1) Liberar portas
(2) Habilitar servidor ftp (para pendrive)
(3) Dmz\n'''

session = requests.session()

def login():
    login_url = 'http://192.168.1.1/login.cgi'
    payload = {
    'name' : 'telecomadmin',
    'pswd' : 'admintelecom'
    }
    session.post(login_url, data = payload)

def logout():
    logout_url = 'http://192.168.1.1/login.cgi?out'
    session.get(logout_url)

def enabletelnet():

    login()
    session.post('http://192.168.1.1/system.cgi?telnet+on', data = '')
    logout()

def disabletelnet():
    login()
    session.post('http://192.168.1.1/system.cgi?telnet+off', data = '')
    logout()

def comando(comando_):
    tn = telnetlib.Telnet('192.168.1.1')
    for command in comando_:
        tn.write(command.encode('ascii') + b"\n")
    try:
        tn.write(b"exit\n")
        print(tn.read_all().decode('ascii'))
    except:
        pass

def other():
    timeparam = {
        'ntpEnabled':'on',
        'NtpType_select':'0',
        'interval':'86400',
        'ntpServer1':'clock.fmt.he.net',
        'ntpServer2':'time.windows.com',
        'ntpServer3':'',
        'ntpServerOther3':'',
        'ntpServer4':'',
        'ntpServerOther4':'',
        'ntpServer5':'',
        'ntpServerOther5':'',
        'timezone':'-03:00 Brasilia'
    }
    while True:
        client_type = int(input('Qual o tipo de cliente:\n(1) Pessoa Fisica\n(2) Corporativo\n'))
        if client_type == 1:
            client_limit = '20'
            break
        elif client_type == 2:
            client_limit = '256'
            break
        else:
            print('Opção inválida!')



    login()
    enabletelnet()
    comandos = [
        'cfgcli -f -s InternetGatewayDevice.X_ASB_COM_PreConfig.X_ASB_COM_ExternalWebAccess true',
        'cfgcli -f -s InternetGatewayDevice.DeviceInfo.X_CT-COM_UPNP.Enable True',
        'cfgcli -s InternetGatewayDevice.Services.X_CT-COM_MWBAND.TotalTerminalNumber ' + client_limit,
    ]
    comando(comandos)
    session.post('http://192.168.1.1/sntp.cgi?post', data = timeparam)
    disabletelnet()
    logout()

def wlan ():
    login()

    verifywlan = session.get('http://192.168.1.1/wlan_config.cgi')
    #logwlan = open('logwlan.txt', 'a')
    #logwlan.write(str(verifywlan.text))

    enabletelnet()
    logout()

    comandos = [
        'cfgcli -f -s InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.WPS.Enable False',
        'cfgcli -f -s InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.Standard "b,g,n"',
        'cfgcli -f -s InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID Direct-WIFI-2G',
        'cfgcli -f -s InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.SSID Direct-WIFI-5G',
        #'cfgcli -f -s InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1.PreSharedKey ' + pswd,
        #'cfgcli -f -s InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.PreSharedKey.1.PreSharedKey ' + pswd,
    ]
    comando(comandos)
    
    try:
        disabletelnet()

        logout()
    except:
        pass

def wan (pppoe_username, pppoe_password, vlanid = '500'):
    login()
    verifywan = session.get('http://192.168.1.1/wan_config.cgi')
    if '1_INTERNET_R_VID_' in verifywan.text:
        conn_id = '10101'
    else:
        conn_id = '0'

    wanparam = {
        'conn_id':conn_id,
        'conn_type':'pppoe',
        'servlist':'INTERNET',
        'conn_mode':'R',
        'ipv':'3',
        'pppoe_username':pppoe_username,
        'pppoe_password':pppoe_password,
        'pppoeswd':'1',
        'natSw':'on',
        'mtu':'1492',
        'dhcp_enable':'on',
        'vlanSw':'2',
        'vlanId':vlanid,
        'm8021p':'0',
        'b_lan1':'1',
        'b_lan2':'2',
        'b_lan3':'3',
        'b_lan4':'4',
        'b_ssid1':'1',
        'b_5g_ssid1':'5',
        'ip_mode':'pppoe',
        'externalIpAddr':'',
        'netmask':'',
        'defGateway':'',
        'firstDns':'',
        'secondDns':'',
        'ipv6_origin':'DHCPv6',
        'en_prefix': 'on',
        'ipv6_prefix':'PPPoE',
        'ipAddr_v6':'',
        'defGw_v6':'',
        'prefix_v6':'',
        'firstDns_v6':'',
        'secondDns_v6':'',
        'aftr_mode':'0',
        'aftr_addr':'',
        'trigger':'AlwaysOn',
        'act':'',
        'tr69_flag':''
    }
    lanv6param = {
        'LanDNS_select': 'WANConnection',
        'LanPri_DNS_text': '',
        'LanSec_DNS_text': '',
        'LanDNS_Interface_select': 'ppp111',
        'LanPrefix_select': 'WANDelegated',
        'LanPrefix_text': '',
        'LanInterface_select': 'ppp111',
        'LanDHCPv6_checkbox': 'on',
        'LanStartAddress_text': '0:0:0:2',
        'LanEndAddress_text': '0:0:0:255',
        'LanAddressInfo_checkbox': '',
        'LanOtherInfo_checkbox': '',
        'LanMaxRA_text': '600',
        'LanMinRA_text': '200'
    }
    session.post('http://192.168.1.1/wan_config.cgi?config', data = wanparam)
    session.post('http://192.168.1.1/lan_ipv6.cgi?config', data = lanv6param)
    config = session.get('http://192.168.1.1/wan_config.cgi').text
    if pppoe_username in config:
        print('Configuração WAN ok!')
    else:
        print('Algo deu errado com a WAN!')
        print('Verifique se continua conectado via navegador!\nLembrando que apenas fechar a aba não funciona\nÉ necessário apertar no botão ''log out''')
        exit()
    logout()

def wlanpost (ssid, pswd):
    login()
    ssid5 = ssid + '-5G'
    ssid1 = ssid + '-2G'
    wlanparam1 = {
        'ap_enable':'on',
        'ssidx':'1',
        'ssid_enable': 'on',
        'ssid': ssid1,
        'wl_beaconType': 'WPA/WPA2',
        'wep_encrypt': 'Both',
        'wepKeyBit': '40-bit',
        'wpa_encrypt_mode': 'TKIPandAESEncryption',
        'wpa_psk': pswd,
        'wl_channel':'11',
        'wl_mode': 'b,g,n',
        'wl_NChannelwidth': '0',
        'wl_N_GuardInterval': '0',
        'wl_power': '100',
    }

    wlanparam5 = {
        'ap_enable': 'on',
        'ssidx': '5',
        'ssid_enable': 'on',
        'ssid': ssid5,
        'wl_beaconType': 'WPA/WPA2',
        'wep_encrypt': 'Both',
        'wepKeyBit': '40-bit',
        'wpa_encrypt_mode': 'TKIPandAESEncryption',
        'wpa_psk': pswd,
        'wl_channel': '161',
        'wl_NChannelwidth': '3',
        'wl_N_GuardInterval': '0',
        'wl_power': '100',
    }

    session.post('http://192.168.1.1/wlan_config.cgi?do_config_all', data = wlanparam1)
    #print(session.get('http://192.168.1.1/wlan_config.cgi').status_code)
    session.post('http://192.168.1.1/wlan_config.cgi?do_config_11ac_all', data = wlanparam5)
    #print(session.get('http://192.168.1.1/wlan_config.cgi?config_11ac').status_code)
    try:
        logout()
    except:
        print('Reinicie o roteador para alterar outras configurações...')
while True:
    print(main_menu)
    main_option = int(input('Digite a opção desejada: '))
    if main_option == 3:
        print('Finalizando script...')
        disabletelnet()
        logout()
        sleep(2)
        print('\n'*1000)
        exit()
    elif main_option == 1:
        pppoe = str(input('PPPoE (sem espaços): '))
        pppoe = pppoe.lower()
        pswdpppoe = str(input('Senha PPPoE: '))
        vlanid = str(input('VLAN: '))
        print('Configurando o roteador...')
        wan(pppoe, pswdpppoe, vlanid)
        other()
        wlan()
       
        print('\n' *1000)
        print('Configuração completa!')

    elif main_option == 2:
       other()
       
