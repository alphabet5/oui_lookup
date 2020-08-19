def mac_to_bits(mac_address):
    return int(mac_address.replace(':', '').replace('.', ''), 16)


def mac_subnet(mac_address,subnet):
    mac = mac_to_bits(mac_address)
    low = mac_to_bits(subnet.partition('/')[0])
    high = mac_to_bits(subnet.partition('/')[0]) + int('1'*(48-int(subnet.partition('/')[2])), 2)
    if mac >= low and mac <= high:
        return True
    else:
        return False


def dl_wireshark_oui(file='wireshark_oui.txt'):
    import requests
    url = 'https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf'
    myfile = requests.get(url)
    open(file, 'wb').write(myfile.content)


def load_wireshark_oui(file, refresh_after_days):
    import os
    try:
        #Check OUI database exists.
        if not os.path.isfile(file):
            dl_wireshark_oui(file=file)
        else:
            #Check OUI database age.
            from datetime import datetime
            db_update_time = os.path.getmtime(file)
            #Check if the mac database is over 90 days old.
            if (datetime.now() - db_update_time).seconds > (60 * 60 * refresh_after_days):
                dl_wireshark_oui()
        f_in = open(file, 'r')
        oui = filter(None, (line.partition('#')[0].rstrip() for line in f_in))
        oui_dict = dict()
        for line in oui:
            part = line.partition('\t')
            if "IEEE Registration Authority" not in part[2]:
                mac_prefix = part[0].replace(':', '').replace('.', '')
                if len(mac_prefix) == 6:
                    oui_dict[mac_prefix] = part[2].replace('\t', ', ')
                else:
                    if mac_prefix[0:6] not in oui_dict.keys():
                        oui_dict[mac_prefix[0:6]] = dict()
                    oui_dict[mac_prefix[0:6]][part[0]] = part[2].replace('\t', ', ')
    except:
        import traceback
        print(traceback.format_exc())
    finally:
        return oui_dict


def oui_lookup(mac_address, oui_dict=None, file='wireshark_oui.txt', refresh_after_days=90):
    mac_address = mac_address.replace(':', '').replace('.', '')
    if oui_dict is None:
        oui_dict = load_wireshark_oui(file=file, refresh_after_days=refresh_after_days)
    if mac_address[0:6] in oui_dict.keys():
        if type(oui_dict[mac_address[0:6]]) == str:
            return oui_dict[mac_address[0:6]]
        else:
            for subnet, company in oui_dict[mac_address[0:6]].items():
                if mac_subnet(mac_address, subnet):
                    return company
    else:
        return "(Unknown)"