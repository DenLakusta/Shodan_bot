


def hendler_priv_ip(ip):
    if ip.split('.')[0] == '192' and ip.split('.')[1] == '168' or ip.split('.')[0] == '172' and ip.split('.')[1] == '76' or ip.split('.')[0] == '10' and ip.split('.')[1] == '10' or ip == '127.0.0.1' or ip == '0.0.0.0':
        print("Please enter public IP")
    else:
        print('scrip works')

def main():
    print(hendler_priv_ip(''))


if __name__ == '__main__':
    main()
