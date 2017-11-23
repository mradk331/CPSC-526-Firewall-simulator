import sys
import os.path


# Reads the configuration file
def get_configuration(config_file):

    configuration_lines = []
    rules = []
    binary_address = ""

    # Default minimum for an ip is 32 bits of 0s
    min_ip = "".ljust(32, "0")

    # Max is 255 for each 8 bits indicated by 32 1's
    max_ip = "".ljust(32, "1")

    # Open file and read lines making sure to get rid of comments, whitespaces, tabs, etc.
    with open(config_file) as file:

        for line in file:

            configuration_rule = line.strip()

            if not configuration_rule.startswith("#"):

                configuration_lines.append(configuration_rule)

    file.close()

    counter = 0
    # Loop through config rules and create an array containing a dictionary for each of the 4 or 5 rules for each line
    while counter < len(configuration_lines):

        line_rule = configuration_lines[counter]
        line_rule = line_rule.split()

        if not (len(line_rule) == 4 or len(line_rule) == 5):
            print("Error: line " + str(counter) + " contains an incorrect amount of rules")
            quit()

        else:

            direction = line_rule[0]
            action = line_rule[1]
            ip_address = line_rule[2]
            ports = line_rule[3]

            # Split port numbers (if any)
            ports = ports.split(",")

            if len(line_rule) == 5:
                flag = line_rule[4]

                # Check if the flag is valid
                if flag != "established":
                    print("Line number " + str(counter + 1) + " contains an invalid flag: " + flag)
                    quit()

            try:
                # Split ip address and routing prefix
                ip_address = ip_address.split("/")

                # If a non wildcard address' length is 1 there is no routing prefix
                if len(ip_address) == 1:

                    if ip_address[0] != "*":

                        # Split each 8 bits of address
                        ip_address[0] = ip_address[0].split(".")

                        if len(ip_address[0]) == 4:

                            for ip in ip_address[0]:

                                # Check that each 8 bits of the address are within the correct range
                                if int(ip) < 0 or int(ip) > 255:
                                    print("Invalid ip address range has been provided on line " + str(counter + 1))
                                    quit()

                                # Otherwise we convert each 8 bits of address into binary
                                else:

                                    # The splice [2:] below gets rid of 0b created to indicate binary in python
                                    binary_address += str(bin(int(ip)))[2:].zfill(8)

                            # Set the minimum and maximum values of the ip address
                            # In this case, the min and max is the same because the routing prefix is all 32 bytes
                            min_ip = binary_address
                            max_ip = binary_address

                            # Re-initialize to 0
                            binary_address = ""

                        else:
                            print("Invalid ip address size provided on line " + str(counter + 1))
                            quit()

                    # If a wildcard is used, we do not change the min and max values for an ip address
                    elif ip_address[0] == "*":
                        min_ip = "".ljust(32, '0')
                        max_ip = "".ljust(32, '1')

                # Otherwise there is an routing prefix
                elif len(ip_address) == 2:

                    routing_prefix = ip_address[1]

                    # Check if the routing prefix is within correct range
                    if int(routing_prefix) < 0 or int(routing_prefix) > 32:
                        print("Invalid routing prefix provided on ip address on line " + str(counter + 1))
                        quit()

                    else:

                        # Split each 8 bits of address
                        ip_address[0] = ip_address[0].split(".")

                        if len(ip_address[0]) == 4:

                            for ip in ip_address[0]:

                                # Check that each 8 bits of the address are within the correct range
                                if int(ip) < 0 or int(ip) > 255:
                                    print("Invalid ip address range has been provided on line " + str(counter + 1))
                                    quit()

                                # Otherwise we convert each 8 bits of address into binary
                                else:

                                    # The splice [2:] below gets rid of 0b created to indicate binary in python
                                    binary_address += str(bin(int(ip)))[2:].zfill(8)

                            # Set the minimum and maximum values for the 32 bit ip address based on the provided
                            # routing prefix
                            # min-ip will set everything after the leading bits in ip address to 0's (min value)
                            # based on the prefix
                            min_ip = binary_address[:int(routing_prefix)].ljust(32, '0')

                            # max-ip will set everything after the leadings bits in ip address to 1's (max value)
                            # based on the prefix
                            max_ip = binary_address[:int(routing_prefix)].ljust(32, '1')

                            binary_address = ""


                        else:
                            print("Invalid ip address size provided on line " + str(counter + 1))
                            quit()

            except Exception as e:
                print("Invalid ip address number on line " + str(counter + 1))
                print(e)
                quit()

            if not (direction == "in" or direction == "out"):

                print("Line number " + str(counter + 1) + " contains an invalid direction: " + direction)
                quit()

            elif not (action == "accept" or action == "drop" or action == "reject"):

                print("Line number " + str(counter + 1) + " contains an invalid action: " + action)
                quit()

            # Try catch block in case configuration file has a non-integer provided as a port rule
            try:

                for port in ports:

                    # Check for wildcard
                    if port == "*":
                        pass

                    # Check for valid port range
                    elif int(port) < 0 or int(port) > 65535:

                        print("Line number " + str(counter + 1) + " contains an invalid port range: " + ports)
                        quit()

            except Exception as e:

                print("Invalid port number on line " + str(counter + 1))
                print(e)
                quit()

            if len(line_rule) == 5:
                rule_dictionary = {'direction': direction, 'action': action, 'min-ip': min_ip, 'max-ip': max_ip,
                                   'ports': ports, 'flag': flag}

            else:
                rule_dictionary = {'direction': direction, 'action': action, 'min-ip': min_ip, 'max-ip': max_ip,
                                   'ports': ports, 'flag': None}

            # Put dictionary in rules array
            rules.append(rule_dictionary)

        counter += 1

    return rules


def get_packets():

    packets = []
    binary_address = ""

    # Take count on the current line/packet we are reading from STDIN
    counter = 1

    # Read STDIN line by line, appending each packet in each line to an array
    for line in sys.stdin.readlines():

        packet = line.strip()

        # Split each field into elements in an array
        packet = packet.split()

        # Check if packet contains the valid number of fields
        if len(packet) != 4:
            print("Packet number " + str(counter) + " contains an invalid number of fields.")
            quit()

        direction = packet[0]
        ip_address = packet[1]
        port = packet[2]
        flag = packet[3]

        # Check if direction is valid
        if not (direction == "in" or direction == "out"):

            print("Packet number " + str(counter) + " contains an invalid direction." + direction)
            quit()

        try:

            # Split each 8 bits in the ip address into array elements
            ip_address = ip_address.split(".")

            if len(ip_address) != 4:
                print("Packet number " + str(counter) + " contains an invalid ip address size.")
                quit()

            for ip in ip_address:

                # Check that each 8 bits of the address are within the correct range
                if int(ip) < 0 or int(ip) > 255:
                    print("Packet number " + str(counter) + " contains an invalid ip address range: " + ip)
                    quit()

                # Otherwise we convert each 8 bits of address into binary
                else:

                    # The splice [2:] below gets rid of 0b created to indicate binary in python
                    binary_address += str(bin(int(ip)))[2:].zfill(8)

            # Check for valid port range
            if int(port) < 0 or int(port) > 65535:

                print("Packet number " + str(counter) + " contains an invalid port range: " + port)
                quit()

            # If the flag given is not 0 or 1 we indicate an error.
            if not (flag == "0" or flag == "1"):

                print("Packet number " + str(counter) + " contains an invalid flag: " + flag)
                quit()

        except Exception as e:
            print("Invalid packet format has been received on line " + str(counter))
            print(e)
            quit()

        counter += 1

        packet_dictionary = {'direction': direction, 'ip_address': binary_address, 'port': port, 'flag': flag}
        packets.append(packet_dictionary)

    return packets

# Filter the incoming and outgoing packets based on the established firewall rules
def filter_packets(rules, packets):



    print()


if __name__ == "__main__":

    config_filename = sys.argv[1]

    # Check if the file exists in directory
    if os.path.isfile(config_filename):

        # Read in the configuration from the file
        rules = get_configuration(config_filename)

        # Get the packets
        packets = get_packets()

        # Filter the packets
        filter_packets(rules, packets)

    else:

        print("The file you have provided does not exist.")