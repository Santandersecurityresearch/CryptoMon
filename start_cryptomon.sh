#!/bin/bash

# Step 1: Check if the user is root
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root. Please use sudo or switch to the root user."
  exit 1
fi

# Step 2: Prompt the user for the MongoDB password
read -sp "Please enter the MongoDB password: " MONGO_PASSWORD
echo

# Step 3: Export the necessary environment variables
export DB_URL="mongodb://cmon:$MONGO_PASSWORD@0.0.0.0:27017/cryptomon?retryWrites=true&w=majority"
export DB_NAME="cryptomon"

# Step 4: Ask the user if they want to load a PCAP file
read -p "Do you want to load a PCAP file? (y/n): " load_pcap

if [[ "$load_pcap" == "y" || "$load_pcap" == "Y" ]]; then
  # Step 5: Prompt the user for the directory containing PCAP files
  read -p "Please enter the directory where the PCAP files are located: " pcap_directory

  # Step 6: Check if the directory exists
  if [ -d "$pcap_directory" ]; then
    # Find all .pcap files in the directory
    pcap_files=($(find "$pcap_directory" -maxdepth 1 -type f -name "*.pcap"))

    # Check if any .pcap files were found
    if [ ${#pcap_files[@]} -eq 0 ]; then
      echo "No PCAP files found in the specified directory."
      exit 1
    else
      # Display available PCAP files and offer the user a selection
      echo "Available PCAP files:"
      select pcap_file in "${pcap_files[@]}"; do
        if [ -n "$pcap_file" ]; then
          echo "You selected PCAP file: $pcap_file"
          break
        else
          echo "Invalid selection. Please try again."
        fi
      done

      # Use loopback interface (lo) for replaying the PCAP file
      interface="lo"

      # Step 7: Start Cryptomon with the selected PCAP file
      echo "Replaying PCAP file on loopback interface..."
      python3 ./cryptomon.py --pcap "$pcap_file" -i "$interface" &
    fi
  else
    echo "Error: The specified directory does not exist."
    exit 1
  fi
else
  # Step 8: Show the available network interfaces and prompt the user to select one
  echo "Available network interfaces:"
  interfaces=$(ls /sys/class/net)
  select interface in $interfaces; do
    if [ -n "$interface" ]; then
      echo "You selected interface: $interface"
      break
    else
      echo "Invalid selection. Please try again."
    fi
  done

  # Step 9: Start Cryptomon with the selected interface
  echo "Starting Cryptomon with interface $interface..."
  python3 ./cryptomon.py -i "$interface" &
fi

# Step 10: Start the API
echo "Starting the API..."
python3 ./api.py &

# Give the API a few seconds to start
sleep 5

# Step 11: Inform the user to open the URL
echo "Please open the following URL in your browser:"
echo "http://0.0.0.0:8000/docs#/"

# End of script
