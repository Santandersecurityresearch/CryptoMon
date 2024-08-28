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

# Step 4: Show the available network interfaces and prompt the user to select one
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

# Step 5: Start the cryptomon program with the selected interface
echo "Starting Cryptomon with interface $interface..."
python3 ./cryptomon.py -i "$interface" &

# Step 6: Start the API
echo "Starting the API..."
python3 ./api.py &

# Give the API a few seconds to start
sleep 5

# Inform the user to open the URL
echo "Please open the following URL in your browser:"
echo "http://0.0.0.0:8000/docs#/"

# End of script

