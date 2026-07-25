import urllib.request

def get_bitcoin_raw_hex(txid):
    # Construct the API URL for the raw blockstream transaction endpoint
    url = f"https://blockstream.info{txid}/hex"
    
    try:
        # Send the GET request to the API
        with urllib.request.urlopen(url) as response:
            if response.status == 200:
                raw_hex = response.read().decode('utf-8')
                return raw_hex
            else:
                return f"Error: Received HTTP status code {response.status}"
    except Exception as e:
        return f"An error occurred: {e}"

# Example Usage: Replace with your actual 64-character Bitcoin TXID
txid_to_check = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
bitcoin_hex = get_bitcoin_raw_hex(txid_to_check)

print("Raw Transaction Hex:")
print(bitcoin_hex)
