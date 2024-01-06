import vt

apiKey = "<API KEY>"

def check_vt_connection(api_key):
    """Check the VirusTotal API connection"""
    try:
        with vt.Client(api_key) as client:
            print("Connected to VirusTotal API was successful.\n")
            client.close()
            return True

    except vt.APIError as e:
        print("Failed to connect to VirusTotal API. Error:", e)
        client.close()
        return False

def check_file(file_path, api_key):
    """Check the file with VirusTotal"""
    try:
        with vt.Client(api_key) as client:
            # Open the file to be scanned
            try:
                f = open(file_path, 'rb')
                # Send the file for analysis
                analysis = client.scan_file(f, wait_for_completion=True)
                print(analysis.status)

                # Print the analysis results
                print("Analysis results:")
                endResults = analysis.results
                for name, result in endResults.items():
                    print(f"{name}: {result['category']}")
        
                client.close()

            except FileNotFoundError:
                print("File not found. Please check the file path.")
                client.close()

    except vt.APIError as e:
        print("Failed to connect to VirusTotal API. Error:", e)
        client.close()


if __name__ == '__main__':
    print("VirusTotal API connection check:")
    status = check_vt_connection(apiKey)
    if status == True:
        userFileInput = input("Provide File Path: ")
        check_file(userFileInput, apiKey)

    else:
        print("Please check your VirusTotal API key.")
