import requests, json, os

class Verify:
    bearerToken = ""
    verifyURL = os.environ.get('VERIFY_URL', "")
    def __init__(self) -> None:
        self.bearerToken = self.getBearerToken()
        pass

    def getBearerToken(self) -> str:
        clientID = os.environ.get('VERIFY_CLIENT_ID', "")
        clientSecret = os.environ.get('VERIFY_CLIENT_SECRET', "")
        bearerURL = "{}/v1.0/endpoint/default/token".format(self.verifyURL)
        headers = {"accept": "application/json"}

        response = requests.post(bearerURL, headers=headers, data={"grant_type": "client_credentials"}, auth = (clientID, clientSecret))

        authResponse = response.json()

        bearerToker = authResponse.get('access_token')
        return bearerToker
        
    def createUser(self, email: str):
        userID = self.getUser(email)
        if userID is not None:
            print("User already exists, exiting...")
            return ""
        userID = self.addUser(email)
        if userID is None:
            print("Error creating user...")
            exit(1)
        print("User created in Verify!")


    def addUser(self, email):
        url = "{}/v2.0/Users".format(self.verifyURL)
        payload = {
            "name": { 
                "givenName": "Demo" ,
                "familyName": "User"
            },
            "emails":[ {"type":"work", "value": email} ],
            "schemas": [
              "urn:ietf:params:scim:schemas:core:2.0:User",
              "urn:ietf:params:scim:schemas:extension:ibm:2.0:User"
            ],
            "urn:ietf:params:scim:schemas:extension:ibm:2.0:User": {
              "userCategory": "federated",
              "twoFactorAuthentication": "false",
              "realm": "www.ibm.com",
              "unqualifiedUserName": email + "@gmail.com"
            },
            "active": "true",
            "userName": email + "@www.ibm.com"
        }
        headers = {
            "accept": "application/scim+json",
            "content-type": "*/*",
            "Authorization": "Bearer {}".format(self.bearerToken)
        }
        try:
            response = requests.post(url, data=json.dumps(payload), headers=headers).json()
            userID = response['id']
        except Exception:
            userID = None
            
        return userID

    def getUser(self, email: str):
        url = "{}/v2.0/Users?filter=emails+eq+%22{}%22".format(self.verifyURL, email)

        headers = {
            "accept": "application/scim+json",
            "content-type": "*/*",
            "Authorization": "Bearer {}".format(self.bearerToken)
        }
        try:
            response = requests.get(url, headers=headers).json()
            userInfo = response.get("Resources")
            if userInfo == None or not userInfo[0]['id']:
                raise Exception("User does not exist")
            userId = userInfo[0]['id']
        except Exception:
            userId = None
        return userId

userEmail = os.environ.get('TZ_EMAIL', "")
if userEmail == "":
    raise Exception("User email cannot be empty!")
verify = Verify()
verify.createUser(userEmail)