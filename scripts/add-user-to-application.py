import requests, os

class Verify:
    bearerToken = ""
    verifyURL = os.environ.get('VERIFY_URL', "")
    applicationName = os.environ.get('APPLICATION_NAME', "")[0:50]
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
    
    def getApplicationID(self, name) -> int:
        url = "{}/v1.0/applications".format(self.verifyURL)

        headers = {
            "accept": "application/json",
            "content-type": "*/*",
            "Authorization": "Bearer {}".format(self.bearerToken)
        }
        
        response = requests.get(url, headers=headers)

        applications = response.json()['_embedded']['applications']
        for application in applications:
            if application['name'] != name:
                continue
            applicationLink = application['_links']['self']['href']
            applicationLinkArray = applicationLink.split("/")
            length = len(applicationLinkArray)
            return applicationLinkArray[length - 1]
        return None

    def updateEntitlement(self, userId, applicationId):

        url = "{}/v1.0/owner/applications/{}/entitlements".format(self.verifyURL, applicationId)
        payload = { "additions": [{ "assignee": {
                "subjectType": "user",
                "subjectId": userId
            } }] 
        }
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "Authorization": "Bearer {}".format(self.bearerToken)
        }

        response = requests.post(url, json=payload, headers=headers)


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
    
    def importUser(self, email: str):
        applicationID = self.getApplicationID(self.applicationName)
        if applicationID is None:
            raise Exception("Unable to get application ID")

        userID = self.getUser(email)
        if userID is not None:
            print("User already exists, exiting...")
            return ""

        self.updateEntitlement(userID, applicationID)

userEmail = os.environ.get('TZ_EMAIL', "")
if userEmail == "":
    raise Exception("User email cannot be empty!")
verify = Verify()
verify.importUser(userEmail)