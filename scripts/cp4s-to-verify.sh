#!/usr/bin/env bash
# cp4s-to-verify.sh
# David Druker, IBM
# 2023-03-23
# v4.72


# 0. marshall and test environment variables
# 1. get ibm-common-services token [cs api]
# 2. enable saml in cs [cs api]
# 3. download cs SAML metadata [cs api]
# 4. extract urls and certs with xslt [command line]
# 5. get verify token [verify api]
# 6. upload signer and encryption certs to verify [verify api]
# 7. create application in verify and add entitlements [verify api]
# 8. download verify SAML metadata [verify api]
# 9. upload verify SAML metadata to cs [cs api]
# 10. register connection in cs [cs api]

#set -e

#-----------------------------------------------------------#
# 0. marshall and test environment variables

# Export the following variables into your shell environment. See, for example, https://github.ibm.com/dgdruker/cp4s-scripts/blob/master/gitops_vars_template.sh

# VERIFY_APP_NAME=<OPTIONAL name for Verify app; must be unique in Verify instance; calculated from FQDN if not supplied>
# FQDN=<REQUIRED; CP4S FQDN=isc-default-route.<CP4S OCP NS>=URL for CP4S web user interface>
# VERIFY_URL=<REQUIRED URL of IBM Security Verify instance> 
# VERIFY_CLIENT_ID=<REQUIRED Verify API client id> 
# VERIFY_CLIENT_SECRET=<REQUIRED Verify API client secret> 
# SCRIPTS=<OPTIONAL file system folder holding other needed scripts; only 'saml-stylesheet.xml' in this case; put it in local folder otherwise>

# (Login to OpenShift cluster before running this script.)

CPROUTE=$(oc get routes cp-console -n ibm-common-services -o jsonpath='{.spec.host}' | awk '{print $1}') # get ibm-common-services route
CPADMIN=$(oc get secret platform-auth-idp-credentials -o jsonpath='{.data.admin_username}' -n ibm-common-services | base64 -d | awk '{print $1}')
CPPASSWORD=$(oc get secret platform-auth-idp-credentials -o jsonpath='{.data.admin_password}' -n ibm-common-services | base64 -d | awk '{print $1}')

export CPROUTE=$CPROUTE
export CPURL="https://${CPROUTE}"
export CPADMIN=$CPADMIN
export CPPASSWORD=$CPPASSWORD

export APPNAME=${VERIFY_APP_NAME:-${FQDN:0:50}}

echo -e "\nTesting that all needed inputs available..."
if [[ $(echo -n "$FQDN" | wc -c) -lt 6 ]]; then
  echo -e "FQDN not defined. Exiting.\n"
  exit
fi
if [[ $(echo "$VERIFY_URL"|grep -c 'https') -ne 1 ]]; then 
  echo -e "VERIFY_URL not defined or not a URL. Exiting.\n"
  exit
fi
if [[ $(echo -n  "$VERIFY_CLIENT_ID" | wc -c) -lt 36 ]]; then
  echo -e "VERIFY_CLIENT_ID not defined or not defined correctly. Exiting.\n"
  exit
fi
if [[ $(echo -n  "$VERIFY_CLIENT_SECRET" | wc -c) -lt 10 ]]; then
  echo -e "VERIFY_CLIENT_SECRET not defined or not defined correctly. Exiting.\n"
  exit
fi
if [ -f "$SCRIPTS/saml-stylesheet.xml" ]; then
  STYLESHEET=$SCRIPTS/saml-stylesheet.xml
elif [ -f "saml-stylesheet.xml" ]; then
  STYLESHEET=./saml-stylesheet.xml
else
  echo -e "saml-stylesheet.xml not found. Exiting.\n"
  exit
fi
echo -e "We are good to go."


#------------functions-------------
cleanupFS(){
  echo -e "\nRemoving common-services artifacts"

  echo -e "\nDisabling ibm-common-services SAML"
  SAML_MGMT_URL=${CPURL}/idmgmt/v1/saml/management
  { curl -k -s -X PUT "$SAML_MGMT_URL" --header "Authorization: Bearer $ACCESS_TOKEN" \
  --header 'Content-Type: application/json' -d '{"enable": false}' > /dev/null; } 2>&1
}
#----------end functions-----------

echo -e "\nIntegrating IBM Security Verify with $FQDN; creating application $APPNAME in $VERIFY_URL"

#-----------------------------------------------------------#
# 1. get ibm-common-services token
echo -e "\nGetting ibm-common-services authorization token"
IDENTITYTOKEN_URL=${CPURL}/idprovider/v1/auth/identitytoken
ACCESS_TOKEN=$(curl -k -s -X POST -H "Content-Type: application/x-www-form-urlencoded" \
-d "grant_type=password&username=${CPADMIN}&password=${CPPASSWORD}&scope=openid" \
--url "$IDENTITYTOKEN_URL"| jq -r .access_token)
if [[ $(echo -n  "$ACCESS_TOKEN" | wc -c) -ne 1024 ]]; then
  echo -e "ACCESS_TOKEN not created. Exiting.\n"
  exit
fi

# check for existing registration
echo -e "\nChecking for existing ibm-common-services registration"
SAML_ATTR_URL=${CPURL}/idprovider/v2/auth/idsource/registration
if [ "$(curl -k -s -X GET --header "Authorization: Bearer $ACCESS_TOKEN" \
    "$SAML_ATTR_URL"|jq -r '.idp[].protocol')" == 'saml' ]; then
  echo "existing SAML registration found"
  exit 1
fi

#-----------------------------------------------------------#
# 2. enable saml in cs [cs api]
echo -e "\nEnabling ibm-common-services SAML service provider"
SAML_MGMT_URL=${CPURL}/idmgmt/v1/saml/management
{ curl -k -s -X PUT "$SAML_MGMT_URL" --header "Authorization: Bearer $ACCESS_TOKEN" \
--header 'Content-Type: application/json' -d '{"enable": true}' > /dev/null; } 2>&1
#to do: test
sleep 5

#-----------------------------------------------------------#
# 3. download cs SAML metadata [cs api]
echo -e "\nDownloading ibm-common-services SAML metadata"
SAML_DOWNLOAD_URL=${CPURL}/idprovider/v3/saml/metadata/defaultSP
curl -k -s -X GET "$SAML_DOWNLOAD_URL" \
--header "Authorization: Bearer $ACCESS_TOKEN" > cs_saml_metadata.xml
# to do: test

#-----------------------------------------------------------#
# 4. extract urls and certs with xslt [command line]
echo -e "\nRunning XSLT processor on ibm-common-services metadata"
xsltproc "$STYLESHEET" cs_saml_metadata.xml
ENTITY_URL=entity.url
ACS_URL=acs.url
# to do: test

#-----------------------------------------------------------#
# 5. get verify token [api]
echo -e "\nGetting IBM Security Verify access token"
VERIFY_TOKEN_URL=$VERIFY_URL/v1.0/endpoint/default/token
VERIFY_ACCESS_TOKEN=$(curl -s -X POST "$VERIFY_TOKEN_URL" -d "client_id=${VERIFY_CLIENT_ID}&client_secret=${VERIFY_CLIENT_SECRET}&grant_type=client_credentials"|jq -r .access_token)
if [[ $(echo -n  "$VERIFY_ACCESS_TOKEN" | wc -c) -lt 40 ]]; then
  echo -e "VERIFY_ACCESS_TOKEN not created or not created correctly. Exiting.\n"
  cleanupFS
  exit
fi

# test that application not already present
echo -e "\nTesting if Verify application already present"
APPTEST="$(curl -s --url "${VERIFY_URL}"/v1.0/applications \
    --header 'Accept: application/json' --header "Authorization: Bearer $VERIFY_ACCESS_TOKEN" \
    | jq -r "._embedded.applications[] | select(.name == \"$APPNAME\") | .applicationState")" 

if [ -n "$APPTEST" ]; then
  echo "duplicate application"
  exit 1 
fi
# to do: test

#-----------------------------------------------------------#
# 6. upload signer and encryption certs to verify [verify api]
echo -e "\nUploading signer and encryption certs extracted from ibm-common-services to Verify"
#FLATAPPNAME="$(echo "${APPNAME}"| sed -e 's/[-.]/_/g')"
FLATAPPNAME=${APPNAME//[.-]/_}

SIGNER_LABEL=${FLATAPPNAME}_signer
ENCRYPTION_LABEL=${FLATAPPNAME}_encryption

generate_cert_data()
{ 
  local CERT="${1:-$VERIFY_CERT}" 
  local LABEL="${2:-$VERIFY_CERT_LABEL}" 
  cat<<EOF
{
    "cert": "$(cat "$CERT")",
    "label": "$LABEL"
}
EOF
}

curl -s --request POST \
     --url "$VERIFY_URL/v1.0/signercert" \
     --header 'Accept: */*' \
     --header "Authorization: Bearer $VERIFY_ACCESS_TOKEN" \
     --header 'Content-Type: application/json' \
     --data "$(generate_cert_data "signer.pem" "$SIGNER_LABEL")"
# to do: test

curl -s --request POST \
     --url "$VERIFY_URL/v1.0/signercert" \
     --header 'Accept: */*' \
     --header "Authorization: Bearer $VERIFY_ACCESS_TOKEN" \
     --header 'Content-Type: application/json' \
     --data "$(generate_cert_data "encryption.pem" "$ENCRYPTION_LABEL")"
# to do: test


sleep 3
#-----------------------------------------------------------#
# 7. create application in verify and add entitlements [verify api]
echo -e "\nChecking for existence of username_lc attribute and creating if needed"
# check for existence of username_lc and return id if found
LC_ATT_ID=$(curl -s --url "$VERIFY_URL"/v1.0/attributes?'search=name="username_lc"' \
  --header 'Accept: application/json' \
  --header "Authorization: Bearer $VERIFY_ACCESS_TOKEN" \
  |jq -r ".[].id")
# to do: test

# if username_lc not found, create it and return id
if [ -z "$LC_ATT_ID" ]; then 
  LC_ATT_ID=$(curl -s --url "$VERIFY_URL"/v1.0/attributes \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --header "Authorization: Bearer $VERIFY_ACCESS_TOKEN" --data '
  {
    "name": "username_lc",
    "description": "Lowercased email needed by CP4S",
    "sourceType": "static",
    "datatype": "string",
    "tags": [
      "sso"
    ],
    "function": {
      "custom": "user.emails[0].value.toLower()"
    }
  }' \
  |jq -r '.id')
fi
# to do: test
sleep 3
getIdentitySourceID() 
{
  identityID=$(curl --location 'https://cp4s-techzone.verify.ibm.com/v1.0/identitysources?search=instanceName%20%3D%20%22IBMid%22' \
    --header 'Accept: */*' \
    --header 'Content-Type: application/json' \
    --header "Authorization: Bearer $VERIFY_ACCESS_TOKEN" \
  )

  # Parse JSON and extract the id field
  local id=$(echo "$identityID" | jq -r '.identitySources[0].id')
  # Return the extracted id
  echo "$id"
}

echo -e "\nGenerating Verify application data"
generate_verify_app_data()
{ 
  local NAME="$APPNAME"
  local DESCRIPTION="$APPNAME"
  local ACS; ACS="$(cat $ACS_URL)"
  local ENTITY; ENTITY="$(cat $ENTITY_URL)"
  local NAMEID="$LC_ATT_ID"
  local SIGNER_CERT="$SIGNER_LABEL"
  local ENCRYPTION_CERT="$ENCRYPTION_LABEL"
  local TARGET_URL="https://${FQDN}"
  local IDENTITY_ID=$(getIdentitySourceID)
  cat<<EOF
{
  "visibleOnLaunchpad": true,
  "applicationState": true,
  "name": "$NAME",
  "templateId": "1",
  "description": "$DESCRIPTION",
  "providers": {
    "saml": {
      "assertionConsumerService": [
        {
          "url": "$ACS",
          "index": 0,
          "default": true
        }
      ],
      "properties": {
        "companyName": "IBM",
        "providerId": "$ENTITY",
        "signAuthnResponse": "true",
        "generateUniqueID": "true",
        "uniqueID": "true",
        "signatureAlgorithm": "RSA-SHA256",
        "defaultNameIdFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "ici_reserved_subjectNameID": "$NAMEID",
        "signatureValidationKeyIdentifier": "$SIGNER_CERT",
        "validateLogoutRequest": "true",
        "validateLogoutResponse": "true",
        "encryptAssertion": "true",
        "encryptionKeyIdentifier": "$ENCRYPTION_CERT",
        "blockEncryptionAlgorithm": "AES-256",
        "encryptionKeyTransportAlgorithm": "RSA-OAEP",
        "validateAuthnRequest": "true"
      }
    },
    "sso": {
      "targetUrl": "$TARGET_URL",
      "userOptions": "saml",
      "idpInitiatedSSOSupport": "true"
    }
  }
}
EOF
}


echo -e "\nUploading Verify application data to create app"
{ curl -s --request POST \
  --url "$VERIFY_URL"/v1.0/applications  \
  --header 'Accept: application/json' \
  --header 'Content-Type: application/json' \
  --header "Authorization: Bearer $VERIFY_ACCESS_TOKEN" \
  --data "$(generate_verify_app_data "$@")" > /dev/null; } 2>&1 
# to do: test
sleep 3

# add birthright entitlement
echo -e "\nAdding birthright entitlement for users of Verify app"
APPLICATIONID=$(curl -s --request GET \
  --url "${VERIFY_URL}"/v1.0/applications \
  --header 'Accept: application/json' --header "Authorization: Bearer $VERIFY_ACCESS_TOKEN" \
  | jq -r "._embedded.applications[] | select(.name == \"$APPNAME\") | ._links.self.href"  \
  | sed -e 's#/appaccess/v1.0/applications/##')
# to do: test

echo $APPLICATIONID
VERIFY_ENTITLEMENTS_URL="${VERIFY_URL}/v1.0/owner/applications/$APPLICATIONID/entitlements"

echo $(curl -s --request POST \
  --url "$VERIFY_ENTITLEMENTS_URL" \
  --header 'Accept: application/json' \
  --header 'Content-Type: application/json' \
  --header "Authorization: Bearer $VERIFY_ACCESS_TOKEN" \
  --data '
{
  "requestAccess": false,
  "birthRightAccess": true
}')
# to do: test

# confirm entitlements
#curl --request GET \
#  --url $VERIFY_ENTITLEMENTS_URL \
#  --header 'Accept: application/json' \
#  --header "Authorization: Bearer $VERIFY_ACCESS_TOKEN"


#-----------------------------------------------------------#
# 8. download verify SAML metadata [verify api]
echo -e "\nDownloading Verify SAML metadata"
VERIFY_METADATA="verify_federation_metadata.xml"

APPACCESS=$(curl -s --request GET \
  --url "${VERIFY_URL}"/v1.0/applications \
  --header 'Accept: application/json' --header "Authorization: Bearer $VERIFY_ACCESS_TOKEN" \
  | jq -r "._embedded.applications[] | select(.name == \"$APPNAME\") | ._links.self.href")
# to do: test

UNIQUEID=$(curl -s --request GET --url \
  "${VERIFY_URL}""${APPACCESS}" \
  --header 'Accept: application/json' --header "Authorization: Bearer $VERIFY_ACCESS_TOKEN" \
  | jq -r '.providers.saml.properties.uniqueID')
# to do: test

curl -s --request GET \
  --url "$VERIFY_URL/v1.0/saml/federations/saml20ip/metadata?virtualId=${UNIQUEID}&keyLabel=server" \
  --header 'Accept: application/json' --header "Authorization: Bearer $VERIFY_ACCESS_TOKEN" \
  | jq -r '.result' > "$VERIFY_METADATA"
# to do: test

#-----------------------------------------------------------#
# 9. upload Verify SAML metadata to cs [cs api]

echo -e "\nUploading Verify SAML metadata to ibm-common-services"
SAML_UPLOAD_URL=${CPURL}/idmgmt/v1/saml/upload
{ curl -k -s -X POST "$SAML_UPLOAD_URL" \
  --header "Authorization: Bearer $ACCESS_TOKEN" \
  --form "data=@$VERIFY_METADATA" > /dev/null; } 2>&1
# to do: test

# check saml
#SAML_STATUS_URL=${CPURL}/idmgmt/v1/saml/status
#curl -k -X GET --header "Authorization: Bearer $ACCESS_TOKEN" $SAML_STATUS_URL

#-----------------------------------------------------------#
# 10. register connection in cs [cs api]

echo -e "\nGenerating ibm-common-services registration data"
generate_registration_data()
{
  cat <<EOF
{
  "name": "verify-registration",
  "description": "verify-registration",
  "protocol": "saml",
  "idp_type": "isv",
  "scim": "yes",
  "scim_base_path": "${VERIFY_URL}/v2.0/",
  "token_attribute_mappings": {
    "uid":"uid",
    "first_name":"given_name",
    "last_name":"family_name", 
    "groups": "groupIds", 
    "email":"email"
  },
  "jit": "no",
  "scim_attribute_mappings":{
    "user":{
      "email": "email",
      "principalName":"userName",
      "givenName":"name.givenName",
      "firstName":"first_name",
      "middleName":"name.middleName",
      "familyName":"name.familyName",
      "formatted":"name.formatted",
      "displayName": "name.formatted"
    },
    "group":{
      "principalName":"displayName",
      "created":"meta.created",
      "lastModified":"meta.lastModified"
    }
  },
  "config": {
      "grant_type": "client_credentials",
      "token_url": "${VERIFY_URL}/v1.0/endpoint/default/token",
      "client_id": "$VERIFY_CLIENT_ID",
      "client_secret":"$VERIFY_CLIENT_SECRET"
  },
  "status": "enabled"
} 
EOF
}

echo -e "\nUploading registration data and creating registration"
SAML_ATTR_URL=${CPURL}/idprovider/v2/auth/idsource/registration
{ curl -k -s \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -X POST --data "$(generate_registration_data)" "$SAML_ATTR_URL" > /dev/null; } 2>&1 
# to do: test

# 10a. confirm registration and saml status
#curl -k -X GET --header "Authorization: Bearer $ACCESS_TOKEN" $SAML_ATTR_URL|jq

echo -e "\nVerify integration complete\n"

echo -e "If initial SAML login fails, likely solution is to perform following steps:"
echo -e "> oc scale deployment isc-entitlements --replicas=0"
echo -e "> oc get pods -lname=isc-entitlements # check that all pods terminated" 
echo -e "> No resources found in cp4s namespace. # <--- look for this " 
echo -e "> oc scale deployment isc-entitlements --replicas=2"
echo -e "> oc get pods -lname=isc-entitlements # check that containers in both pod running" 
echo -e "> isc-entitlements-xxxx-yyyy 1/1 ....  # <--- look for two of these" 

#------------------------------------------------#
# additional API calls

# get list of existing certs
#curl --request GET \
#  --url $VERIFY_URL/v1.0/signercert --header 'Accept: application/json' --header "Authorization: Bearer $VERIFY_ACCESS_TOKEN" \
#  | jq '.[].label'


# get all existing applications
#curl --request GET \
#  --url $VERIFY_URL/v1.0/applications \
#  --header 'Accept: application/json' --header "Authorization: Bearer $VERIFY_ACCESS_TOKEN" |jq  "._embedded.applications[].name" 


# more commands. not used
#SAML_STATUS_URL=${CPURL}/idmgmt/v1/saml/status
#curl -k -X GET --header "Authorization: Bearer $ACCESS_TOKEN" $SAML_STATUS_URL

#curl -k -X GET --header "Authorization: Bearer $ACCESS_TOKEN" "$CPURL/idmgmt/identity/api/v1/directory/ldap/list"