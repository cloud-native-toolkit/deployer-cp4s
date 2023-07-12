#!/usr/bin/env bash
# cp4s-unverify.sh
# David Druker, IBM
# 2023-03-23
# v2.2

# 0. process inputs
# 1. get ibm-common-services token [cs api]
# 2. disable saml in cs [cs api]
# 3. remove connection in cs [cs api]
# 4. get verify token [verify api]
# 5. remove signer and encryption certs to verify [verify api]
# 6. remove application in verify and add entitlements [verify api]


# set -x

# REQUIRED: export FQDN=<FQDN of CP4S into shell environment>
# REQUIRED: log into CP4S OpenShift cluster
FQDN="cp-console.apps.ocp-060000gtqm-4ldg.cloud.techzone.ibm.com"
VERIFY_URL="https://cp4s-techzone.verify.ibm.com"
VERIFY_CLIENT_ID="6957d942-8480-4b8e-8fba-27ec80958954"
VERIFY_CLIENT_SECRET="13oeZ3XM4K"

CPROUTE=$(oc get routes cp-console -n ibm-common-services -o jsonpath='{.spec.host}' | awk '{print $1}') # get ibm-common-services route
CPADMIN=$(oc get secret platform-auth-idp-credentials -o jsonpath='{.data.admin_username}' -n ibm-common-services | base64 -d | awk '{print $1}')
CPPASSWORD=$(oc get secret platform-auth-idp-credentials -o jsonpath='{.data.admin_password}' -n ibm-common-services | base64 -d | awk '{print $1}')

export CPROUTE=$CPROUTE
export CPURL="https://${CPROUTE}"
export CPADMIN=$CPADMIN
export CPPASSWORD=$CPPASSWORD

export APPNAME=${VERIFY_APP_NAME:-${FQDN:0:50}}


#-----------------------------------------------------------#
# 1. get ibm-common-services token
echo -e "\nGetting ibm-common-services authorization token"
IDENTITYTOKEN_URL=${CPURL}/idprovider/v1/auth/identitytoken
ACCESS_TOKEN=$(curl -k -s -X POST -H "Content-Type: application/x-www-form-urlencoded" \
-d "grant_type=password&username=${CPADMIN}&password=${CPPASSWORD}&scope=openid" \
--url $IDENTITYTOKEN_URL| jq -r .access_token)

#------------------------------------------------#
# 2. disable saml in cs [cs api]
echo -e "\nDisabling ibm-common-services SAML"
SAML_MGMT_URL=${CPURL}/idmgmt/v1/saml/management
curl -k -s -X PUT $SAML_MGMT_URL --header "Authorization: Bearer $ACCESS_TOKEN" \
--header 'Content-Type: application/json' -d '{"enable": false}' 2>&1 1>/dev/null

#------------------------------------------------#
# 3. remove registration in cs [cs api]
echo -e "\nRemoving ibm-common-services registration"
SAML_ATTR_URL=${CPURL}/idprovider/v2/auth/idsource/registration
REGNAME=$(curl -k -s -X GET --header "Authorization: Bearer $ACCESS_TOKEN" $SAML_ATTR_URL|jq -r '.idp[].name')

curl -k -s -X DELETE "${CPURL}/idprovider/v2/auth/idsource/registration/$REGNAME" \
  --header "Authorization: Bearer $ACCESS_TOKEN"  2>&1 1>/dev/null

#------------------------------------------------#
# 4. get verify token [verify api]
echo -e "\nGetting Verify access token"
VERIFY_TOKEN_URL=$VERIFY_URL/v1.0/endpoint/default/token
VERIFY_ACCESS_TOKEN=$(curl -s -X POST $VERIFY_TOKEN_URL -d "client_id=${VERIFY_CLIENT_ID}&client_secret=${VERIFY_CLIENT_SECRET}&grant_type=client_credentials"|jq -r .access_token)
VERIFY_ACCESS="Authorization: Bearer $VERIFY_ACCESS_TOKEN"

#------------------------------------------------#
# 5. remove signer and encryption certs to verify [verify api]
FLATAPPNAME="$(echo ${APPNAME}| sed -e 's/[-.]/_/g')"
SIGNER_LABEL=${FLATAPPNAME}_signer
ENCRYPTION_LABEL=${FLATAPPNAME}_encryption
ALT_SIGNER_LABEL=${APPNAME}_signer
ALT_ENCRYPTION_LABEL=${APPNAME}_encryption

echo -e "\nRemoving signer certificate $SIGNER_LABEL"
curl -s --request DELETE \
  --url $VERIFY_URL/v1.0/signercert/$SIGNER_LABEL \
  --header 'Accept: application/json' --header "Authorization: Bearer $VERIFY_ACCESS_TOKEN" >/dev/null

curl -s --request DELETE \
  --url $VERIFY_URL/v1.0/signercert/$ALT_SIGNER_LABEL \
  --header 'Accept: application/json' --header "Authorization: Bearer $VERIFY_ACCESS_TOKEN" >/dev/null

echo -e "\nRemoving encryption certificate $ENCRYPTION_LABEL"
curl -s --request DELETE \
  --url $VERIFY_URL/v1.0/signercert/$ENCRYPTION_LABEL \
  --header 'Accept: application/json' --header "Authorization: Bearer $VERIFY_ACCESS_TOKEN" >/dev/null
curl -s --request DELETE \
  --url $VERIFY_URL/v1.0/signercert/$ALT_ENCRYPTION_LABEL \
  --header 'Accept: application/json' --header "Authorization: Bearer $VERIFY_ACCESS_TOKEN"  >/dev/null

#echo -e "\nRemaining certificates in Verify tenant:"
#curl -s --request GET \
#  --url $VERIFY_URL/v1.0/signercert --header 'Accept: application/json' --header "Authorization: Bearer $VERIFY_ACCESS_TOKEN" \
#  | jq '.[].label'


#------------------------------------------------#
# 6. remove application in verify [verify api]
echo -e "\nRemove Verify application"
APP_ID=$(curl -s --url "${VERIFY_URL}"/v1.0/applications \
  --header 'Accept: application/json' --header "Authorization: Bearer $VERIFY_ACCESS_TOKEN" \
  | jq -r "._embedded.applications[] | select(.name == \"$APPNAME\") | ._links.self.href" \
  |sed -e 's#/appaccess/v1.0/applications/##')

curl -s --request DELETE \
  --url $VERIFY_URL/v1.0/applications/$APP_ID \
  --header 'Accept: application/json' --header "Authorization: Bearer $VERIFY_ACCESS_TOKEN"  2>&1 1>/dev/null

#echo -e "\nRemaining applications in Verify tenant"
#curl -s --request GET \
#  --url $VERIFY_URL/v1.0/applications \
#  --header 'Accept: application/json' --header "Authorization: Bearer $VERIFY_ACCESS_TOKEN" |jq  "._embedded.applications[].name" 

echo -e "\nCP4S to Verify integration removed\n "
# curl --url "${VERIFY_URL}"/v1.0/applications \
#   --header 'Accept: application/json' --header "Authorization: Bearer $VERIFY_ACCESS_TOKEN" \
#   | jq -r "._embedded.applications[] | select(.name == \"$APPNAME\") | ._links.self.href"

# curl --request DELETE \
#      --url $VERIFY_URL/v1.0/applications/$APP_ID
