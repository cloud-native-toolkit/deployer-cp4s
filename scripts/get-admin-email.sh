if [[ -z "$(params.verify-admin-email)" ]]; then
    tz_api_token=$(oc get secret tz-user-email -o go-template='{{index .data "apiKey" | base64decode}}')
    if [[ -z $tz_api_token ]]; then
        echo "User email is not set. Please set the User Email and rerun this pipeline."
        exit 1
    fi 
else
    email="$(params.verify-admin-email)"
fi
echo $email | tee $(results.output.path)